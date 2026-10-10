"""Leakage-aware retrospective evaluation of frozen, historical FIRST EPSS scores.

Outcome is *future first listing in the CISA KEV catalog*, NOT first exploitation.
Do not use the current CVE warehouse score / KEV flag to predict past dates.
Only past-dated EPSS CSV and later KEV dateAdded are examined. No fitting.
"""
from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import io
import json
import math
import re
from itertools import chain
import time
import urllib.request
import urllib.error
from datetime import date, timedelta
from pathlib import Path

# Immutable upstream public archive revision checked against the official repo.
EPSS_REPO = "empiricalsec/epss_scores"
EPSS_COMMIT = "df0307edc6e83b63538825ca70d8f46aab0b3df1"
EPSS_BASE = f"https://raw.githubusercontent.com/{EPSS_REPO}/{EPSS_COMMIT}"
# 17 consecutive first-of-month anchors. Dates and signal thresholds are fixed
# before seeing any evaluation outcomes. v4 vs v5 results are NEVER conflated.
ANCHORED_FILES = {
    "2025-04-01": (1825748, "48fe8e5da6071feb8b763ba811b94774553cba1c"),
    "2025-05-01": (1851185, "fe4bb6e01bf01704d9c52e0b40d54879ae02d77e"),
    "2025-06-01": (1874754, "95d804293b060809b84d23eabd44c90f05890733"),
    "2025-07-01": (1899113, "908c547bd80f91556b808945d4e793c9663c21f1"),
    "2025-08-01": (1921796, "0160b0268dd89a361b688e7345411d472009552a"),
    "2025-09-01": (1947223, "3b9170902742d881005d54cf2c33ce6c8c83f7d6"),
    "2025-10-01": (1977008, "06a303f001b55336feda850c724a8b64750aa7d9"),
    "2025-11-01": (2001479, "e6351f4caa86ed586af986fb9fd688a6012e7cf1"),
    "2025-12-01": (2023296, "57a1c073883b398bbebf9fdce829d673463bdd86"),
    "2026-01-01": (2055383, "cf90695c1a14fdb7c614124667484e7f6cc8ec4e"),
    "2026-02-01": (2085994, "8697de3f92763bdff76b1b7c8ecdfaaad44ed5b9"),
    "2026-03-01": (2119564, "dd291f22058b382a7c41b0ef91eeea73c8c79af9"),
    "2026-04-01": (2161319, "6a8fc0075d0220652494a91714506c3b491cee76"),
    "2026-05-01": (2200348, "9dc0c653d42c199bf46c0242d9a3785d62e6b55b"),
    "2026-06-01": (2247901, "d9215382e8f53e942c9c79d7b5224c58f1083449"),
    "2026-07-01": (2442935, "25f5fc934224f9eabf269bff5cad43da45cfc23a"),
    "2026-08-01": (2507180, "d85a2f7e7177dd42f058e27373e7b3b1e320170f"),
}
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
GIT_BLOB_SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
TOP_K = (100, 500, 1000)
HORIZONS = (7, 30)
THRESHOLDS = (0.05, 0.10, 0.20)
MIN_EPSS_ROWS = 100_000
MAX_GZIP = 10 * 1024 * 1024


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git_blob_sha(data: bytes) -> str:
    return hashlib.sha1(f"blob {len(data)}\0".encode("ascii") + data).hexdigest()


def verify_archive_bytes(day: str, compressed: bytes,
                         specifications: dict | None = None) -> None:
    entries = specifications if specifications is not None else ANCHORED_FILES
    if day not in entries:
        raise ValueError("Unapproved historic EPSS date")
    expected_size, expected_blob = entries[day]
    if (not GIT_BLOB_SHA1_RE.fullmatch(expected_blob)
            or len(compressed) != expected_size
            or git_blob_sha(compressed) != expected_blob):
        raise ValueError("Historical official EPSS Git blob/size mismatch")


def download_historic(day: str, folder: Path, *, opener=urllib.request.urlopen,
                      sleeper=time.sleep) -> tuple[Path, str]:
    """Pinned repository revision + Git blob SHA, not mutable current EPSS."""
    if day not in ANCHORED_FILES:
        raise ValueError("Unapproved historical score date")
    folder.mkdir(parents=True, exist_ok=True)
    local = folder / f"epss_scores-{day}.csv.gz"
    if local.is_symlink():
        raise ValueError("Refusing symlink historical EPSS")
    if local.is_file():
        payload = local.read_bytes()
        verify_archive_bytes(day, payload)
        return local, digest(payload)
    url = f"{EPSS_BASE}/{day[:4]}/epss_scores-{day}.csv.gz"
    last_error = None
    for attempt in range(3):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "ECLIPSE-HISTORICAL-EPSS-AUDIT/1.0"})
            with opener(req, timeout=90) as response:
                # Enforce compressed size bound even on absent Content-Length.
                payload = response.read(MAX_GZIP + 1)
            if len(payload) > MAX_GZIP:
                raise ValueError("EPSS daily compressed archive exceeds bounded budget")
            verify_archive_bytes(day, payload)
            tmp = local.with_suffix(local.suffix + ".tmp")
            try:
                tmp.write_bytes(payload)
                tmp.replace(local)
            finally:
                tmp.unlink(missing_ok=True)
            return local, digest(payload)
        except ValueError:
            raise  # Fail closed on unexpected/mutated archive; do not retry unknown bytes.
        except (OSError, urllib.error.URLError) as exc:
            last_error = exc
            if attempt < 2:
                sleeper((2, 5)[attempt])
    raise RuntimeError("Official historical EPSS download unavailable") from last_error


def read_kev(content: bytes, *, last_observed_date: date) -> tuple[dict[str, date], dict]:
    """CISA original catalog; dateAdded is a proxy label, not exploitation date."""
    if not 0 < len(content) <= 25 * 1024 * 1024:
        raise ValueError("Unexpected KEV catalog length")
    payload = json.loads(content)
    records = payload.get("vulnerabilities")
    if not isinstance(records, list) or len(records) < 1000:
        raise ValueError("Incomplete KEV catalog")
    if payload.get("count") != len(records):
        raise ValueError("CISA KEV catalog count mismatch")
    released = payload.get("dateReleased")
    if not isinstance(released, str):
        raise ValueError("CISA catalog release date missing")
    released_date = date.fromisoformat(released[:10])
    if released_date < last_observed_date:
        raise ValueError("KEV snapshot predates the last evaluation horizon")
    labels: dict[str, date] = {}
    for record in records:
        if not isinstance(record, dict):
            raise ValueError("Malformed CISA KEV record")
        name = record.get("cveID")
        if not isinstance(name, str) or not CVE_RE.fullmatch(name) or name in labels:
            raise ValueError("Duplicate/invalid CISA KEV identifier")
        added = date.fromisoformat(record["dateAdded"])
        if added > released_date:
            raise ValueError("KEV dateAdded after catalog release")
        labels[name] = added
    return labels, {"sha256": digest(content), "catalog_version": payload.get("catalogVersion"),
                    "catalog_date_released": released,
                    "catalog_rows": len(records),
                    "label_definition": "CISA KEV first catalog-registration date, NOT first exploit date"}


def read_daily_csv(raw: bytes, day: date, *, min_rows: int = MIN_EPSS_ROWS):
    """Reads a single original daily FIRST gzip, no latest score lookup."""
    if len(raw) > MAX_GZIP:
        raise ValueError("Historical EPSS archive too large")
    try:
        stream = gzip.open(io.BytesIO(raw), mode="rt", encoding="utf-8-sig", newline="")
        with stream as source:
            comments = []
            while True:
                header = source.readline()
                if not header:
                    raise ValueError("EPSS archive lacks CSV header")
                if not header.startswith("#"):
                    break
                comments.append(header)
            reader = csv.DictReader(chain([header], source))
            if not {"cve", "epss", "percentile"} <= set(reader.fieldnames or []):
                raise ValueError("Unexpected historical EPSS CSV schema")
            scored = []
            observed = set()
            for row in reader:
                cve = row.get("cve")
                if not isinstance(cve, str) or not CVE_RE.fullmatch(cve) or cve in observed:
                    raise ValueError("Malformed/duplicate historical EPSS CVE")
                observed.add(cve)
                p = float(row["epss"])
                pct = float(row["percentile"])
                if not (math.isfinite(p) and 0 <= p <= 1 and math.isfinite(pct) and 0 <= pct <= 1):
                    raise ValueError("Out-of-range historical EPSS probability/percentile")
                scored.append((p, cve))
    except (OSError, EOFError, UnicodeError, csv.Error) as exc:
        raise ValueError("Invalid historical EPSS gzip/CSV") from exc
    if len(scored) < min_rows:
        raise ValueError("Historical EPSS cohort suspiciously small")
    for comment in comments:
        for segment in comment.lstrip("#").split(","):
            key,sep,value = segment.strip().partition(":")
            if sep and key.strip().lower() == "score_date":
                if date.fromisoformat(value.strip()[:10]) != day:
                    raise ValueError("Historical EPSS file contains different score_date")
    return scored, {"raw_scored_rows": len(scored), "score_date": day.isoformat(),
                    "official_git_revision": EPSS_COMMIT,
                    "official_git_blob_sha1": ANCHORED_FILES.get(day.isoformat(), (None, None))[1]}


def _metrics(ranked: list[tuple[float, str]], hits: set[str], cutoff: int, anchor: date,
             kev_dates: dict[str, date]) -> dict:
    n = min(cutoff, len(ranked))
    selected = ranked[:n]
    identified = [(cve, (kev_dates[cve] - anchor).days) for _, cve in selected if cve in hits]
    prevalence = len(hits)/len(ranked) if ranked else None
    precision = len(identified)/n if n else None
    recall = len(identified)/len(hits) if hits else None
    return {"budget": cutoff, "evaluated_top": n, "hits": len(identified),
            "precision": precision, "recall_among_scored_future_kev": recall,
            "random_expected_hits": n*prevalence if prevalence is not None else None,
            "lift_vs_random": precision/prevalence if prevalence else None,
            "lead_days": [d for _,d in identified],
            "hit_examples": [cve for cve,_ in identified[:5]]}


def evaluate_day(day: date, scored: list[tuple[float, str]], labels: dict[str, date],
                 *, horizons: tuple[int, ...] = HORIZONS,
                 top_k: tuple[int, ...] = TOP_K,
                 thresholds: tuple[float, ...] = THRESHOLDS) -> dict:
    """No current warehouse attributes, CVSS, latest EPSS, future KEV flags or training."""
    previous = {cve for cve, added in labels.items() if added <= day}
    eligible = [(prob, cve) for prob, cve in scored if cve not in previous]
    if not eligible:
        raise ValueError("No eligible historical EPSS-scored CVEs")
    eligible.sort(key=lambda item: (-item[0], item[1]))
    result = {"as_of": day.isoformat(), "forecast_available_at": "after FIRST daily score release",
              "model_era": "EPSS_V4" if day < date(2026,6,15) else "EPSS_V5",
              "score_population": len(scored),"already_kev_as_of": len(scored)-len(eligible),
              "rankable_epss_scored_not_yet_kev":len(eligible),
              "evaluations": {}}
    for horizon in horizons:
        target = day + timedelta(days=horizon)
        added = {cve for cve,added_date in labels.items() if day < added_date <= target}
        scored_hits = added & {cve for _,cve in eligible}
        ranked_hit = scored_hits
        observations = {str(k):_metrics(eligible,ranked_hit,k,day,labels) for k in top_k}
        thresholds_out = {}
        for t in thresholds:
            # Rank is sorted descending; equal score explicitly included in threshold.
            chosen = [(p,cve) for p,cve in eligible if p >= t]
            nhit = sum(cve in ranked_hit for _,cve in chosen)
            thresholds_out[str(t)] = {"threshold":t,"selected":len(chosen),"hits":nhit,
               "precision": nhit/len(chosen) if chosen else None,
               "recall_among_scored_future_kev": nhit/len(ranked_hit) if ranked_hit else None}
        result["evaluations"][str(horizon)] = {
            "horizon_days":horizon,"through":target.isoformat(),
            "new_kev_all_catalog":len(added),
            "new_kev_rankable_in_historical_epss":len(ranked_hit),
            "new_kev_not_in_historical_epss":len(added)-len(ranked_hit),
            "base_rate_scored":len(ranked_hit)/len(eligible),
            "top_k": observations,"thresholds":thresholds_out}
    return result


def combine(day_reports: list[dict], horizon: int, group: str) -> dict:
    selected = [x for x in day_reports if group == "ALL" or x["model_era"] == group]
    by_anchor = [x["evaluations"][str(horizon)] for x in selected]
    result={"monthly_anchor_dates":[x["as_of"] for x in selected],
            "new_kev_all_catalog":sum(x["new_kev_all_catalog"] for x in by_anchor),
            "new_kev_rankable_in_historical_epss":sum(x["new_kev_rankable_in_historical_epss"] for x in by_anchor),
            "total_rankable_cve_date_decisions":sum(x["rankable_epss_scored_not_yet_kev"] for x in selected),
            "total_kev_catalog_coverage":None, "top_k":{}, "thresholds":{}}
    all_pos=result["new_kev_all_catalog"]
    result["total_kev_catalog_coverage"]=(result["new_kev_rankable_in_historical_epss"]/all_pos if all_pos else None)
    scored_pos=result["new_kev_rankable_in_historical_epss"]
    for k in TOP_K:
        hits=sum(a["top_k"][str(k)]["hits"] for a in by_anchor)
        reviewed=sum(a["top_k"][str(k)]["evaluated_top"] for a in by_anchor)
        result["top_k"][str(k)]={"hits":hits,"reviewed":reviewed,
          "precision":hits/reviewed if reviewed else None,
          "recall_among_scored_future_kev":hits/scored_pos if scored_pos else None,
          "random_expected_hits":sum(a["top_k"][str(k)]["random_expected_hits"] for a in by_anchor),
          "lift_vs_random": (hits/sum(a["top_k"][str(k)]["random_expected_hits"] for a in by_anchor)
                             if sum(a["top_k"][str(k)]["random_expected_hits"] for a in by_anchor) > 0 else None)}
    for t in THRESHOLDS:
        tkey=str(t)
        hits=sum(a["thresholds"][tkey]["hits"] for a in by_anchor)
        reviewed=sum(a["thresholds"][tkey]["selected"] for a in by_anchor)
        result["thresholds"][tkey]={"hits":hits,"reviewed":reviewed,
            "precision":hits/reviewed if reviewed else None,
            "recall_among_scored_future_kev":hits/scored_pos if scored_pos else None}
    return result


def evaluate_all(kev_bytes: bytes, archive_folder: Path, *, output: Path,
                 cutoff_date: date = date(2026, 10, 10),
                 downloader=download_historic, min_rows: int=MIN_EPSS_ROWS) -> dict:
    max_horizon = max(HORIZONS)
    anchors = list(ANCHORED_FILES)
    latest_window=max(date.fromisoformat(x)+timedelta(days=max_horizon) for x in anchors)
    if cutoff_date < latest_window:
        raise ValueError("Outcome observation cutoff too early for full anchor horizon")
    labels, kev_provenance=read_kev(kev_bytes,last_observed_date=latest_window)
    if date.fromisoformat(kev_provenance["catalog_date_released"][:10]) > cutoff_date:
        raise ValueError("Label catalog is from the future")
    results=[]
    for index,day_string in enumerate(anchors,1):
        day=date.fromisoformat(day_string)
        archive,archive_sha=downloader(day_string,archive_folder)
        payload=archive.read_bytes()
        verify_archive_bytes(day_string,payload)
        scores,provenance=read_daily_csv(payload,day,min_rows=min_rows)
        outcome=evaluate_day(day,scores,labels)
        outcome["source"]={**provenance,"compressed_sha256":archive_sha}
        results.append(outcome)
        print(f"HISTORICAL_EPSS_KEV_ANCHORS_COMPLETED={index}/{len(anchors)}",flush=True)
    report={"schema_version":1,"result":"HISTORICAL_EPSS_TO_FUTURE_KEV_BACKTEST_EVALUATED",
       "method":"Fixed monthly as-of EPSS cohorts, future KEV dateAdded labels, no training or current CVE/EPSS features",
       "data_sources":{"epss_repo":EPSS_REPO,"epss_git_revision":EPSS_COMMIT,
                       "kev":kev_provenance},
       "targets":{"positive":"CISA KEV dateAdded in (EPSS_date, EPSS_date+horizon]",
                  "not_equal_to":"first exploitation; attack against any customer; verified affected asset"},
       "predeclared":{"anchors":anchors,"horizons_days":HORIZONS,"top_k":TOP_K,
                      "probability_thresholds":THRESHOLDS,"run_cutoff_date":cutoff_date.isoformat()},
       "summary":{group:{str(h):combine(results,h,group) for h in HORIZONS}
                  for group in ("EPSS_V4","EPSS_V5","ALL")},
       "anchors":results,
       "warnings":[
         "Retrospective KEV dateAdded is catalog recognition, NOT exploitation onset. Earlier exploitation may already have occurred.",
         "Uses a 2026-10-10 KEV catalog to reconstruct past dateAdded labels; later corrections/removals can bias the historical registry.",
         "The historical EPSS-scored CVE population is the candidate universe; unscored subsequent KEV entries are counted separately.",
         "Only model scores from immutable historical daily CSVs; NO current CVE/KEV/CVSS/affected-product metadata as historical features.",
         "No customer asset inventory, application versions, internet exposure, exploit validity or remediation effectiveness evaluated.",
         "Monthly first-of-month anchors; 30-day windows can occasionally overlap; date-level release timing is approximate.",
         "EPSS v4/v5 changed June 2026; model-era breakdown required; thresholds fixed before observing outcomes.",
         "Class imbalance is severe: evaluate precision, coverage, workload and random-baseline lift, not accuracy.",
         "Descriptive backtest is NOT a claim of prospective alarm performance or a deployable customer alert SLA."
       ]}
    output.parent.mkdir(parents=True,exist_ok=True)
    temp=output.with_suffix(output.suffix+".tmp")
    try:
        temp.write_text(json.dumps(report,ensure_ascii=False,indent=2,sort_keys=True)+"\n",encoding="utf-8")
        temp.replace(output)
    finally:
        temp.unlink(missing_ok=True)
    return report


def main() -> None:
    parser=argparse.ArgumentParser(description="Historical EPSS vs future first CISA KEV listing (no leakage)")
    parser.add_argument("--kev",required=True,type=Path)
    parser.add_argument("--archive-folder",required=True,type=Path)
    parser.add_argument("--out",required=True,type=Path)
    parser.add_argument("--cutoff-date",type=date.fromisoformat,default=date(2026,10,10))
    args=parser.parse_args()
    report=evaluate_all(args.kev.read_bytes(),args.archive_folder,output=args.out,cutoff_date=args.cutoff_date)
    print(json.dumps({"result":report["result"],"anchors":len(report["anchors"]),
        "summary":report["summary"]},sort_keys=True))


if __name__=="__main__": main()
