"""Prospectively valid EPSS-only experimental ranking + retrospective missing-cohort audit.

ALERT FEATURE BORDER: only the current and PREVIOUS score date's EPSS values.
Later KEV registration and later EPSS appearance are LABELS / DIAGNOSTICS ONLY.
The last warehouse CVE/CVSS/version fields are NEVER permitted as historical features.
No vendor-feed files, customer assets, or production risk-score behavior are touched.
"""
from __future__ import annotations

import argparse
import json
import math
from collections import Counter
from datetime import date, timedelta
from pathlib import Path

from .kev_backtest import (
    ANCHORED_FILES, TOP_K, HORIZONS, download_historic, read_daily_csv,
    read_kev, evaluate_day, verify_archive_bytes, digest,
)

# Predeclared before observing this experiment's outcome: 80% absolute FIRST
# EPSS rank plus up to 20% positive *within-era prior-month* EPSS momentum.
# No historical model training or threshold search.
BASELINE_SHARE = 0.80
CUTOFF = date(2026, 10, 10)
DAYS = tuple(ANCHORED_FILES)
SCORE_BUCKETS = (0.01, 0.05, 0.10, 0.20)


def _era(day: date) -> str:
    return "EPSS_V4" if day < date(2026, 6, 15) else "EPSS_V5"


def _rank(current: dict[str, float], preexisting_kev: set[str]) -> list[tuple[float, str]]:
    if any(not isinstance(p, float) or not math.isfinite(p) or not 0 <= p <= 1 for p in current.values()):
        raise ValueError("Invalid historical EPSS probabilities")
    return sorted(((p, cve) for cve, p in current.items() if cve not in preexisting_kev),
                  key=lambda pair: (-pair[0], pair[1]))


def select_review_queue(ranked: list[tuple[float, str]],
                        previous: dict[str, float] | None,
                        budget: int) -> list[str]:
    """Equal workload, deterministically merging EPSS absolute and positive momentum.

    Fallback fills empty momentum slots with the ordinary EPSS ranking; a CVE
    never appears twice. A missing previous month never becomes 0.0 EPSS.
    """
    if budget <= 0:
        raise ValueError("Budget must be positive")
    if not ranked:
        return []
    current = {cve: p for p, cve in ranked}
    limit = min(budget, len(ranked))
    if previous is None:
        return [cve for _, cve in ranked[:limit]]
    baseline_slots = min(int(budget * BASELINE_SHARE), limit)
    chosen = [cve for _, cve in ranked[:baseline_slots]]
    chosen_set = set(chosen)
    positive_momentum = sorted(
        ((p - previous[cve], p, cve) for cve, p in current.items()
         if cve in previous and p > previous[cve] and cve not in chosen_set),
        key=lambda item: (-item[0], -item[1], item[2]))
    for _, _, cve in positive_momentum[:limit - len(chosen)]:
        chosen.append(cve)
        chosen_set.add(cve)
    if len(chosen) < limit:
        for _, cve in ranked:
            if cve not in chosen_set:
                chosen.append(cve)
                chosen_set.add(cve)
                if len(chosen) == limit:
                    break
    assert len(chosen) == limit and len(set(chosen)) == len(chosen)
    return chosen


def _bucket(probability: float) -> str:
    if probability < SCORE_BUCKETS[0]: return "<0.01"
    if probability < SCORE_BUCKETS[1]: return "0.01-<0.05"
    if probability < SCORE_BUCKETS[2]: return "0.05-<0.10"
    if probability < SCORE_BUCKETS[3]: return "0.10-<0.20"
    return ">=0.20"


def _future_appearance(cve: str, idx: int, snapshots: list[dict[str, float]], dates: tuple[str, ...]) -> str | None:
    for next_idx in range(idx + 1, len(snapshots)):
        if cve in snapshots[next_idx]:
            return dates[next_idx]
    return None


def analyze_anchors(snapshots: list[dict[str, float]], labels: dict[str, date],
                    *, dates: tuple[str,...] = DAYS,
                    top_k: tuple[int,...] = TOP_K,
                    horizons: tuple[int,...] = HORIZONS) -> dict:
    if not snapshots or len(snapshots) != len(dates):
        raise ValueError("One historical score dictionary required for each anchor")
    if sorted(dates) != list(dates) or len(set(dates)) != len(dates):
        raise ValueError("Anchor dates must be strictly chronological")
    if tuple(horizons) != (7, 30) or tuple(top_k) != (100, 500, 1000):
        raise ValueError("Predeclared workload/horizon budgets have changed")
    for table in snapshots:
        if not isinstance(table, dict) or not table:
            raise ValueError("An empty or corrupt historical EPSS table")
    prior_seen: set[str] = set()
    monthly = []
    missing_details: list[dict] = []
    aggregate = {era: {str(h): {
        "paired_anchors": 0, "rankable_future_kev": 0, "future_kev_all": 0,
        "baseline": {str(k): Counter() for k in top_k},
        "fixed_80_20": {str(k): Counter() for k in top_k},
        "gained_kev_from_baseline": {str(k): 0 for k in top_k},
        "lost_kev_vs_baseline": {str(k): 0 for k in top_k},
    } for h in horizons} for era in ("EPSS_V4", "EPSS_V5", "ALL")}
    missing_classes = Counter()
    score_buckets = Counter()
    already_kev_as_of_counts = []
    for i, date_str in enumerate(dates):
        asof = date.fromisoformat(date_str)
        now = snapshots[i]
        prev_day = date.fromisoformat(dates[i-1]) if i else None
        prev = snapshots[i-1] if prev_day and _era(prev_day) == _era(asof) else None
        old_kevs = {cve for cve, first_added in labels.items() if first_added <= asof}
        ranked = _rank(now, old_kevs)
        prev_scored_set = set(prev) if prev is not None else set()
        all_scored = {cve for _, cve in ranked}
        paired = prev is not None
        baseline = {k: set(cve for _, cve in ranked[:k]) for k in top_k}
        candidate = {k: set(select_review_queue(ranked, prev, k)) for k in top_k}
        row = {"as_of": date_str, "era": _era(asof), "paired_comparison": paired,
               "rankable_current_epss": len(ranked), "already_kev_in_scored": len(now)-len(ranked),
               "newly_scored_since_previous_same_era": len(all_scored - prev_scored_set) if paired else None,
               "evaluations": {}}
        already_kev_as_of_counts.append(len(now)-len(ranked))
        for horizon in horizons:
            future = {cve for cve, date_added in labels.items()
                      if asof < date_added <= asof + timedelta(days=horizon)}
            positives = future & all_scored
            missing = sorted(future - all_scored)
            horizon_row = {"future_new_kev": len(future),
                           "rankable_future_kev": len(positives),
                           "not_scored_on_asof": len(missing),
                           "workloads": {},
                           "epss_score_distribution_of_rankable_future_kev": dict(sorted(Counter(
                               _bucket(now[cve]) for cve in positives).items()))}
            for cve in positives:
                if horizon == 30:
                    score_buckets[_bucket(now[cve])] += 1
            for k in top_k:
                first = baseline[k] & positives
                alt = candidate[k] & positives
                metrics = {"budget": k, "reviewed_baseline": len(baseline[k]),
                           "baseline_hits": len(first),
                           "candidate_hits": len(alt) if paired else None,
                           "candidate_reviewed": len(candidate[k]) if paired else None,
                           "unique_new_hits_vs_baseline": len(alt - first) if paired else None,
                           "lost_hits_vs_baseline": len(first - alt) if paired else None,
                           "baseline_hit_examples": sorted(first)[:4],
                           "candidate_new_hit_examples": sorted(alt - first)[:4] if paired else []}
                horizon_row["workloads"][str(k)] = metrics
                if paired:
                    for group in (_era(asof), "ALL"):
                        accum = aggregate[group][str(horizon)]
                        base = accum["baseline"][str(k)]
                        alternative = accum["fixed_80_20"][str(k)]
                        base["hits"] += len(first)
                        base["reviewed"] += len(baseline[k])
                        alternative["hits"] += len(alt)
                        alternative["reviewed"] += len(candidate[k])
                        accum["gained_kev_from_baseline"][str(k)] += len(alt - first)
                        accum["lost_kev_vs_baseline"][str(k)] += len(first - alt)
            row["evaluations"][str(horizon)] = horizon_row
            if paired:
                for group in (_era(asof), "ALL"):
                    aggregate[group][str(horizon)]["paired_anchors"] += 1
                    aggregate[group][str(horizon)]["rankable_future_kev"] += len(positives)
                    aggregate[group][str(horizon)]["future_kev_all"] += len(future)
            if horizon == 30:
                for cve in missing:
                    added_day = labels[cve]
                    first_future = _future_appearance(cve, i, snapshots, dates)
                    observed_before = cve in prior_seen
                    cve_year = int(cve.split("-")[1])
                    classification = ("PREVIOUSLY_SCORED_BUT_MISSING_NOW" if observed_before
                        else "FIRST_SEEN_ON_LATER_MONTHLY_SNAPSHOT" if first_future is not None
                        else "NOT_SEEN_IN_OTHER_MONTHLY_SNAPSHOTS")
                    missing_classes[classification] += 1
                    missing_details.append({
                        "as_of":date_str, "cve":cve, "kev_catalog_date_added":added_day.isoformat(),
                        "cve_identifier_year":cve_year,
                        "identifier_year_after_anchor_year":cve_year > asof.year,
                        "previously_scored_at_an_earlier_anchor":observed_before,
                        "first_later_scored_monthly_anchor":first_future,
                        "number_of_remaining_monthly_snapshots":len(snapshots)-1-i,
                        "missing_class":classification,
                        "availability_limit":"Monthly EPSS snapshots only. CVE ID year IS NOT publication date; neither publication nor exploit onset inferred.",
                    })
        prior_seen.update(now)
        monthly.append(row)
    outputs = {}
    for group, by_h in aggregate.items():
        outputs[group] = {}
        for horizon, item in by_h.items():
            cleaned = {key:value for key,value in item.items()
                       if key not in ("baseline", "fixed_80_20")}
            cleaned["baseline"] = {}
            cleaned["fixed_80_20"] = {}
            for k in top_k:
                key = str(k)
                for model in ("baseline", "fixed_80_20"):
                    ctr = item[model][key]
                    cleaned[model][key] = {
                        "hits":ctr["hits"], "reviewed":ctr["reviewed"],
                        "precision":ctr["hits"]/ctr["reviewed"] if ctr["reviewed"] else None,
                        "recall_among_rankable_future_kev": (
                            ctr["hits"]/item["rankable_future_kev"] if item["rankable_future_kev"] else None),
                    }
                cleaned.setdefault("net_gain_vs_baseline",{})[key] = (
                    item["fixed_80_20"][key]["hits"] - item["baseline"][key]["hits"])
            outputs[group][horizon] = cleaned
    return {
        "schema_version":1,
        "result":"EPSS_MOMENTUM_AND_MISSING_COHORT_RETROSPECTIVE_AUDIT",
        "feature_boundary":"EPSS score for anchor and immediately preceding same-era monthly anchor only",
        "momentum_policy":{"fixed_baseline_share":BASELINE_SHARE,
                           "momentum":"positive absolute EPSS change on previous same-era month (already scored)",
                           "fallback":"absolute EPSS rank if no positive eligible trend",
                           "never_tuned_on_KEV_labels":True},
        "full_unrankable_30_day_cohort":{
            "missing_kev_anchor_events":len(missing_details),
            "classes":dict(sorted(missing_classes.items())),
            "identifier_year_after_anchor_year_events":sum(
                x["identifier_year_after_anchor_year"] for x in missing_details),
            "no_future_monthly_anchor_to_see_new_appearance":sum(
                x["number_of_remaining_monthly_snapshots"]==0 for x in missing_details),
            "cve_details":missing_details,
        },
        "full_scored_future_kev_30_day_probability_buckets":dict(sorted(score_buckets.items())),
        "results_paired_same_model_era":outputs,
        "monthly_anchors":monthly,
        "warnings":[
            "CISA KEV dateAdded is a retrospective catalog registration proxy, not first real-world exploitation.",
            "All model feature choices must precede KEV listing; future EPSS appearances are descriptive diagnostics ONLY.",
            "Month-start EPSS snapshot cannot determine exact dates of initial CVE publication, first EPSS scoring, or exploitation.",
            "CVE ID year is not CVE publication date. Do NOT label a CVE as unpublished solely from its identifier year.",
            "Historical CISA label source is 2026-10-10 preserved catalog; possible retrospective edits bias analyses.",
            "EPSS v4 and v5 are not cross-compared for momentum; first anchor of each era excluded from paired tests.",
            "Under heavy label class imbalance, tiny gains/losses do not validate deployable precision.",
            "No vendor verification, current CVE metadata, contemporary CVSS, or customer asset information included.",
        ]
    }


def evaluate_all(kev_source: bytes, destination: Path, scores_dir: Path,
                 *, cutoff_date: date=CUTOFF,
                 downloader=download_historic,
                 min_rows: int=100_000) -> dict:
    last_horizon = max(date.fromisoformat(x) + timedelta(days=30) for x in DAYS)
    if cutoff_date < last_horizon:
        raise ValueError("Labels would extend beyond observation cutoff")
    labels, provenance=read_kev(kev_source,last_observed_date=last_horizon)
    if date.fromisoformat(provenance["catalog_date_released"][:10]) > cutoff_date:
        raise ValueError("KEV label catalog is from the future")
    snapshots: list[dict[str,float]] = []
    source_proof=[]
    old_baseline=[]
    for idx,ds in enumerate(DAYS,1):
        p,sha=downloader(ds,scores_dir)
        contents=p.read_bytes()
        verify_archive_bytes(ds,contents)
        rows,metadata=read_daily_csv(contents,date.fromisoformat(ds),min_rows=min_rows)
        snapshots.append({cve:score for score,cve in rows})
        baseline=evaluate_day(date.fromisoformat(ds),rows,labels)
        old_baseline.append(baseline)
        source_proof.append({"as_of":ds,"source_sha256":sha,
                             "source_git_blob_sha1":ANCHORED_FILES[ds][1],
                             "scored_records":len(rows)})
        print(f"EPSS_AUDIT_ANCHOR_VERIFIED={idx}/{len(DAYS)}",flush=True)
    result=analyze_anchors(snapshots,labels)
    # Reconcile every unrankable and scored-positive denominator to prior research.
    for observed,expected in zip(result["monthly_anchors"],old_baseline):
        for h in ("7","30"):
            current=observed["evaluations"][h]
            reference=expected["evaluations"][h]
            if (current["future_new_kev"]!=reference["new_kev_all_catalog"] or
                current["rankable_future_kev"]!=reference["new_kev_rankable_in_historical_epss"] or
                current["not_scored_on_asof"]!=reference["new_kev_not_in_historical_epss"]):
                raise ValueError("Old historical EPSS/KEV denominators changed")
            for k in TOP_K:
                if current["workloads"][str(k)]["baseline_hits"] != reference["top_k"][str(k)]["hits"]:
                    raise ValueError("Absolute-EPSS baseline changed unexpectedly")
    full=sum(x["evaluations"]["30"]["future_new_kev"] for x in result["monthly_anchors"])
    ranked=sum(x["evaluations"]["30"]["rankable_future_kev"] for x in result["monthly_anchors"])
    if (len(result["monthly_anchors"])!=17 or full!=374 or ranked!=203 or
        result["full_unrankable_30_day_cohort"]["missing_kev_anchor_events"]!=171):
        raise ValueError("Original preregistered 17-anchor label totals changed")
    result["provenance"]={"kev":provenance,"source_files":source_proof,
                          "outcome_observed_no_later_than":cutoff_date.isoformat()}
    destination.parent.mkdir(parents=True,exist_ok=True)
    tmp=destination.with_suffix(".partial")
    try:
        tmp.write_text(json.dumps(result,sort_keys=True,indent=2,ensure_ascii=False)+"\n",encoding="utf8")
        tmp.replace(destination)
    finally:
        tmp.unlink(missing_ok=True)
    return result


def main() -> None:
    p=argparse.ArgumentParser(description="Predeclared EPSS trend vs KEV and EPSS-unrankable cohort, non-production")
    p.add_argument("--kev",required=True,type=Path)
    p.add_argument("--epss-dir",required=True,type=Path)
    p.add_argument("--out",required=True,type=Path)
    p.add_argument("--cutoff-date",type=date.fromisoformat,default=CUTOFF)
    args=p.parse_args()
    result=evaluate_all(args.kev.read_bytes(),args.out,args.epss_dir,cutoff_date=args.cutoff_date)
    a=result["results_paired_same_model_era"]["ALL"]["30"]
    print(json.dumps({"result":result["result"],"anchors":len(result["monthly_anchors"]),
                      "unrankable_30_day":result["full_unrankable_30_day_cohort"]["missing_kev_anchor_events"],
                      "paired_anchors":a["paired_anchors"],
                      "top500":{"baseline":a["baseline"]["500"]["hits"],
                                "fixed_80_20":a["fixed_80_20"]["500"]["hits"]}},sort_keys=True))


if __name__=="__main__": main()
