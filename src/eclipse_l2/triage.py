"""ECLIPSE L2: evidence-first, explainable *triage queues*, NOT a customer risk score.

KEV (observed exploitation), EPSS (30-day population forecast), and CNA CVSS
(technical severity) measure different things and are deliberately never added
or multiplied. No product exposure, remediation SLA or live attack is inferred.
No vendor-advisory integration: that work is owned by a separate project branch.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import heapq
import json
import math
import sqlite3
from collections import Counter
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Iterator

from eclipse_l0.core import CVE_ID

SOURCE_KINDS = {
    "cve": "CVEProject CVE List V5 pinned historical source",
    "kev": "CISA KEV full catalog at warehouse build time",
    "epss": "FIRST EPSS daily forecast at warehouse build time",
}
QUEUE_ORDER = (
    "CONFIRMED_EXPLOITATION_REVIEW",
    "ELEVATED_FORECAST_REVIEW",
    "HIGH_IMPACT_REVIEW",
    "ROUTINE_EVIDENCE_REVIEW",
    "UNPUBLISHED_HOLD",
)
EXPORT_FIELDS = (
    "cve_id", "record_state", "queue", "rule_id", "kev_status", "kev_date_added",
    "epss_probability", "epss_percentile", "epss_status", "epss_score_date",
    "cvss_base_score", "cvss_kind", "impact_signal", "affected_rows_present",
    "publisher_affected_version_data", "date_published", "date_updated",
    "missing_fields", "customer_exposure",
)


@dataclass(frozen=True)
class Policy:
    """An *illustrative* attention policy, NOT calibrated to client outcomes."""
    epss_attention_probability: float = 0.10
    cvss_impact_attention: float = 9.0
    max_epss_age_days: int = 7

    def __post_init__(self) -> None:
        if (not math.isfinite(self.epss_attention_probability)
                or not 0 < self.epss_attention_probability <= 1):
            raise ValueError("Invalid EPSS policy cutoff")
        if (not math.isfinite(self.cvss_impact_attention)
                or not 0 < self.cvss_impact_attention <= 10):
            raise ValueError("Invalid impact policy cutoff")
        if not 0 <= self.max_epss_age_days <= 365:
            raise ValueError("Invalid EPSS recency budget")


def _metadata(con: sqlite3.Connection, *, as_of: date) -> dict:
    try:
        m = {k: json.loads(v) for k, v in con.execute(
            "SELECT key,value FROM warehouse_metadata")}
    except sqlite3.DatabaseError as exc:
        raise ValueError("A verified full SQLite warehouse is required") from exc
    required = ("source_archive_sha256", "source_index_sha256",
                "cve_full_ingest_verified", "kev_source_sha256",
                "epss_source_sha256", "epss_score_date")
    if any(k not in m for k in required) or m["cve_full_ingest_verified"] is not True:
        raise ValueError("Incomplete CVE/KEV/EPSS provenance; fail closed")
    for key in ("source_archive_sha256", "source_index_sha256",
                "kev_source_sha256", "epss_source_sha256"):
        h = m[key]
        if not isinstance(h, str) or len(h) != 64 or any(c not in "0123456789abcdef" for c in h):
            raise ValueError("Invalid original-source digest: " + key)
    timestamp = m["epss_score_date"]
    if not isinstance(timestamp, str):
        raise ValueError("Missing EPSS feed score date")
    try:
        score_at = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("Invalid EPSS timestamp") from exc
    if score_at.tzinfo is None:
        raise ValueError("EPSS timestamp lacks timezone")
    score_date = score_at.astimezone(timezone.utc).date()
    if score_date > as_of:
        raise ValueError("Cannot use EPSS evidence from the future")
    m["epss_score_date_only"] = score_date.isoformat()
    m["epss_age_days"] = (as_of - score_date).days
    return m


def _data_rows(con: sqlite3.Connection, vendor: str | None,
               product: str | None) -> Iterator[sqlite3.Row]:
    # Vendor/product strings are EXACT casefolded CVE assertions, not asset exposure.
    wheres = []
    params: list[str] = []
    if vendor is not None or product is not None:
        constraints = []
        if vendor is not None:
            constraints.append("a.vendor_norm = ?")
            params.append(vendor.strip().casefold())
        if product is not None:
            constraints.append("a.product_norm = ?")
            params.append(product.strip().casefold())
        if not all(params):
            raise ValueError("Vendor/product filter must not be empty")
        wheres.append("EXISTS (SELECT 1 FROM warehouse_affected a WHERE "
                      "a.cve_id=c.cve_id AND " + " AND ".join(constraints) + ")")
    sql = """
    SELECT c.cve_id,c.record_state,c.date_published,c.date_updated,
      s.cvss_score,s.cvss_kind,s.cvss_severity,
      k.cve_id AS kev_id,k.date_added AS kev_date_added,
      e.probability,e.percentile,
      EXISTS(SELECT 1 FROM warehouse_affected a WHERE a.cve_id=c.cve_id) AS has_affected,
      EXISTS(SELECT 1 FROM warehouse_affected a
             WHERE a.cve_id=c.cve_id AND a.versions_json IS NOT NULL) AS has_versions
    FROM cve_current c
      LEFT JOIN warehouse_summary s ON c.cve_id=s.cve_id
      LEFT JOIN kev_current k ON c.cve_id=k.cve_id AND k.present=1
      LEFT JOIN warehouse_epss e ON c.cve_id=e.cve_id
    """ + ("WHERE " + " AND ".join(wheres) if wheres else "") + " ORDER BY c.cve_id"
    yield from con.execute(sql, params)


def evaluate(row: sqlite3.Row | dict, *, fresh_epss: bool,
             score_date: str, policy: Policy) -> dict:
    """One CVE, one auditable queue; explicit unknowns are not considered safe."""
    r = dict(row)
    cve = r.get("cve_id")
    if not isinstance(cve, str) or not CVE_ID.fullmatch(cve):
        raise ValueError("Malformed warehouse CVE key")
    state = r.get("record_state")
    score = r.get("cvss_score")
    probability = r.get("probability")
    percentile = r.get("percentile")
    if score is not None and (not isinstance(score, (int, float))
                              or not math.isfinite(score) or not 0 <= score <= 10):
        raise ValueError("Unexpected CNA CVSS")
    if probability is not None and (not isinstance(probability, (int, float))
                                    or not math.isfinite(probability) or not 0 <= probability <= 1):
        raise ValueError("Unexpected FIRST EPSS")
    if percentile is not None and (not isinstance(percentile, (int, float))
                                   or not math.isfinite(percentile) or not 0 <= percentile <= 1):
        raise ValueError("Unexpected FIRST percentile")
    kev = r.get("kev_id") is not None
    if kev and r["kev_id"] != cve:
        raise ValueError("KEV join mismatch")
    if probability is None:
        epss_status = "MISSING_FOR_CVE"
    elif not fresh_epss:
        epss_status = "STALE_FEED_UNUSABLE_FOR_FRESH_TRIAGE"
    else:
        epss_status = "FRESH_MODEL_ESTIMATE"

    if state != "PUBLISHED":
        queue,rule = "UNPUBLISHED_HOLD","NOT_PUBLISHED_REJECTED_OR_RESERVED"
    elif kev:
        queue,rule = "CONFIRMED_EXPLOITATION_REVIEW","KEV_PRESENT_OVERRIDES_EPSS"
    elif probability is not None and fresh_epss and probability >= policy.epss_attention_probability:
        queue,rule = "ELEVATED_FORECAST_REVIEW","EPSS_FRESH_OVER_POLICY_ATTENTION_THRESHOLD"
    elif score is not None and score >= policy.cvss_impact_attention:
        queue,rule = "HIGH_IMPACT_REVIEW","CNA_CVSS_OVER_POLICY_ATTENTION_THRESHOLD"
    else:
        queue,rule = "ROUTINE_EVIDENCE_REVIEW","NO_ABOVE_THRESHOLD_SIGNAL_OBSERVED"

    missing = []
    if probability is None: missing.append("epss_score_missing")
    elif not fresh_epss: missing.append("epss_feed_stale")
    if score is None: missing.append("cna_cvss_missing")
    if not r.get("has_affected"): missing.append("publisher_affected_rows_missing")
    if not r.get("has_versions"): missing.append("publisher_version_predicates_missing")
    return {
        "cve_id": cve, "record_state": state, "queue": queue, "rule_id": rule,
        "kev_status": "PRESENT_IN_KEV_SNAPSHOT" if kev else "NOT_LISTED_IN_KEV_SNAPSHOT",
        "kev_date_added": r.get("kev_date_added"),
        "epss_probability": probability, "epss_percentile": percentile,
        "epss_status": epss_status, "epss_score_date": score_date,
        "cvss_base_score": score, "cvss_kind": r.get("cvss_kind"),
        "impact_signal": "CNA_CVSS_BASE_SCORE_NOT_CUSTOMER_IMPACT" if score is not None else "UNKNOWN",
        "affected_rows_present": bool(r.get("has_affected")),
        "publisher_affected_version_data": "PRESENT_NOT_CUSTOMER_VERIFIED" if r.get("has_versions") else "UNKNOWN",
        "date_published": r.get("date_published"), "date_updated": r.get("date_updated"),
        "missing_fields": missing,
        "customer_exposure": "NOT_ASSESSED",
        "evidence_fields": [
            "cve_current.record_state", "cve_current.date_published",
            "kev_current.present", "kev_current.date_added",
            "warehouse_epss.probability", "warehouse_epss.percentile",
            "warehouse_summary.cvss_score", "warehouse_summary.cvss_kind",
            "warehouse_affected.versions_json",
        ],
    }


def _sort_key(r: dict):
    # KEV before forecast before CNA severity; no weighted additive score.
    # Missing EPSS sorts after known EPSS *within* a given queue, not as zero.
    return (
        QUEUE_ORDER.index(r["queue"]),
        -(r["epss_probability"] if r["epss_probability"] is not None else -1),
        -(r["cvss_base_score"] if r["cvss_base_score"] is not None else -1),
        r["cve_id"],
    )


def analyze(db: Path, *, as_of: date, policy: Policy | None = None,
            vendor: str | None = None, product: str | None = None,
            top: int = 100, csv_path: Path | None = None) -> dict:
    """Stream full warehouse with O(top) retained cases; optional all-row CSV."""
    if not 0 <= top <= 1000:
        raise ValueError("top must be between 0 and 1000")
    if not db.is_file():
        raise ValueError("SQLite warehouse missing")
    policy = policy or Policy()
    con = sqlite3.connect(f"file:{db.resolve().as_posix()}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA query_only=ON")
    sink = None
    try:
        m = _metadata(con, as_of=as_of)
        fresh = m["epss_age_days"] <= policy.max_epss_age_days
        totals: Counter[str] = Counter()
        gaps: Counter[str] = Counter()
        feed_states: Counter[str] = Counter()
        def assessed_rows():
            nonlocal sink
            if csv_path is not None:
                csv_path.parent.mkdir(parents=True,exist_ok=True)
                sink = csv_path.open("w",encoding="utf-8",newline="")
                writer = csv.DictWriter(sink,fieldnames=EXPORT_FIELDS)
                writer.writeheader()
            else:
                writer = None
            for row in _data_rows(con,vendor,product):
                item = evaluate(row,fresh_epss=fresh,score_date=m["epss_score_date_only"],policy=policy)
                totals[item["queue"]] += 1
                feed_states[item["epss_status"]] += 1
                for gap in item["missing_fields"]:
                    gaps[gap] += 1
                if writer is not None:
                    writer.writerow({k:json.dumps(item[k],ensure_ascii=False) if k=="missing_fields" else item[k]
                                     for k in EXPORT_FIELDS})
                yield item
        selected = heapq.nsmallest(top,assessed_rows(),key=_sort_key)
        count = sum(totals.values())
        if vendor is None and product is None:
            observed=con.execute("SELECT COUNT(*) FROM cve_current").fetchone()[0]
            if count != observed:
                raise ValueError("Full warehouse streaming omitted CVE records")
        result = {
            "schema_version":1,
            "classification":"EXPLAINABLE_POLICY_QUEUES_NOT_VALIDATED_RISK_SCORE",
            "scope":"EXACT_PUBLISHER_REPORTED_PRODUCT_NAMES" if vendor is not None or product is not None else "FULL_PINNED_CVE_SNAPSHOT",
            "filter":{"vendor_exact_casefold":vendor.strip().casefold() if vendor else None,
                      "product_exact_casefold":product.strip().casefold() if product else None},
            "as_of_utc_day":as_of.isoformat(),"records_evaluated":count,
            "queue_counts":{q:totals[q] for q in QUEUE_ORDER},
            "evidence_gap_counts":dict(sorted(gaps.items())),
            "epss_status_counts":dict(sorted(feed_states.items())),
            "epss_age_days":m["epss_age_days"],"epss_fresh_for_policy":fresh,
            "sources":{
                "cve":{"description":SOURCE_KINDS["cve"],"sha256":m["source_archive_sha256"],
                       "index_sha256":m["source_index_sha256"],
                       "snapshot_note":"Historical snapshot, NOT today's changed CVEs"},
                "kev":{"description":SOURCE_KINDS["kev"],"sha256":m["kev_source_sha256"],
                       "not_listed_means":"not listed in THIS catalog; not proof of no exploitation"},
                "epss":{"description":SOURCE_KINDS["epss"],"sha256":m["epss_source_sha256"],
                        "score_timestamp":m["epss_score_date"],
                        "model_scope":"Population-level next-30-days forecast, not company probability"},
            },
            "policy":{"epss_attention_probability":policy.epss_attention_probability,
                      "cvss_impact_attention":policy.cvss_impact_attention,
                      "max_epss_age_days":policy.max_epss_age_days,
                      "validation":"User-adjustable demonstration thresholds; not fitted to attack outcomes"},
            "preview":selected,
            "warnings":[
                "No customer asset inventory used; exposure, mitigation, and patch state NOT assessed.",
                "Unlisted KEV does not mean unexploited; missing or low EPSS does not mean safe.",
                "CNA CVSS is technical base severity, NOT organization-specific consequence.",
                "All 403,696 CVEs, including REJECTED/RESERVED, counted; non-published held separately.",
                "Publisher vendor/product matches cannot confirm an installed affected version.",
                "KEV and EPSS captured at warehouse construction, not at the historical CVE snapshot time.",
                "Vendor advisory cross-check is out of scope until the parallel verification completes.",
            ] + ([] if fresh else ["EPSS feed is stale: do not promote candidates on obsolete forecast."]),
        }
        return result
    finally:
        if sink is not None:
            sink.close()
        con.close()


def main() -> None:
    p=argparse.ArgumentParser(description="ECLIPSE evidence-first triage; not customer risk scoring")
    p.add_argument("--db",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True)
    p.add_argument("--csv",type=Path)
    p.add_argument("--as-of",type=date.fromisoformat,default=datetime.now(timezone.utc).date())
    p.add_argument("--vendor")
    p.add_argument("--product")
    p.add_argument("--epss-attention",type=float,default=0.10)
    p.add_argument("--cvss-attention",type=float,default=9.0)
    p.add_argument("--max-epss-age-days",type=int,default=7)
    p.add_argument("--top",type=int,default=100)
    args=p.parse_args()
    report=analyze(args.db,as_of=args.as_of,vendor=args.vendor,product=args.product,
       top=args.top,csv_path=args.csv,policy=Policy(
           epss_attention_probability=args.epss_attention,
           cvss_impact_attention=args.cvss_attention,
           max_epss_age_days=args.max_epss_age_days))
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(report,ensure_ascii=False,sort_keys=True,indent=2)+"\n",encoding="utf-8")
    print(json.dumps({"result":"TRIAGE_QUEUES_GENERATED_NOT_CUSTOMER_RISK",
                      "rows":report["records_evaluated"],"queue_counts":report["queue_counts"],
                      "epss_fresh":report["epss_fresh_for_policy"]},sort_keys=True))


if __name__=="__main__":
    main()
