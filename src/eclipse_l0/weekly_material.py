"""Read-only, version-aware important security content revision detection.

Only a new publisher response AND an unchanged extractor can make a
publisher-content-change *candidate*. Observation time is NOT publication time.
An unreviewed parser result can NEVER claim confirmed exploitation/fix/impact.
CVE attribution is forbidden for HTML pagewide links and multi-CVE documents
without separately scoped evidence. The full version ledger is never mutated.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import date, datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sqlite3

from .vendor_registry import load_registry
from .vendor_replay import inspect_db

HEX=re.compile(r"^[0-9a-f]{64}$")
CVE=re.compile(r"^CVE-\d{4}-\d{4,}$")
MAX_EVENTS=15000
MAX_DB_BYTES=50*1024*1024
MAX_OUTPUT_BYTES=32*1024*1024

# Compare only sources capable of conveying a change in a security assertion.
# Exclude transient parsing, timestamps, navigation links, and marketing text.
FIELDS={
    "affected":"AFFECTED_PRODUCT_OR_VERSION_CLAIM_CHANGED",
    "product_status_claims_unreviewed":"AFFECTED_PRODUCT_OR_VERSION_CLAIM_CHANGED",
    "remediations_unreviewed":"REMEDIATION_OR_FIXED_STATUS_CHANGED",
    "remediation":"REMEDIATION_OR_FIXED_STATUS_CHANGED",
    "solutions":"REMEDIATION_OR_FIXED_STATUS_CHANGED",
    "workarounds":"WORKAROUND_OR_MITIGATION_CHANGED",
    "mitigations":"WORKAROUND_OR_MITIGATION_CHANGED",
    "known_exploitation":"EXPLOITATION_ASSERTION_CHANGED_UNREVIEWED",
    "exploitation_status":"EXPLOITATION_ASSERTION_CHANGED_UNREVIEWED",
    "cvss":"SEVERITY_OR_ATTACK_REQUIREMENT_CHANGED",
    "metrics":"SEVERITY_OR_ATTACK_REQUIREMENT_CHANGED",
    "attack_prerequisites":"SEVERITY_OR_ATTACK_REQUIREMENT_CHANGED",
}
ALLOWED_EVENTS={"baseline","facts_updated","source_changed_only","extraction_revised"}


def canonical(data):
    return json.dumps(data,ensure_ascii=False,sort_keys=True,separators=(",",":"))


def sha(data):
    return hashlib.sha256(data).hexdigest()


def _utc(value):
    if not isinstance(value,str):
        raise ValueError("Timestamp required")
    try:
        moment=datetime.fromisoformat(value.replace("Z","+00:00"))
    except ValueError as exc:
        raise ValueError("Invalid observed timestamp") from exc
    if moment.tzinfo is None:
        raise ValueError("Naive observed timestamp")
    return moment.astimezone(timezone.utc)


def _normalized(value):
    # JSON array order changes alone must not cause change alerts.
    if isinstance(value,list):
        return sorted((canonical(_normalized(x)) for x in value))
    if isinstance(value,dict):
        return {k:_normalized(v) for k,v in sorted(value.items())}
    return value


def _diff(before,after):
    return sorted({tag for k,tag in FIELDS.items()
                   if _normalized(before.get(k))!=_normalized(after.get(k))})


def _cves(value):
    if not isinstance(value,list) or len(value)!=len(set(value)) or any(
            not isinstance(v,str) or not CVE.fullmatch(v) for v in value):
        raise ValueError("Invalid source CVE identities")
    return sorted(value)


def _scoped(before,after,categories):
    """Strict CVE association; never infer per-CVE scope from HTML page links."""
    old=_cves(before.get("cve_ids",[]));new=_cves(after.get("cve_ids",[]))
    if old!=new:
        return [],"CVE_MEMBERSHIP_CHANGED_REVIEW_UNSCOPED"
    if len(old)==1 and categories:
        # A single-CVE source can still contain a navigation CVE. Restrict
        # this proof to per-CVE publisher sources or structured CSAF claims.
        return old,"SINGLE_CVE_ADVISORY_PENDING_LINK_REVIEW"
    def scoped_ids(obj):
        rows=obj.get("product_status_claims_unreviewed") or []
        if not isinstance(rows,list):raise ValueError("Malformed CSAF claims")
        return {r["cve_id"] for r in rows if isinstance(r,dict) and
                isinstance(r.get("cve_id"),str) and CVE.fullmatch(r["cve_id"])}
    if "AFFECTED_PRODUCT_OR_VERSION_CLAIM_CHANGED" in categories:
        before_ids=scoped_ids(before);after_ids=scoped_ids(after)
        # For multi-CVE documents field diffs must be calculated per-CVE.
        affected=set()
        for cid in sorted(before_ids|after_ids):
            def scoped_rows(obj):
                return [r for r in (obj.get("product_status_claims_unreviewed") or [])
                        if isinstance(r,dict) and r.get("cve_id")==cid]
            if _normalized(scoped_rows(before))!=_normalized(scoped_rows(after)):
                affected.add(cid)
        if affected:
            return sorted(affected),"STRUCTURED_CSAF_PER_CVE_PRODUCT_STATUS"
    return [],"MULTI_CVE_OR_PAGEWIDE_LINK_REVIEW_UNSCOPED"


def _event(row,older,newer):
    # A mismatched historic version, same source bytes, or changed parser is
    # NOT evidence of publisher-authored new security content.
    if row["event_kind"] not in ALLOWED_EVENTS:
        raise ValueError("Unknown ledger event kind")
    old_facts=json.loads(older["facts_json"])
    new_facts=json.loads(newer["facts_json"])
    if not isinstance(old_facts,dict) or not isinstance(new_facts,dict):
        raise ValueError("Invalid version facts")
    old_parser=old_facts.get("_extractor_revision","legacy_v1")
    new_parser=new_facts.get("_extractor_revision","legacy_v1")
    if not isinstance(old_parser,str) or not isinstance(new_parser,str):
        raise ValueError("Invalid extractor identity")
    body_changed=older["source_sha256"]!=newer["source_sha256"]
    parser_stable=old_parser==new_parser
    cats=_diff(old_facts,new_facts)
    cves,link_status=_scoped(old_facts,new_facts,cats)
    # This prefix means content difference under a stable parser, not proof
    # of author intent, original release date, or independent verification.
    content_change=(row["event_kind"]=="facts_updated" and
                    body_changed and parser_stable and bool(cats))
    if not content_change:cves=[]
    extraction_reviewed=(older["extract_status"]=="human_verified" and
                         newer["extract_status"]=="human_verified")
    status=("MATERIAL_SOURCE_CONTENT_CHANGE_HUMAN_EXTRACTION_REVIEWED"
            if content_change and extraction_reviewed else
            "MATERIAL_SOURCE_CONTENT_CHANGE_REVIEW_REQUIRED"
            if content_change else "NO_CONFIRMED_SECURITY_ASSERTION_DIFF")
    return {
        "source_id":row["source_id"],"advisory_id":row["advisory_id"],
        "source_url":newer["source_url"],
        "old_version":older["version"],"new_version":newer["version"],
        "observed_utc":row["observed_utc"],
        "original_event_kind":row["event_kind"],
        "old_source_sha256":older["source_sha256"],
        "new_source_sha256":newer["source_sha256"],
        "old_facts_sha256":older["facts_sha256"],
        "new_facts_sha256":newer["facts_sha256"],
        "same_extractor_revision":parser_stable,
        "source_response_bytes_changed":body_changed,
        "security_claim_change_categories":cats if content_change else [],
        "change_status":status,
        "candidate_cve_ids":cves,
        "cve_link_status":link_status if content_change else "NOT_APPLICABLE",
        "human_verified_extraction_both_versions":extraction_reviewed,
        "publisher_release_date_confirmed":False,
        "publisher_authored_change_confirmed":False,
        "actual_exploitation_confirmed":False,
        "customer_impact_confirmed":False,
        "eligible_for_weekly_research":bool(content_change and cves),
        "safe_for_client_automatic_claims":False,
    }


def analyze_vendor_history(db_path,registry,*,start,end):
    """Extract bounded observed revisions with all source bytes/hash constraints."""
    if isinstance(start,str):start=date.fromisoformat(start)
    if isinstance(end,str):end=date.fromisoformat(end)
    if not isinstance(start,date) or not isinstance(end,date) or end<start or (end-start).days>31:
        raise ValueError("Invalid weekly window")
    proof=inspect_db(Path(db_path),registry)
    db=sqlite3.connect(Path(db_path).resolve().as_uri()+"?mode=ro",uri=True)
    db.row_factory=sqlite3.Row
    db.execute("PRAGMA query_only=ON")
    events=[]
    totals=Counter()
    try:
        history=db.execute("""SELECT e.source_id,e.advisory_id,e.event_kind,e.observed_utc,
                   e.version FROM vendor_document_events e ORDER BY e.event_id""")
        for event in history:
            moment=_utc(event["observed_utc"]).date()
            if moment<start or moment>end:continue
            totals["observed_events_in_window"]+=1
            if totals["observed_events_in_window"]>MAX_EVENTS:
                raise ValueError("Exceeded revision audit event budget")
            if event["event_kind"]=="baseline":
                totals["baseline_not_update"]+=1
                continue
            if event["version"]<=1:
                raise ValueError("Non-baseline version has no prior state")
            version_rows=list(db.execute("""SELECT * FROM vendor_document_versions
                  WHERE source_id=? AND advisory_id=? AND version IN (?,?)
                  ORDER BY version""",
                  (event["source_id"],event["advisory_id"],
                   event["version"]-1,event["version"])))
            if len(version_rows)!=2 or [a["version"] for a in version_rows]!=[event["version"]-1,event["version"]]:
                raise ValueError("Missing exact adjacent version comparison")
            current=version_rows[1]
            if current["observed_utc"]!=event["observed_utc"]:
                raise ValueError("Event and version observation date mismatch")
            audit=_event(event,version_rows[0],current)
            totals[audit["change_status"]]+=1
            if audit["eligible_for_weekly_research"]:
                totals["scoped_cve_review_candidates"]+=len(audit["candidate_cve_ids"])
            events.append(audit)
    finally:
        db.close()
    events.sort(key=lambda x:(x["observed_utc"],x["source_id"],x["advisory_id"],x["new_version"]))
    return {
        "schema_version":1,
        "kind":"ECLIPSE_OBSERVED_VENDOR_FACTS_DIFF_REVIEW_ONLY",
        "window":{"start_utc":start.isoformat(),"end_utc":end.isoformat()},
        "source_vendor_sqlite_sha256":proof["sqlite_sha256"],
        "verified_source_ledger_versions":proof["versions"],
        "vendor_registry_source_count":len(registry["sources"]),
        "events":events,
        "event_counts":dict(sorted(totals.items())),
        "all_events_recomputed_from_adjacent_versioned_evidence":True,
        "historical_cve_record_update_diffs_complete":False,
        "vendor_weekly_monitoring_complete":False,
        "safe_for_weekly_report_auto_publication":False,
        "limitations":[
          "Publisher response changed, but observation date is not official publisher revision date.",
          "Extraction is unreviewed unless both source versions were human verified.",
          "Single-CVE association must be independently scoped before customer reporting.",
          "CVE metadata dateUpdated alone is not a proof of material security change.",
          "History missing from this ledger cannot be reconstructed or labeled as unchanged."
        ]
    }


def write_report(path,db_path,registry,start,end):
    path=Path(path)
    if path.exists() or path.is_symlink():
        raise ValueError("Refuse overwrite")
    result=analyze_vendor_history(db_path,registry,start=start,end=end)
    body=(canonical(result)+"\n").encode()
    if len(body)>MAX_OUTPUT_BYTES:raise ValueError("Output too large")
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open("xb") as f:f.write(body)
    return {k:v for k,v in result.items() if k not in ("events","limitations")}


def verify_report(path,db_path,registry):
    report=Path(path)
    if not report.is_file() or report.is_symlink() or report.stat().st_size>MAX_OUTPUT_BYTES:
        raise ValueError("Invalid revision report")
    raw=report.read_bytes()
    given=json.loads(raw)
    if given.get("kind")!="ECLIPSE_OBSERVED_VENDOR_FACTS_DIFF_REVIEW_ONLY":
        raise ValueError("Untrusted revision report")
    expected=analyze_vendor_history(db_path,registry,**{"start":given["window"]["start_utc"],
                                                        "end":given["window"]["end_utc"]})
    if raw!=(canonical(expected)+"\n").encode():
        raise ValueError("Revision evidence is not reproducible from versioned SQLite")
    return {"result":"INDEPENDENT_VENDOR_VERSION_DIFF_VERIFIED",
            "sqlite_sha256":expected["source_vendor_sqlite_sha256"],
            "event_counts":expected["event_counts"],
            "candidate_events":len(expected["events"]),
            "weekly_complete":False}


def main():
    p=argparse.ArgumentParser(description="Observed vendor revision triage, NOT official revision-date feed")
    sub=p.add_subparsers(dest="command",required=True)
    b=sub.add_parser("build")
    b.add_argument("--start",required=True);b.add_argument("--end",required=True)
    b.add_argument("--out",type=Path,required=True)
    v=sub.add_parser("verify")
    v.add_argument("--report",type=Path,required=True)
    for x in (b,v):
        x.add_argument("--vendor-db",type=Path,required=True)
        x.add_argument("--registry",type=Path,default=Path("config/vendor_source_registry.json"))
    a=p.parse_args()
    registry=load_registry(a.registry)
    result=(write_report(a.out,a.vendor_db,registry,a.start,a.end)
            if a.command=="build" else verify_report(a.report,a.vendor_db,registry))
    print(json.dumps(result,ensure_ascii=False,sort_keys=True,indent=2))


if __name__=="__main__":
    main()
