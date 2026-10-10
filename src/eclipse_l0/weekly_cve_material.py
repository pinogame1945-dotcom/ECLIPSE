"""Diff pinned BEFORE/AFTER CVE V5 source snapshots. No diff without history.

The 6,355-row single-snapshot week cannot by itself identify which of 3,685
updated CVEs changed security meaning. This module requires TWO actual CVE
record bodies, each with a content hash, and distinguishes security-field
changes from metadata-only changes. It NEVER equates dateUpdated to importance.
Publisher edit date/time and customer exposure remain unverified.
"""
from __future__ import annotations
import argparse
from collections import Counter
from datetime import date, datetime, timezone
import hashlib
import json
from pathlib import Path
import re

from .weekly_material import canonical, _normalized

MAX_INPUT_BYTES=64*1024*1024
MAX_RECORD_BYTES=640*1024
MAX_PAIRS=30000
CVE=re.compile(r"^CVE-\d{4}-\d{4,}$")
SHA=re.compile(r"^[0-9a-f]{64}$")
ALLOWED={"affected":"AFFECTED_PRODUCTS_OR_VERSIONS_CHANGED",
         "metrics":"SEVERITY_OR_ATTACK_VECTOR_CHANGED",
         "problemTypes":"WEAKNESS_CLASSIFICATION_CHANGED",
         "solutions":"REMEDIATION_CHANGED",
         "workarounds":"WORKAROUND_CHANGED",
         "exploits":"EXPLOIT_PROOF_REFERENCES_CHANGED",
         "descriptions":"CNA_DESCRIPTION_CHANGED_REVIEW_ONLY"}
SECURITY_MAIN={"AFFECTED_PRODUCTS_OR_VERSIONS_CHANGED",
               "SEVERITY_OR_ATTACK_VECTOR_CHANGED",
               "REMEDIATION_CHANGED","WORKAROUND_CHANGED",
               "EXPLOIT_PROOF_REFERENCES_CHANGED"}


def _payload_hash(payload):
    raw=canonical(payload).encode("utf-8")
    if len(raw)>MAX_RECORD_BYTES:raise ValueError("CVE record too large")
    return hashlib.sha256(raw).hexdigest()


def _record_id(record):
    if not isinstance(record,dict):raise ValueError("CVE object missing")
    meta=record.get("cveMetadata")
    if not isinstance(meta,dict):
        raise ValueError("Only CVE V5 raw record accepted")
    cid=meta.get("cveId")
    if not isinstance(cid,str) or not CVE.fullmatch(cid):
        raise ValueError("Invalid CVE V5 identity")
    if meta.get("state")!="PUBLISHED":
        raise ValueError("CVE V5 non-published state cannot support weekly security change")
    cna=(record.get("containers") or {}).get("cna")
    if not isinstance(cna,dict):
        raise ValueError("No original CNA body to compare")
    return cid,cna


def compare_pair(item):
    if not isinstance(item,dict):raise ValueError("Malformed CVE revision item")
    before=item.get("before");after=item.get("after")
    old_id,old_cna=_record_id(before)
    new_id,new_cna=_record_id(after)
    if old_id!=new_id or item.get("cve_id")!=new_id:
        raise ValueError("CVE ID mismatch across source versions")
    old_digest=_payload_hash(before)
    new_digest=_payload_hash(after)
    if item.get("before_canonical_sha256")!=old_digest or item.get("after_canonical_sha256")!=new_digest:
        raise ValueError("CVE source bytes/hash pair not internally authentic")
    if old_digest==new_digest:
        changed=[]
    else:
        changed=sorted({meaning for field,meaning in ALLOWED.items()
                       if _normalized(old_cna.get(field)) !=
                          _normalized(new_cna.get(field))})
    # ADP claims are a separate publisher-origin stream. Changes there do not
    # count as a CNA revision, but must not silently disappear.
    old_adp=(before.get("containers") or {}).get("adp") or []
    new_adp=(after.get("containers") or {}).get("adp") or []
    adp_changed=_normalized(old_adp)!=_normalized(new_adp)
    meta_changed=_normalized(before.get("cveMetadata"))!=_normalized(after.get("cveMetadata"))
    if changed and SECURITY_MAIN.intersection(changed):
        label="MATERIAL_CNA_SECURITY_CONTENT_CHANGE_REVIEW"
    elif changed:
        label="DESCRIPTION_OR_WEAKNESS_UPDATED_REVIEW"
    elif adp_changed:
        label="ADP_PUBLISHER_CONTENT_CHANGED_SCOPE_UNREVIEWED"
    elif meta_changed:
        label="CVE_METADATA_ONLY_CHANGE"
    else:
        label="NON_SECURITY_FIELD_OR_NO_CHANGE"
    return {
        "cve_id":new_id,"result":label,
        "changed_cna_security_categories":changed,
        "adp_content_changed":adp_changed,
        "metadata_changed":meta_changed,
        "previous_canonical_record_sha256":old_digest,
        "current_canonical_record_sha256":new_digest,
        "source_pair_provenance":"PROVIDED_TWO_VERSION_CVE_V5_ORIGINAL_RECORDS_HASHES_CHECKED",
        "change_is_new_to_our_observer_not_proof_of_week_of_vendor_publication":True,
        "candidate_for_material_security_review":label in (
            "MATERIAL_CNA_SECURITY_CONTENT_CHANGE_REVIEW",
            "ADP_PUBLISHER_CONTENT_CHANGED_SCOPE_UNREVIEWED"),
        "confirmed_current_exploitation":False,
        "confirmed_publisher_revision_date":False,
        "confirmed_customer_impact":False,
    }


def analyze_pair_jsonl(raw,start,end):
    if not isinstance(raw,bytes) or not 0<len(raw)<=MAX_INPUT_BYTES:
        raise ValueError("Missing, oversized or invalid CVE revision pair file")
    if isinstance(start,str):start=date.fromisoformat(start)
    if isinstance(end,str):end=date.fromisoformat(end)
    if end<start or (end-start).days>31:raise ValueError("Invalid weekly window")
    output=[];used=set();counts=Counter()
    for line in raw.splitlines():
        if not line.strip():continue
        if len(output)>=MAX_PAIRS:raise ValueError("Too many source revision pairs")
        item=json.loads(line)
        cid=item.get("cve_id")
        # OBSERVED timing must have real timezone (the source may have been
        # published earlier; do not rewrite to CVE's claimed updated date).
        observed=item.get("observed_utc")
        if not isinstance(observed,str):raise ValueError("Missing revision observation time")
        try:instant=datetime.fromisoformat(observed.replace("Z","+00:00"))
        except ValueError as exc:raise ValueError("Invalid revision observation time") from exc
        if instant.tzinfo is None:raise ValueError("Naive revision observed time")
        if instant.astimezone(timezone.utc).date()<start or instant.astimezone(timezone.utc).date()>end:
            raise ValueError("Out-of-window pair must be routed to its own observation window")
        if cid in used:raise ValueError("Duplicate CVE version pair requires explicit ordering")
        used.add(cid)
        result=compare_pair(item)
        result["observed_utc"]=instant.astimezone(timezone.utc).isoformat(timespec="seconds")
        output.append(result)
        counts[result["result"]]+=1
    output.sort(key=lambda x:x["cve_id"])
    return {
        "schema_version":1,"kind":"ECLIPSE_TWO_RAW_CVE_SNAPSHOTS_DIFF_REVIEW_NOT_PUBLISHER_CHANGE_FEED",
        "window":{"start_utc":start.isoformat(),"end_utc":end.isoformat()},
        "pair_input_sha256":hashlib.sha256(raw).hexdigest(),
        "pairs_compared":len(output),
        "counts_by_class":dict(sorted(counts.items())),
        "events":output,
        "input_record_source_authenticity_independently_verified":False,
        "no_prior_version_no_diff":True,
        "source_versions_preexisting_and_immutable_required":True,
        "weekly_CVE_update_coverage_certified":False,
        "safe_for_customer_auto_claims":False
    }


def write_report(pair_input,out,start,end):
    out=Path(out)
    if out.exists() or out.is_symlink():raise ValueError("Refuse overwrite")
    raw=Path(pair_input).read_bytes()
    data=analyze_pair_jsonl(raw,start,end)
    out.parent.mkdir(parents=True,exist_ok=True)
    with out.open("xb") as f:f.write((canonical(data)+"\n").encode())
    return {k:v for k,v in data.items() if k!="events"}


def verify_report(pair_input,report):
    given=Path(report).read_bytes()
    if len(given)>MAX_INPUT_BYTES:raise ValueError("Oversized report")
    parsed=json.loads(given)
    if parsed.get("kind")!="ECLIPSE_TWO_RAW_CVE_SNAPSHOTS_DIFF_REVIEW_NOT_PUBLISHER_CHANGE_FEED":
        raise ValueError("Untrusted pair report")
    reread=analyze_pair_jsonl(Path(pair_input).read_bytes(),
                             parsed["window"]["start_utc"],parsed["window"]["end_utc"])
    if given!=(canonical(reread)+"\n").encode():
        raise ValueError("CVE revision report not independently reproducible")
    return {"result":"INDEPENDENT_CVE_RAW_VERSION_DIFF_VERIFIED",
            "pairs_compared":reread["pairs_compared"],
            "classes":reread["counts_by_class"],
            "source_authenticity_independently_verified":False}


def main():
    p=argparse.ArgumentParser(description="V5 CVE revision comparison — requires TWO pinned records per CVE")
    sub=p.add_subparsers(dest="command",required=True)
    b=sub.add_parser("build")
    b.add_argument("--pairs",type=Path,required=True)
    b.add_argument("--start",required=True)
    b.add_argument("--end",required=True)
    b.add_argument("--out",type=Path,required=True)
    v=sub.add_parser("verify")
    v.add_argument("--pairs",type=Path,required=True)
    v.add_argument("--report",type=Path,required=True)
    args=p.parse_args()
    result=(write_report(args.pairs,args.out,args.start,args.end)
            if args.command=="build" else verify_report(args.pairs,args.report))
    print(json.dumps(result,ensure_ascii=False,sort_keys=True,indent=2))


if __name__=="__main__":
    main()
