"""Auditable weekly UPDATE review queue, distinct from verified publication/KEV.

No source before-state => cannot classify CVE dateUpdated as a security change.
Historical vendor or raw CVE version comparisons can be attached as read-only
review evidence. Never promote a revision directly to an approved report item.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import io
import json
from pathlib import Path
import tempfile
import zipfile

from .weekly_evidence import canonical, sha, verify as verify_l1
from .weekly_triage import _read_jsonl, _jsonlines
from .weekly_temporal import publication_signals

NAMES={"source-weekly-evidence.zip","updated_cve_decision_ledger.jsonl",
       "material_update_review_candidates.jsonl","unverified_high_risk_updates.jsonl",
       "update_review_summary.json","source_revision_evidence.json",
       "update_review_manifest.json"}
MAX_SOURCE=90*1024*1024
MAX_PROOF=32*1024*1024


def _check_evidence(evidence, *, first,last,candidates):
    if not isinstance(evidence,dict):raise ValueError("Invalid revision evidence")
    by_id={}
    if evidence.get("kind")=="ECLIPSE_TWO_RAW_CVE_SNAPSHOTS_DIFF_REVIEW_NOT_PUBLISHER_CHANGE_FEED":
        if evidence.get("window")!={"start_utc":first,"end_utc":last}:
            raise ValueError("CVE revision evidence week mismatch")
        if evidence.get("input_record_source_authenticity_independently_verified") is not False:
            raise ValueError("CVE source pair authenticity overclaimed")
        for item in evidence.get("events",[]):
            if not isinstance(item,dict) or item.get("cve_id") not in candidates:
                raise ValueError("CVE revision not in updated-only L1 set")
            cid=item["cve_id"]
            if cid in by_id:raise ValueError("Duplicated revision proof for CVE")
            by_id[cid]=[{"source_kind":"CVE_V5_PAIR","status":item["result"],
                          "scope":"CVE_ID_DIRECT_SOURCE_PAIR",
                          "changed_fields":item.get("changed_cna_security_categories",[]),
                          "eligible_for_review":item.get("candidate_for_material_security_review") is True,
                          "time_basis":"OBSERVED_UTC_NOT_PUBLISHER_UPDATE"}]
    elif evidence.get("kind")=="ECLIPSE_OBSERVED_VENDOR_FACTS_DIFF_REVIEW_ONLY":
        if evidence.get("window")!={"start_utc":first,"end_utc":last}:
            raise ValueError("Vendor revision evidence week mismatch")
        if evidence.get("vendor_weekly_monitoring_complete") is not False:
            raise ValueError("Vendor source coverage overclaimed")
        for item in evidence.get("events",[]):
            if not isinstance(item,dict):raise ValueError("Invalid vendor event")
            if item.get("eligible_for_weekly_research") is not True:continue
            for cid in item.get("candidate_cve_ids",[]):
                if cid not in candidates:continue
                by_id.setdefault(cid,[]).append({
                    "source_kind":"VENDOR_ADVISORY_VERSION_PAIR",
                    "source_id":item["source_id"],"advisory_id":item["advisory_id"],
                    "source_url":item["source_url"],
                    "old_source_sha256":item["old_source_sha256"],
                    "new_source_sha256":item["new_source_sha256"],
                    "status":item["change_status"],
                    "scope":item["cve_link_status"],
                    "changed_fields":item["security_claim_change_categories"],
                    "eligible_for_review":True,
                    "time_basis":"VENDOR_OBSERVED_UTC_NOT_PUBLISHER_UPDATE_DATE"
                })
    else:raise ValueError("Unsupported revision proof type")
    return by_id


def compute(source_bytes, *, vendor_material=None,cve_material=None,watch_limit=50):
    if not isinstance(watch_limit,int) or isinstance(watch_limit,bool) or not 1<=watch_limit<=300:
        raise ValueError("Invalid watch candidate count")
    if not source_bytes or len(source_bytes)>MAX_SOURCE:raise ValueError("Invalid weekly L1")
    with tempfile.TemporaryDirectory() as d:
        p=Path(d)/"weekly.zip"
        p.write_bytes(source_bytes)
        proof=verify_l1(p)
    with zipfile.ZipFile(io.BytesIO(source_bytes)) as z:
        data=_read_jsonl(z.read("vulnerabilities.jsonl"))
        index=json.loads(z.read("weekly_index.json"))
    if proof["candidate_total"]!=len(data):raise ValueError("Incomplete weekly L1")
    first=index["window_start_utc"];last=index["window_end_utc"]
    updates={r["cve_id"]:r for r in data
             if r["record_state"]=="PUBLISHED"
             and "CVE_SOURCE_DATE_UPDATED_IN_WINDOW" in r["week_reasons"]
             and "CVE_SOURCE_DATE_PUBLISHED_IN_WINDOW" not in r["week_reasons"]
             and "CISA_KEV_DATE_ADDED_IN_WINDOW" not in r["week_reasons"]}
    seen=set();paired={};sources={}
    for key,raw in (("vendor",vendor_material),("cve",cve_material)):
        if raw is None:continue
        if not 0<len(raw)<=MAX_PROOF:raise ValueError("Invalid revision evidence bytes")
        obj=json.loads(raw)
        linked=_check_evidence(obj,first=first,last=last,candidates=updates)
        for cid,items in linked.items():
            paired.setdefault(cid,[]).extend(items)
        sources[key]={"sha256":sha(raw),"event_count":len(obj["events"]),
                      "proof_kind":obj["kind"],
                      "source_authenticity_and_scope_reviewed":False}
    ledger=[];queue=[]
    for cid,row in sorted(updates.items()):
        matches=paired.get(cid,[])
        category=("MATERIAL_CHANGE_REVIEW_CANDIDATE" if
                  any(x["eligible_for_review"] for x in matches) else
                  "UPDATE_REASON_ONLY_BEFORE_STATE_UNAVAILABLE_OR_NO_MATERIAL_PROOF")
        cvss=(row.get("cvss") or {}).get("base_score")
        epss=(row.get("epss") or {}).get("probability")
        score,_=publication_signals(row,matched_vendor=False)
        # Source score is for *manual inspection priority only*, not
        # evidence a revision changed security severity.
        item={"cve_id":cid,"state":category,
              "source_cve_updated_utc":row["cve_updated_utc"],
              "source_cve_published_utc":row["cve_published_utc"],
              "cvss_source_score":cvss,
              "epss_snapshot_probability_date_unknown":epss,
              "review_order_score_only":score,
              "review_evidence":matches,
              "no_material_change_ever_asserted":False,
              "selected_for_weekly_report":False}
        ledger.append(item)
        if category=="MATERIAL_CHANGE_REVIEW_CANDIDATE":
            queue.append(item)
    # Strict separation: material-review queue is not conflated with
    # the unverified-risk backlog.
    unverified=[x for x in ledger if x["state"]!= "MATERIAL_CHANGE_REVIEW_CANDIDATE"]
    unverified.sort(key=lambda x:(-x["review_order_score_only"],x["cve_id"]))
    queue.sort(key=lambda x:(-x["review_order_score_only"],x["cve_id"]))
    summary={
        "kind":"ECLIPSE_WEEKLY_UPDATED_CVE_CONTENT_CHANGE_REVIEW_NOT_WEEKLY_REPORT",
        "schema_version":1,"window":{"start_utc":first,"end_utc":last},
        "l1_full_original_cves":len(data),"l1_source_sha256":sha(source_bytes),
        "updated_only_published_cves":len(ledger),
        "supported_material_change_review_candidates":len(queue),
        "unverified_or_unmatched_updated_cves":len(unverified),
        "unverified_high_risk_watch_count":min(len(unverified),watch_limit),
        "source_version_proofs_provided":sources,
        "no_prior_source_does_not_mean_no_security_update":True,
        "source_date_updated_alone_never_confirmed_material_change":True,
        "all_report_selection_requires_further_review":True,
        "weekly_update_coverage_certified":False
    }
    material_inputs={"vendor_material":vendor_material.decode("utf-8") if vendor_material else None,
                     "cve_material":cve_material.decode("utf-8") if cve_material else None}
    return {
      "source-weekly-evidence.zip":source_bytes,
      "updated_cve_decision_ledger.jsonl":_jsonlines(ledger),
      "material_update_review_candidates.jsonl":_jsonlines(queue),
      "unverified_high_risk_updates.jsonl":_jsonlines(unverified[:watch_limit]),
      "update_review_summary.json":(canonical(summary)+"\n").encode(),
      "source_revision_evidence.json":(canonical(material_inputs)+"\n").encode()
    }


def create(source,out,*,vendor_material=None,cve_material=None,watch_limit=50):
    source=Path(source);out=Path(out)
    if out.exists() or out.is_symlink():raise ValueError("Refuse overwrite")
    if not source.is_file() or source.is_symlink():raise ValueError("Unsafe original L1")
    def load(v):
        if v is None:return None
        p=Path(v)
        if not p.is_file() or p.is_symlink():raise ValueError("Unsafe revision evidence")
        return p.read_bytes()
    files=compute(source.read_bytes(),vendor_material=load(vendor_material),
                  cve_material=load(cve_material),watch_limit=watch_limit)
    manifest={"schema_version":1,"kind":"ECLIPSE_WEEKLY_UPDATE_REVIEW_HASH_AND_RECOMPUTE",
              "watch_limit":watch_limit,
              "member_sha256":{k:sha(v) for k,v in sorted(files.items())}}
    files["update_review_manifest.json"]=(canonical(manifest)+"\n").encode()
    out.parent.mkdir(parents=True,exist_ok=True)
    try:
        with zipfile.ZipFile(out,"x",compression=zipfile.ZIP_DEFLATED,compresslevel=6) as z:
            for key,value in sorted(files.items()):
                info=zipfile.ZipInfo(key,date_time=(1980,1,1,0,0,0))
                info.compress_type=zipfile.ZIP_DEFLATED
                z.writestr(info,value)
        return verify(out)
    except BaseException:
        out.unlink(missing_ok=True)
        raise


def verify(path):
    p=Path(path)
    if not p.is_file() or p.is_symlink():raise ValueError("Invalid update ZIP")
    with zipfile.ZipFile(p) as z:
        names=z.namelist()
        if len(names)!=len(NAMES) or set(names)!=NAMES:
            raise ValueError("Bad update ZIP member set")
        parts={name:z.read(name) for name in names}
    m=json.loads(parts["update_review_manifest.json"])
    if m.get("kind")!="ECLIPSE_WEEKLY_UPDATE_REVIEW_HASH_AND_RECOMPUTE" or set(m.get("member_sha256",{}))!=NAMES-{"update_review_manifest.json"}:
        raise ValueError("Bad update proof manifest")
    for name in NAMES-{"update_review_manifest.json"}:
        if m["member_sha256"][name]!=sha(parts[name]):raise ValueError("Update evidence hash mismatch")
    external=json.loads(parts["source_revision_evidence.json"])
    data=compute(parts["source-weekly-evidence.zip"],
                 vendor_material=external["vendor_material"].encode() if external["vendor_material"] else None,
                 cve_material=external["cve_material"].encode() if external["cve_material"] else None,
                 watch_limit=m["watch_limit"])
    if any(parts[name]!=val for name,val in data.items()):
        raise ValueError("Update review cannot be independently reproduced")
    summary=json.loads(parts["update_review_summary.json"])
    return {"result":"INDEPENDENT_WEEKLY_UPDATE_REVIEW_QUEUE_REPRODUCED",
            "original_cves":summary["l1_full_original_cves"],
            "updated_only":summary["updated_only_published_cves"],
            "material_review_candidates":summary["supported_material_change_review_candidates"],
            "unverified_updated":summary["unverified_or_unmatched_updated_cves"],
            "watchlist_high_risk_unverified":summary["unverified_high_risk_watch_count"],
            "update_weekly_coverage_certified":False}


def main():
    p=argparse.ArgumentParser(description="Source-change evidence queue; does not create a weekly report")
    sub=p.add_subparsers(dest="cmd",required=True)
    b=sub.add_parser("build")
    b.add_argument("--source-weekly-zip",type=Path,required=True)
    b.add_argument("--vendor-material",type=Path)
    b.add_argument("--cve-material",type=Path)
    b.add_argument("--watch-limit",type=int,default=50)
    b.add_argument("--out",type=Path,required=True)
    v=sub.add_parser("verify")
    v.add_argument("--zip",type=Path,required=True)
    args=p.parse_args()
    result=(create(args.source_weekly_zip,args.out,vendor_material=args.vendor_material,
                   cve_material=args.cve_material,watch_limit=args.watch_limit)
            if args.cmd=="build" else verify(args.zip))
    print(json.dumps(result,ensure_ascii=False,sort_keys=True,indent=2))


if __name__=="__main__":main()
