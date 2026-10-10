"""Phase 2-D: transparent three-layer evidence handoff, no editorial report.

L1 is the original byte-exact full weekly evidence ZIP. L2 is a reversible
prioritized *index* across ALL CVE candidates (including unselected counts).
L3 adds full original CVE evidence and official advisory pointers for review.
Do not use tier order as a vulnerability severity or customer-impact verdict.
"""
from __future__ import annotations
from collections import Counter
from datetime import datetime
import argparse
import hashlib
import json
import math
from pathlib import Path
import tempfile
import zipfile

from .weekly_evidence import canonical, sha, verify as verify_weekly

SCHEMA=1
ZIP_NAMES={
    "source-weekly-evidence.zip",
    "triage_index.json",
    "priority_candidates.jsonl",
    "deep_dive_candidates.jsonl",
    "triage_quality.json",
    "triage_manifest.json",
}
MAX_BASE_ZIP_BYTES=90*1024*1024
MAX_MEMBER_BYTES=120*1024*1024
SCORE_RULE="KEV_NEW>KEV_PRESENT>CVSS_CRITICAL>=9>EPSS>=0.5>CVSS_HIGH>=7>VENDOR_CANDIDATE>WATCH"
BUCKET_ORDER=(
    "P0_NEW_KEV","P1_EXISTING_KEV","P2_CNA_CVSS_CRITICAL",
    "P3_EPSS_HIGH_DATE_UNKNOWN","P4_CNA_CVSS_HIGH",
    "P5_VENDOR_CVE_REFERENCE_UNREVIEWED","WATCHLIST_NO_STRONG_SIGNAL",
    "INACTIVE_REJECTED_OR_OTHER"
)
NO_VERSIONS_CERTIFIED=True


def _read_jsonl(raw:bytes):
    return [json.loads(line) for line in raw.splitlines() if line]


def _jsonlines(rows):
    return "".join(canonical(row)+"\n" for row in rows).encode("utf-8")


def _num(value,min_value,max_value,field):
    if value is None:
        return None
    if isinstance(value,bool) or not isinstance(value,(int,float)):
        raise ValueError("Non-numeric official "+field)
    if not math.isfinite(value) or not min_value<=value<=max_value:
        raise ValueError("Non-finite or out-of-range official "+field)
    return float(value)


def classify(row):
    if not isinstance(row,dict) or not isinstance(row.get("cve_id"),str):
        raise ValueError("Invalid original CVE record")
    state=row.get("record_state")
    reasons=row.get("week_reasons")
    if not isinstance(reasons,list) or not all(isinstance(x,str) for x in reasons):
        raise ValueError("Invalid week reason list")
    kev=row.get("kev")
    if not isinstance(kev,dict) or not isinstance(kev.get("present"),bool):
        raise ValueError("Missing source-attributed KEV presence")
    score=_num((row.get("cvss") or {}).get("base_score"),0,10,"CVSS")
    epss_data=row.get("epss")
    epss=_num(epss_data.get("probability"),0,1,"EPSS") if epss_data is not None else None
    vendor=row.get("linked_vendor_documents")
    if not isinstance(vendor,list) or any(not isinstance(v,str) for v in vendor):
        raise ValueError("Invalid official vendor linkage")
    tags=[]
    if "CISA_KEV_DATE_ADDED_IN_WINDOW" in reasons:
        if not kev["present"]:
            raise ValueError("KEV added signal with no actual source membership")
        tags.append("CISA_KEV_ADDED_TO_CATALOG_IN_WINDOW")
    if kev["present"]:
        tags.append("CISA_KEV_PRESENT_ACTUAL_EXPLOITATION_IN_CATALOG")
    if score is not None and score>=9.0:tags.append("CNA_REPORTED_CVSS_AT_LEAST_9")
    elif score is not None and score>=7.0:tags.append("CNA_REPORTED_CVSS_AT_LEAST_7")
    if epss is not None and epss>=0.5:
        tags.append("FIRST_EPSS_AT_LEAST_0_5_SNAPSHOT_DATE_UNKNOWN")
    if vendor:tags.append("OFFICIAL_VENDOR_CVE_CANDIDATE_LINK_UNREVIEWED")
    if state!="PUBLISHED":
        bucket=BUCKET_ORDER[7]
    elif "CISA_KEV_DATE_ADDED_IN_WINDOW" in reasons:
        bucket=BUCKET_ORDER[0]
    elif kev["present"]:
        bucket=BUCKET_ORDER[1]
    elif score is not None and score>=9.0:
        bucket=BUCKET_ORDER[2]
    elif epss is not None and epss>=0.5:
        bucket=BUCKET_ORDER[3]
    elif score is not None and score>=7.0:
        bucket=BUCKET_ORDER[4]
    elif vendor:
        bucket=BUCKET_ORDER[5]
    else:
        bucket=BUCKET_ORDER[6]
    return {
        "cve_id":row["cve_id"],"record_state":state,
        "attention_bucket":bucket,"rule_only_noneditorial":True,
        "source_reason_tags":tags,"week_reasons":reasons,
        "cvss_base":score,"cvss_attribution":(row.get("cvss") or {}).get("attribution"),
        "kev_present":kev["present"],"kev_date_added":kev.get("date_added"),
        "epss_probability":epss,
        "epss_score_date":(epss_data or {}).get("score_date") if epss_data is not None else None,
        "vendor_document_keys":sorted(set(vendor)),
        "vendor_document_links_unreviewed":True,
        "selected_for_weekly_report":False,
        "actual_customer_impact":"NOT_ASSESSED"
    }


def compute(base_bytes):
    if not 0<len(base_bytes)<=MAX_BASE_ZIP_BYTES:raise ValueError("Base weekly ZIP size outside bound")
    # Independent base contract requires on-disk path, no trusted unvalidated
    # extracted member should be treated as a verified original.
    with tempfile.TemporaryDirectory(prefix="eclipse-l1-audit-") as d:
        base=Path(d)/"source-weekly-evidence.zip"
        base.write_bytes(base_bytes)
        proof=verify_weekly(base)
    with zipfile.ZipFile(__import__("io").BytesIO(base_bytes)) as z:
        rows=_read_jsonl(z.read("vulnerabilities.jsonl"))
        docs=_read_jsonl(z.read("vendor_advisories.jsonl"))
        evidence=_read_jsonl(z.read("evidence.jsonl"))
        index=json.loads(z.read("weekly_index.json"))
        quality=json.loads(z.read("quality_report.json"))
        base_manifest=json.loads(z.read("manifest.json"))
    if quality["weekly_coverage_certified"] is not False:
        raise ValueError("A fixed weekly source snapshot cannot certify complete monitoring")
    doc_map={}
    for doc in docs:
        key=doc.get("document_key")
        if not isinstance(key,str) or key in doc_map:raise ValueError("Duplicate/invalid vendor doc")
        doc_map[key]=doc
    lookup={}
    ev_index={}
    for item in evidence:
        subject=item.get("subject")
        if not isinstance(subject,str):raise ValueError("Malformed evidence subject")
        ev_index.setdefault(subject,[]).append(item)
    order={key:i for i,key in enumerate(BUCKET_ORDER)}
    ranked=[];detail=[];seen=set()
    for item in rows:
        p=classify(item)
        cid=p["cve_id"]
        if cid in seen:raise ValueError("Duplicate CVE in base weekly source")
        seen.add(cid)
        if any(k not in doc_map for k in p["vendor_document_keys"]):
            raise ValueError("Missing unreviewed vendor source referenced by CVE "+cid)
        ranked.append(p)
        # All non-inactive higher-attention items receive a detailed analysis
        # *candidate*, irrespective of absence of structured manufacturer info.
        # Missing info is explicit and blocks a premature verified impact claim.
        if order[p["attention_bucket"]]<=3 or (
                order[p["attention_bucket"]]==4 and p["vendor_document_keys"]):
            refs=[{"document_key":k,"publisher_url":doc_map[k]["source_url"],
                   "official_source_sha256":doc_map[k]["source_sha256"],
                   "facts_sha256":doc_map[k]["normalized_facts_sha256"],
                   "facts_status":doc_map[k]["source_extract_status"],
                   "vendor_cve_link_unreviewed":True}
                  for k in p["vendor_document_keys"]]
            gaps=[]
            if not refs:gaps.append("NO_OFFICIAL_VENDOR_ADVISORY_IN_FIXED_SNAPSHOT")
            if item.get("attack_prerequisites")=="NOT_STRUCTURED_OR_VERIFIED":
                gaps.append("EXPLOIT_PREREQUISITES_NOT_STRUCTURED_OR_VERIFIED")
            if item.get("technical_root_cause")=="NOT_STRUCTURED_OR_VERIFIED":
                gaps.append("TECHNICAL_ROOT_CAUSE_NOT_STRUCTURED_OR_VERIFIED")
            gaps.append("CUSTOMER_AFFECTED_VERSION_NOT_ASSESSED")
            if p["epss_probability"] is not None:
                gaps.append("EPSS_SCORE_DATE_NOT_STORED_IN_FIXED_SNAPSHOT")
            detail.append({
                "cve_id":cid,"attention_bucket":p["attention_bucket"],
                "primary_cve_record_source_sha256":item["source_cve_record_sha256"],
                "original_cve_payload_unaltered":item,
                "vendor_evidence_pointers_unreviewed":refs,
                "primary_cve_evidence_records":ev_index.get(cid,[]),
                "evidence_gaps":gaps,
                "analysis_ready_for_human_or_ChatGPT_review":True,
                "actual_exploitation_mechanism_confirmed_by_this_packet":False,
                "publisher_fixed_versions_verified":False,
                "client_impact_verified":False
            })
    ranked.sort(key=lambda p:(order[p["attention_bucket"]],
                              -p["cvss_base"] if p["cvss_base"] is not None else 1,
                              -p["epss_probability"] if p["epss_probability"] is not None else 1,
                              p["cve_id"]))
    detail.sort(key=lambda p:(order[p["attention_bucket"]],p["cve_id"]))
    buckets=Counter(p["attention_bucket"] for p in ranked)
    l2=[p for p in ranked if order[p["attention_bucket"]]<=5]
    watch_count=sum(buckets[k] for k in BUCKET_ORDER[6:])
    all_ranked_ids={p["cve_id"] for p in ranked}
    if len(all_ranked_ids)!=proof["candidate_total"] or len(rows)!=len(all_ranked_ids):
        raise ValueError("Prioritization lost original source CVEs")
    if len(l2)+watch_count!=len(rows):
        raise ValueError("L1/L2 candidate partition not exhaustive")
    summary={
        "schema_version":SCHEMA,"purpose":"WEEKLY_TRIAGE_EVIDENCE_NOT_REPORT",
        "utc_window":base_manifest["window"],
        "l1_all_cves_count":len(rows),
        "l1_byte_exact_original_zip_member":"source-weekly-evidence.zip",
        "l1_original_zip_sha256":sha(base_bytes),
        "l2_priority_index_count":len(l2),
        "l2_no_assessment_watch_or_inactive_count":watch_count,
        "l2_buckets_all_candidates":{name:buckets[name] for name in BUCKET_ORDER},
        "l3_source_supported_deep_dive_candidates":len(detail),
        "selection_procedure":SCORE_RULE,
        "score_semantics":"ORDERED_RULES_NOT_NUMERIC_CROSS_CVE_RISK_MODEL",
        "source_vendor_documents_in_original_zip":proof["vendor_documents"],
        "source_evidence_rows":proof["evidence_entries"],
        "no_cve_removed_from_l1":True,
        "vendor_scope_is_not_a_global_cve_filter":True,
        "critical_unmatched_vendor_cve_kept":True,
        "editorial_selection_performed":False,
        "completeness":"SOURCE_FIXED_WEEK_SNAPSHOT_NOT_LIVE_COMPLETE"
    }
    cover={
        "weekly_coverage_certified":False,
        "base_source_date_or_kev_candidate_count":len(rows),
        "vendor_sources_missing_from_original_weekly_snapshot":quality["missing_publisher_data_in_vendor_snapshot"],
        "original_source_quality_notes":quality["critical_notes"],
        "cve_full_corpus_unrestricted_by_vendor":True,
        "structured_technical_facts_not_invented":True,
        "vendor_links_can_include_UNREVIEWED_pagewide_candidates":True,
        "epss_score_date_not_available":True,
        "no_auto_cvss_cvss_keyword_attack_mechanism_inference":True,
        "ranking_does_not_certify_severity_exploit_or_customer_exposure":True,
        "only_high_signal_candidates_have_deep_dive_packets_but_all_l1_preserved":True,
        "not_an_editorial_or_customer_weekly_report":True
    }
    return (summary,_jsonlines(l2),_jsonlines(detail),cover)


def _output_files(source_bytes:bytes):
    index,priorities,deep,quality=compute(source_bytes)
    return {
        "source-weekly-evidence.zip":source_bytes,
        "triage_index.json":(canonical(index)+"\n").encode(),
        "priority_candidates.jsonl":priorities,
        "deep_dive_candidates.jsonl":deep,
        "triage_quality.json":(canonical(quality)+"\n").encode(),
    }


def create(*,source,out):
    source=Path(source)
    out=Path(out)
    if out.exists() or out.is_symlink():raise ValueError("Refuse to overwrite evidence ZIP")
    if not source.is_file() or source.is_symlink():raise ValueError("Unsafe input ZIP")
    contents=_output_files(source.read_bytes())
    if any(len(body)>MAX_MEMBER_BYTES for body in contents.values()):
        raise ValueError("Triage member exceeds safe bound")
    manifest={
        "schema_version":SCHEMA,"kind":"ECLIPSE_THREE_LAYER_EVIDENCE_NOT_WEEKLY_REPORT",
        "l1_original_byte_exact_sha256":sha(contents["source-weekly-evidence.zip"]),
        "member_sha256":{n:sha(v) for n,v in sorted(contents.items())},
        "member_bytes":{n:len(v) for n,v in sorted(contents.items())},
        "rule_only_no_editorial_truncation":True,
        "source_integrity_verified_with_original_manifest":True,
        "weekly_completeness_verified":False,
        "customer_product_exposure_verified":False
    }
    contents["triage_manifest.json"]=(canonical(manifest)+"\n").encode()
    out.parent.mkdir(parents=True,exist_ok=True)
    try:
        with zipfile.ZipFile(out,"x",compression=zipfile.ZIP_DEFLATED,compresslevel=6) as z:
            for name in sorted(contents):
                i=zipfile.ZipInfo(name,date_time=(1980,1,1,0,0,0))
                i.compress_type=zipfile.ZIP_DEFLATED
                z.writestr(i,contents[name],compress_type=zipfile.ZIP_DEFLATED,compresslevel=6)
        proof=verify(out)
        return {"result":"ECLIPSE_L1_L2_L3_EVIDENCE_HANDOFF_VERIFIED",
                "zip_sha256":sha(out.read_bytes()),"bytes":out.stat().st_size,
                **{key:proof[key] for key in ("l1_total","l2_total","l3_total","watch_or_inactive")}}
    except BaseException:
        out.unlink(missing_ok=True)
        raise


def verify(path):
    p=Path(path)
    if not p.is_file() or p.is_symlink():raise ValueError("Invalid triage ZIP")
    with zipfile.ZipFile(p) as z:
        names=z.namelist()
        if len(names)!=len(ZIP_NAMES) or set(names)!=ZIP_NAMES or len(set(names))!=len(names):
            raise ValueError("Missing, duplicate or extra triage ZIP member")
        if any(z.getinfo(n).file_size>MAX_MEMBER_BYTES for n in names):
            raise ValueError("Excessive triage member inflation")
        content={n:z.read(n) for n in names}
    m=json.loads(content["triage_manifest.json"])
    if (m.get("schema_version")!=SCHEMA or
        m.get("kind")!="ECLIPSE_THREE_LAYER_EVIDENCE_NOT_WEEKLY_REPORT" or
        m.get("rule_only_no_editorial_truncation") is not True or
        m.get("source_integrity_verified_with_original_manifest") is not True or
        m.get("weekly_completeness_verified") is not False or
        m.get("customer_product_exposure_verified") is not False or
        set(m.get("member_sha256",{}))!=ZIP_NAMES-{"triage_manifest.json"}):
        raise ValueError("Untrusted three-layer handoff manifest")
    for n in ZIP_NAMES-{"triage_manifest.json"}:
        if (sha(content[n])!=m["member_sha256"][n] or
            len(content[n])!=m.get("member_bytes",{}).get(n)):
            raise ValueError("Triage SHA or length mismatch: "+n)
    if sha(content["source-weekly-evidence.zip"])!=m["l1_original_byte_exact_sha256"]:
        raise ValueError("Altered L1 full weekly evidence ZIP")
    ix=json.loads(content["triage_index.json"])
    quality=json.loads(content["triage_quality.json"])
    if quality.get("weekly_coverage_certified") is not False or ix.get("no_cve_removed_from_l1") is not True:
        raise ValueError("Research snapshot falsely claims full weekly coverage")
    expected=_output_files(content["source-weekly-evidence.zip"])
    # Rerun ALL prioritization from validated original L1; recomputing hashes
    # alone would not detect dropping high-severity or vendor-unmatched rows.
    for n in expected:
        if content[n]!=expected[n]:
            raise ValueError("Recomputed deterministic triage is not equivalent: "+n)
    return {"result":"INDEPENDENT_THREE_LAYER_EVIDENCE_CONTRACT_VERIFIED",
        "l1_total":ix["l1_all_cves_count"],
        "l2_total":ix["l2_priority_index_count"],
        "l3_total":ix["l3_source_supported_deep_dive_candidates"],
        "watch_or_inactive":ix["l2_no_assessment_watch_or_inactive_count"],
        "counts_by_bucket":ix["l2_buckets_all_candidates"],
        "source_zip_sha256":m["l1_original_byte_exact_sha256"],
        "weekly_coverage_certified":False}


def main():
    p=argparse.ArgumentParser(description="Three-layer evidence handoff; never authors a weekly report")
    sub=p.add_subparsers(dest="command",required=True)
    a=sub.add_parser("build")
    a.add_argument("--source-weekly-zip",type=Path,required=True)
    a.add_argument("--out",type=Path,required=True)
    v=sub.add_parser("verify")
    v.add_argument("--zip",type=Path,required=True)
    arg=p.parse_args()
    result=create(source=arg.source_weekly_zip,out=arg.out) if arg.command=="build" else verify(arg.zip)
    print(json.dumps(result,ensure_ascii=False,sort_keys=True,indent=2))


if __name__=="__main__":main()
