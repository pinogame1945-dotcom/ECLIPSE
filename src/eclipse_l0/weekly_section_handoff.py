"""Weekly handoff with SEPARATE new-disclosure and existing-CVE-update totals.

Never dilute the NEW 50 shortlist with unreviewed old-CVE dateUpdated events.
Revision-based items have their own uncapped review ledger and separate
high-risk unverified queue. This is an evidence packet, NOT report copy.
Two independent ZIPs must share the exact same byte-for-byte L1 snapshot.
"""
from __future__ import annotations

import argparse
import io
import json
from pathlib import Path
import tempfile
import zipfile

from .weekly_evidence import canonical,sha
from .weekly_triage import _jsonlines,_read_jsonl
from .weekly_important import verify as verify_new
from .weekly_update_queue import verify as verify_update

SCHEMA=1
MEMBERS={
    "new_cve_candidate_evidence.zip", "existing_cve_update_evidence.zip",
    "new_kev_and_disclosures.jsonl",
    "material_update_research_only.jsonl",
    "unverified_update_high_risk_watch.jsonl",
    "weekly_distinct_section_summary.json",
    "weekly_section_manifest.json",
}
MAX_PACK=130*1024*1024
MAX_MEMBER=120*1024*1024


def _zip_member(container, name):
    if name not in container.namelist():
        raise ValueError("Expected independent evidence member absent: "+name)
    if container.getinfo(name).file_size>MAX_MEMBER:
        raise ValueError("Unsafe handoff source inflation")
    return container.read(name)


def _verify_child(zip_bytes, verifier):
    if not zip_bytes or len(zip_bytes)>MAX_PACK:
        raise ValueError("Invalid or oversized child ZIP")
    with tempfile.TemporaryDirectory() as scratch:
        p=Path(scratch)/"source.zip"
        p.write_bytes(zip_bytes)
        return verifier(p)


def compute(new_zip_bytes, updates_zip_bytes):
    new_proof=_verify_child(new_zip_bytes,verify_new)
    updates_proof=_verify_child(updates_zip_bytes,verify_update)
    with zipfile.ZipFile(io.BytesIO(new_zip_bytes)) as newz:
        new_l1=_zip_member(newz,"source-weekly-evidence.zip")
        new_index=json.loads(_zip_member(newz,"important_index.json"))
        top=_read_jsonl(_zip_member(newz,"top50_research_candidates.jsonl"))
    with zipfile.ZipFile(io.BytesIO(updates_zip_bytes)) as updatesz:
        updated_l1=_zip_member(updatesz,"source-weekly-evidence.zip")
        update_index=json.loads(_zip_member(updatesz,"update_review_summary.json"))
        reviewed=_read_jsonl(_zip_member(updatesz,"material_update_review_candidates.jsonl"))
        sample=_read_jsonl(_zip_member(updatesz,"unverified_high_risk_updates.jsonl"))
        updated_all=_read_jsonl(_zip_member(updatesz,"updated_cve_decision_ledger.jsonl"))
    if new_l1!=updated_l1:
        raise ValueError("New and revised information use different original source snapshot")
    if sha(new_l1)!=new_proof["source_zip_sha256"]:
        raise ValueError("Selected-new evidence L1 source hash mismatch")
    if new_proof["l1_total"]!=updates_proof["original_cves"]:
        raise ValueError("Original CVE population mismatch")
    if new_index["window"] != (update_index["window"]["start_utc"]+".."+update_index["window"]["end_utc"]):
        raise ValueError("Separate weekly section windows do not match")
    selected_ids=[x["cve_id"] for x in top]
    update_ids=[x["cve_id"] for x in updated_all]
    review_ids=[x["cve_id"] for x in reviewed]
    if len(selected_ids)!=len(set(selected_ids)) or len(update_ids)!=len(set(update_ids)):
        raise ValueError("Duplicate CVE in handoff candidate set")
    if len(review_ids)!=len(set(review_ids)) or not set(review_ids)<=set(update_ids):
        raise ValueError("Review queue is not subset of updated-only originals")
    if set(selected_ids)&set(update_ids):
        raise ValueError("A CVE cannot be counted as both NEW event and UPDATE event")
    if len(top)!=new_proof["top50"] or len(reviewed)!=updates_proof["material_review_candidates"]:
        raise ValueError("Invalid source evidence item counts")
    if len(updated_all)!=updates_proof["updated_only"] or len(sample)!=updates_proof["watchlist_high_risk_unverified"]:
        raise ValueError("Incomplete separate change audit populations")
    if any(
        (x.get("new_kev_added_in_window") is not True and
         x.get("new_cve_publication_in_window") is not True)
        for x in top
    ):
        raise ValueError("Old metadata updates were included in new information")
    if any(x.get("selected_for_weekly_report") is not False for x in top+reviewed+sample):
        raise ValueError("Unreviewed evidence incorrectly declared ready to publish")

    material_count=len(reviewed)
    unverified_count=updates_proof["unverified_updated"]
    total_updates=updates_proof["updated_only"]
    if total_updates!=material_count+unverified_count:
        raise ValueError("Material/unverified change accounting does not balance")
    summary={
        "schema_version":SCHEMA,
        "kind":"ECLIPSE_WEEKLY_TWO_SEPARATE_CVE_REPORT_SECTIONS_REVIEW_HANDOFF",
        "window":update_index["window"],
        "original_l1_cves":new_proof["l1_total"],
        "original_l1_zip_sha256":sha(new_l1),
        "new_information":{
            "section_key":"NEW_KEV_AND_NEW_CVE_DISCLOSURES",
            "research_candidate_count":len(top),
            "new_kev_mandatory":new_proof["mandatory_kev"],
            "new_cve_disclosures_non_kev":new_proof["top50_new_publications"],
            "target_count":new_proof["target"],
            "counts_independent_of_existing_cve_updates":True,
            "editorial_approval_completed":False,
        },
        "existing_cve_updates":{
            "section_key":"EXISTING_CVE_SOURCE_MATERIAL_UPDATES",
            "separate_from_new_information":True,
            "reviewable_updated_only_cves_in_L1":total_updates,
            "material_content_revision_review_candidates":material_count,
            "unverified_or_unmatched_update_candidates":unverified_count,
            "high_risk_unverified_watch_sample_count":len(sample),
            "fixed_target_or_quota":None,
            "material_change_content_verified_as_official_publication":False,
            "customer_impact_confirmed":False,
            "uncertainty_is_not_reinterpreted_as_no_update":True,
            "any_change_notification_requires_source_review":True,
        },
        "source_scope":{
            "new_source_zip_sha256":sha(new_zip_bytes),
            "update_source_zip_sha256":sha(updates_zip_bytes),
            "same_byte_exact_L1_source_in_both":True,
            "covered_all_CVE_updates_of_week":False,
            "unreviewed_updates_must_not_reduce_new_50_slots":True,
            "no_cve_counted_in_both_new_and_update_sections":True,
            "not_a_customer_report":True,
        }
    }
    return {
        "new_cve_candidate_evidence.zip":new_zip_bytes,
        "existing_cve_update_evidence.zip":updates_zip_bytes,
        "new_kev_and_disclosures.jsonl":_jsonlines(top),
        "material_update_research_only.jsonl":_jsonlines(reviewed),
        "unverified_update_high_risk_watch.jsonl":_jsonlines(sample),
        "weekly_distinct_section_summary.json":(canonical(summary)+"\n").encode(),
    }


def create(new,updated,out):
    out=Path(out)
    for src in (new,updated):
        src=Path(src)
        if not src.is_file() or src.is_symlink():
            raise ValueError("Required immutable evidence ZIP missing/unsafe")
    if out.exists() or out.is_symlink():
        raise ValueError("Refuse to overwrite weekly distinct-section handoff")
    files=compute(Path(new).read_bytes(),Path(updated).read_bytes())
    manifest={"schema_version":SCHEMA,"kind":"TWO_SECTIONS_FULL_RECOMPUTE_V1",
              "member_sha256":{name:sha(value) for name,value in sorted(files.items())}}
    files["weekly_section_manifest.json"]=(canonical(manifest)+"\n").encode()
    out.parent.mkdir(parents=True,exist_ok=True)
    try:
        with zipfile.ZipFile(out,"x",compression=zipfile.ZIP_DEFLATED,compresslevel=6) as z:
            for name,body in sorted(files.items()):
                member=zipfile.ZipInfo(name,date_time=(1980,1,1,0,0,0))
                member.compress_type=zipfile.ZIP_DEFLATED
                z.writestr(member,body)
        return verify(out)
    except BaseException:
        out.unlink(missing_ok=True)
        raise


def verify(out):
    out=Path(out)
    if not out.is_file() or out.is_symlink() or out.stat().st_size>MAX_PACK:
        raise ValueError("Bad distinct-section ZIP")
    with zipfile.ZipFile(out) as z:
        names=z.namelist()
        if set(names)!=MEMBERS or len(names)!=len(MEMBERS):
            raise ValueError("Bad distinct-section member set")
        if any(z.getinfo(x).file_size>MAX_MEMBER for x in names):
            raise ValueError("Oversized section handoff ZIP member")
        files={name:z.read(name) for name in names}
    manifest=json.loads(files["weekly_section_manifest.json"])
    if manifest.get("schema_version")!=SCHEMA or manifest.get("kind")!="TWO_SECTIONS_FULL_RECOMPUTE_V1" or set(manifest.get("member_sha256",{}))!=MEMBERS-{"weekly_section_manifest.json"}:
        raise ValueError("Bad distinct-section hash manifest")
    for name in MEMBERS-{"weekly_section_manifest.json"}:
        if sha(files[name])!=manifest["member_sha256"][name]:
            raise ValueError("Section handoff hash invalid: "+name)
    computed=compute(files["new_cve_candidate_evidence.zip"],files["existing_cve_update_evidence.zip"])
    if any(files[name]!=body for name,body in computed.items()):
        raise ValueError("Two-section handoff not reproducible from immutable source ZIPs")
    overview=json.loads(files["weekly_distinct_section_summary.json"])
    return {
        "result":"INDEPENDENT_TWO_SEPARATE_WEEKLY_CVE_SECTIONS_VERIFIED",
        "original_l1_cves":overview["original_l1_cves"],
        "new_candidates":overview["new_information"]["research_candidate_count"],
        "new_kev":overview["new_information"]["new_kev_mandatory"],
        "newly_published_non_kev":overview["new_information"]["new_cve_disclosures_non_kev"],
        "update_only_count":overview["existing_cve_updates"]["reviewable_updated_only_cves_in_L1"],
        "material_update_review_candidates":overview["existing_cve_updates"]["material_content_revision_review_candidates"],
        "update_unverified_count":overview["existing_cve_updates"]["unverified_or_unmatched_update_candidates"],
        "unverified_update_high_risk_watch_sample":overview["existing_cve_updates"]["high_risk_unverified_watch_sample_count"],
        "new_slots_never_consumed_by_unverified_updates":True,
        "report_ready":False,
    }


def main():
    p=argparse.ArgumentParser(description="New CVEs/KEV and existing CVE revisions: separate evidence sections")
    sub=p.add_subparsers(dest="cmd",required=True)
    b=sub.add_parser("build")
    b.add_argument("--new",type=Path,required=True)
    b.add_argument("--updates",type=Path,required=True)
    b.add_argument("--out",type=Path,required=True)
    v=sub.add_parser("verify")
    v.add_argument("--zip",type=Path,required=True)
    args=p.parse_args()
    proof=(create(args.new,args.updates,args.out) if args.cmd=="build" else verify(args.zip))
    print(json.dumps(proof,ensure_ascii=False,sort_keys=True,indent=2))


if __name__=="__main__":
    main()
