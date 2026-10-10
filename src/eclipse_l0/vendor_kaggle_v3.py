"""ECLIPSE private vendor evidence generation 3: strict immutable v2 ancestry.

This does NOT approve publisher redistribution, product applicability, exploitation,
continuous monitoring, or weekly coverage. It never mutates the CVE warehouse.
A single provider snapshot is archived as unreviewed official sample evidence.
"""
from __future__ import annotations
import argparse, hashlib, json, re, shutil, sqlite3
from datetime import datetime, timezone
from pathlib import Path
from contextlib import closing
from .vendor_kaggle_successor import validate as validate_v2, rows
from .vendor_replay import inspect_db
from .vendor_kaggle import PART_NAME, sha256, json_bytes
from .vendor_registry import load_registry

SLUG="eclipse-vendor-evidence-20261010-v3"
INDEX="vendor-evidence-v3-index.json"
SCOPE="ECLIPSE_VENDOR_PRIVATE_GENERATION_3"
PARENT_SLUG="eclipse-vendor-evidence-20261010-v2"
MAX_BYTES=50*1024*1024
EXPECTED_SOURCE_IDS=(
 "mozilla-mfsa","debian-dsa","apple-security-releases","adobe-security-bulletins",
 "android-security-bulletins","postgresql-security","cisco-public-advisories",
 "sap-security-patch-days","drupal-core-security","apache-httpd-security",
 "jenkins-security","nginx-security","openssl-security","tomcat-security",
 "wordpress-core-security")
MIN_COMPLETE_SOURCES=12
HEX=re.compile(r"^[0-9a-f]{64}$")

def trusted_parent(v2_idx, v1_idx):
    v2_path=Path(v2_idx)
    v2=json.loads(v2_path.read_text("utf-8"))
    validate_v2(v2,Path(v1_idx))
    if v2["scope"]!="ECLIPSE_VENDOR_PRIVATE_GENERATION_2" or v2["dataset_slug"]!=PARENT_SLUG:
        raise ValueError("Unexpected parent Kaggle vendor generation")
    return v2

def _ancestor(parent_db, child_db, registry, v2_idx, v1_idx):
    parent_index=trusted_parent(v2_idx,v1_idx)
    prior=inspect_db(parent_db,registry);new=inspect_db(child_db,registry)
    if prior["sqlite_sha256"]!=parent_index["sqlite_sha256"]:
        raise ValueError("Untrusted Kaggle v2 ancestor bytes")
    # Every previously recorded advisory version must retain its complete row.
    prior_versions=rows(parent_db,"vendor_document_versions","source_id,advisory_id,version")
    child_versions=rows(child_db,"vendor_document_versions","source_id,advisory_id,version")
    current={(x[0],x[1],x[2]):x for x in child_versions}
    if any(current.get((x[0],x[1],x[2]))!=x for x in prior_versions):
        raise ValueError("An immutable parent document version was altered or deleted")
    # Event order and exact contents prove append-only reconstruction.
    a=rows(parent_db,"vendor_document_events","event_id")
    b=rows(child_db,"vendor_document_events","event_id")
    if a!=b[:len(a)]:
        raise ValueError("Parent event chain altered or replaced")
    old=rows(parent_db,"vendor_documents","source_id,advisory_id")
    now=rows(child_db,"vendor_documents","source_id,advisory_id")
    old_first={(x[0],x[1]):x[5] for x in old}
    now_first={(x[0],x[1]):x[5] for x in now}
    if any(now_first.get(k)!=v for k,v in old_first.items()):
        raise ValueError("Parent advisory first-seen timestamp changed or advisory lost")
    for s,c in prior["source_counts"].items():
        if new["source_counts"].get(s,0)<c:
            raise ValueError("Parent source lost a document: "+s)
    for key in ("advisories","versions","events"):
        if new[key]<prior[key]:
            raise ValueError("Parent history count decreased")
    return prior,new,parent_index

def _collection(manifest, before, after):
    report=json.loads(Path(manifest).read_text("utf-8"))
    if report.get("mode")!="ONE_SHOT_OFFICIAL_UNREVIEWED_PILOT":
        raise ValueError("Wrong vendor-only observation report")
    results=report.get("source_results",[])
    ids=[r.get("source_id") for r in results]
    if tuple(ids)!=EXPECTED_SOURCE_IDS:
        raise ValueError("Unexpected source cohort, duplicate or reorder")
    if (any(r.get("status") not in ("PASS","FAIL") for r in results) or
        report.get("sources_pass")!=sum(r["status"]=="PASS" for r in results) or
        report.get("sources_failed")!=sum(r["status"]=="FAIL" for r in results) or
        report.get("sources_partial")!=0 or report.get("sources_degraded")!=0 or
        report["sources_pass"]<MIN_COMPLETE_SOURCES):
        raise ValueError("Excessive failed, partial or degraded official sources")
    if any(r["status"]=="PASS" and
           (r.get("saved",0)<=0 or r.get("replay_unchanged")!=r.get("saved") or r.get("errors"))
           for r in results):
        raise ValueError("Unsound read/parse or idempotent replay evidence")
    if any(r["status"]=="FAIL" and not r.get("errors") for r in results):
        raise ValueError("Failed source lacked explicit recorded error")
    if report.get("db_counts",{}).get("integrity")!="ok" or any(
       report["db_counts"].get(k)!=after[k] for k in ("advisories","versions","events")):
        raise ValueError("Collection receipt disagrees with verified SQLite")
    if after["advisories"]<=before["advisories"]:
        raise ValueError("No new official source documents; not a meaningful generation")
    successful={x["source_id"] for x in results if x["status"]=="PASS"}
    if any(after["source_counts"].get(s,0)<=before["source_counts"].get(s,0)
           for s in successful if before["source_counts"].get(s,0)==0):
        raise ValueError("Passed newly enabled source has no new archived document")
    # Failure reasons and source IDs, no original vendor HTML or confidential text.
    gaps=[{"source_id":r["source_id"],"reason":[str(x)[:240] for x in r["errors"][:4]]}
          for r in results if r["status"]=="FAIL"]
    return {"attempted":len(results),"passed":len(successful),"failed":len(gaps),
            "missing_samples":gaps,
            "sampling_max_items":report.get("requested_max_items_per_source")}

def stage(parent_db, child_db, v2_idx, v1_idx, collection_manifest, dest, registry):
    before,after,parent=_ancestor(parent_db,child_db,registry,v2_idx,v1_idx)
    collection=_collection(collection_manifest,before,after)
    dest=Path(dest)
    if dest.exists() and any(dest.iterdir()):raise ValueError("Overwrite of successor staging refused")
    dest.mkdir(parents=True,exist_ok=True)
    try:
        part=dest/PART_NAME
        with part.open("xb") as output,Path(child_db).open("rb") as original:
            shutil.copyfileobj(original,output,1024*1024)
        if not 0<part.stat().st_size<=MAX_BYTES or sha256(part)!=after["sqlite_sha256"]:
            raise ValueError("Failed successor SQLite byte-exact stage")
        idx={"schema_version":3,"scope":SCOPE,"dataset_slug":SLUG,
             "parent_slug":PARENT_SLUG,"parent_index_sha256":sha256(v2_idx),
             "parent_sqlite_sha256":before["sqlite_sha256"],
             "parent_counts":{k:before[k] for k in ("advisories","versions","events")},
             "part_name":PART_NAME,"sqlite_sha256":after["sqlite_sha256"],
             "sqlite_bytes":part.stat().st_size,
             "counts":{k:after[k] for k in ("advisories","versions","events")},
             "source_counts":after["source_counts"],
             "collection_manifest_sha256":sha256(collection_manifest),
             "sampling":{"cohort":list(EXPECTED_SOURCE_IDS),**collection},
             "append_only_verified":True,"human_verified_claims":False,
             "production_enabled":False,"weekly_source_coverage_assured":False,
             "commercial_reuse_rights":"not_reviewed",
             "raw_vendor_source_bodies_included":False,
             "customer_records_included":False,"cve_warehouse_touched":False,
             "created_utc":datetime.now(timezone.utc).isoformat(timespec="seconds")}
        (dest/INDEX).write_bytes(json_bytes(idx))
        return {"state":"PRIVATE_V3_STAGED_NO_UPLOAD_YET","counts":idx["counts"],
                "new_advisories":after["advisories"]-before["advisories"],
                "new_versions":after["versions"]-before["versions"],
                "sampling":collection,"index_sha256":sha256(dest/INDEX)}
    except BaseException:
        for p in (dest/INDEX,dest/PART_NAME):
            p.unlink(missing_ok=True)
        raise

def validate_index(idx,v2_idx,v1_idx):
    parent=trusted_parent(v2_idx,v1_idx)
    pc=parent["counts"];counts=idx.get("counts",{})
    if (idx.get("schema_version")!=3 or idx.get("scope")!=SCOPE or
        idx.get("dataset_slug")!=SLUG or idx.get("parent_slug")!=PARENT_SLUG or
        idx.get("parent_index_sha256")!=sha256(v2_idx) or
        idx.get("parent_sqlite_sha256")!=parent["sqlite_sha256"] or
        idx.get("parent_counts")!=pc or idx.get("part_name")!=PART_NAME or
        idx.get("append_only_verified") is not True or
        idx.get("production_enabled") is not False or
        idx.get("weekly_source_coverage_assured") is not False or
        idx.get("human_verified_claims") is not False or
        idx.get("customer_records_included") is not False or
        idx.get("raw_vendor_source_bodies_included") is not False or
        idx.get("cve_warehouse_touched") is not False or
        idx.get("commercial_reuse_rights")!="not_reviewed" or
        any(type(counts.get(k))!=int or counts[k]<pc[k] for k in ("advisories","versions","events")) or
        counts.get("versions")!=counts.get("events") or
        not isinstance(idx.get("source_counts"),dict) or
        sum(idx["source_counts"].values())!=counts.get("advisories") or
        not isinstance(idx.get("sqlite_sha256"),str) or not HEX.fullmatch(idx["sqlite_sha256"]) or
        not isinstance(idx.get("collection_manifest_sha256"),str) or not HEX.fullmatch(idx["collection_manifest_sha256"]) or
        not isinstance(idx.get("sqlite_bytes"),int) or not 0<idx["sqlite_bytes"]<=MAX_BYTES):
        raise ValueError("Untrusted vendor Kaggle V3 index, rollback or unapproved claims")
    sampling=idx.get("sampling")
    if (not isinstance(sampling,dict) or sampling.get("cohort")!=list(EXPECTED_SOURCE_IDS)
        or sampling.get("attempted")!=len(EXPECTED_SOURCE_IDS) or
        type(sampling.get("passed"))!=int or sampling["passed"]<MIN_COMPLETE_SOURCES or
        type(sampling.get("failed"))!=int or sampling["failed"]!=len(EXPECTED_SOURCE_IDS)-sampling["passed"] or
        not isinstance(sampling.get("missing_samples"),list) or
        len(sampling["missing_samples"])!=sampling["failed"]):
        raise ValueError("V3 must disclose every failed vendor source")
    return parent

def restore(trusted_idx,v2_idx,v1_idx,downloaded,dest,registry):
    original=Path(trusted_idx).read_bytes()
    idx=json.loads(original)
    validate_index(idx,v2_idx,v1_idx)
    download=Path(downloaded)
    meta=download/INDEX
    part=download/PART_NAME
    if not meta.is_file() or meta.is_symlink() or meta.read_bytes()!=original:
        raise ValueError("Provider-supplied index differs from independently trusted preupload index")
    if (not part.is_file() or part.is_symlink() or
        part.stat().st_size!=idx["sqlite_bytes"] or sha256(part)!=idx["sqlite_sha256"]):
        raise ValueError("Provider-supplied SQLite differs from independently trusted checksum")
    target=Path(dest)
    if target.exists():raise ValueError("Never overwrite original or recovered archive")
    target.parent.mkdir(parents=True,exist_ok=True)
    try:
        with target.open("xb") as output,part.open("rb") as original:
            shutil.copyfileobj(original,output,1024*1024)
        check=inspect_db(target,registry)
        if (check["sqlite_sha256"]!=idx["sqlite_sha256"] or
            any(check[k]!=idx["counts"][k] for k in idx["counts"]) or
            check["source_counts"]!=idx["source_counts"]):
            raise ValueError("Independently recovered Kaggle V3 counts differ")
        return {"result":"PRIVATE_VENDOR_V3_INDEPENDENT_READBACK_VERIFIED",
                "sqlite_sha256":check["sqlite_sha256"],"counts":idx["counts"],
                "new_sources_passed":idx["sampling"]["passed"],
                "failures_not_hidden":idx["sampling"]["missing_samples"],
                "sqlite_integrity":check["integrity"],
                "historical_v2_index_verified":True,
                "customer_assets_included":False,"CVE_warehouse_untouched":True}
    except BaseException:
        target.unlink(missing_ok=True)
        raise

def main():
    p=argparse.ArgumentParser()
    sub=p.add_subparsers(dest="command",required=True)
    s=sub.add_parser("stage")
    for name in ("parent-db","child-db","v2-index","v1-index","collection-manifest","dest"):
        s.add_argument("--"+name,required=True,type=Path)
    r=sub.add_parser("restore")
    for name in ("trusted-index","v2-index","v1-index","downloaded","dest"):
        r.add_argument("--"+name,required=True,type=Path)
    for a in (s,r):
        a.add_argument("--registry",type=Path,default=Path("config/vendor_source_registry.json"))
    x=p.parse_args()
    reg=load_registry(x.registry)
    result=(stage(x.parent_db,x.child_db,x.v2_index,x.v1_index,x.collection_manifest,x.dest,reg)
            if x.command=="stage" else restore(x.trusted_index,x.v2_index,x.v1_index,x.downloaded,x.dest,reg))
    print(json.dumps(result,ensure_ascii=False,indent=2))

if __name__=="__main__":main()
