"""Append-only successor snapshots for an isolated private vendor evidence dataset."""
import argparse
from contextlib import closing
from datetime import datetime,timezone
import hashlib,json,shutil,sqlite3
from pathlib import Path
from .vendor_registry import load_registry
from .vendor_replay import inspect_db
from .vendor_kaggle import validate_index,sha256,json_bytes,PART_NAME,MAX_SNAPSHOT_BYTES,EXPECTED_SOURCE_DIGEST

SLUG="eclipse-vendor-evidence-20261010-v2"
INDEX="vendor-evidence-v2-index.json"
SCOPE="ECLIPSE_VENDOR_PRIVATE_GENERATION_2"

def parent_index(path):
    raw=Path(path).read_bytes()
    obj=json.loads(raw)
    validate_index(obj)
    if obj["sqlite_sha256"]!=EXPECTED_SOURCE_DIGEST:raise ValueError("Untrusted parent digest")
    return obj,hashlib.sha256(raw).hexdigest()

def rows(path,table,order):
    with closing(sqlite3.connect(Path(path).resolve().as_uri()+"?mode=ro",uri=True)) as db:
        db.execute("PRAGMA query_only=ON")
        return db.execute("SELECT * FROM "+table+" ORDER BY "+order).fetchall()

def prove_chain(parent_db,child_db,registry,parent_idx):
    parent,_=parent_index(parent_idx)
    prior=inspect_db(parent_db,registry)
    newer=inspect_db(child_db,registry)
    if prior["sqlite_sha256"]!=parent["sqlite_sha256"]:
        raise ValueError("Wrong source generation")
    for tab,order in (("vendor_document_versions","source_id,advisory_id,version"),
                      ("vendor_document_events","event_id")):
        old=rows(parent_db,tab,order)
        new=rows(child_db,tab,order)
        if old!=new[:len(old)]:raise ValueError("Existing immutable audit events changed: "+tab)
    old=rows(parent_db,"vendor_documents","source_id,advisory_id")
    new=rows(child_db,"vendor_documents","source_id,advisory_id")
    first={(x[0],x[1]):x[5] for x in old}
    current={(x[0],x[1]):x[5] for x in new}
    if any(current.get(k)!=v for k,v in first.items()):
        raise ValueError("Vendor document lost or first-seen changed")
    if any(newer["source_counts"].get(s,0)<count for s,count in prior["source_counts"].items()):
        raise ValueError("A publisher's history was lost")
    for key in ("advisories","versions","events"):
        if newer[key]<prior[key]:raise ValueError("Rollback of vendor history")
    return prior,newer

def stage(parent_db,child_db,parent_idx,manifest,dest,registry):
    prior,newer=prove_chain(parent_db,child_db,registry,parent_idx)
    audit=json.loads(Path(manifest).read_text("utf-8"))
    if (audit.get("mode")!="ONE_SHOT_OFFICIAL_UNREVIEWED_PILOT" or
        (audit.get("sources_pass"),audit.get("sources_partial"),audit.get("sources_failed"))!=(9,0,0) or
        audit.get("db_counts",{}).get("integrity")!="ok" or
        any(audit["db_counts"].get(k)!=newer[k] for k in ("advisories","versions","events"))):
        raise ValueError("Incomplete or inconsistent official 9-source collection")
    dest=Path(dest)
    if dest.exists() and any(dest.iterdir()):raise ValueError("Refuse overwrite of staged files")
    dest.mkdir(parents=True,exist_ok=True)
    part=dest/PART_NAME
    with part.open("xb") as d,Path(child_db).open("rb") as s:
        shutil.copyfileobj(s,d,1024*1024)
    if not 0<part.stat().st_size<=MAX_SNAPSHOT_BYTES or sha256(part)!=newer["sqlite_sha256"]:
        raise ValueError("Staging digest incorrect")
    idx={
        "schema_version":2,"scope":SCOPE,"dataset_slug":SLUG,
        "parent_slug":"eclipse-vendor-evidence-20261010-v1",
        "parent_index_sha256":sha256(parent_idx),
        "parent_sqlite_sha256":prior["sqlite_sha256"],
        "parent_counts":{k:prior[k] for k in ("advisories","versions","events")},
        "sqlite_sha256":newer["sqlite_sha256"],"sqlite_bytes":part.stat().st_size,
        "counts":{k:newer[k] for k in ("advisories","versions","events")},
        "source_counts":newer["source_counts"],"part_name":PART_NAME,
        "collection_manifest_sha256":sha256(manifest),
        "append_only_verified":True,"customer_records_included":False,
        "raw_vendor_source_bodies_included":False,"cve_database_touched":False,
        "human_verified_vendor_claims":False,
        "created_utc":datetime.now(timezone.utc).isoformat(timespec="seconds")
    }
    (dest/INDEX).write_bytes(json_bytes(idx))
    return {"result":"PRIVATE_V2_STAGED", "counts":idx["counts"],
            "new_documents":newer["advisories"]-prior["advisories"],
            "new_versions":newer["versions"]-prior["versions"],
            "trusted_index_sha256":sha256(dest/INDEX)}

def validate(index,parent_idx):
    parent,_=parent_index(parent_idx)
    prev={"advisories":125,"versions":202,"events":202}
    counts=index.get("counts",{})
    if (index.get("scope")!=SCOPE or index.get("schema_version")!=2 or
        index.get("dataset_slug")!=SLUG or index.get("part_name")!=PART_NAME or
        index.get("parent_sqlite_sha256")!=parent["sqlite_sha256"] or
        index.get("parent_index_sha256")!=sha256(parent_idx) or
        index.get("parent_counts")!=prev or
        index.get("append_only_verified") is not True or
        index.get("cve_database_touched") is not False or
        index.get("customer_records_included") is not False or
        index.get("raw_vendor_source_bodies_included") is not False or
        any(type(counts.get(k))!=int or counts[k]<v for k,v in prev.items()) or
        counts.get("versions")!=counts.get("events") or
        sum(index.get("source_counts",{}).values())!=counts.get("advisories")):
        raise ValueError("Untrusted vendor generation or rollback")
    if not 0<index.get("sqlite_bytes",0)<=MAX_SNAPSHOT_BYTES:raise ValueError("Size invalid")

def restore(trusted_index,parent_idx,downloaded,dest,registry):
    trusted=Path(trusted_index).read_bytes()
    idx=json.loads(trusted)
    validate(idx,parent_idx)
    downloaded=Path(downloaded)
    file=downloaded/INDEX
    part=downloaded/PART_NAME
    if not file.is_file() or file.is_symlink() or file.read_bytes()!=trusted:
        raise ValueError("Private Kaggle provided changed evidence index")
    if (not part.is_file() or part.is_symlink() or
        part.stat().st_size!=idx["sqlite_bytes"] or sha256(part)!=idx["sqlite_sha256"]):
        raise ValueError("Private Kaggle returned altered vendor SQLite")
    dest=Path(dest)
    if dest.exists():raise ValueError("Never replace verified source")
    dest.parent.mkdir(parents=True,exist_ok=True)
    try:
        with dest.open("xb") as dst,part.open("rb") as src:shutil.copyfileobj(src,dst)
        check=inspect_db(dest,registry)
        if (check["sqlite_sha256"]!=idx["sqlite_sha256"] or
            any(check[k]!=idx["counts"][k] for k in idx["counts"]) or
            check["source_counts"]!=idx["source_counts"]):
            raise ValueError("Restored vendor generation did not match trusted receipt")
        return {"result":"PRIVATE_VENDOR_GENERATION_2_INDEPENDENTLY_VERIFIED",
                "parent_sha256":idx["parent_sqlite_sha256"],
                "sqlite_sha256":check["sqlite_sha256"],"counts":idx["counts"],
                "verified_sqlite_integrity":check["integrity"],
                "prior_history_unchanged":True,"cve_warehouse_unchanged":True}
    except BaseException:
        dest.unlink(missing_ok=True);raise

def main():
    p=argparse.ArgumentParser()
    cmds=p.add_subparsers(dest="op",required=True)
    a=cmds.add_parser("stage")
    b=cmds.add_parser("restore")
    for name in ("parent-db","child-db","parent-index","collection-manifest","dest"):
        a.add_argument("--"+name,type=Path,required=True)
    for name in ("trusted-index","parent-index","downloaded","dest"):
        b.add_argument("--"+name,type=Path,required=True)
    for q in (a,b):q.add_argument("--registry",type=Path,default=Path("config/vendor_source_registry.json"))
    x=p.parse_args()
    registry=load_registry(x.registry)
    result=(stage(x.parent_db,x.child_db,x.parent_index,x.collection_manifest,x.dest,registry)
            if x.op=="stage" else restore(x.trusted_index,x.parent_index,x.downloaded,x.dest,registry))
    print(json.dumps(result,ensure_ascii=False,indent=2))

if __name__=="__main__":main()
