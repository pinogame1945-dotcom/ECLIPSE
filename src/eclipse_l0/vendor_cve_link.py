"""Read-only join audit for separately versioned ECLIPSE vendor and CVE databases.

No mutations, no inferential CVE links from HTML navigation, no product impact
assertions. Vendor 'cve_ids' were automatically extracted and are *provisional*.
CVE snapshot identities and evidence hashes are captured in the join receipt.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path
import re
import sqlite3

from .vendor_replay import inspect_db
from .vendor_registry import load_registry

CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")
STATES = {"MATCHED_PUBLISHED","MATCHED_REJECTED","MATCHED_OTHER_STATE",
          "UNMATCHED_SNAPSHOT","UNASSIGNED"}
REQUIRED_META = ("source_index_sha256","source_archive_sha256")


def _open_ro(path: Path) -> sqlite3.Connection:
    p = Path(path)
    if not p.is_file() or p.is_symlink():
        raise ValueError("Read-only source SQLite missing or symlinked")
    db = sqlite3.connect(p.resolve().as_uri()+"?mode=ro",uri=True)
    db.row_factory=sqlite3.Row
    db.execute("PRAGMA query_only=ON")
    return db


def link_audit(vendor_db: Path,cve_db: Path, registry: dict, *, check_full_cve_count:bool=False) -> dict:
    vendor_info=inspect_db(vendor_db,registry)
    with _open_ro(vendor_db) as vendor, _open_ro(cve_db) as cve:
        vendor_tables={x[0] for x in vendor.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        cve_tables={x[0] for x in cve.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not {"vendor_documents","vendor_document_versions"}.issubset(vendor_tables):
            raise ValueError("Missing vendor evidence ledger")
        if not {"cve_current","warehouse_metadata"}.issubset(cve_tables):
            raise ValueError("Not a full ECLIPSE CVE warehouse; refuse to join")
        # The real warehouse stores all metadata using json.dumps(), including
        # SHA strings. Direct regex matching sees double quotes and fails.
        meta={}
        for x in cve.execute("SELECT key,value FROM warehouse_metadata"):
            try:
                meta[x["key"]]=json.loads(x["value"])
            except (ValueError,TypeError) as exc:
                raise ValueError("Invalid JSON-encoded CVE snapshot metadata") from exc
        if any(not re.fullmatch(r"[0-9a-f]{64}",meta.get(key,"")) for key in REQUIRED_META):
            raise ValueError("CVE snapshot index/original archive hashes missing")
        cve_count=cve.execute("SELECT COUNT(*) FROM cve_current").fetchone()[0]
        if check_full_cve_count and cve_count!=403696:
            raise ValueError("Current CVE warehouse count differs from pinned 403,696 snapshot")
        statuses=Counter()
        per_source={}
        links=[]
        docs=vendor.execute("""SELECT d.source_id,d.advisory_id,d.current_facts_sha,
                     d.current_source_sha,v.facts_json,v.extract_status
                     FROM vendor_documents d JOIN vendor_document_versions v
                     ON v.source_id=d.source_id AND v.advisory_id=d.advisory_id
                     AND v.facts_sha256=d.current_facts_sha
                     AND v.source_sha256=d.current_source_sha
                     WHERE v.version=(SELECT MAX(last.version)
                          FROM vendor_document_versions last
                          WHERE last.source_id=d.source_id AND last.advisory_id=d.advisory_id)
                     ORDER BY d.source_id,d.advisory_id""")
        for row in docs:
            sid=row["source_id"]
            source_stats=per_source.setdefault(sid,Counter())
            source_stats["documents"]+=1
            facts=json.loads(row["facts_json"])
            assert isinstance(facts,dict)
            ids=facts.get("cve_ids",[])
            if not isinstance(ids,list) or len(set(ids))!=len(ids):
                raise ValueError("Unverifiable CVE IDs in vendor evidence")
            for ident in ids:
                if not isinstance(ident,str) or not CVE.fullmatch(ident):
                    raise ValueError("Malformed vendor CVE identifier")
            if not ids:
                statuses["UNASSIGNED"]+=1
                source_stats["unassigned_documents"]+=1
            for cve_id in ids:
                found=cve.execute("SELECT record_state,hash FROM cve_current WHERE cve_id=?",
                                  (cve_id,)).fetchone()
                if found is None:
                    state="UNMATCHED_SNAPSHOT"
                    cve_record_hash=None
                elif found["record_state"]=="PUBLISHED":
                    state="MATCHED_PUBLISHED"
                    cve_record_hash=found["hash"]
                elif found["record_state"]=="REJECTED":
                    state="MATCHED_REJECTED"
                    cve_record_hash=found["hash"]
                else:
                    state="MATCHED_OTHER_STATE"
                    cve_record_hash=found["hash"]
                if state not in STATES:
                    raise ValueError("Unknown link state")
                statuses[state]+=1
                source_stats[state]+=1
                links.append({
                    "source_id":sid,"advisory_id":row["advisory_id"],
                    "vendor_facts_sha256":row["current_facts_sha"],
                    "vendor_source_sha256":row["current_source_sha"],
                    "cve_id":cve_id,"status":state,
                    "cve_record_sha256":cve_record_hash,
                    "link_confidence":"EXTRACTED_UNREVIEWED",
                    "customer_impact_certified":False
                })
        if sum(x["documents"] for x in per_source.values())!=vendor_info["advisories"]:
            raise ValueError("Not all current vendor documents were joined/audited")
        return {
            "schema_version":1,
            "result":"READ_ONLY_SNAPSHOT_LINK_AUDIT",
            "observed_utc":datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "vendor_snapshot":{
              "sqlite_sha256":vendor_info["sqlite_sha256"],"advisories":vendor_info["advisories"],
              "versions":vendor_info["versions"],"events":vendor_info["events"]},
            "cve_snapshot":{
              "source_index_sha256":meta["source_index_sha256"],
              "source_archive_sha256":meta["source_archive_sha256"],
              "current_cve_records":cve_count
            },
            "counts":dict(sorted(statuses.items())),
            "per_source":{s:dict(sorted(c.items())) for s,c in sorted(per_source.items())},
            "links":links,
            "policy":{
              "writes_performed":False,
              "cve_snapshot_immutable":True,
              "vendor_snapshot_immutable":True,
              "unmatched_retained_for_later_snapshot":True,
              "unassigned_vendor_advisories_retained":True,
              "rejected_cve_never_treated_as_active":True,
              "product_version_conflicts_not_yet_evaluated":True,
              "all_extracted_ids_provisional":True
            }
        }


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--vendor-db",type=Path,required=True)
    p.add_argument("--cve-db",type=Path,required=True)
    p.add_argument("--registry",type=Path,default=Path("config/vendor_source_registry.json"))
    p.add_argument("--out",type=Path,required=True)
    p.add_argument("--require-full-cve",action="store_true")
    args=p.parse_args()
    result=link_audit(args.vendor_db,args.cve_db,load_registry(args.registry),
                      check_full_cve_count=args.require_full_cve)
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(result,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    print(json.dumps({"result":result["result"],"counts":result["counts"],
                      "source_index_sha256":result["cve_snapshot"]["source_index_sha256"],
                      "link_assertions":"UNREVIEWED"},ensure_ascii=False,indent=2))


if __name__=="__main__":
    main()
