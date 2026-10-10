"""Private, bounded, EXACT CSAF product monitor for customer inventory.

No secret customer inventory is ever posted to public GitHub, Actions or Kaggle.
Publisher status rows are EVIDENCE CANDIDATES; never convert them to confirmed
installed-version exposure or patched status. Matching is publisher-specific,
CVE-specific, product-id-specific where supplied, and strictly exact by name.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import unicodedata

from .vendor_registry import load_registry
from .vendor_replay import inspect_db

SOURCES={
    "redhat-csaf": ("Red Hat", "red hat"),
    "siemens-csaf": ("Siemens", "siemens")
}
STATES={"known_affected", "known_not_affected", "fixed", "first_fixed", "under_investigation"}
CVE=re.compile(r"^CVE-\d{4}-\d{4,}$")
MAX_INVENTORY=100
MAX_RESULTS=12000
MAX_SOURCE_ROWS=120000
MAX_CATALOG=20000
MAX_TITLE=180


def _normalized(value):
    if not isinstance(value,str) or not 1<=len(value.strip())<=MAX_TITLE:
        raise ValueError("Missing/oversized publisher product label")
    if any(ord(c)<32 for c in value):
        raise ValueError("Control character in publisher product label")
    return " ".join(unicodedata.normalize("NFKC",value).casefold().split())


def _open_ro(path):
    path=Path(path)
    if not path.is_file() or path.is_symlink():
        raise ValueError("Missing trusted local vendor SQLite database")
    db=sqlite3.connect(path.resolve().as_uri()+"?mode=ro",uri=True)
    db.row_factory=sqlite3.Row
    db.execute("PRAGMA query_only=ON")
    return db


def _load_inventory(path):
    path=Path(path)
    if not path.is_file() or path.is_symlink():
        raise ValueError("Customer inventory must be provided from PRIVATE local file")
    raw=path.read_bytes()
    if len(raw)>150_000:
        raise ValueError("Customer inventory is too large")
    try:
        obj=json.loads(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError("Invalid private inventory JSON") from exc
    if not isinstance(obj,dict) or obj.get("schema_version")!=1:
        raise ValueError("Unsupported private inventory schema")
    # Compatible with customer_products.load_inventory, but no import from
    # separately developed main; a future integration must be independently reviewed.
    rows=obj.get("products")
    if not isinstance(rows,list) or not 1<=len(rows)<=MAX_INVENTORY:
        raise ValueError("Expected 1..100 explicit customer products")
    seen=set()
    normalized=[]
    for i,row in enumerate(rows):
        if not isinstance(row,dict):
            raise ValueError("Invalid private inventory row")
        id_=row.get("id",f"product-{i+1}")
        if not isinstance(id_,str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}",id_) or id_ in seen:
            raise ValueError("Invalid/duplicate private inventory id")
        seen.add(id_)
        product=_normalized(row.get("product"))
        vendor=_normalized(row.get("vendor"))
        allowed={"red hat":"redhat-csaf","siemens":"siemens-csaf"}
        if vendor not in allowed:
            raise ValueError("Only explicitly scoped Red Hat and Siemens products supported in pilot")
        product_id=row.get("csaf_product_id")
        if product_id is not None and (not isinstance(product_id,str) or
                                      not re.fullmatch(r"[A-Za-z0-9:._+/-]{1,180}",product_id)):
            raise ValueError("Publisher product_id must be an exact explicit opaque ID")
        version=row.get("installed_version")
        if version is not None:
            if not isinstance(version,str) or len(version)>160 or any(ord(c)<32 for c in version):
                raise ValueError("Invalid display-only installed version")
        # ALIASES are intentionally not used without independent publisher-ID
        # evidence; accepting aliases here would undermine strict scope.
        normalized.append({"inventory_id":id_,"source_id":allowed[vendor],
                           "vendor":row["vendor"],"product":row["product"],
                           "name_key":product,"csaf_product_id":product_id,
                           "installed_version":version})
    return normalized, hashlib.sha256(raw).hexdigest()


def _docs(db):
    return db.execute("""SELECT d.source_id,d.advisory_id,d.source_url,
              d.current_facts_sha,d.current_source_sha,v.facts_json
          FROM vendor_documents d JOIN vendor_document_versions v
            ON d.source_id=v.source_id AND d.advisory_id=v.advisory_id
           AND v.version=(SELECT MAX(z.version) FROM vendor_document_versions z
                 WHERE z.source_id=d.source_id AND z.advisory_id=d.advisory_id)
          WHERE d.source_id IN ('redhat-csaf','siemens-csaf')
          ORDER BY d.source_id,d.advisory_id""")


def _claims(facts):
    if not isinstance(facts,dict):
        raise ValueError("Malformed stored publisher evidence")
    ids=facts.get("cve_ids",[])
    if not isinstance(ids,list):
        raise ValueError("Untrusted publisher CVE list")
    claims=facts.get("product_status_claims_unreviewed",[])
    if not isinstance(claims,list) or len(claims)>MAX_SOURCE_ROWS:
        raise ValueError("Malformed/oversized product-status claims")
    for row in claims:
        if not isinstance(row,dict):
            raise ValueError("Malformed publisher product status")
        cve=row.get("cve_id")
        if cve is None:
            continue
        if not isinstance(cve,str) or not CVE.fullmatch(cve) or cve not in ids:
            raise ValueError("CSAF product claim outside source CVE scope")
        if row.get("status") not in STATES or not isinstance(row.get("product_id"),str):
            raise ValueError("Unexpected CSAF product status")
        yield row


def _matches(inventory,row):
    label=row.get("product_name")
    if not isinstance(label,str) or not label.strip():
        return False
    if inventory["name_key"]!=_normalized(label):
        return False
    if inventory["csaf_product_id"] is not None:
        return row.get("product_id")==inventory["csaf_product_id"]
    return True


def _remediations(facts,cve_id,pid):
    out=[]
    rows=facts.get("remediations_unreviewed",[])
    if not isinstance(rows,list) or len(rows)>MAX_SOURCE_ROWS:
        raise ValueError("Malformed CSAF remediation facts")
    for row in rows:
        if not isinstance(row,dict):
            raise ValueError("Malformed remediation evidence")
        if row.get("cve_id")!=cve_id:
            continue
        ids=row.get("product_ids",[])
        if not isinstance(ids,list) or pid not in ids:
            # No scope inference from group ids or empty lists (possibly global).
            continue
        out.append({
            "category":row.get("category"),
            "publisher_text_unreviewed":row.get("details_original"),
            "evidence_path":row.get("evidence_path"),
            "publisher_product_id":pid,
            "review_state":"TEXT_ONLY_NO_PATCH_RECOMMENDATION"
        })
        if len(out)>=5:
            break
    return out


def product_catalog(db_path,registry,source_id,*,max_entries=200):
    if source_id not in SOURCES:
        raise ValueError("Only CSAF product-tree sources allowed")
    if not 1<=max_entries<=1000:
        raise ValueError("Invalid catalog size")
    checked=inspect_db(Path(db_path),registry)
    products={}
    count=0
    with closing(_open_ro(db_path)) as db:
        for doc in _docs(db):
            if doc["source_id"]!=source_id:
                continue
            facts=json.loads(doc["facts_json"])
            for claim in _claims(facts):
                count+=1
                if count>MAX_SOURCE_ROWS:
                    raise ValueError("Publisher catalog budget exhausted")
                label=claim.get("product_name")
                if label is None:
                    continue
                key=(claim["product_id"],label)
                entry=products.setdefault(key,{
                    "publisher_source":source_id,
                    "publisher_product_id":claim["product_id"],
                    "publisher_product_name":label,
                    "observed_cve_claims":0,
                    "review_state":"UNREVIEWED_VENDOR_PRODUCT_TREE"})
                entry["observed_cve_claims"]+=1
                if len(products)>MAX_CATALOG:
                    raise ValueError("Excessive CSAF product catalog")
    ordered=sorted(products.values(),key=lambda row:(-row["observed_cve_claims"],
            row["publisher_product_name"],row["publisher_product_id"]))
    return {"scope":"PUBLISHER_PRODUCT_NAMES_NOT_EXPOSURE","source_id":source_id,
            "known_catalog_ids":len(ordered),"entries":ordered[:max_entries],
            "entries_not_shown":max(0,len(ordered)-max_entries),
            "vendor_snapshot_sha256":checked["sqlite_sha256"]}


def match_customer_products(db_path,inventory_path,registry):
    products, inventory_sha=_load_inventory(Path(inventory_path))
    checked=inspect_db(Path(db_path),registry)
    by_source=defaultdict(list)
    for product in products:
        by_source[product["source_id"]].append(product)
    source_rows=Counter()
    candidates=[]
    document_count=0
    for_source=defaultdict(Counter)
    with closing(_open_ro(db_path)) as db:
        for doc in _docs(db):
            document_count+=1
            sid=doc["source_id"]
            relevant=by_source.get(sid,[])
            if not relevant:
                continue
            facts=json.loads(doc["facts_json"])
            claims=list(_claims(facts))
            source_rows[sid]+=len(claims)
            if source_rows[sid]>MAX_SOURCE_ROWS:
                raise ValueError("Vendor source assertions exceed bounded budget")
            # Exact label can be used only if it resolves to one publisher
            # product_id per document; when two IDs share the label do not
            # silently apply the strongest/worst status to the wrong SKU.
            label_pid=defaultdict(set)
            for claim in claims:
                if isinstance(claim.get("product_name"),str):
                    label_pid[_normalized(claim["product_name"])].add(claim["product_id"])
            for product in relevant:
                matching=[row for row in claims if _matches(product,row)]
                if not matching:
                    continue
                for_source[sid]["documents_with_matching_product_labels"]+=1
                for claim in matching:
                    ambiguous=(product["csaf_product_id"] is None
                               and len(label_pid[product["name_key"]])!=1)
                    cve=claim["cve_id"]
                    if cve is None:
                        state="NO_CVE_ASSIGNED"
                    elif ambiguous:
                        state="MULTIPLE_PRODUCT_IDS_REQUIRE_SELECTION"
                    else:
                        state="EXACT_PUBLISHER_PRODUCT_ID" if product["csaf_product_id"] else "EXACT_PUBLISHER_NAME_ONE_ID"
                    candidates.append({
                        "inventory_id":product["inventory_id"],
                        "inventory_product":product["product"],
                        "installed_version_display_only":product["installed_version"],
                        "publisher":SOURCES[sid][0],"source_id":sid,
                        "advisory_id":doc["advisory_id"],"source_url":doc["source_url"],
                        "publisher_product_id":claim["product_id"],
                        "publisher_product_name":claim["product_name"],
                        "cve_id":cve,
                        "publisher_product_status_unreviewed":claim["status"],
                        "match_state":state,
                        "cve_publisher_evidence_path":claim.get("evidence_path"),
                        "product_tree_evidence_path":claim.get("product_evidence_path"),
                        "vendor_facts_sha256":doc["current_facts_sha"],
                        "vendor_source_sha256":doc["current_source_sha"],
                        "explicitly_targeted_remediation_texts_unreviewed":
                            _remediations(facts,cve,claim["product_id"])
                            if not ambiguous and cve else [],
                        "customer_version_impact":"NOT_ASSESSED",
                        "fixed_version_certified":False,
                        "notification_approved":False
                    })
                    if len(candidates)>MAX_RESULTS:
                        raise ValueError("Potential customer report too large; refine inventory")
    matched={row["inventory_id"] for row in candidates}
    not_seen=[{
        "inventory_id":p["inventory_id"],
        "finding":"NO_EXACT_PUBLISHER_PRODUCT_LABEL_IN_SNAPSHOT_NOT_PROOF_OF_SAFETY"
    } for p in products if p["inventory_id"] not in matched]
    candidates.sort(key=lambda x:(x["inventory_id"],x["source_id"],x["advisory_id"],
                                 x["cve_id"] or "",x["publisher_product_id"],x["publisher_product_status_unreviewed"]))
    return {
        "schema_version":1,
        "classification":"PRIVATE_CSAF_PRODUCT_MONITOR_REVIEW_ONLY",
        "generated_utc":datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source_provenance":{"vendor_sqlite_sha256":checked["sqlite_sha256"],
            "vendor_documents_all_sources":checked["advisories"],
            "vendor_versions_all_sources":checked["versions"],
            "private_inventory_sha256":inventory_sha},
        "coverage":{"scoped_sources":sorted(by_source),
            "monitored_products":len(products),"candidate_status_rows":len(candidates),
            "distinct_product_cve_candidates":len({(r["inventory_id"],r["cve_id"]) for r in candidates if r["cve_id"]}),
            "inventory_entries_without_exact_evidence":len(not_seen),
            "per_source":{sid:dict(for_source[sid]) for sid in sorted(by_source)}},
        "candidate_findings":candidates,
        "unmatched_inventory_products":not_seen,
        "security_policy":{"no_installed_version_interpretation":True,
            "no_automatic_customer_exposure_or_patch_assertions":True,
            "redhat_siemens_csaf_only":True,
            "source_specific_exact_product_id_or_name":True,
            "client_inventory_never_sent_to_github_or_kaggle":True,
            "both_source_and_customer_data_private":True}
    }


def main():
    p=argparse.ArgumentParser(description="PRIVATE local/offline vendor product evidence matching")
    sub=p.add_subparsers(dest="mode",required=True)
    a=sub.add_parser("catalog")
    a.add_argument("--source",required=True,choices=sorted(SOURCES))
    a.add_argument("--limit",type=int,default=200)
    b=sub.add_parser("assess")
    b.add_argument("--inventory",type=Path,required=True)
    for subcmd in (a,b):
        subcmd.add_argument("--vendor-db",type=Path,required=True)
        subcmd.add_argument("--registry",type=Path,default=Path("config/vendor_source_registry.json"))
        subcmd.add_argument("--out",type=Path,required=True)
    args=p.parse_args()
    registry=load_registry(args.registry)
    result=(product_catalog(args.vendor_db,registry,args.source,max_entries=args.limit)
            if args.mode=="catalog" else
            match_customer_products(args.vendor_db,args.inventory,registry))
    args.out.parent.mkdir(parents=True,exist_ok=True)
    if args.out.exists():
        raise ValueError("Will not overwrite a prior private customer report")
    args.out.write_text(json.dumps(result,ensure_ascii=False,sort_keys=True,indent=2)+"\n",encoding="utf-8")
    print(json.dumps({"result":result["classification"] if args.mode=="assess" else result["scope"],
                      "entries":result["coverage"]["candidate_status_rows"] if args.mode=="assess" else result["known_catalog_ids"],
                      "private_output_written":str(args.out)},ensure_ascii=False))


if __name__=="__main__":
    main()
