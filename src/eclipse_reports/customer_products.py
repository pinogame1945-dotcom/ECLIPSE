"""Customer PRODUCT watchlist -> sourced CVE candidate report from a restored local warehouse.

This is not an asset scanner. An affected[] vendor/product label is a publisher
statement, NOT a confirmation that the customer's installed version is affected.
Do NOT submit real client profiles to the public ECLIPSE repo or GitHub Actions.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import sqlite3
from collections import Counter
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from eclipse_l0.warehouse import SOURCE_COUNT, SOURCE_INDEX_SHA256, SOURCE_SHA256

MAX_PRODUCTS=200
MAX_ALIASES=12
MAX_MATCHED=200000
MAX_PREVIEW=200
MAX_MATCH_STR=140
COLUMNS=("inventory_id","vendor","product","installed_version","cve_id",
         "review_queue","publisher_status","cvss_score","cvss_type","epss_probability",
         "epss_score_date","epss_state","kev_in_snapshot","kev_date_added",
         "date_published","date_updated","publisher_version_statements",
         "publisher_description","cve_reference","customer_version_impact")


def _name(value, field, *, required=True):
    if value is None and not required:return None
    if not isinstance(value,str) or (required and not value.strip()) or len(value)>MAX_MATCH_STR:
        raise ValueError("Invalid "+field)
    if any(ord(c)<32 for c in value):
        raise ValueError("Control character in "+field)
    return value.strip()


def _normalized(value):
    return value.strip().casefold()


def load_inventory(path:Path)->dict:
    data=json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data,dict) or data.get("schema_version")!=1:
        raise ValueError("Inventory schema_version must be 1")
    customer=_name(data.get("customer_name"),"customer_name")
    entries=data.get("products")
    if not isinstance(entries,list) or not 1<=len(entries)<=MAX_PRODUCTS:
        raise ValueError("Explicit 1..200 monitored products required; no unfiltered report")
    products=[]
    seen=set()
    for i,item in enumerate(entries):
        if not isinstance(item,dict):
            raise ValueError("Invalid product entry")
        vendor=_name(item.get("vendor"),"vendor")
        product=_name(item.get("product"),"product")
        identifier=_name(item.get("id",f"product-{i+1}"),"product id")
        version=_name(item.get("installed_version"),"installed_version",required=False)
        if identifier in seen:
            raise ValueError("Duplicate inventory id")
        seen.add(identifier)
        patterns=[(vendor,product,"PRIMARY_EXACT")]
        aliases=item.get("aliases",[])
        if not isinstance(aliases,list) or len(aliases)>MAX_ALIASES:
            raise ValueError("Too many aliases")
        for alias in aliases:
            if not isinstance(alias,dict):
                raise ValueError("Alias must be an explicit vendor/product object")
            patterns.append((_name(alias.get("vendor"),"alias.vendor"),
                             _name(alias.get("product"),"alias.product"),"EXPLICIT_ALIAS"))
        unique={}
        for v,p,origin in patterns:
            unique.setdefault((_normalized(v),_normalized(p)),origin)
        products.append({"id":identifier,"vendor":vendor,"product":product,
                         "installed_version":version,
                         "labels":[{"vendor_norm":v,"product_norm":p,"origin":origin}
                                   for (v,p),origin in unique.items()]})
    return {"schema_version":1,"customer_name":customer,"products":products}


def _warehouse_meta(con, *, as_of:date, expected_count:int) ->dict:
    required=("source_index_sha256","source_archive_sha256","cve_full_ingest_verified",
              "kev_source_sha256","epss_source_sha256","epss_score_date")
    meta={r[0]:json.loads(r[1]) for r in con.execute("SELECT key,value FROM warehouse_metadata")}
    if any(k not in meta for k in required) or meta["cve_full_ingest_verified"] is not True:
        raise ValueError("Incomplete warehouse provenance")
    if (meta["source_index_sha256"]!=SOURCE_INDEX_SHA256 or
            meta["source_archive_sha256"]!=SOURCE_SHA256):
        if expected_count==SOURCE_COUNT:
            raise ValueError("CVE archive is not the independently pinned full snapshot")
    for key in ("source_index_sha256","source_archive_sha256",
                "kev_source_sha256","epss_source_sha256"):
        val=meta[key]
        if not isinstance(val,str) or len(val)!=64 or any(c not in "0123456789abcdef" for c in val):
            raise ValueError("Invalid "+key)
    count=con.execute("SELECT COUNT(*) FROM cve_current").fetchone()[0]
    if count!=expected_count:
        raise ValueError(f"Unexpected CVE coverage {count} vs {expected_count}")
    checked=con.execute("PRAGMA quick_check").fetchone()[0]
    if checked!="ok":
        raise ValueError("SQLite quick_check failed")
    timestamp=meta["epss_score_date"]
    if not isinstance(timestamp,str):
        raise ValueError("Missing EPSS date")
    score_at=datetime.fromisoformat(timestamp.replace("Z","+00:00"))
    if score_at.tzinfo is None:
        raise ValueError("EPSS timestamp lacks UTC offset")
    epss_day=score_at.astimezone(timezone.utc).date()
    if epss_day>as_of:
        raise ValueError("Cannot use future EPSS")
    meta["epss_age_days"]=(as_of-epss_day).days
    return meta


def _date_or_none(value):
    if value is None:return None
    if not isinstance(value,str):return None
    try:return date.fromisoformat(value[:10])
    except ValueError:return None


def _safe_cell(value):
    """Defang Excel formulas in exported fields from inventory and source JSON."""
    value=str(value if value is not None else "")
    if value and value.lstrip().startswith(("=","+","-","@")):
        return "'"+value
    return value


def _run_query(con, labels):
    values=[]
    terms=[]
    for label in labels:
        terms.append("(a.vendor_norm=? AND a.product_norm=?)")
        values.extend([label["vendor_norm"],label["product_norm"]])
    query="""
    SELECT a.cve_id,a.container,a.ordinal,a.vendor,a.product,a.default_status,
           a.versions_json,c.record_state,c.date_published,c.date_updated,
           s.title,s.description_en,s.cvss_score,s.cvss_kind,
           k.date_added AS kev_date_added,e.probability AS epss,e.percentile
      FROM warehouse_affected a
      JOIN cve_current c ON c.cve_id=a.cve_id
      LEFT JOIN warehouse_summary s ON s.cve_id=a.cve_id
      LEFT JOIN kev_current k ON k.cve_id=a.cve_id AND k.present=1
      LEFT JOIN warehouse_epss e ON e.cve_id=a.cve_id
      WHERE c.record_state='PUBLISHED' AND ("""+" OR ".join(terms)+""")
      ORDER BY a.cve_id,a.container,a.ordinal
    """
    yield from con.execute(query,values)


def _severity(epss,cvss,kev,date_pub,date_upd,cutoff,epss_fresh):
    if kev:return "KEV_LISTED_REVIEW"
    # Publication is an actionable review signal, not confirmation of a new exploit.
    if (date_pub and date_pub>=cutoff) or (date_upd and date_upd>=cutoff):
        return "RECENT_CVE_PUBLICATION_OR_UPDATE"
    if cvss is not None and cvss>=9.0:return "CNA_HIGH_SEVERITY_REVIEW"
    if epss is not None and epss_fresh and epss>=0.10:return "EPSS_FORECAST_REVIEW"
    return "HISTORICAL_INFORMATION_REVIEW"


def _order(item):
    priority=("KEV_LISTED_REVIEW","RECENT_CVE_PUBLICATION_OR_UPDATE",
              "CNA_HIGH_SEVERITY_REVIEW","EPSS_FORECAST_REVIEW",
              "HISTORICAL_INFORMATION_REVIEW")
    score=item["cvss_score"] if item["cvss_score"] is not None else -1
    forecast=item["epss_probability"] if item["epss_state"]=="FRESH" and item["epss_probability"] is not None else -1
    return priority.index(item["review_queue"]),-score,-forecast,item["cve_id"],item["inventory_id"]


def _cve_candidates(con,product,cutoff,meta,mode):
    # Aggregation prevents duplicate hits from CNA/ADP containers and explicit aliases.
    pending=None
    for row in _run_query(con,product["labels"]):
        data=dict(row)
        cve=data["cve_id"]
        if pending is not None and pending["cve_id"]!=cve:
            yield pending
            pending=None
        if pending is None:
            published=_date_or_none(data["date_published"])
            updated=_date_or_none(data["date_updated"])
            kev=data["kev_date_added"] is not None
            cvss=data["cvss_score"]
            epss=data["epss"]
            if cvss is not None and (not math.isfinite(cvss) or not 0<=cvss<=10):
                raise ValueError("Invalid CNA CVSS")
            if epss is not None and (not math.isfinite(epss) or not 0<=epss<=1):
                raise ValueError("Invalid FIRST EPSS")
            epss_fresh=meta["epss_age_days"]<=7
            queue=_severity(epss,cvss,kev,published,updated,cutoff,epss_fresh)
            in_scope=(mode=="all" or kev or queue=="RECENT_CVE_PUBLICATION_OR_UPDATE")
            pending={"inventory_id":product["id"],"vendor":product["vendor"],"product":product["product"],
                "installed_version":product["installed_version"],"cve_id":cve,
                "review_queue":queue,"publisher_status":data["record_state"],
                "cvss_score":cvss,"cvss_type":data["cvss_kind"],
                "epss_probability":epss,"epss_score_date":meta["epss_score_date"],
                "epss_state":"MISSING" if epss is None else ("FRESH" if epss_fresh else "STALE"),
                "kev_in_snapshot":kev,"kev_date_added":data["kev_date_added"],
                "date_published":data["date_published"],"date_updated":data["date_updated"],
                "publisher_version_statements":[],"publisher_description":(data["description_en"] or data["title"] or "")[:1000],
                "cve_reference":"https://www.cve.org/CVERecord?id="+cve,
                "customer_version_impact":"NOT_ASSESSED",
                "source_match_kind":"PUBLISHER_AFFECTED_ARRAY_PRODUCT_LABEL",
                "in_requested_scope":in_scope}
        if len(pending["publisher_version_statements"])<24:
            pending["publisher_version_statements"].append({
                "container":data["container"],"vendor":data["vendor"],"product":data["product"],
                "default_status":data["default_status"],"versions_raw":json.loads(data["versions_json"]) if data["versions_json"] is not None else None,
                "evidence_location":f"warehouse_affected/{cve}/{data['container']}/{data['ordinal']}"})
    if pending is not None:yield pending


def build_report(db:Path,inventory_path:Path,out_dir:Path,*,as_of:date,
                 days:int=90,mode:str="recent",expected_count:int=SOURCE_COUNT,
                 preview:int=120,demo:bool=False)->dict:
    if not 1<=days<=366 or mode not in ("recent","all") or not 0<=preview<=MAX_PREVIEW:
        raise ValueError("Invalid report lookback/mode/preview")
    if not db.is_file() or not inventory_path.is_file():
        raise ValueError("Existing local SQLite warehouse and customer inventory required")
    if db.resolve()==inventory_path.resolve() or db.resolve().is_relative_to(out_dir.resolve()):
        raise ValueError("Never place the source database inside report output")
    inventory=load_inventory(inventory_path)
    input_sha=hashlib.sha256(inventory_path.read_bytes()).hexdigest()
    con=sqlite3.connect(f"file:{db.resolve().as_posix()}?mode=ro",uri=True)
    con.row_factory=sqlite3.Row
    con.execute("PRAGMA query_only=ON")
    try:
        meta=_warehouse_meta(con,as_of=as_of,expected_count=expected_count)
        cutoff=as_of-timedelta(days=days)
        rows=[]
        total_matching=0
        per_product=[]
        queued=Counter()
        all_cves=set()
        for product in inventory["products"]:
            count=0
            eligible=0
            kev=0
            for item in _cve_candidates(con,product,cutoff,meta,mode):
                total_matching+=1
                count+=1
                all_cves.add(item["cve_id"])
                if total_matching>MAX_MATCHED:
                    raise ValueError("Too many publisher product references; refine inventory")
                if not item["in_requested_scope"]:continue
                eligible+=1
                kev+=int(item["kev_in_snapshot"])
                queued[item["review_queue"]]+=1
                rows.append(item)
            per_product.append({"inventory_id":product["id"],"vendor":product["vendor"],
                "product":product["product"],"installed_version":product["installed_version"],
                "matched_published_cve_ids_all_history":count,
                "included_product_cve_rows":eligible,"kev_listed_included":kev,
                "match_scope":"EXACT_VENDOR_AND_PRODUCT_CASEFOLDED_IN_PUBLISHER_AFFECTED_ARRAY"})
    finally:con.close()
    rows.sort(key=_order)
    out_dir.mkdir(parents=True,exist_ok=True)
    csv_path=out_dir/"candidate-vulnerabilities.csv"
    with csv_path.open("w",encoding="utf-8-sig",newline="") as f:
        writer=csv.DictWriter(f,fieldnames=COLUMNS)
        writer.writeheader()
        for item in rows:
            flat={k:(json.dumps(item[k],ensure_ascii=False) if k=="publisher_version_statements"
                 else item[k]) for k in COLUMNS}
            writer.writerow({k:_safe_cell(v) for k,v in flat.items()})
    report={"schema_version":1,
        "classification":"CUSTOMER_PRODUCT_REFERENCE_REPORT_NOT_VERIFIED_ASSET_EXPOSURE",
        "customer_name":inventory["customer_name"],"synthetic_demo":demo,
        "as_of":as_of.isoformat(),"lookback_start_inclusive":cutoff.isoformat(),
        "mode":mode,"summary":{
            "monitored_inventory_entries":len(inventory["products"]),
            "published_product_cve_pairs_all_history":total_matching,
            "distinct_cve_ids_all_history":len(all_cves),
            "product_cve_rows_in_report":len(rows),
            "distinct_cve_ids_in_report":len({r["cve_id"] for r in rows}),
            "kev_listed_product_cve_rows":sum(r["kev_in_snapshot"] for r in rows),
            "queue_counts":dict(sorted(queued.items()))},
        "products":per_product,"preview":rows[:preview],
        "preview_omitted_rows":max(0,len(rows)-preview),
        "provenance":{"inventory_sha256":input_sha,
            "CVE_archive_sha256":meta["source_archive_sha256"],
            "CVE_index_sha256":meta["source_index_sha256"],
            "KEV_source_sha256":meta["kev_source_sha256"],
            "EPSS_source_sha256":meta["epss_source_sha256"],
            "EPSS_score_timestamp":meta["epss_score_date"],
            "EPSS_age_days_at_report_as_of":meta["epss_age_days"],
            "source_snapshot":"2026-10-10 frozen CVE original; KEV/EPSS captured separately at warehouse creation"},
        "limitations":[
            "Customer product list is provided locally; it has NOT been verified against assets/CMDB.",
            "Matching is exact casefold vendor AND product; missing/alternative names may be unreported.",
            "The publisher affected[] array may contain unaffected versions; matched product != vulnerable deployment.",
            "Installed version is display-only; no semantic version-range decision or remediation validity check.",
            "No advisories are joined before independent vendor source verification completes.",
            "Missing results do NOT establish safety; CVEs without usable affected[] labels cannot be matched.",
            "The CVE snapshot is frozen to 2026-10-10 and is NOT a current/continuous feed.",
            "KEV catalog membership != observed compromise of this customer; EPSS != customer's attack probability.",
            "The CSV includes ALL in-scope matched publisher product-CVE rows, not merely slide excerpts.",
        ]}
    (out_dir/"customer-product-report.json").write_text(
        json.dumps(report,ensure_ascii=False,sort_keys=True,indent=2)+"\n",encoding="utf-8")
    return report


def main():
    p=argparse.ArgumentParser(description="Private local product portfolio -> sourced vulnerability review list")
    p.add_argument("--db",required=True,type=Path)
    p.add_argument("--inventory",required=True,type=Path)
    p.add_argument("--out-dir",required=True,type=Path)
    p.add_argument("--as-of",type=date.fromisoformat,default=date(2026,10,10))
    p.add_argument("--days",type=int,default=90)
    p.add_argument("--mode",choices=("recent","all"),default="recent")
    p.add_argument("--preview",type=int,default=120)
    p.add_argument("--demo",action="store_true",help="Only use with a genuinely fictitious profile")
    args=p.parse_args()
    os.umask(0o077)
    if args.out_dir.resolve() in (args.db.resolve(),args.inventory.resolve()):
        p.error("Output must not overwrite source database or inventory")
    result=build_report(args.db,args.inventory,args.out_dir,as_of=args.as_of,
                        days=args.days,mode=args.mode,preview=args.preview,demo=args.demo)
    print(json.dumps({"result":"CUSTOMER_PRODUCT_CVE_REFERENCE_REPORT_GENERATED",
        "product_entries":result["summary"]["monitored_inventory_entries"],
        "matched_product_cve_rows":result["summary"]["product_cve_rows_in_report"],
        "customer_exposure":"NOT_ASSESSED"},ensure_ascii=False))


if __name__=="__main__":main()
