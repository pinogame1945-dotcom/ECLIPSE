"""Conservative evidence-level vendor/CVE product comparison; NEVER customer exposure.

Proves only exact normalized product identity or literal predicate agreement under
strict scope. All differences are REVIEW candidates, not proven contradictions.
The two SQLite input warehouses are opened read-only and never modified.
"""
from __future__ import annotations
from collections import Counter,defaultdict
from datetime import datetime,timezone
import argparse
import hashlib
import json
from pathlib import Path
import re
import unicodedata

from .vendor_cve_link import _open_ro
from .vendor_registry import load_registry
from .vendor_replay import inspect_db

ALLOWED={"paloalto-advisories","redhat-csaf","siemens-csaf","fortinet-psirt"}
EXACT_STATUS={"affected","unaffected"}
MAX_ROWS=180000
MAX_LINKS=24000
SAMPLE_LIMIT=16


def name_key(name):
    """Whitespace/case normalization only. No aggressive fuzzy matching."""
    if not isinstance(name,str) or not name.strip():return None
    return " ".join(unicodedata.normalize("NFKC",name).casefold().split())


def literal_exact_versions(versions):
    if not isinstance(versions,list):return {}
    extracted={}
    for row in versions:
        if not isinstance(row,dict):continue
        name=row.get("version")
        state=row.get("status")
        if not isinstance(name,str) or state not in EXACT_STATUS:continue
        name=name.strip()
        if (not name or len(name)>100 or
            not re.fullmatch(r"[0-9]+(?:[._+-][A-Za-z0-9]+)*",name) or
            any(k in row for k in ("lessThan","lessThanOrEqual","changes","versionType"))):
            # versionType often changes range comparison semantics. Literal
            # equality requires no range semantics or implicit defaults.
            continue
        if name in extracted and extracted[name]!=state:
            return {}  # conflicting source row cannot support conclusions
        extracted[name]=state
    return extracted


def _eligible_facts(sid,facts):
    ids=facts.get("cve_ids",[])
    if not isinstance(ids,list):raise ValueError("Malformed vendor CVE evidence")
    if sid=="paloalto-advisories":
        # Manufacturer per-CVE CNA body; PAN-SA notices have no direct CVE.
        if len(ids)!=1:return [],"NO_DIRECT_CVE_SCOPE"
        rows=facts.get("affected",[])
        if not isinstance(rows,list):raise ValueError("Malformed Palo Alto claims")
        return [{"cve_id":ids[0],"vendor":r.get("vendor"),"product":r.get("product"),
                 "version_rows":r.get("versions_raw"),"kind":"CNA_DIRECT",
                 "evidence":"containers.cna.affected"}
                for r in rows if isinstance(r,dict)],None
    if sid in ("redhat-csaf","siemens-csaf"):
        rows=facts.get("product_status_claims_unreviewed",[])
        if not isinstance(rows,list):raise ValueError("Malformed CSAF claims")
        return [{"cve_id":r.get("cve_id"),"vendor":None,
                 "product":r.get("product_name"),"kind":"CSAF_NAMED_PRODUCT",
                 "claim":r.get("status"),"evidence":r.get("evidence_path"),
                 "product_tree":r.get("product_evidence_path")}
                for r in rows if isinstance(r,dict) and r.get("cve_id") in ids
                and r.get("status") in ("known_affected","known_not_affected",
                                        "fixed","first_fixed","under_investigation")],None
    if sid=="fortinet-psirt":
        # CVE references scraped from page-wide HTML may be navigation/sidebar;
        # therefore do NOT attach a Fortinet version row to any CVE.
        return [],"HTML_PAGEWIDE_CVE_LINK_UNVERIFIED"
    return [],"NO_STRUCTURED_PER_CVE_PRODUCT_SCOPE"


def _cve_affected(cve,cve_id,cache):
    if cve_id not in cache:
        cache[cve_id]=list(cve.execute("""
          SELECT container, ordinal, vendor, product, versions_json, default_status
          FROM warehouse_affected WHERE cve_id=? ORDER BY container,ordinal""",(cve_id,)))
    return cache[cve_id]


def content_audit(vendor_db,cve_db,registry,*,require_full_cve=False):
    verified=inspect_db(Path(vendor_db),registry)
    counts=Counter()
    by_source=defaultdict(Counter)
    samples=defaultdict(list)
    scanned=0
    links=0
    with _open_ro(Path(vendor_db)) as vdb,_open_ro(Path(cve_db)) as cdb:
        tables={x[0] for x in cdb.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not {"warehouse_affected","cve_current","warehouse_metadata"}.issubset(tables):
            raise ValueError("Full CVE affected-product warehouse missing")
        metadata={}
        for row in cdb.execute("SELECT key,value FROM warehouse_metadata"):
            metadata[row["key"]]=json.loads(row["value"])
        index_sha=metadata.get("source_index_sha256")
        source_sha=metadata.get("source_archive_sha256")
        if any(not isinstance(h,str) or not re.fullmatch("[0-9a-f]{64}",h)
               for h in (index_sha,source_sha)):
            raise ValueError("Untrusted CVE source provenance")
        cve_total=cdb.execute("SELECT COUNT(*) FROM cve_current").fetchone()[0]
        if require_full_cve and cve_total!=403696:
            raise ValueError("Full CVE snapshot count is not 403696")
        cache={}
        docs=vdb.execute("""SELECT d.source_id,d.advisory_id,d.current_facts_sha,
                v.facts_json FROM vendor_documents d JOIN vendor_document_versions v
                ON d.source_id=v.source_id AND d.advisory_id=v.advisory_id
                AND v.version=(SELECT MAX(z.version) FROM vendor_document_versions z
                    WHERE z.source_id=d.source_id AND z.advisory_id=d.advisory_id)
                ORDER BY d.source_id,d.advisory_id""")
        document_count=0
        for doc in docs:
            document_count+=1
            sid=doc["source_id"]
            if sid not in ALLOWED:
                counts["DOCUMENT_UNSUPPORTED_FOR_PRODUCT_COMPARISON"]+=1
                by_source[sid]["DOCUMENT_UNSUPPORTED_FOR_PRODUCT_COMPARISON"]+=1
                continue
            facts=json.loads(doc["facts_json"])
            claims,reason=_eligible_facts(sid,facts)
            if reason:
                counts[reason]+=1
                by_source[sid][reason]+=1
                continue
            if not claims:
                counts["DOCUMENT_NO_STRUCTURED_PRODUCT_CLAIMS"]+=1
                by_source[sid]["DOCUMENT_NO_STRUCTURED_PRODUCT_CLAIMS"]+=1
                continue
            for claim in claims:
                scanned+=1
                if scanned>MAX_ROWS:raise ValueError("Product audit row budget exceeded")
                cve_id=claim.get("cve_id")
                if not isinstance(cve_id,str) or not re.fullmatch(r"CVE-\d{4}-\d{4,}",cve_id):
                    counts["CLAIM_NO_VALID_CVE"]+=1
                    by_source[sid]["CLAIM_NO_VALID_CVE"]+=1
                    continue
                item=cdb.execute("SELECT record_state FROM cve_current WHERE cve_id=?",
                                 (cve_id,)).fetchone()
                if not item or item["record_state"]!="PUBLISHED":
                    cls="CLAIM_CVE_NOT_PUBLISHED_IN_SNAPSHOT"
                    counts[cls]+=1
                    by_source[sid][cls]+=1
                    continue
                product=name_key(claim.get("product"))
                vendor=name_key(claim.get("vendor"))
                if not product:
                    cls="CLAIM_PRODUCT_UNRESOLVED"
                    counts[cls]+=1
                    by_source[sid][cls]+=1
                    continue
                cve_affected=_cve_affected(cdb,cve_id,cache)
                rows=[]
                for row in cve_affected:
                    if name_key(row["product"])!=product:continue
                    if vendor and name_key(row["vendor"])!=vendor:continue
                    if row["container"]!="cna":continue  # ADP assertions separate
                    rows.append(row)
                if not rows:
                    cls="NO_EXACT_CNA_PRODUCT_NAME_MATCH"
                    counts[cls]+=1
                    by_source[sid][cls]+=1
                    continue
                if len(rows)>1:
                    cls="MULTIPLE_CNA_PRODUCT_ROWS_NEED_REVIEW"
                    counts[cls]+=1
                    by_source[sid][cls]+=1
                    continue
                links+=1
                if links>MAX_LINKS:raise ValueError("Cross-publisher comparison budget exceeded")
                row=rows[0]
                if claim["kind"]=="CSAF_NAMED_PRODUCT":
                    cls="PRODUCT_NAME_EXACT_MATCH_CSAF_STATUS_UNMAPPED"
                    # A CSAF product-tree name may itself include product
                    # version/edition; do not derive version compatibility.
                    v_fixed={}
                    c_fixed={}
                else:
                    v_fixed=literal_exact_versions(claim.get("version_rows"))
                    try:
                        cve_versions=json.loads(row["versions_json"]) if row["versions_json"] else []
                    except json.JSONDecodeError as exc:
                        raise ValueError("Malformed CVE authoritative versions_json") from exc
                    c_fixed=literal_exact_versions(cve_versions)
                    if not v_fixed or not c_fixed:
                        original=claim.get("version_rows")
                        # Byte-structural equality of ordered, publisher
                        # predicates provides evidence of the same text but
                        # NOT independent corroboration; often the CNA is
                        # mirrored into both repositories.
                        if isinstance(original,list) and original and isinstance(cve_versions,list) and cve_versions:
                            if json.dumps(original,sort_keys=True,ensure_ascii=False)==json.dumps(cve_versions,sort_keys=True,ensure_ascii=False):
                                cls="PREDICATE_RAW_STRUCTURAL_EQUAL_POSSIBLY_SHARED_CNA"
                            else:
                                cls="PREDICATE_RAW_STRUCTURAL_DIFFERENCE_REVIEW_ONLY"
                        else:
                            cls="PRODUCT_MATCH_VERSION_SYNTAX_INCOMPARABLE"
                    else:
                        shared=set(v_fixed)&set(c_fixed)
                        if not shared:
                            cls="PRODUCT_MATCH_NO_SHARED_EXACT_VERSION"
                        elif any(v_fixed[key]!=c_fixed[key] for key in shared):
                            cls="EXACT_VERSION_STATUS_DISAGREEMENT_REVIEW_ONLY"
                        else:
                            cls="EXACT_VERSION_STATUS_AGREEMENT_FOR_SHARED_LITERALS"
                counts[cls]+=1
                by_source[sid][cls]+=1
                if len(samples[cls])<SAMPLE_LIMIT:
                    sample={"source":sid,"advisory":doc["advisory_id"],
                            "cve_id":cve_id,"cve_record_state":item["record_state"],
                            "product":claim["product"],"vendor":claim.get("vendor"),
                            "vendor_status":claim.get("claim"),
                            "vendor_evidence_path":claim["evidence"],
                            "cve_evidence_path":f"warehouse_affected(cna,{row['ordinal']})",
                            "cve_product":row["product"],"cve_vendor":row["vendor"],
                            "vendor_document_facts_sha":doc["current_facts_sha"],
                            "comparison":cls,"shared_exact_versions":[]}
                    if v_fixed and c_fixed:
                        sample["shared_exact_versions"]=sorted(set(v_fixed)&set(c_fixed))[:15]
                    samples[cls].append(sample)
        if document_count!=verified["advisories"]:
            raise ValueError("Not all vendor documents processed")
    return {
      "result":"SOURCE_ATTRIBUTED_PRODUCT_PREDICATE_AUDIT_REVIEW_ONLY",
      "created_utc":datetime.now(timezone.utc).isoformat(timespec="seconds"),
      "snapshot":{"vendor_sqlite_sha256":verified["sqlite_sha256"],
          "vendor_documents":verified["advisories"],
          "cve_source_index_sha256":index_sha,
          "cve_source_archive_sha256":source_sha,
          "cve_records":cve_total},
      "counts":dict(sorted(counts.items())),
      "per_source":{s:dict(sorted(c.items())) for s,c in sorted(by_source.items())},
      "evidence_samples":dict(sorted(samples.items())),
      "scanned_structured_claims":scanned,"matched_comparable_product_pairs":links,
      "policy":{"input_databases_read_only":True,
        "no_vendor_product_exposure_certification":True,
        "no_automatic_fuzzy_product_aliases":True,
        "no_unscoped_HTML_CVE_product_linking":True,
        "no_assumed_version_range_semantics":True,
        "differences_review_only_never_auto_conflicts":True,
        "cannot_prove_agreement_from_missing_claims":True,
        "customer_delivery_allowed":False}}


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--vendor-db",type=Path,required=True)
    p.add_argument("--cve-db",type=Path,required=True)
    p.add_argument("--registry",type=Path,default=Path("config/vendor_source_registry.json"))
    p.add_argument("--out",type=Path,required=True)
    p.add_argument("--require-full-cve",action="store_true")
    a=p.parse_args()
    result=content_audit(a.vendor_db,a.cve_db,load_registry(a.registry),
                         require_full_cve=a.require_full_cve)
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(result,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    print(json.dumps({"result":result["result"],"counts":result["counts"],
                      "structured_claims":result["scanned_structured_claims"],
                      "strict_product_matches":result["matched_comparable_product_pairs"],
                      "no_customer_claims":True},ensure_ascii=False))


if __name__=="__main__":main()
