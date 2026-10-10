"""Faithful CSAF 2.0 vendor security evidence extraction.

All output is unreviewed provenance, not an exposure prediction. Unlike many
flat CVE converters, product IDs are resolved through the publisher's actual
product_tree and remediation evidence retains its associated product references.
No version comparisons or invented fix-version ranges are performed.
"""
from __future__ import annotations

from collections import defaultdict
import re

CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
STATUSES = ("known_affected", "known_not_affected", "fixed", "first_fixed", "under_investigation")
MAX_PRODUCTS = 50000
MAX_ROWS = 12000


def _string(value, limit=1200):
    return str(value)[:limit] if value is not None else ""


def _catalog(tree: dict) -> tuple[dict, list]:
    found = {}
    collisions = []
    if not isinstance(tree, dict):
        return found, ["No publisher product_tree provided"]
    total = [0]
    def register(item, path):
        if not isinstance(item, dict):
            return
        pid = item.get("product_id")
        name = item.get("name")
        if not isinstance(pid, str) or not pid.strip():
            return
        if not isinstance(name, str) or not name.strip():
            raise ValueError("Publisher product_id lacks a product name: "+str(path))
        if pid in found and found[pid]["name"] != name:
            collisions.append({"id":pid,"first":found[pid]["name"],"second":name})
            return
        found[pid] = {"name":_string(name),"evidence_path":path}
        total[0] += 1
        if total[0] > MAX_PRODUCTS:
            raise ValueError("CSAF product catalog exceeds bounded audit cap")

    def walk(branches, path, depth=0):
        if depth > 20:
            raise ValueError("Excessive nested CSAF branch depth")
        if branches is None:
            return
        if not isinstance(branches, list):
            raise ValueError("Malformed CSAF product_tree.branches")
        for k, branch in enumerate(branches):
            if not isinstance(branch, dict):
                raise ValueError("Malformed CSAF product branch")
            addr=f"{path}[{k}]"
            register(branch.get("product"),addr+".product")
            walk(branch.get("branches"),addr+".branches",depth+1)
    walk(tree.get("branches"),"product_tree.branches")
    for i,product in enumerate(tree.get("full_product_names",[]) or []):
        register(product, f"product_tree.full_product_names[{i}]")
    for i, rel in enumerate(tree.get("relationships",[]) or []):
        if not isinstance(rel, dict):
            continue
        register(rel.get("full_product_name"), f"product_tree.relationships[{i}].full_product_name")
    if collisions:
        raise ValueError("Conflicting CSAF product IDs cannot be unambiguously resolved")
    return found, []


def normalize_csaf(doc: dict, fallback_title: str) -> dict:
    if not isinstance(doc, dict) or not isinstance(doc.get("document"), dict):
        raise ValueError("CSAF document missing")
    vulns=doc.get("vulnerabilities")
    if not isinstance(vulns, list) or not vulns:
        raise ValueError("No CSAF vulnerability records")
    catalog,notes=_catalog(doc.get("product_tree"))
    all_cves=set()
    affected=[]
    status_claims=[]
    remediation_claims=[]
    unresolved_ids=set()
    for i,v in enumerate(vulns):
        if not isinstance(v,dict):
            raise ValueError("Malformed CSAF vulnerability object")
        cve=v.get("cve")
        if cve is not None:
            if not isinstance(cve,str) or not CVE.fullmatch(cve):
                raise ValueError("Invalid CSAF CVE identifier at vulnerabilities["+str(i)+"]")
            all_cves.add(cve.upper())
        status=v.get("product_status") or {}
        if not isinstance(status,dict):
            raise ValueError("Invalid CSAF product_status")
        claimed={}
        for key in STATUSES:
            ids=status.get(key,[])
            if not isinstance(ids,list):
                raise ValueError("Invalid CSAF product status list")
            if len(ids)!=len(set(ids)):
                raise ValueError("Duplicated product ID in CSAF status list")
            for pid in ids:
                if not isinstance(pid,str) or not pid.strip():
                    raise ValueError("Missing product ID in CSAF status")
                claimed.setdefault(pid,[]).append(key)
                metadata=catalog.get(pid)
                if metadata is None:
                    unresolved_ids.add(pid)
                claim={
                    "cve_id":cve.upper() if isinstance(cve,str) else None,
                    "product_id":pid,
                    "product_name":metadata["name"] if metadata else None,
                    "status":key,
                    "evidence_path":f"vulnerabilities[{i}].product_status.{key}",
                    "product_evidence_path":metadata["evidence_path"] if metadata else None
                }
                status_claims.append(claim)
                if key=="known_affected":
                    # Legacy consumers explicitly treat status as still unreviewed.
                    affected.append({
                        "product_id_unresolved":pid,
                        "product_name_from_csaf":metadata["name"] if metadata else None,
                        "cve_id":claim["cve_id"],
                        "status":"known_affected_from_csaf",
                        "evidence_path":claim["evidence_path"],
                        "name_evidence_path":claim["product_evidence_path"]
                    })
        for pid,keys in claimed.items():
            if "known_affected" in keys and ("known_not_affected" in keys or "fixed" in keys):
                raise ValueError("Contradictory CSAF status for product ID: "+pid)
        rems=v.get("remediations",[]) or []
        if not isinstance(rems,list):
            raise ValueError("Malformed CSAF remediation list")
        for j,rem in enumerate(rems):
            if not isinstance(rem,dict) or not isinstance(rem.get("category"),str):
                raise ValueError("Malformed CSAF remediation")
            ids=rem.get("product_ids",[]) or []
            groups=rem.get("group_ids",[]) or []
            if not isinstance(ids,list) or not isinstance(groups,list):
                raise ValueError("Malformed CSAF remediation targets")
            if any(not isinstance(pid,str) for pid in ids+groups):
                raise ValueError("Non-string CSAF remediation target")
            remediation_claims.append({
                "cve_id":cve.upper() if isinstance(cve,str) else None,
                "category":_string(rem["category"],80),
                "details_original":_string(rem.get("details"),4000),
                "url":_string(rem.get("url"),1000) or None,
                "product_ids":ids,
                "group_ids":groups,
                "all_products_explicitly":not ids and not groups,
                "evidence_path":f"vulnerabilities[{i}].remediations[{j}]"
            })
    if len(status_claims)+len(remediation_claims)>MAX_ROWS:
        raise ValueError("Oversized structured CSAF assertions")
    title=doc["document"].get("title") or fallback_title
    if not isinstance(title,str) or not title.strip():
        raise ValueError("Missing CSAF advisory title")
    return {
        "title":title[:500],
        "cve_ids":sorted(all_cves),
        "affected":affected,
        "product_status_claims_unreviewed":status_claims,
        "remediations_unreviewed":remediation_claims,
        "product_tree_present":isinstance(doc.get("product_tree"),dict),
        "product_catalog_size":len(catalog),
        "unresolved_product_ids":sorted(unresolved_ids),
        "evidence_fields":["document.title","product_tree.branches",
            "product_tree.full_product_names","product_tree.relationships",
            "vulnerabilities[*].cve","vulnerabilities[*].product_status",
            "vulnerabilities[*].remediations"],
        "extraction_notes":notes+[
            "Publisher CSAF product names and statuses are retained verbatim with paths.",
            "CSAF fixed/first_fixed are product status assertions, NOT a computed version range.",
            "No version comparison, normalized patch selection, or customer impact determination.",
            "All structured rows require independent accuracy and vendor-reuse review."
        ]
    }
