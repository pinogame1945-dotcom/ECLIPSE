"""Evidence-coverage diagnostics without pretending extraction is verified.

These diagnostics describe only the *sampled* official advisory.  They do not
calculate vendor-wide completeness or quality of vulnerability conclusions.
"""
from __future__ import annotations


def inspect_facts(facts: dict, source_id: str) -> dict:
    if not isinstance(facts,dict):
        raise ValueError("No facts to inspect")
    cves=facts.get("cve_ids",[])
    affected=facts.get("affected",[])
    rems=facts.get("remediations_unreviewed",[])
    statuses=facts.get("product_status_claims_unreviewed",[])
    if any(not isinstance(a,dict) for a in affected):
        raise ValueError("Malformed affected claims")
    notes=[]
    if not cves:
        notes.append("CVE association not validated; vendor advisory may be CVE-unassigned or parser may have missed it.")
    if source_id in ("atlassian-security","gitlab-security-releases","yamaha-network"):
        notes.append("HTML body-wide CVEs may be unrelated navigation; candidate IDs cannot be treated as affirmed.")
    if source_id == "microsoft-msrc":
        notes.append("Monthly CVRF is a multi-CVE source; per-CVE affected-product mapping unimplemented.")
    unresolved=facts.get("unresolved_product_ids",[])
    if unresolved:
        notes.append("Some CSAF publisher product IDs have no matching product label.")
    explicit_remediations=len(rems)+sum(bool(a.get("remediation_raw")) for a in affected)
    product_labels=sum(bool(a.get("product_name_from_csaf") or a.get("product_release") or a.get("product")) for a in affected)
    statuses_present={k:sum(x.get("status")==k for x in statuses if isinstance(x,dict))
                      for k in ("known_affected","known_not_affected","fixed","first_fixed","under_investigation")}
    fixed_claims=statuses_present["fixed"]+statuses_present["first_fixed"]
    return {
        "qualification":"SAMPLED_UNREVIEWED_EVIDENCE_ONLY",
        "quality_assured":False,
        "safe_for_customer_facing_auto_claims":False,
        "cve_ids_provisionally_extracted":len(cves),
        "cve_link_review_required":True,
        "affected_entries_unreviewed":len(affected),
        "affected_entries_with_product_label":product_labels,
        "affected_entries_with_raw_version_evidence":sum(bool(a.get("affected_versions_raw") or a.get("versions_raw")) for a in affected),
        "csaf_product_catalog_entries":facts.get("product_catalog_size",0),
        "csaf_product_status_rows_unreviewed":len(statuses),
        "csaf_product_status_counts":statuses_present,
        "csaf_unresolved_product_ids":len(unresolved),
        "remediation_entries_unreviewed":explicit_remediations,
        "publisher_marked_fixed_product_status_rows":fixed_claims,
        "normalized_fixed_version_ranges_verified":0,
        "actual_exploitation_state":"NOT_ASSESSED",
        "detected_html_cve_candidates_unlinked":len(facts.get("unreviewed_page_cve_candidates",[])),
        "detected_article_cve_candidates_unlinked":len(facts.get("unreviewed_article_cve_candidates",[])),
        "evidence_field_paths":len(facts.get("evidence_fields",[])),
        "cautions":notes,
    }


def summarize_source_quality(details: list[dict]) -> dict:
    """Count sampled assertions, not *actual accuracy* or vendor completeness."""
    return {"sampled_documents":len(details),
            "documents_with_CVE_candidates":sum(bool(x.get("field_quality",{}).get("cve_ids_provisionally_extracted")) for x in details),
            "sampled_affected_evidence_rows":sum(x.get("field_quality",{}).get("affected_entries_unreviewed",0) for x in details),
            "sampled_explicit_remediation_rows":sum(x.get("field_quality",{}).get("remediation_entries_unreviewed",0) for x in details),
            "docs_with_unresolved_csaf_product_ids":sum(bool(x.get("field_quality",{}).get("csaf_unresolved_product_ids")) for x in details),
            "docs_with_article_cve_candidates_unlinked":sum(bool(x.get("field_quality",{}).get("detected_article_cve_candidates_unlinked")) for x in details),
            "verified_product_exposure_assessments":0,
            "vendor_wide_coverage_assured":False}
