"""ECLIPSE important ~50 candidate handoff. No editorial report or lost CVEs.

Mandatory: NEW CISA KEV in the requested week; source-matched vendor entries
from the exact 126-row user-approved registry. All other candidates require
multiple risk signals and compete for remaining places. Mandatory overflow is
NEVER silently truncated. Each original CVE remains in the byte-exact L1 ZIP.
"""
from __future__ import annotations

import argparse
from collections import Counter
import io
import json
import math
from pathlib import Path
import tempfile
import unicodedata
import zipfile

from .weekly_evidence import canonical, sha, verify as verify_source
from .weekly_triage import classify, _read_jsonl, _jsonlines, MAX_BASE_ZIP_BYTES
from .weekly_temporal import temporal_fields, select_top50, DIVERSITY_PENALTY

SCHEMA = 1
TARGET = 50
MIN_DISCRETIONARY_SCORE = 55
NAMES = {
    "source-weekly-evidence.zip", "important_vendor_126.json",
    "important_index.json", "important_candidates.jsonl",
    "top50_research_candidates.jsonl", "decision_ledger.jsonl",
    "important_quality.json", "important_manifest.json",
}
MAX_MEMBER_BYTES = 120 * 1024 * 1024
MAX_POLICY_BYTES = 128 * 1024


def vendor_key(value):
    if not isinstance(value, str):
        return ""
    # Strict aliases: NEVER use substring matching ("apple" in "pineapple").
    return "".join(c for c in unicodedata.normalize("NFKC", value).casefold()
                   if c.isalnum())


def validate_policy(data):
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise ValueError("Unsupported 126-vendor policy schema")
    entries = data.get("entries")
    if not isinstance(entries, list) or len(entries) != 126:
        raise ValueError("The approved vendor source must contain exactly 126 candidate rows")
    aliases = {}
    unique = set()
    for idx, entry in enumerate(entries):
        if not isinstance(entry, dict) or not isinstance(entry.get("vendor"), str):
            raise ValueError("Invalid vendor row")
        vendor = entry["vendor"].strip()
        key = vendor_key(vendor)
        if not key or len(vendor) > 120:
            raise ValueError("Empty or oversized vendor name")
        unique.add(key)
        alternate = entry.get("aliases", [])
        if not isinstance(alternate, list) or not all(isinstance(v, str) for v in alternate):
            raise ValueError("Invalid vendor aliases")
        if len(alternate) > 12:
            raise ValueError("Too many vendor aliases")
        for alias in [vendor, *alternate]:
            k = vendor_key(alias)
            if not k or len(alias) > 120:
                raise ValueError("Invalid empty vendor alias")
            owner = aliases.get(k)
            if owner is not None and owner != key:
                raise ValueError("Ambiguous aliases map to different vendors")
            aliases[k] = key
    expected_unique = data.get("expected_unique_vendors")
    if expected_unique is not None and (
        type(expected_unique) is not int or expected_unique != len(unique)):
        raise ValueError("Policy unique vendor count mismatch")
    return aliases, len(unique)


def _numeric(value, lo, hi):
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (float, int)):
        raise ValueError("Invalid numeric risk source")
    if not math.isfinite(value) or not lo <= value <= hi:
        raise ValueError("Invalid risk value")
    return float(value)


def risk_signals(p):
    """Signal-only ordering: no claim of current EPSS or proven exploitability."""
    cvss = _numeric(p["cvss_base"], 0, 10)
    epss = _numeric(p["epss_probability"], 0, 1)
    score = 0
    reasons = []
    if p["kev_present"]:
        score += 70
        reasons.append("CISA_KEV_PREVIOUSLY_LISTED")
    if epss is not None:
        if epss >= 0.5:
            score += 60
            reasons.append("EPSS_SNAPSHOT_AT_LEAST_0_5_DATE_UNKNOWN")
        elif epss >= 0.1:
            score += 35
            reasons.append("EPSS_SNAPSHOT_AT_LEAST_0_1_DATE_UNKNOWN")
        elif epss >= 0.01:
            score += 10
            reasons.append("EPSS_SNAPSHOT_AT_LEAST_0_01_DATE_UNKNOWN")
    if cvss is not None:
        if cvss >= 9:
            score += 25
            reasons.append("CNA_CVSS_AT_LEAST_9")
        elif cvss >= 7:
            score += 12
            reasons.append("CNA_CVSS_AT_LEAST_7")
    if p["vendor_document_keys"]:
        reasons.append("VENDOR_DOCUMENT_CVE_LINK_UNREVIEWED_NOT_MANDATORY_PROOF")
    return score, reasons


def _source_verified(source):
    if not 0 < len(source) <= MAX_BASE_ZIP_BYTES:
        raise ValueError("Invalid source evidence ZIP size")
    with tempfile.TemporaryDirectory(prefix="eclipse-important-source-") as tmp:
        path = Path(tmp) / "weekly.zip"
        path.write_bytes(source)
        proof = verify_source(path)
    with zipfile.ZipFile(io.BytesIO(source)) as z:
        rows = _read_jsonl(z.read("vulnerabilities.jsonl"))
        index = json.loads(z.read("weekly_index.json"))
        quality = json.loads(z.read("quality_report.json"))
    if len(rows) != proof["candidate_total"]:
        raise ValueError("Source CVE proof count mismatch")
    if quality.get("weekly_coverage_certified") is not False:
        raise ValueError("Historical snapshot must not claim weekly completeness")
    return rows, index, quality


def compute(source, policy_bytes, target=TARGET, min_score=MIN_DISCRETIONARY_SCORE):
    if not isinstance(target, int) or isinstance(target, bool) or not 1 <= target <= 500:
        raise ValueError("Invalid desired featured candidate count")
    if not isinstance(min_score, int) or isinstance(min_score, bool) or not 0 <= min_score <= 200:
        raise ValueError("Invalid minimum discretionary score")
    if not 0 < len(policy_bytes) <= MAX_POLICY_BYTES:
        raise ValueError("Missing or oversized 126-vendor policy")
    policy = json.loads(policy_bytes)
    aliases, unique_count = validate_policy(policy)
    rows, base_index, source_quality = _source_verified(source)
    ledger = []
    seen = set()
    for row in rows:
        p = classify(row)
        cid = p["cve_id"]
        if cid in seen:
            raise ValueError("Duplicate CVE in source")
        seen.add(cid)
        # CNA affected.vendor only. Vendor-document pagewide CVE hits are
        # unreviewed and MUST NOT confer mandatory 126-vendor status.
        matched = set()
        for affected in row.get("cve_affected_original_predicates") or []:
            if not isinstance(affected, dict):
                raise ValueError("Invalid original affected predicate")
            name_key = aliases.get(vendor_key(affected.get("vendor")))
            if name_key:
                matched.add(name_key)
        active = p["record_state"] == "PUBLISHED"
        new_kev = ("CISA_KEV_DATE_ADDED_IN_WINDOW" in p["week_reasons"]
                   and p["kev_present"])
        points, evidence_tags = risk_signals(p)
        time_info = temporal_fields(row, matched_vendor=bool(matched), new_kev=new_kev)
        mandatory = active and (new_kev or bool(matched))
        if not active:
            lane = "INACTIVE"
        elif new_kev:
            lane = "MANDATORY_NEW_KEV"
        elif matched:
            lane = "MANDATORY_126_VENDOR"
        elif points >= min_score:
            lane = "RISK_ELIGIBLE"
        else:
            lane = "WATCH"
        ledger.append({
            "cve_id": cid, "record_state": p["record_state"],
            "lane": lane, "new_kev_added_in_window": bool(new_kev and active),
            **time_info,
            "approved_vendor_matched_by_cna": sorted(matched),
            "risk_signal_score": points, "risk_signal_tags": evidence_tags,
            "cvss_base": p["cvss_base"],
            "epss_snapshot_probability": p["epss_probability"],
            "epss_snapshot_score_date": p["epss_score_date"],
            "vendor_document_keys_unreviewed": p["vendor_document_keys"],
            "selected_for_priority_review": False,
            "selected_for_top50_research": False,
            "selected_for_weekly_report": False,
        })
    def order_key(x):
        # New KEV first; among same lane, cumulative signals then stable ID.
        return (-x["risk_signal_score"],
                -(x["epss_snapshot_probability"] or 0.0),
                -(x["cvss_base"] or 0.0), x["cve_id"])
    kev = sorted((x for x in ledger if x["lane"] == "MANDATORY_NEW_KEV"),
                 key=order_key)
    vendors = sorted((x for x in ledger if x["lane"] == "MANDATORY_126_VENDOR"),
                     key=order_key)
    other = sorted((x for x in ledger if x["lane"] == "RISK_ELIGIBLE"),
                   key=order_key)
    obligatory = kev + vendors
    # Never drop a mandatory item to make the weekly target look pretty.
    optional = other[:max(0, target - len(obligatory))]
    chosen = obligatory + optional
    by_id = {x["cve_id"]: x for x in ledger}
    for candidate in chosen:
        by_id[candidate["cve_id"]]["selected_for_priority_review"] = True
    # L2 keeps all important-vendor CVEs, even historic ones. L3 is a
    # *different* time-aware selection: NEW KEV or new CVE publication.
    # Historical KEV membership never makes a metadata-only update new.
    top50, eligible_fresh_count = select_top50(ledger, target)
    for candidate in top50:
        by_id[candidate["cve_id"]]["selected_for_top50_research"] = True
    top50_rows = [dict(item, top50_rank=i + 1,
                       shortlist_basis=("NEW_KEV_MANDATORY" if item["new_kev_added_in_window"]
                                        else "NEW_CVE_PUBLICATION_RISK_REVIEW"))
                  for i, item in enumerate(top50)]
    ledger.sort(key=lambda x: x["cve_id"])
    selected = [dict(item, review_rank=i + 1,
                     selection_basis=("UNCONDITIONAL" if item["lane"].startswith("MANDATORY")
                                      else "RISK_SIGNALS_WITHIN_REMAINING_CAPACITY"))
                for i, item in enumerate(chosen)]
    counts = Counter(x["lane"] for x in ledger)
    if len(ledger) != base_index["candidate_total"] or len(ledger) != len(seen):
        raise ValueError("L1 completeness invariant violated")
    if len(chosen) != len({r["cve_id"] for r in chosen}):
        raise ValueError("Important selection duplicates CVEs")
    index = {
        "schema_version": SCHEMA,
        "kind": "ECLIPSE_IMPORTANT_50_REVIEW_CANDIDATES_NOT_WEEKLY_REPORT",
        "window": base_index["window_start_utc"] + ".." + base_index["window_end_utc"],
        "l1_original_cve_count": len(ledger),
        "l1_source_zip_sha256": sha(source),
        "mandatory_new_kev_count": len(kev),
        "mandatory_126_vendor_count_excluding_new_kev_overlap": len(vendors),
        "discretionary_risk_count": len(optional),
        "important_review_candidate_count": len(chosen),
        "target_count": target,
        "exceeds_target_due_to_mandatory_items": len(chosen) > target,
        "mandatory_overflow": max(0, len(obligatory) - target),
        "risk_eligible_not_selected": len(other) - len(optional),
        "top50_research_count": len(top50),
        "top50_newly_published_non_kev": sum(not x["new_kev_added_in_window"] and x["new_cve_publication_in_window"] for x in top50),
        "top50_existing_kev_without_new_registration": sum(not x["new_kev_added_in_window"] and "CISA_KEV_PREVIOUSLY_LISTED" in x["risk_signal_tags"] for x in top50),
        "updated_only_unverified_material_changes": sum(x["updated_without_confirmed_material_change"] for x in ledger),
        "new_published_high_signal_eligible": eligible_fresh_count,
        "new_published_high_signal_not_in_top50": eligible_fresh_count - (len(top50) - len(kev)),
        "target_not_filled_if_insufficient_fresh_risk_candidates": max(0, target - len(top50)),
        "product_diversity_penalty_ranking_only": DIVERSITY_PENALTY,
        "time_policy": "NEW_KEV_OR_NEW_PUBLISHED_CVE_WITH_STRUCTURED_RISK_SIGNALS_ONLY",
        "metadata_updates_without_confirmed_change_excluded_from_top50": True,
        "top50_new_kev": len(kev),
        "top50_126_vendor_non_kev": sum(bool(x["approved_vendor_matched_by_cna"]) and not x["new_kev_added_in_window"] for x in top50),
        "top50_other_non_kev": sum(not x["approved_vendor_matched_by_cna"] and not x["new_kev_added_in_window"] for x in top50),
        "top50_is_research_selection_not_editorial_approval": True,
        "l2_all_126_vendor_matches_retained_even_if_not_top50": True,
        "decision_ledger_count": len(ledger),
        "lane_counts": dict(sorted(counts.items())),
        "vendor_policy_candidate_rows": 126,
        "vendor_policy_unique_vendors": unique_count,
        "vendor_policy_sha256": sha(policy_bytes),
        "vendor_match_basis": "STRICT_CVE_CNA_AFFECTED_VENDOR_EXACT_OR_APPROVED_ALIAS",
        "not_fuzzy_product_or_pagewide_vendor_inference": True,
        "min_discretionary_signal_score": min_score,
        "ranking_is_not_verified_severity_or_editorial_approval": True,
        "source_weekly_completeness_certified": False,
    }
    quality = {
        "weekly_coverage_certified": False,
        "important_126_vendor_catalog_registered": True,
        "important_126_vendor_collector_coverage_certified": False,
        "official_vendor_source_links_reviewed": False,
        "cna_vendor_names_may_be_incomplete_or_noncanonical": True,
        "epss_score_date_missing": True,
        "cvss_alone_does_not_trigger_discretionary_inclusion": True,
        "high_risk_unselected_retained_in_original_l1": True,
        "mandatory_items_never_hidden_by_target": True,
        "top50_is_provisional_multi_signal_research_shortlist": True,
        "vendor_logo_alone_cannot_enter_top50": True,
        "old_kev_membership_alone_cannot_enter_top50": True,
        "cve_updated_date_not_evidence_of_security_change": True,
        "vendor_observed_revisions_are_not_confirmed_publisher_updates": True,
        "product_diversity_only_changes_ranking_no_cve_merging": True,
        "no_final_editorial_or_client_exposure_verdict": True,
        "source_original_notes": source_quality["critical_notes"],
    }
    return {
        "source-weekly-evidence.zip": source,
        "important_vendor_126.json": policy_bytes,
        "important_index.json": (canonical(index) + "\n").encode(),
        "important_candidates.jsonl": _jsonlines(selected),
        "top50_research_candidates.jsonl": _jsonlines(top50_rows),
        "decision_ledger.jsonl": _jsonlines(ledger),
        "important_quality.json": (canonical(quality) + "\n").encode(),
    }


def _payload(source, policy, target, min_score):
    files = compute(source, policy, target, min_score)
    if any(len(content) > MAX_MEMBER_BYTES for content in files.values()):
        raise ValueError("Oversized output member")
    return files


def create(source_path, policy_path, output_path, *, target=TARGET, min_score=MIN_DISCRETIONARY_SCORE):
    output_path = Path(output_path)
    if output_path.exists() or output_path.is_symlink():
        raise ValueError("Refusing to overwrite priority handoff")
    source_path, policy_path = Path(source_path), Path(policy_path)
    if (not source_path.is_file() or source_path.is_symlink()
            or not policy_path.is_file() or policy_path.is_symlink()):
        raise ValueError("Missing or unsafe source/policy")
    data = _payload(source_path.read_bytes(), policy_path.read_bytes(), target, min_score)
    manifest = {
        "schema_version": SCHEMA,
        "kind": "ECLIPSE_IMPORTANT_REVIEW_NOT_REPORT",
        "target_count": target, "min_discretionary_score": min_score,
        "member_sha256": {n: sha(v) for n, v in sorted(data.items())},
        "member_bytes": {n: len(v) for n, v in sorted(data.items())},
        "complete_weekly_monitoring_proven": False,
    }
    data["important_manifest.json"] = (canonical(manifest) + "\n").encode()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with zipfile.ZipFile(output_path, "x", compression=zipfile.ZIP_DEFLATED,
                             compresslevel=6) as z:
            for name in sorted(data):
                info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                z.writestr(info, data[name], compress_type=zipfile.ZIP_DEFLATED,
                           compresslevel=6)
        return verify(output_path)
    except BaseException:
        output_path.unlink(missing_ok=True)
        raise


def verify(path):
    path = Path(path)
    if not path.is_file() or path.is_symlink():
        raise ValueError("Invalid important candidates ZIP")
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        if len(names) != len(NAMES) or set(names) != NAMES:
            raise ValueError("Important ZIP files missing or duplicated")
        if any(z.getinfo(n).file_size > MAX_MEMBER_BYTES for n in names):
            raise ValueError("Excessive ZIP inflation")
        data = {n: z.read(n) for n in names}
    manifest = json.loads(data["important_manifest.json"])
    if (manifest.get("schema_version") != SCHEMA
        or manifest.get("kind") != "ECLIPSE_IMPORTANT_REVIEW_NOT_REPORT"
        or manifest.get("complete_weekly_monitoring_proven") is not False
        or set(manifest.get("member_sha256", {})) != NAMES - {"important_manifest.json"}):
        raise ValueError("Unsafe priority manifest")
    for name in NAMES - {"important_manifest.json"}:
        if (sha(data[name]) != manifest["member_sha256"][name]
            or len(data[name]) != manifest.get("member_bytes", {}).get(name)):
            raise ValueError("Important member hash/length mismatch")
    expected = _payload(data["source-weekly-evidence.zip"],
                        data["important_vendor_126.json"],
                        manifest["target_count"], manifest["min_discretionary_score"])
    for name, content in expected.items():
        if data[name] != content:
            raise ValueError("Important ranking not reproducible from L1 and policy: " + name)
    index = json.loads(data["important_index.json"])
    if index["important_review_candidate_count"] != len(_read_jsonl(data["important_candidates.jsonl"])):
        raise ValueError("Important selection count mismatch")
    if index["top50_research_count"] != len(_read_jsonl(data["top50_research_candidates.jsonl"])):
        raise ValueError("L3 research shortlist count mismatch")
    return {
        "result": "INDEPENDENT_126_VENDOR_AND_KEV_IMPORTANT_CANDIDATE_CONTRACT_VERIFIED",
        "l1_total": index["l1_original_cve_count"],
        "selected": index["important_review_candidate_count"],
        "top50": index["top50_research_count"],
        "top50_new_publications": index["top50_newly_published_non_kev"],
        "top50_existing_kev_without_new_registration": index["top50_existing_kev_without_new_registration"],
        "updated_only_unverified": index["updated_only_unverified_material_changes"],
        "top50_vendor": index["top50_126_vendor_non_kev"],
        "top50_other": index["top50_other_non_kev"],
        "mandatory_kev": index["mandatory_new_kev_count"],
        "mandatory_vendor_only": index["mandatory_126_vendor_count_excluding_new_kev_overlap"],
        "risk_selected": index["discretionary_risk_count"],
        "mandatory_overflow": index["mandatory_overflow"],
        "target": index["target_count"],
        "source_zip_sha256": index["l1_source_zip_sha256"],
        "weekly_coverage_certified": False,
    }


def main():
    parser = argparse.ArgumentParser(description="Important ~50 review candidates; retain full L1")
    commands = parser.add_subparsers(dest="cmd", required=True)
    build = commands.add_parser("build")
    build.add_argument("--source-weekly-zip", type=Path, required=True)
    build.add_argument("--vendor-policy", type=Path, required=True)
    build.add_argument("--target", type=int, default=TARGET)
    build.add_argument("--min-score", type=int, default=MIN_DISCRETIONARY_SCORE)
    build.add_argument("--out", type=Path, required=True)
    check = commands.add_parser("verify")
    check.add_argument("--zip", type=Path, required=True)
    args = parser.parse_args()
    if args.cmd == "build":
        result = create(args.source_weekly_zip, args.vendor_policy, args.out,
                        target=args.target, min_score=args.min_score)
    else:
        result = verify(args.zip)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
