"""Time-aware ranking for a *research shortlist*, not a weekly impact verdict.

Published CVE in UTC window and newly-added KEV are distinct source events.
An old KEV CVE with only dateUpdated this week never becomes a new weekly alert.
Source CVSS and EPSS are unverified temporal snapshots, NOT confirmed exploits.
"""
from __future__ import annotations

from collections import Counter
import math

NEW_PUBLICATION = "CVE_SOURCE_DATE_PUBLISHED_IN_WINDOW"
NEW_KEV = "CISA_KEV_DATE_ADDED_IN_WINDOW"
DIVERSITY_PENALTY = 16


def _num(value, lo, hi):
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (float, int)):
        raise ValueError("Invalid temporal ranking numeric source")
    if not math.isfinite(value) or not lo <= value <= hi:
        raise ValueError("Invalid temporal risk number")
    return float(value)


def _diversity_key(record, cve_id):
    """CNA vendor/product grouping is only a ranking hint, not CVE deduplication."""
    affected = record.get("cve_affected_original_predicates") or []
    keys = sorted({
        (str(x.get("vendor") or "").casefold().strip(),
         str(x.get("product") or "").casefold().strip())
        for x in affected
        if isinstance(x, dict) and x.get("product")
    })
    if not keys:
        return ["unknown", cve_id]
    return list(keys[0])


def publication_signals(record, vendor_matched: bool):
    """Only source-backed numerical data, no implied exploit conditions."""
    score = _num((record.get("cvss") or {}).get("base_score"), 0, 10)
    epss_record = record.get("epss") or {}
    epss = _num(epss_record.get("probability"), 0, 1)
    points = round((score or 0) * 10, 2)
    tags = []
    if score is not None and score >= 9:
        tags.append("CNA_CVSS_AT_LEAST_9")
    if vendor_matched:
        points += 8
        tags.append("APPROVED_CNA_VENDOR_MATCH_BONUS_8")
    if epss is not None:
        if epss >= .5:
            points += 14
            tags.append("EPSS_SNAPSHOT_AT_LEAST_0_5_BONUS_14_DATE_UNKNOWN")
        elif epss >= .1:
            points += 10
            tags.append("EPSS_SNAPSHOT_AT_LEAST_0_1_BONUS_10_DATE_UNKNOWN")
        elif epss >= .01:
            points += 6
            tags.append("EPSS_SNAPSHOT_AT_LEAST_0_01_BONUS_6_DATE_UNKNOWN")
    eligible = ((score is not None and score >= 9)
                or (score is not None and score >= 7 and epss is not None and
                    (epss >= .5 or vendor_matched and epss >= .1)))
    return points, tags, bool(eligible)


def temporal_fields(record, *, matched_vendor, new_kev):
    reasons = record.get("week_reasons") or []
    active = record.get("record_state") == "PUBLISHED"
    new_publication = active and NEW_PUBLICATION in reasons
    updated_only = active and not new_publication and not new_kev
    points, tags, eligible = publication_signals(record, matched_vendor)
    return {
        "temporal_event_basis": ("NEW_CISA_KEV_REGISTRATION" if active and new_kev
                                 else "NEW_CVE_PUBLICATION" if new_publication
                                 else "CVE_METADATA_UPDATED_ONLY_CHANGE_UNVERIFIED" if updated_only
                                 else "INACTIVE_RECORD"),
        "new_cve_publication_in_window": bool(new_publication),
        "updated_without_confirmed_material_change": bool(updated_only),
        "source_cve_published_utc": record.get("cve_published_utc"),
        "source_cve_updated_utc": record.get("cve_updated_utc"),
        "new_publication_heuristic_score": points,
        "new_publication_heuristic_tags": tags,
        "new_publication_risk_eligible": bool(new_publication and eligible),
        "diversity_group_key": _diversity_key(record, record["cve_id"]),
    }


def select_top50(ledger, target):
    """Mandatory new KEV first; newly published high-signal only thereafter.

    Repeated *same CNA product* receives a ranking penalty, NOT a hard cap.
    This does not certify affected versions, advisories, or attack prerequisites.
    """
    fresh_kev = [x for x in ledger if x["record_state"] == "PUBLISHED"
                 and x["new_kev_added_in_window"]]
    fresh_kev.sort(key=lambda x: (
        -x["new_publication_heuristic_score"], x["cve_id"]))
    others = [x for x in ledger if x["record_state"] == "PUBLISHED"
              and not x["new_kev_added_in_window"]
              and x["new_cve_publication_in_window"]
              and x["new_publication_risk_eligible"]]
    pool = list(others)
    chosen = list(fresh_kev)
    products = Counter()
    while pool and len(chosen) < target:
        pool.sort(key=lambda x: (
            -(x["new_publication_heuristic_score"]
              - DIVERSITY_PENALTY * products[tuple(x["diversity_group_key"])]),
            -x["new_publication_heuristic_score"],
            -(x["cvss_base"] or 0),
            -(x["epss_snapshot_probability"] or 0),
            x["cve_id"]))
        pick = pool.pop(0)
        chosen.append(pick)
        products[tuple(pick["diversity_group_key"])] += 1
    if any(not x["new_kev_added_in_window"] and
           not x["new_cve_publication_in_window"] for x in chosen):
        raise ValueError("Old KEV or metadata-only update entered fresh shortlist")
    if len(chosen) != len({x["cve_id"] for x in chosen}):
        raise ValueError("Duplicate time-aware CVE shortlist entry")
    return chosen, len(others)
