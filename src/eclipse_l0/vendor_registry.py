"""Reviewed official-source registry validation and status reporting.

These are source-level *one-shot* proofs. Read/parse verified is NOT production
coverage, accuracy, licensing, or continuous availability certification.
"""
from __future__ import annotations

import argparse
from datetime import datetime
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

STATES = {"not_tested", "probe_failed", "read_parse_verified"}
COLLECTORS = {"rss_html","api_cvrf_xml","json","csaf_csv_json","csaf_json",
              "html","atom_html","api_json","oauth_api"}
SOURCE_ID = re.compile(r"^[a-z][a-z0-9-]{2,79}$")


def _url(url, allowed_hosts):
    if not isinstance(url, str):
        return False
    p = urlsplit(url)
    return (p.scheme == "https" and p.hostname in allowed_hosts
            and not p.username and not p.password and p.port in (None, 443)
            and not p.fragment)


def _date(value):
    if not isinstance(value, str):
        raise ValueError("Missing verified timestamp")
    timestamp = datetime.fromisoformat(value.replace("Z","+00:00"))
    if timestamp.tzinfo is None:
        raise ValueError("Naive verification timestamp")


def validate(registry: dict) -> dict:
    if not isinstance(registry, dict) or registry.get("schema_version") != 1:
        raise ValueError("Unsupported source registry version")
    sources = registry.get("sources")
    if not isinstance(sources, list) or not sources:
        raise ValueError("Registry has no sources")
    seen = set()
    counts = {k:0 for k in sorted(STATES)}
    for source in sources:
        if not isinstance(source, dict):
            raise ValueError("Expected source record")
        sid = source.get("source_id")
        if not isinstance(sid, str) or not SOURCE_ID.fullmatch(sid) or sid in seen:
            raise ValueError("Duplicate/bad source identifier: "+str(sid))
        seen.add(sid)
        state = source.get("verification_status")
        if state not in STATES:
            raise ValueError("Unknown verification state: "+str(state))
        counts[state] += 1
        if source.get("collector_kind") not in COLLECTORS:
            raise ValueError("Unknown collector type: "+sid)
        allowed = source.get("allowed_hosts")
        if (not isinstance(allowed,list) or not allowed
                or any(not isinstance(h,str) or not re.fullmatch(r"[a-z0-9.-]+",h) for h in allowed)
                or len(allowed)!=len(set(allowed))):
            raise ValueError("Bad official host allowlist: "+sid)
        if not _url(source.get("discovery_url"), allowed):
            raise ValueError("Discovery URL outside official allowlist: "+sid)
        if not _url(source.get("detail_sample_url"), allowed):
            raise ValueError("Detail URL outside official allowlist: "+sid)
        if not source.get("vendor") or not source.get("product_scope"):
            raise ValueError("Missing vendor/product scope: "+sid)
        if not isinstance(source.get("pending_gates"), list) or not source["pending_gates"]:
            raise ValueError("Every source must declare remaining review gates: "+sid)
        if not isinstance(source.get("verified_capabilities"),list):
            raise ValueError("Capabilities must be an array: "+sid)
        if source.get("enabled_for_production") is not False:
            raise ValueError("No source in this prototype is approved for production: "+sid)
        if source.get("live_polling") != "not_enabled":
            raise ValueError("Unexpected scheduled polling promotion: "+sid)
        if source.get("durable_advisory_ingestion") != "not_implemented":
            raise ValueError("Evidence ledger code is not a connected durable collector: "+sid)
        if source.get("commercial_reuse_rights") != "not_reviewed":
            raise ValueError("Commercial reuse statement changed without rights review: "+sid)
        if source.get("coverage_assurance") != "not_established":
            raise ValueError("Coverage has not been established: "+sid)
        pilot = source.get("one_shot_evidence_pipeline")
        if pilot is not None:
            if state != "read_parse_verified" or not isinstance(pilot, dict):
                raise ValueError("Only verified sources can claim successful ingestion pilots: "+sid)
            if pilot.get("status") != "local_sqlite_probe_pass":
                raise ValueError("Invalid pilot status: "+sid)
            if pilot.get("review_state") != "parsed_unreviewed":
                raise ValueError("No human-reviewed status has been certified: "+sid)
            if pilot.get("persistence_state") != "one_run_local_sqlite_artifact_7_days_only":
                raise ValueError("No production-persistent vendor DB is certified: "+sid)
            if pilot.get("advisory_sample_count") != 1 or pilot.get("baseline_event_count") != 1 or pilot.get("idempotent_replay_count") != 1:
                raise ValueError("Pilot result count not backed by one-shot evidence: "+sid)
            if not re.fullmatch(r"https://github\.com/pinogame1945-dotcom/ECLIPSE/actions/runs/[0-9]+",str(pilot.get("run_url",""))):
                raise ValueError("Missing official Actions pilot evidence: "+sid)
            _date(pilot.get("last_run_utc"))
        cross = source.get("cross_run_evidence")
        if cross is not None:
            if state != "read_parse_verified" or not isinstance(cross,dict):
                raise ValueError("Cross-run proof must belong to verified official sources: "+sid)
            if cross.get("verification_level") != "short_lived_artifact_replay_only":
                raise ValueError("Cross-run evidence is not production persistence: "+sid)
            if cross.get("lifecycle") != "not_durable_7_day_actions_artifact":
                raise ValueError("Cross-run retention cannot be promoted without separate durable proof: "+sid)
            if cross.get("sample_advisories_retained") != 1 or cross.get("source_data_review") != "parsed_unreviewed":
                raise ValueError("Unexpected cross-run scope or approval claim: "+sid)
            for field in ("previous_successful_run_url","current_successful_run_url"):
                if not re.fullmatch(r"https://github\.com/pinogame1945-dotcom/ECLIPSE/actions/runs/[0-9]+",str(cross.get(field,""))):
                    raise ValueError("Missing cross-run actions evidence: "+sid)
            _date(cross.get("verified_at_utc"))
        evidence = source.get("evidence_run_url")
        when = source.get("last_verified_utc")
        if state == "read_parse_verified":
            if not source["verified_capabilities"] or not evidence:
                raise ValueError("Verified source lacks evidence: "+sid)
            _date(when)
            if not re.fullmatch(r"https://github\.com/pinogame1945-dotcom/ECLIPSE/actions/runs/[0-9]+",evidence):
                raise ValueError("Unexpected evidence provenance URL: "+sid)
        else:
            if source["verified_capabilities"] or when is not None:
                raise ValueError("Untested/failed source must not claim successful verified capabilities: "+sid)
    return {"total_sources":len(sources),"statuses":counts,
            "production_enabled":0, "source_ids":sorted(seen)}


def load_registry(path: Path) -> dict:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    validate(value)
    return value


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--registry",type=Path,default=Path("config/vendor_source_registry.json"))
    args=p.parse_args()
    summary=validate(load_registry(args.registry))
    print(json.dumps(summary,ensure_ascii=False,indent=2))


if __name__=="__main__":
    main()
