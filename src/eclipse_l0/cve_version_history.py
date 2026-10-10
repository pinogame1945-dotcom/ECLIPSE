"""CVE V5 original-source rolling revision store for the official CVE deltaLog.

Runs AFTER cve_delta.observe but BEFORE the single eclipse-state git commit.
The same Git transaction advances BOTH the deltaLog watermark and source-body
history. A fetch failure aborts the commit: no acknowledged but lost changes.
On first sighting a CVE is a baseline, never a claimed security update.
Snapshots are byte-exact, compressed, hash-checked, and retained for 65 days
subject to an explicit public Git state budget (NOT long-term archival).
"""
from __future__ import annotations

import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import tempfile
import urllib.request
import zipfile

from .cve_delta import _canonical_link, _time
from .weekly_material import canonical
from .weekly_cve_material import compare_pair, _payload_hash

SCHEMA = 1
HORIZON_DAYS = 65
MAX_EVENTS = 5000
MAX_CVES = 5000
MAX_LATEST = 50000
MAX_ARCHIVES = 1500
MAX_STORE_BYTES = 350 * 1024 * 1024
MAX_DOC_BYTES = 2 * 1024 * 1024
MAX_PACK_BYTES = 70 * 1024 * 1024
MAX_INDEX_BYTES = 30 * 1024 * 1024
MAX_REPORT_BYTES = 5 * 1024 * 1024
FILENAME = re.compile(r"^\d{8}T\d{6}Z-[0-9a-f]{12}\.cvepack$")
CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")
HEX = re.compile(r"^[0-9a-f]{64}$")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _canonical_bytes(value):
    return (canonical(value) + "\n").encode("utf-8")


def _now(value):
    instant = value or datetime.now(timezone.utc)
    if instant.tzinfo is None:
        raise ValueError("CVE history observation clock must be timezone-aware")
    return instant.astimezone(timezone.utc)


def _source_get(url):
    req = urllib.request.Request(url, headers={
        "User-Agent": "ECLIPSE-CVE-V5-history/1.0",
        "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=24) as response:
        final = response.geturl()
        if final != url:
            raise ValueError("Official CVE raw URL redirected: origin not pinned")
        body = response.read(MAX_DOC_BYTES + 1)
    return body


def _validate_record(raw, cid):
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= MAX_DOC_BYTES:
        raise ValueError("CVE source record missing or over byte budget")
    try:
        doc = json.loads(raw)
    except (ValueError, UnicodeError) as exc:
        raise ValueError("Invalid CVE original JSON") from exc
    if not isinstance(doc, dict) or not isinstance(doc.get("cveMetadata"), dict):
        raise ValueError("CVE record is not V5")
    if doc["cveMetadata"].get("cveId") != cid:
        raise ValueError("Official CVE original body ID mismatch")
    return doc


def _validated_delta(delta):
    if not isinstance(delta, dict) or delta.get("event_count") != len(delta.get("events", [])):
        raise ValueError("CVE delta event count does not match source")
    if type(delta["event_count"]) is not int or not 0 <= delta["event_count"] <= MAX_EVENTS:
        raise ValueError("Unbounded CVE delta")
    if not isinstance(delta.get("watermark_utc"), str):
        raise ValueError("CVE delta watermark absent")
    watermark = _time(delta["watermark_utc"])
    seen = {}
    max_stamp = None
    for event in delta["events"]:
        if not isinstance(event, dict):
            raise ValueError("Invalid delta record event")
        cid = event.get("cve_id")
        if not isinstance(cid, str) or not CVE.fullmatch(cid):
            raise ValueError("Invalid delta CVE identity")
        if event.get("kind") not in ("cve_record_added", "cve_record_updated"):
            raise ValueError("Invalid CVE delta event kind")
        url = _canonical_link(cid, event.get("record_url"))
        stamp = _time(event.get("source_fetch_utc"))
        if stamp > watermark:
            raise ValueError("CVE source event after watermark")
        if cid in seen and seen[cid]["record_url"] != url:
            raise ValueError("Conflicting official record URLs for one CVE")
        if cid not in seen:
            seen[cid] = {"cve_id": cid, "record_url": url, "count": 0,
                         "newest_fetch_utc": stamp.isoformat(timespec="milliseconds")}
        seen[cid]["count"] += 1
        if stamp > _time(seen[cid]["newest_fetch_utc"]):
            seen[cid]["newest_fetch_utc"] = stamp.isoformat(timespec="milliseconds")
        max_stamp = max(max_stamp, stamp) if max_stamp else stamp
    if len(seen) > MAX_CVES:
        raise ValueError("Too many distinct CVEs for bounded source read")
    if delta.get("baseline") is True and seen:
        raise ValueError("Initial CVE delta baseline must not emit security events")
    if delta.get("baseline") not in (True, False):
        raise ValueError("Missing CVE delta baseline flag")
    return seen, watermark


def _initial():
    return {"schema_version": SCHEMA, "kind": "CVE_V5_ROLLING_ORIGINAL_RECORD_HISTORY",
            "retention_days": HORIZON_DAYS, "latest": {}, "archives": {},
            "last_watermark_utc": None, "last_observed_utc": None,
            "latest_store_not_complete_all_CVEs": True,
            "publisher_revision_date_not_verified": True,
            "long_term_archival_not_guaranteed": True}


def _load(root):
    path = root / "manifest.json"
    if not path.is_file():
        if path.is_symlink():
            raise ValueError("Unsafe history manifest")
        return _initial()
    if path.is_symlink() or path.stat().st_size > MAX_INDEX_BYTES:
        raise ValueError("Unsafe/oversize history manifest")
    manifest = json.loads(path.read_bytes())
    if (not isinstance(manifest, dict) or manifest.get("schema_version") != SCHEMA
            or manifest.get("kind") != "CVE_V5_ROLLING_ORIGINAL_RECORD_HISTORY"
            or manifest.get("retention_days") != HORIZON_DAYS
            or not isinstance(manifest.get("latest"), dict)
            or not isinstance(manifest.get("archives"), dict)):
        raise ValueError("Unrecognized CVE source history; refusing reset")
    if len(manifest["latest"]) > MAX_LATEST or len(manifest["archives"]) > MAX_ARCHIVES:
        raise ValueError("History ledger over cap")
    return manifest


def _archive(root, archive, meta, cache):
    if archive not in cache:
        if not FILENAME.fullmatch(archive):
            raise ValueError("Unsafe saved archive name")
        path = root / "archives" / archive
        if not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_PACK_BYTES:
            raise ValueError("Missing/oversize prior immutable archive: " + archive)
        data = path.read_bytes()
        if sha(data) != meta.get("sha256") or len(data) != meta.get("bytes"):
            raise ValueError("Archived source content hash/length mismatch: " + archive)
        cache[archive] = data
    return cache[archive]


def audit(root):
    root = Path(root)
    m = _load(root)
    cache = {}
    tracked = set(m["archives"])
    folder = root / "archives"
    files = set(p.name for p in folder.iterdir()) if folder.exists() else set()
    if files != tracked:
        raise ValueError("Untracked or missing raw-source ZIP in history")
    for name, meta in m["archives"].items():
        if not isinstance(meta, dict) or not HEX.fullmatch(meta.get("sha256", "")):
            raise ValueError("Malformed archive index")
        _archive(root, name, meta, cache)
    counts = Counter()
    for cid, row in m["latest"].items():
        if not CVE.fullmatch(cid) or not isinstance(row, dict):
            raise ValueError("Corrupt latest history row")
        arc = row.get("archive")
        if arc not in m["archives"]:
            raise ValueError("Latest CVE points to pruned archive")
        if not HEX.fullmatch(row.get("raw_sha256", "")):
            raise ValueError("Bad latest raw SHA")
        with zipfile.ZipFile(io.BytesIO(cache[arc])) as z:
            member = cid + ".json"
            if member not in z.namelist():
                raise ValueError("Latest CVE member missing")
            data = z.read(member)
        if sha(data) != row["raw_sha256"]:
            raise ValueError("Latest raw CVE content mismatch")
        _validate_record(data, cid)
        counts["latest_v5_records"] += 1
    return {"integrity": "VERIFIED_ROLLING_ORIGINAL_RECORD_BYTES",
            "latest": counts["latest_v5_records"], "shards": len(tracked),
            "archive_bytes": sum(x["bytes"] for x in m["archives"].values()),
            "last_watermark_utc": m.get("last_watermark_utc"),
            "retention_days": HORIZON_DAYS,
            "complete_cve_history": False}


def _prior(root, row, archives, cache, cid):
    archive = row["archive"]
    data = _archive(root, archive, archives[archive], cache)
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        names = z.namelist()
        if cid + ".json" not in names:
            raise ValueError("Missing prior CVE archive member")
        raw = z.read(cid + ".json")
    if sha(raw) != row["raw_sha256"]:
        raise ValueError("Previous stored CVE source checksum mismatch")
    return _validate_record(raw, cid)


def _fetched(seen, fetcher, max_workers):
    if not 1 <= max_workers <= 32:
        raise ValueError("Unexpected request worker count")
    replies = {}
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        submitted = {pool.submit(fetcher, item["record_url"]): cid
                     for cid, item in sorted(seen.items())}
        for future in as_completed(submitted):
            cid = submitted[future]
            raw = future.result()
            doc = _validate_record(raw, cid)
            replies[cid] = (raw, doc)
    if len(replies) != len(seen):
        raise ValueError("Incomplete CVE original-source batch")
    return replies


def collect(delta, state_dir, out, *, observed_at=None, fetcher=None,
            max_workers=16):
    """Transactional at git-push boundary. No loss-tolerant fallback/skip."""
    state_dir = Path(state_dir)
    if state_dir.is_symlink():
        raise ValueError("History path is symlinked")
    observed = _now(observed_at)
    seen, watermark = _validated_delta(delta)
    root = state_dir / "cve-version-history"
    old = _load(root)
    if old["last_watermark_utc"] is not None:
        past = _time(old["last_watermark_utc"])
        if watermark < past:
            raise ValueError("History event watermark regressed")
        if seen and any(_time(x["newest_fetch_utc"]) <= past for x in seen.values()):
            raise ValueError("Replayed or conflicting CVE history event")
    else:
        if delta.get("baseline") is not True:
            # Existing cve-delta cursor without history is NOT proof that
            # previous versions exist. First observed records are baselines.
            pass
    cache = {}
    for archive, meta in old["archives"].items():
        _archive(root, archive, meta, cache)
    for cid, row in old["latest"].items():
        if not isinstance(row, dict) or row.get("archive") not in old["archives"]:
            raise ValueError("Previous latest row has no verified archive")
    fetcher = fetcher or _source_get
    replies = _fetched(seen, fetcher, max_workers) if seen else {}
    latest = dict(old["latest"])
    archives = dict(old["archives"])
    cutoff = observed - timedelta(days=HORIZON_DAYS)
    # Inactive CVEs get an explicit coverage gap on reappearance, never a
    # fabricated comparison to a silently discarded old version.
    pruned_ids = []
    for cid, item in list(latest.items()):
        if _time(item["last_seen_utc"]) < cutoff:
            pruned_ids.append(cid)
            del latest[cid]
    records = {}
    events = []
    pairs = []
    for cid in sorted(seen):
        raw, doc = replies[cid]
        previous = latest.get(cid)
        raw_digest = sha(raw)
        source_at = seen[cid]["newest_fetch_utc"]
        descriptor = {"cve_id": cid,
                      "delta_event_count_collapsed": seen[cid]["count"],
                      "intermediate_revisions_recoverable": seen[cid]["count"] == 1,
                      "source_fetch_utc": source_at,
                      "observed_utc": observed.isoformat(timespec="seconds"),
                      "new_raw_sha256": raw_digest,
                      "source_url": seen[cid]["record_url"],
                      "publisher_release_date_confirmed": False}
        if previous is None:
            descriptor["change_class"] = "FIRST_OBSERVED_BASELINE_NO_BEFORE"
        elif previous["raw_sha256"] == raw_digest:
            descriptor["change_class"] = "UNCHANGED_RAW_SOURCE_ON_DELTA_EVENT"
        else:
            prev_doc = _prior(root, previous, archives, cache, cid)
            if prev_doc["cveMetadata"].get("state") != "PUBLISHED" or doc["cveMetadata"].get("state") != "PUBLISHED":
                descriptor["change_class"] = "NON_PUBLISHED_STATE_TRANSITION_REVIEW"
            else:
                pair = {
                    "cve_id": cid, "before": prev_doc, "after": doc,
                    "before_canonical_sha256": _payload_hash(prev_doc),
                    "after_canonical_sha256": _payload_hash(doc),
                    "observed_utc": observed.isoformat(timespec="seconds")}
                diff = compare_pair(pair)
                descriptor["change_class"] = diff["result"]
                descriptor["changed_security_categories"] = diff["changed_cna_security_categories"]
                descriptor["potential_material_review"] = diff["candidate_for_material_security_review"]
                pairs.append(pair)
        # Every observed snapshot is stored on first sight or real raw change.
        if previous is None or previous["raw_sha256"] != raw_digest:
            records[cid] = raw
            latest[cid] = {"archive": None, "raw_sha256": raw_digest,
                           "last_seen_utc": observed.isoformat(timespec="seconds"),
                           "last_delta_fetch_utc": source_at, "source_url": seen[cid]["record_url"]}
        else:
            latest[cid] = dict(previous, last_seen_utc=observed.isoformat(timespec="seconds"),
                               last_delta_fetch_utc=source_at)
        events.append(descriptor)
    # Remove old unreferenced archives only after the retention window.
    referenced = {row["archive"] for row in latest.values() if row["archive"]}
    for filename, meta in list(archives.items()):
        if filename not in referenced and _time(meta["observed_utc"]) < cutoff:
            del archives[filename]
    pack = None
    pack_name = None
    if records:
        fingerprint = sha(_canonical_bytes({cid:sha(raw) for cid,raw in sorted(records.items())}))
        pack_name = observed.strftime("%Y%m%dT%H%M%SZ") + "-" + fingerprint[:12] + ".cvepack"
        if pack_name in archives:
            raise ValueError("Archive name collision: refusing overwrite")
        buf = io.BytesIO()
        with zipfile.ZipFile(buf,"w",compression=zipfile.ZIP_DEFLATED,compresslevel=6) as z:
            for cid, body in sorted(records.items()):
                member=zipfile.ZipInfo(cid+".json",date_time=(1980,1,1,0,0,0))
                member.compress_type=zipfile.ZIP_DEFLATED
                z.writestr(member,body,compress_type=zipfile.ZIP_DEFLATED,compresslevel=6)
        pack = buf.getvalue()
        if len(pack)>MAX_PACK_BYTES:
            raise ValueError("Source pack over explicit Git storage limit")
        archives[pack_name] = {"sha256":sha(pack),"bytes":len(pack),
                               "observed_utc":observed.isoformat(timespec="seconds"),
                               "records":len(records)}
        for cid in records:
            latest[cid]["archive"] = pack_name
    if len(latest)>MAX_LATEST or len(archives)>MAX_ARCHIVES or sum(a["bytes"] for a in archives.values())>MAX_STORE_BYTES:
        raise ValueError("Rolling Git history budget exhausted; private Kaggle archive required")
    next_state = dict(old, latest=latest, archives=archives,
                      last_watermark_utc=watermark.isoformat(timespec="milliseconds"),
                      last_observed_utc=observed.isoformat(timespec="seconds"),
                      last_batch_event_sha256=sha(_canonical_bytes(delta)))
    # The presence of a cve-delta event does NOT imply body update.
    summary = {"schema_version":1,"result":"ROLLING_CVE_V5_SOURCE_HISTORY_STAGED_NOT_COMMITTED",
               "observed_utc":observed.isoformat(timespec="seconds"),
               "input_delta_event_count":len(delta["events"]),
               "distinct_fetched_cves":len(seen),"snapshots_archived":len(records),
               "prior_versions_compared":len(pairs),
               "collapsed_intermediate_events":sum(x["count"]-1 for x in seen.values()),
               "pruned_old_cve_latest_entries":len(pruned_ids),
               "archive_retention_days":HORIZON_DAYS,
               "state_rolling_bytes":sum(a["bytes"] for a in archives.values()),
               "baseline":delta["baseline"],"more_backlog":delta.get("more_backlog",False),
               "change_classes":dict(sorted(Counter(e["change_class"] for e in events).items())),
               "first_sightings_are_not_new_security_alerts":True,
               "source_is_mutable_main_branch_not_commit_pinned":True,
               "not_complete_all_CVE_changes":True,
               "long_term_durability_not_certified":True}
    report = {"summary":summary,"events":events,"raw_pair_count":len(pairs)}
    report_bytes = _canonical_bytes(report)
    if len(report_bytes)>MAX_REPORT_BYTES:
        raise ValueError("History execution report oversized")
    # All IO below occurs only AFTER full source fetch/validation and budget
    # checks. A failing action never runs the subsequent git commit/push.
    root.mkdir(parents=True,exist_ok=True)
    (root/"archives").mkdir(exist_ok=True)
    for fname in set(old["archives"])-set(archives):
        (root/"archives"/fname).unlink()
    if pack is not None:
        with (root/"archives"/pack_name).open("xb") as w:w.write(pack)
    temp = root/"manifest.next.json"
    if temp.exists():
        raise ValueError("Orphan partial history state: refusing blind reset")
    temp.write_bytes(_canonical_bytes(next_state))
    os.replace(temp,root/"manifest.json")
    out = Path(out)
    out.parent.mkdir(parents=True,exist_ok=True)
    if out.exists() or out.is_symlink():
        raise ValueError("Refusing overwrite of CVE history execution report")
    out.write_bytes(report_bytes)
    return summary


def main():
    p=argparse.ArgumentParser(description="Capture full original CVE V5 bodies after delta observer, before atomic commit")
    sub=p.add_subparsers(dest="cmd",required=True)
    cap=sub.add_parser("capture")
    cap.add_argument("--delta-report",type=Path,required=True)
    cap.add_argument("--state-dir",type=Path,required=True)
    cap.add_argument("--out",type=Path,required=True)
    cap.add_argument("--workers",type=int,default=16)
    check=sub.add_parser("audit")
    check.add_argument("--state-dir",type=Path,required=True)
    args=p.parse_args()
    result=(collect(json.loads(args.delta_report.read_bytes()),args.state_dir,args.out,max_workers=args.workers)
            if args.cmd=="capture" else audit(args.state_dir/"cve-version-history"))
    print(json.dumps(result,ensure_ascii=False,sort_keys=True,indent=2))


if __name__=="__main__":
    main()
