"""Export source-backed CVE before/after pairs from the 65-day rolling store.

Reconstructs verifiable V5 pairs for weekly_cve_material.build and
weekly_update_queue.build. Never manufactures a 'before' from one snapshot.
The week is the OBSERVATION window, not the CVE publisher's revision date.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import date, datetime, timezone
import gzip
import io
import json
from pathlib import Path
import zipfile

from .cve_version_history import _load, _archive, _validate_record, sha
from .weekly_cve_material import _payload_hash, analyze_pair_jsonl
from .weekly_material import canonical

MAX_EXPORT_BYTES = 64 * 1024 * 1024


def _body(root, archive, cid, digest, manifest, cache):
    if archive not in manifest["archives"]:
        raise ValueError("Missing or expired CVE source shard required for pair")
    raw_pack = _archive(root, archive, manifest["archives"][archive], cache)
    with zipfile.ZipFile(io.BytesIO(raw_pack)) as z:
        filename = cid + ".json"
        if filename not in z.namelist():
            raise ValueError("Archived CVE original member missing")
        raw = z.read(filename)
    if sha(raw) != digest:
        raise ValueError("Historical CVE source hash differs from transition ledger")
    return _validate_record(raw,cid)


def build_pairs(state_root,start,end):
    start = date.fromisoformat(start) if isinstance(start,str) else start
    end = date.fromisoformat(end) if isinstance(end,str) else end
    if end<start or (end-start).days>31:
        raise ValueError("Invalid historical CVE observation window")
    root = Path(state_root)/"cve-version-history"
    manifest = _load(root)
    if not manifest["event_logs"]:
        raise ValueError("No recorded version transitions, cannot infer a diff")
    entries = {}
    logs_used = 0
    for fname, spec in sorted(manifest["event_logs"].items()):
        moment = datetime.fromisoformat(spec["observed_utc"].replace("Z","+00:00"))
        when = moment.astimezone(timezone.utc).date()
        if not start<=when<=end:
            continue
        blob = (root/"events"/fname).read_bytes()
        if sha(blob)!=spec["sha256"] or len(blob)!=spec["bytes"]:
            raise ValueError("Original CVE transition file tampered")
        logs_used+=1
        for line in gzip.decompress(blob).splitlines():
            e=json.loads(line)
            if not e.get("before_archive") or not e.get("after_archive"):
                continue
            if e.get("before_raw_sha256")==e.get("new_raw_sha256"):
                continue
            entries.setdefault(e["cve_id"],[]).append(e)
    cache={}
    payload=[]
    multipoll=0
    skipped_nonpublished=0
    for cid, events in sorted(entries.items()):
        # Pair the pre-week state against latest observed state. An intermediate
        # security alert might be reverted; flag all multi-event trajectories.
        events.sort(key=lambda e:(e["observed_utc"],e["source_fetch_utc"],e["new_raw_sha256"]))
        if len(events)>1:multipoll+=1
        earliest,latest=events[0],events[-1]
        before=_body(root,earliest["before_archive"],cid,
                     earliest["before_raw_sha256"],manifest,cache)
        after=_body(root,latest["after_archive"],cid,
                    latest["new_raw_sha256"],manifest,cache)
        if before["cveMetadata"].get("state")!="PUBLISHED" or after["cveMetadata"].get("state")!="PUBLISHED":
            skipped_nonpublished+=1
            continue
        pair={
          "cve_id":cid, "before":before,"after":after,
          "before_canonical_sha256":_payload_hash(before),
          "after_canonical_sha256":_payload_hash(after),
          "observed_utc":latest["observed_utc"],
          "intermediate_source_revisions_observed":len(events)>1,
          "transition_events_in_window":len(events),
          "source_body_hash_check_from_version_ledger":True}
        payload.append(pair)
    bytes_out = ("".join(canonical(row)+"\n" for row in payload)).encode("utf-8")
    if len(bytes_out)>MAX_EXPORT_BYTES:
        raise ValueError("CVE history export exceeds bounded pair review size")
    summary={
      "schema_version":1,
      "result":"CVE_SOURCE_HISTORY_PAIR_EXPORT_FOR_REVIEW_NOT_PUBLISHER_DATE",
      "start_observed_utc":start.isoformat(),
      "end_observed_utc":end.isoformat(),
      "transition_logs_used":logs_used,
      "source_cves_with_changes":len(entries),
      "published_v5_pairs_exported":len(payload),
      "nonpublished_state_transitions_separate_review":skipped_nonpublished,
      "cves_with_multiple_observed_transitions":multipoll,
      "source_record_authenticity_independently_verified":False,
      "CVE_metadata_only_update_does_not_mean_material_change":True,
      "source_git_history_retained_only_65_days":True,
      "publisher_revision_date_not_proven":True
    }
    if bytes_out:
        proved=analyze_pair_jsonl(bytes_out,start,end)
        if proved["pairs_compared"]!=len(payload):
            raise ValueError("Independent source-pair classification disagreement")
        summary["security_change_classes"]=proved["counts_by_class"]
    else:
        summary["security_change_classes"]={}
    return bytes_out,summary


def main():
    p=argparse.ArgumentParser(description="Export source-backed 65-day CVE version pairs")
    p.add_argument("--state-dir",required=True,type=Path)
    p.add_argument("--start",required=True)
    p.add_argument("--end",required=True)
    p.add_argument("--pairs-out",required=True,type=Path)
    p.add_argument("--summary-out",required=True,type=Path)
    a=p.parse_args()
    out,stats=build_pairs(a.state_dir,a.start,a.end)
    for target in (a.pairs_out,a.summary_out):
        if target.exists() or target.is_symlink():
            raise ValueError("Refuse overwrite of CVE source-history exports")
    a.pairs_out.parent.mkdir(parents=True,exist_ok=True)
    a.summary_out.parent.mkdir(parents=True,exist_ok=True)
    a.pairs_out.write_bytes(out)
    a.summary_out.write_text(canonical(stats)+"\n",encoding="utf-8")
    print(canonical(stats))


if __name__=="__main__":
    main()
