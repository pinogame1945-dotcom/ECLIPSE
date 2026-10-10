"""Durable CISA KEV catalog observation and provenance-aware event detection.

State is a plain JSON file intended for a separate PUBLIC Git branch. No
customer inventories, access tokens, or classified/private data are stored.
First run creates a baseline, NOT a historical flood of 'new' alerts.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
from datetime import date, datetime, timezone
from pathlib import Path

from eclipse_l0.core import CVE_ID, stable_json_hash

SOURCE = 'https://github.com/cisagov/kev-data'
VERSION = 1
MATERIAL_FIELDS = frozenset({
    'vendorProject', 'product', 'dateAdded', 'vulnerabilityName',
    'shortDescription', 'requiredAction', 'knownRansomwareCampaignUse',
    'notes', 'dueDate', 'cwes',
})


def _dump(obj: object) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(',', ':')) + '\n'


def _atomic_text(path: Path, data: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(mode='w', encoding='utf-8',
                                         dir=path.parent, delete=False)
    try:
        with handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(handle.name, path)
    finally:
        if os.path.exists(handle.name):
            os.unlink(handle.name)


def _released(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        stamp = datetime.fromisoformat(value.replace('Z', '+00:00'))
        return stamp.replace(tzinfo=timezone.utc) if stamp.tzinfo is None else stamp.astimezone(timezone.utc)
    except ValueError:
        return None


def _validated_feed(source: Path, min_records: int) -> tuple[dict, dict[str, dict], str]:
    raw = source.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    feed = json.loads(raw)
    if not isinstance(feed, dict) or not isinstance(feed.get('vulnerabilities'), list):
        raise ValueError('CISA KEV feed missing vulnerabilities array')
    rows = feed['vulnerabilities']
    if len(rows) < min_records:
        raise ValueError(f'Suspiciously small KEV catalog ({len(rows)} < {min_records})')
    if type(feed.get('count')) is int and feed['count'] != len(rows):
        raise ValueError('CISA KEV count mismatch')
    index: dict[str, dict] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError('Malformed KEV record (not object)')
        cve = row.get('cveID')
        if not isinstance(cve, str) or not CVE_ID.fullmatch(cve) or cve in index:
            raise ValueError('Duplicate or malformed KEV CVE ID: ' + str(cve))
        try:
            date.fromisoformat(row['dateAdded'])
        except (ValueError, KeyError, TypeError):
            raise ValueError(f'Invalid KEV dateAdded for {cve}') from None
        index[cve] = row
    return feed, index, digest


def observe(feed_path: Path, state_dir: Path, output_path: Path, *,
            min_records: int = 1000, observed_at: datetime | None = None,
            max_removed_fraction: float = 0.01) -> dict:
    """Reconcile latest official KEV into a Git-commit-friendly snapshot.

    Git commit of all files is the atomic boundary for remote persistence;
    run this only against a clean, dedicated state-branch checkout.
    """
    if min_records < 1 or not 0 <= max_removed_fraction < 1:
        raise ValueError('Invalid ingestion safety limits')
    observed_at = observed_at or datetime.now(timezone.utc)
    if observed_at.tzinfo is None:
        raise ValueError('observed_at must be timezone-aware')
    observed = observed_at.astimezone(timezone.utc).isoformat(timespec='seconds')
    feed, index, digest = _validated_feed(feed_path, min_records)
    state_file = state_dir / 'kev-current.json'
    previous: dict | None = None
    if state_file.is_file():
        previous = json.loads(state_file.read_text(encoding='utf-8'))
        if previous.get('schema_version') != VERSION or not isinstance(previous.get('records'), dict):
            raise ValueError('Incompatible/corrupt saved KEV state')
        old_date = _released(previous.get('date_released'))
        new_date = _released(feed.get('dateReleased'))
        if old_date and new_date and new_date < old_date:
            raise ValueError('Rejecting older KEV release (stale source or rollback)')
    old = previous['records'] if previous else {}
    removed = set(old) - set(index)
    if previous and len(removed) > max(1, int(len(old) * max_removed_fraction)):
        raise ValueError(f'Mass removal safety guard: {len(removed)} records missing')
    # Validate persisted identities before deciding changes, to avoid silent
    # recovery from corrupt state or duplicate event emission.
    for cve, row in old.items():
        if not CVE_ID.fullmatch(cve) or row.get('cveID') != cve:
            raise ValueError('Invalid persisted KEV record: ' + str(cve))
    events: list[dict] = []
    if previous:
        for cve in sorted(set(index) | removed):
            before = old.get(cve)
            after = index.get(cve)
            if before is None:
                kind = 'added'
            elif after is None:
                kind = 'removed'
            elif stable_json_hash(before) != stable_json_hash(after):
                kind = 'updated'
            else:
                continue
            changed_fields = sorted(k for k in (set(before or {}) | set(after or {}))
                                    if (before or {}).get(k) != (after or {}).get(k))
            event_id = hashlib.sha256(f'{digest}|{kind}|{cve}'.encode()).hexdigest()
            events.append({
                'event_id': event_id, 'kind': kind, 'cve_id': cve,
                'observed_utc': observed, 'date_added': (after or before).get('dateAdded'),
                'changed_fields': changed_fields,
                'material_change': kind != 'updated' or bool(MATERIAL_FIELDS.intersection(changed_fields)),
                'previous_record_sha256': stable_json_hash(before) if before is not None else None,
                'current_record_sha256': stable_json_hash(after) if after is not None else None,
                'record': after or before,
                'source': SOURCE, 'feed_sha256': digest,
            })
    # A reserialized catalog with only top-level metadata modified does not
    # generate vulnerability change events, but its digest is recorded.
    data_changed = previous is None or bool(events) or previous.get('source_sha256') != digest
    snapshot = {
        'schema_version': VERSION, 'source': SOURCE,
        'initialized_utc': previous['initialized_utc'] if previous else observed,
        'observed_utc': observed,
        'source_sha256': digest,
        'date_released': feed.get('dateReleased'),
        'catalog_version': feed.get('catalogVersion'),
        'count': len(index),
        'records': index,
    }
    if data_changed:
        _atomic_text(state_file, _dump(snapshot))
    if events:
        # Append by month of actual system observation (not KEV dateAdded).
        month = observed_at.astimezone(timezone.utc).strftime('%Y-%m')
        log_path = state_dir / 'events' / f'{month}.jsonl'
        prior_lines = log_path.read_text(encoding='utf-8') if log_path.exists() else ''
        _atomic_text(log_path, prior_lines + ''.join(_dump(ev) for ev in events))
    counts = {kind: sum(ev['kind'] == kind for ev in events)
              for kind in ('added', 'updated', 'removed')}
    result = {
        'baseline': previous is None,
        'state_changed': data_changed,
        'observed_utc': observed, 'source': SOURCE,
        'source_sha256': digest, 'source_date_released': feed.get('dateReleased'),
        'catalog_count': len(index),
        'event_count': len(events), 'material_event_count': sum(ev['material_change'] for ev in events),
        **{f'{key}_count': value for key, value in counts.items()},
        'events': events,
        'interpretation': ('First observation is baseline (no historical alert). '
                           'Events are first observed by ECLIPSE; KEV dateAdded is a separate date.'),
    }
    _atomic_text(output_path, _dump(result))
    return result


def main() -> None:
    p = argparse.ArgumentParser(description='Observe official KEV feed against a durable state branch')
    p.add_argument('--feed', required=True, type=Path)
    p.add_argument('--state-dir', required=True, type=Path)
    p.add_argument('--out', required=True, type=Path)
    args = p.parse_args()
    result = observe(args.feed, args.state_dir, args.out)
    print(json.dumps({k: v for k, v in result.items() if k != 'events'}, indent=2))


if __name__ == '__main__':
    main()
