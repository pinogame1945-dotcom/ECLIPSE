"""CVE Program official rolling deltaLog observer (change *index*, not full-CVE DB).

The upstream deltaLog contains a rolling window. A commit of state and report
artifacts is required for durable semantics. Baseline produces no alerts.
Each change is an upstream CVE-list event, NOT proof of exploitation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

from .core import CVE_ID
from .kev_monitor import _atomic_text, _dump

SOURCE = 'https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json'
STATE_VERSION = 1


def _time(value: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError('CVE delta fetchTime missing')
    try:
        dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError as exc:
        raise ValueError('Malformed CVE delta fetchTime') from exc
    if dt.tzinfo is None:
        raise ValueError('Naive CVE delta fetchTime')
    return dt.astimezone(timezone.utc)


def _canonical_link(cve: str, link: str) -> str:
    if not isinstance(link, str):
        raise ValueError(f'Missing CVE source link: {cve}')
    url = urlsplit(link)
    if (url.scheme != 'https' or url.hostname != 'raw.githubusercontent.com'
            or url.username or url.password or url.port or url.query or url.fragment
            or not url.path.startswith('/CVEProject/cvelistV5/main/cves/')
            or not url.path.endswith('/'+cve+'.json')):
        raise ValueError(f'Untrusted CVE official source URL: {cve}')
    return link


def _changes(raw: bytes) -> list[dict]:
    if len(raw) > 40 * 1024 * 1024:
        raise ValueError('CVE rolling change index unexpectedly large')
    doc = json.loads(raw)
    if not isinstance(doc, list) or not doc:
        raise ValueError('CVE deltaLog is not a nonempty array')
    result = []
    last_time = None
    for entry in doc:
        if not isinstance(entry, dict):
            raise ValueError('Malformed CVE log entry')
        when = _time(entry.get('fetchTime'))
        # We sort after parsing; do not rely on upstream ordering.
        if last_time is None or when > last_time:
            last_time = when
        for field in ('new', 'updated'):
            items = entry.get(field, [])
            if not isinstance(items, list):
                raise ValueError('Unexpected CVE delta group shape')
            for item in items:
                if not isinstance(item, dict):
                    raise ValueError('Invalid CVE delta item')
                cve = item.get('cveId')
                if not isinstance(cve, str) or not CVE_ID.fullmatch(cve):
                    raise ValueError('Invalid CVE ID in change index')
                result.append({
                    'cve_id': cve,
                    'kind': 'cve_record_added' if field == 'new' else 'cve_record_updated',
                    'source_fetch_utc': when.isoformat(timespec='milliseconds'),
                    'source_updated_utc': item.get('dateUpdated'),
                    'record_url': _canonical_link(cve, item.get('githubLink')),
                })
    return sorted(result, key=lambda x: (x['source_fetch_utc'], x['cve_id'], x['kind']))


def observe(log: Path, state_dir: Path, output: Path, *, max_events: int = 5000,
            observed_at: datetime | None = None) -> dict:
    if max_events < 1:
        raise ValueError('Invalid event limit')
    now = observed_at or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError('observed_at requires timezone')
    now = now.astimezone(timezone.utc)
    content = log.read_bytes()
    digest = hashlib.sha256(content).hexdigest()
    rows = _changes(content)
    # If a feed contains no changed CVEs, do not report it as a real CVE alarm.
    if not rows:
        raise ValueError('CVE log contains no CVE rows; check upstream')
    earliest = _time(rows[0]['source_fetch_utc'])
    latest = _time(rows[-1]['source_fetch_utc'])
    if latest > now + timedelta(minutes=15):
        raise ValueError('CVE feed timestamp is in the future')
    state_file = state_dir / 'cve-delta-checkpoint.json'
    previous = json.loads(state_file.read_text('utf-8')) if state_file.exists() else None
    if previous is not None and (previous.get('schema_version') != STATE_VERSION
                                 or 'watermark_utc' not in previous):
        raise ValueError('CVE checkpoint invalid/incompatible')
    if previous is None:
        # First run is a baseline at the latest known change; historical deltaLog
        # entries belong to the prior window and must not trigger alerts.
        new_state = {
            'schema_version': STATE_VERSION, 'source': SOURCE,
            'watermark_utc': latest.isoformat(timespec='milliseconds'),
            'baseline_at_utc': now.isoformat(timespec='seconds'),
            'source_sha256': digest,
            'note': 'Rolling CVE changes after initial observation only. Not a complete CVE archive.',
        }
        _atomic_text(state_file, _dump(new_state))
        batch, baseline, more = [], True, False
    else:
        watermark = _time(previous['watermark_utc'])
        if earliest > watermark + timedelta(days=1):
            raise ValueError('CVE delta retention gap; full recovery/re-baseline is required')
        if latest < watermark:
            raise ValueError('CVE change index appears older than checkpoint')
        new_rows = [row for row in rows if _time(row['source_fetch_utc']) > watermark]
        batch = []
        # Only advance the watermark through FULL fetch-time groups. This ensures
        # no records at the same timestamp are lost when limiting each run.
        grouped = {}
        for row in new_rows:
            grouped.setdefault(row['source_fetch_utc'], []).append(row)
        for stamp in sorted(grouped):
            group = grouped[stamp]
            if len(group) > max_events:
                raise ValueError('One CVE fetch-time group exceeds bounded limit')
            if len(batch) + len(group) > max_events:
                break
            batch.extend(group)
        more = len(batch) < len(new_rows)
        baseline = False
        if batch:
            previous['watermark_utc'] = batch[-1]['source_fetch_utc']
            previous['source_sha256'] = digest
            _atomic_text(state_file, _dump(previous))
            # Each report is the bounded set *observed* on this poll, not a CVE publication list.
            month = now.strftime('%Y-%m')
            event_log = state_dir / 'cve-observations' / (month + '.jsonl')
            event_log.parent.mkdir(parents=True, exist_ok=True)
            with event_log.open('a', encoding='utf-8') as handle:
                for row in batch:
                    event = dict(row, observed_utc=now.isoformat(timespec='seconds'),
                                 delta_log_sha256=digest)
                    handle.write(_dump(event))
            # The Git state branch is a rolling alert window, not a permanent
            # vulnerability data lake. Bound recent event files to ~2 months.
            keep_from = (now - timedelta(days=65)).strftime('%Y-%m')
            for oldfile in event_log.parent.glob('????-??.jsonl'):
                if oldfile.stem < keep_from:
                    oldfile.unlink()
    payload = {
        'schema_version': 1, 'baseline': baseline,
        'observed_utc': now.isoformat(timespec='seconds'),
        'source': SOURCE, 'delta_log_sha256': digest,
        'event_count': len(batch), 'more_backlog': more,
        'watermark_utc': (latest.isoformat(timespec='milliseconds') if baseline
                          else (batch[-1]['source_fetch_utc'] if batch else previous['watermark_utc'])),
        'events': batch,
        'warning': 'CVE list change ≠ confirmed exploitation; record bodies must be fetched separately for vendor / impact analysis.',
    }
    _atomic_text(output, _dump(payload))
    return payload


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--log', required=True, type=Path)
    p.add_argument('--state-dir', required=True, type=Path)
    p.add_argument('--out', required=True, type=Path)
    p.add_argument('--max-events', type=int, default=5000)
    args = p.parse_args()
    result = observe(args.log, args.state_dir, args.out, max_events=args.max_events)
    print(json.dumps({k: v for k, v in result.items() if k != 'events'}, indent=2))


if __name__ == '__main__':
    main()
