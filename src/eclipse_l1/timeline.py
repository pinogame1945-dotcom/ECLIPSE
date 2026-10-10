"""Merge independently observed public KEV, CVE and publisher-advisory events.

Only an explicit CVE ID connects two security events. A shared product/vendor
name is not evidence of one incident. No automated customer exposure verdict.
CVE changes are index events, not CVE publication or exploitation events.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

from eclipse_l0.core import CVE_ID
from eclipse_l0.kev_monitor import _atomic_text, _dump

SCHEMA = 1
KEV_SOURCE = 'https://github.com/cisagov/kev-data'
CVE_SOURCE = 'https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json'


def _utc(value: str) -> datetime:
    try:
        dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except (AttributeError, ValueError) as exc:
        raise ValueError('Invalid observation time') from exc
    if dt.tzinfo is None:
        raise ValueError('Observation has no time zone')
    return dt.astimezone(timezone.utc)


def official_record_url(cve: str, url: str) -> str:
    """CVE records must come from the CVEProject official source, never URL injection."""
    if not CVE_ID.fullmatch(cve) or not isinstance(url, str):
        raise ValueError('Invalid CVE identifier or URL')
    p = urlsplit(url)
    if (p.scheme != 'https' or p.hostname != 'raw.githubusercontent.com' or
        p.username or p.password or p.port or p.query or p.fragment or
        not p.path.startswith('/CVEProject/cvelistV5/main/cves/') or
        not p.path.endswith('/'+cve+'.json')):
        raise ValueError('Non-official record URL rejected')
    return url


def _read_jsonl(folder: Path, start: datetime, end: datetime) -> list[dict]:
    rows = []
    # Two adjacent month files can both matter near a month boundary.
    if not folder.exists():
        return rows
    for file in sorted(folder.glob('????-??.jsonl')):
        for line in file.read_text(encoding='utf-8').splitlines():
            if not line.strip():
                continue
            item = json.loads(line)
            stamp = _utc(item['observed_utc'])
            if start <= stamp <= end:
                rows.append(item)
    return rows


def _event_id(event: dict) -> str:
    return hashlib.sha256(_dump(event).encode()).hexdigest()


def compile_timeline(state_dir: Path, output: Path, *, hours: int = 24,
                     as_of: datetime | None = None, advisory_files: list[Path] | None = None,
                     max_events: int = 10000) -> dict:
    """Create a reportable window from durable public observation logs.

    Missing coverage is explicit; a quiet feed cannot be treated as zero threats.
    The initial KEV baseline is REQUIRED. A missing CVE observer is a warning.
    """
    if not 1 <= hours <= 31 * 24 or max_events < 1:
        raise ValueError('Invalid reporting window/row bound')
    now = as_of or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError('as_of must be timezone-aware')
    now = now.astimezone(timezone.utc)
    start = now - timedelta(hours=hours)
    state_path = state_dir / 'kev-current.json'
    if not state_path.is_file():
        raise ValueError('KEV baseline unavailable: refusing an apparently empty briefing')
    kev_state = json.loads(state_path.read_text(encoding='utf-8'))
    if kev_state.get('schema_version') != 1 or not isinstance(kev_state.get('records'), dict):
        raise ValueError('Invalid persisted KEV state')
    coverage = {
        'kev': {'observed_state': True, 'state_last_changed_utc': kev_state.get('observed_utc')},
        'cve_delta': {'observed_state': (state_dir/'cve-delta-checkpoint.json').exists()},
        'epss': {'observed_state': (state_dir/'epss-selected.json').exists()},
        'manufacturer': {'observed_state': bool(advisory_files), 'notice': 'Only explicitly supplied authorized advisory feeds'},
    }
    warnings = []
    for source in ('cve_delta','epss','manufacturer'):
        if not coverage[source]['observed_state']:
            warnings.append(f'{source} source missing / NOT monitored by this report')
    # Saved KEV state timestamp is the last content update, NOT a poll heartbeat.
    # Workflow health must be observed independently; do not invent recency.
    events = []
    for row in _read_jsonl(state_dir/'events', start, now):
        if row.get('source') != KEV_SOURCE or not CVE_ID.fullmatch(str(row.get('cve_id',''))):
            raise ValueError('Invalid persisted KEV event')
        if row.get('record', {}).get('cveID') != row['cve_id']:
            raise ValueError('KEV event ID mismatch')
        if not row.get('material_change'):
            continue
        kind = row.get('kind')
        if kind not in {'added','updated','removed'}:
            raise ValueError('Invalid KEV change type')
        events.append({
            'event_id': row.get('event_id') or _event_id(row), 'type': 'kev_'+kind,
            'source_kind': 'kev', 'cve_id': row['cve_id'],
            'observed_utc': row['observed_utc'], 'source_time': row.get('date_added'),
            'source_time_meaning': 'CISA KEV registration date, NOT exploit start',
            'source_url': 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
            'source_sha256': row.get('feed_sha256'), 'record': row['record'],
            'changed_fields': row.get('changed_fields', []),
        })
    for row in _read_jsonl(state_dir/'cve-observations', start, now):
        cve = row.get('cve_id')
        kind = row.get('kind')
        if kind not in {'cve_record_added','cve_record_updated'}:
            raise ValueError('Unexpected CVE change type')
        official_record_url(cve, row.get('record_url'))
        events.append({
            'event_id': _event_id(row), 'type': kind, 'source_kind': 'cve',
            'cve_id': cve, 'observed_utc': row['observed_utc'],
            'source_time': row.get('source_fetch_utc'),
            'source_time_meaning': 'CVE change-index fetch time, NOT exploit start',
            'source_url': row['record_url'], 'source_sha256': row.get('delta_log_sha256'),
            'record': {}, 'changed_fields': [],
        })
    for file in advisory_files or []:
        feed = json.loads(file.read_text(encoding='utf-8'))
        if feed.get('baseline'):
            # Prevent the initial RSS snapshot from becoming a barrage of alerts.
            continue
        for row in feed.get('events', []):
            when = _utc(row['observed_utc'])
            if not start <= when <= now:
                continue
            ids = row.get('cve_ids') or []
            if not isinstance(ids, list) or any(not CVE_ID.fullmatch(str(i)) for i in ids):
                raise ValueError('Invalid advisory CVE identifiers')
            if not isinstance(row.get('link'), str) or not row['link'].startswith('https://'):
                raise ValueError('Advisory must cite an HTTPS source link')
            # Upstream source parser already enforces official host allowlist.
            # This module never downloads or follows arbitrary links.
            for cve in ids or [None]:
                events.append({
                    'event_id': _event_id({**row, 'cve_id': cve}),
                    'type': 'manufacturer_advisory_'+str(row.get('kind','updated')),
                    'source_kind': 'manufacturer', 'cve_id': cve,
                    'observed_utc': row['observed_utc'],
                    'source_time': row.get('source_date'),
                    'source_time_meaning': 'Publisher-supplied RSS publication/update time',
                    'source_url': row['link'], 'source_sha256': feed.get('source_sha256'),
                    'record': {k:row.get(k) for k in ('vendor','title','description_excerpt','link')},
                    'changed_fields': [],
                })
    # Dedupe only identical observation IDs; multiple distinct changes remain visible.
    unique = {e['event_id']:e for e in events}
    if len(unique) > max_events:
        raise ValueError('Too many events to produce a safe report (reduce window)')
    events = sorted(unique.values(), key=lambda e:(e['observed_utc'],e['event_id']))
    result = {'schema_version':SCHEMA,'window':{'start_utc':start.isoformat(timespec='seconds'),
              'end_utc':now.isoformat(timespec='seconds')},'event_count':len(events),
              'events':events,'coverage':coverage,'warnings':warnings,
              'interpretation': 'Source observations only. Zero events does not mean zero cyber threats.'}
    _atomic_text(output,_dump(result))
    return result


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--state-dir',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True)
    p.add_argument('--hours',type=int,default=24)
    p.add_argument('--advisory-events',type=Path,action='append',default=[])
    args=p.parse_args()
    data=compile_timeline(args.state_dir,args.out,hours=args.hours,advisory_files=args.advisory_events)
    print(json.dumps({'events':data['event_count'],'warnings':data['warnings']},ensure_ascii=False))

if __name__=='__main__':main()
