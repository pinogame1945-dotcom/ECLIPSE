"""Source-configurable official manufacturer RSS/Atom feed adapter.

NO manufacturer feed is auto-subscribed or redistributed by default. Verify
terms separately for each allowed host. A feed item is a *pointer* to an
advisory, not proof of an exploitable vulnerability or affected version.
"""
from __future__ import annotations

import argparse
import hashlib
import html
import json
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from .kev_monitor import _atomic_text, _dump

ATOM = '{http://www.w3.org/2005/Atom}'


def _plain(value: str, limit: int = 360) -> str:
    return re.sub(r'\s+', ' ', html.unescape(re.sub('<[^>]+>', ' ', value or ''))).strip()[:limit]


def _allowed_url(url: str, hosts: list[str]) -> bool:
    try:
        parsed = urlsplit(url)
        host = (parsed.hostname or '').lower()
        return (parsed.scheme == 'https' and not parsed.username and not parsed.password
                and parsed.port in (None, 443) and host in hosts)
    except ValueError:
        return False


def parse_feed(raw: bytes, *, source_id: str, vendor: str, allowed_hosts: list[str]) -> list[dict]:
    if not re.fullmatch(r'[a-z0-9][a-z0-9_-]{1,39}', source_id):
        raise ValueError('Invalid feed source ID')
    if not isinstance(vendor, str) or not vendor.strip() or not allowed_hosts:
        raise ValueError('Vendor name / allowlisted official hosts required')
    if len(raw) > 4 * 1024 * 1024 or b'<!DOCTYPE' in raw.upper() or b'<!ENTITY' in raw.upper():
        raise ValueError('Unsafe or oversized XML source')
    root = ET.fromstring(raw)
    rows = []
    if root.tag == 'rss':
        for item in root.findall('./channel/item'):
            link = item.findtext('link', '').strip()
            row = {'link': link, 'title': _plain(item.findtext('title', ''), 160),
                   'description_excerpt': _plain(item.findtext('description', '')),
                   'source_date': item.findtext('pubDate', '')}
            rows.append(row)
    elif root.tag == ATOM + 'feed':
        for item in root.findall(ATOM + 'entry'):
            link = next((e.attrib.get('href', '') for e in item.findall(ATOM+'link')
                         if e.attrib.get('rel', 'alternate') == 'alternate'), '')
            row = {'link': link, 'title': _plain(item.findtext(ATOM + 'title', ''), 160),
                   'description_excerpt': _plain(item.findtext(ATOM+'summary', '') or item.findtext(ATOM+'content', '')),
                   'source_date': item.findtext(ATOM+'updated', '') or item.findtext(ATOM+'published', '')}
            rows.append(row)
    else:
        raise ValueError('Only RSS 2.0 and Atom feeds are supported')
    if not rows:
        raise ValueError('Official advisory feed returned zero items; refuse empty baseline')
    items = {}
    for item in rows:
        if not _allowed_url(item['link'], allowed_hosts):
            raise ValueError('Advisory link outside verified official host allowlist')
        if not item['title']:
            raise ValueError('Untitled advisory entry')
        link = item['link']
        if link in items:
            raise ValueError('Duplicate advisory URL')
        items[link] = {**item, 'source_id': source_id, 'vendor': vendor,
                       'cve_ids': sorted(set(re.findall(r'CVE-\d{4}-\d{4,}',
                                              item['title']+' '+item['description_excerpt']))) }
    return list(items.values())


def observe_advisories(xml: Path, state_dir: Path, out: Path, *, source_id: str,
                       vendor: str, allowed_hosts: list[str], observed_at: datetime | None = None) -> dict:
    stamp = observed_at or datetime.now(timezone.utc)
    if stamp.tzinfo is None:
        raise ValueError('Naive advisory observation time')
    stamp = stamp.astimezone(timezone.utc).isoformat(timespec='seconds')
    raw = xml.read_bytes()
    parsed = parse_feed(raw, source_id=source_id, vendor=vendor, allowed_hosts=allowed_hosts)
    if not state_dir.exists():
        state_dir.mkdir(parents=True, exist_ok=True)
    state_file = state_dir / ('advisory-' + source_id + '.json')
    old = json.loads(state_file.read_text('utf-8')) if state_file.exists() else None
    if old and (old.get('schema_version') != 1 or old.get('vendor') != vendor):
        raise ValueError('Advisory state incompatible')
    before = old.get('records', {}) if old else {}
    current = {r['link']: hashlib.sha256(_dump(r).encode()).hexdigest() for r in parsed}
    events = []
    if old:
        for row in parsed:
            if before.get(row['link']) != current[row['link']]:
                events.append({**row, 'kind': 'added' if row['link'] not in before else 'updated',
                               'observed_utc': stamp, 'evidence_sha256': hashlib.sha256(raw).hexdigest()})
    # Missing items in a limited rolling RSS window are not advisory retractions.
    merged = {**before, **current}
    new_state = {'schema_version': 1, 'vendor': vendor, 'records': merged}
    if not old or new_state != old:
        _atomic_text(state_file, _dump(new_state))
    payload = {'source_id': source_id, 'baseline': old is None, 'observed_utc': stamp,
               'source_sha256': hashlib.sha256(raw).hexdigest(), 'events': events,
               'event_count': len(events),
               'warning': 'RSS item is a publication pointer, not a verified patch/impact assessment.'}
    _atomic_text(out, _dump(payload))
    return payload


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--xml', type=Path, required=True)
    p.add_argument('--state-dir', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--source-id', required=True)
    p.add_argument('--vendor', required=True)
    p.add_argument('--allowed-host', action='append', required=True)
    args = p.parse_args()
    result = observe_advisories(args.xml, args.state_dir, args.out, source_id=args.source_id,
                                vendor=args.vendor, allowed_hosts=args.allowed_host)
    print(json.dumps({k:v for k,v in result.items() if k!='events'}, indent=2))


if __name__ == '__main__':
    main()
