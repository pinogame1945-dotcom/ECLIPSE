"""Read-only, bounded official KEV -> sample CVE L0 ingestion pilot.

This does NOT fetch the CVE all-records archive, write remote Git branches, or
claim complete CVE coverage. Failures are explicit per-record in a CSV manifest.
"""
from __future__ import annotations

import argparse
import csv
from contextlib import closing
import hashlib
import json
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, build_opener, HTTPRedirectHandler

from .core import CVE_ID, _upsert_cve, audit, connect, ingest_kev_json, report

MAX_SOURCE_BYTES = 25 * 1024 * 1024
MAX_CVE_BYTES = 2 * 1024 * 1024
OFFICIAL_CVE_HOST = 'https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/'


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def cve_url(cve_id: str) -> str:
    """Deterministic official CVE List V5 source path for one identifier."""
    if not isinstance(cve_id, str) or not CVE_ID.fullmatch(cve_id):
        raise ValueError('Invalid CVE identifier')
    _, year, number = cve_id.split('-')
    group = f'{int(number) // 1000}xxx'
    return f'{OFFICIAL_CVE_HOST}{year}/{group}/{cve_id}.json'


def fetch_record(url: str, max_bytes: int = MAX_CVE_BYTES) -> bytes:
    """Request a single fixed-host JSON record, with redirects refused."""
    if not url.startswith(OFFICIAL_CVE_HOST) or not re.fullmatch(
        r'https://raw\.githubusercontent\.com/CVEProject/cvelistV5/main/cves/\d{4}/\d+xxx/CVE-\d{4}-\d{4,}\.json', url
    ):
        raise ValueError('Unexpected CVE URL')
    req = Request(url, headers={'User-Agent': 'PROJECT-ECLIPSE-bounded-pilot/0.7', 'Accept': 'application/json'})
    with build_opener(NoRedirect()).open(req, timeout=16) as resp:
        raw = resp.read(max_bytes + 1)
        if len(raw) > max_bytes:
            raise ValueError('CVE JSON exceeds per-record byte cap')
    return raw


def run_pilot(kev_path: Path, output: Path, *, limit: int = 10, min_records: int = 1000,
              fetcher=fetch_record) -> dict:
    if limit not in (1, 2, 10, 25, 50):
        raise ValueError('Pilot sample size must be 1, 2 (tests) or 10, 25, 50')
    if not kev_path.is_file() or kev_path.stat().st_size > MAX_SOURCE_BYTES:
        raise ValueError('KEV feed not found or exceeds 25 MiB')
    output.mkdir(parents=True, exist_ok=True)
    data = kev_path.read_bytes()
    catalog = json.loads(data)
    if not isinstance(catalog, dict) or not isinstance(catalog.get('vulnerabilities'), list):
        raise ValueError('Invalid official KEV catalog')
    records = catalog['vulnerabilities']
    if len(records) < min_records:
        raise ValueError('KEV baseline too small; refuse pilot')
    # Stable ordering: newest CISA catalog addition first, CVE ID tie break.
    selection = sorted(records, key=lambda row: (row['dateAdded'], row['cveID']), reverse=True)[:limit]
    # The DB is a disposable smoke-test artifact; it is NOT a production master store.
    db = output / 'pilot.sqlite3'
    observations = []
    with closing(connect(db)) as con:
        ingestion = ingest_kev_json(con, kev_path, f'pilot-kev-{hashlib.sha256(data).hexdigest()}',
                                    min_records=min_records)
        for entry in selection:
            cve = entry['cveID']
            url = cve_url(cve)
            result = {'cve_id': cve, 'kev_date_added': entry['dateAdded'], 'source': url,
                      'status': 'not_fetched', 'bytes': 0, 'sha256': '', 'error': ''}
            try:
                raw = fetcher(url)
                if len(raw) > MAX_CVE_BYTES:
                    raise ValueError('CVE JSON exceeds per-record byte cap')
                obj = json.loads(raw)
                if (not isinstance(obj, dict)
                        or (obj.get('cveMetadata') or {}).get('cveId') != cve):
                    raise ValueError('Fetched CVE does not match requested CVE ID')
                _upsert_cve(con, obj, raw, 'bounded-pilot-cve')
                con.commit()
                result.update(status='imported', bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
            except (HTTPError, URLError, TimeoutError, ValueError, KeyError, OSError,
                    json.JSONDecodeError) as exc:
                # Never silently replace missing official evidence with guessed records.
                result.update(status='failed', error=f'{type(exc).__name__}: {str(exc)[:190]}')
            observations.append(result)
        integrity = audit(con)
        counts = report(con)
        con.execute('PRAGMA wal_checkpoint(TRUNCATE)')
    with (output / 'pilot-cve-observations.csv').open('w', encoding='utf-8-sig', newline='') as handle:
        writer = csv.DictWriter(handle, fieldnames=[
            'cve_id', 'kev_date_added', 'source', 'status', 'bytes', 'sha256', 'error'])
        writer.writeheader()
        writer.writerows(observations)
    success = sum(row['status'] == 'imported' for row in observations)
    result = {
        'mode': 'READ_ONLY_BOUNDED_SMOKE_TEST',
        'observed_utc': datetime.now(timezone.utc).isoformat(timespec='seconds'),
        'kev_official_catalog_sha256': hashlib.sha256(data).hexdigest(),
        'kev_catalog_rows': len(records),
        'kev_sqlite_ingestion': ingestion,
        'selected_kev_identifiers': len(selection),
        'cve_records_imported': success,
        'cve_records_missing_or_invalid': len(selection) - success,
        'sample_rule': 'KEV dateAdded descending then CVE ID descending; NOT random and NOT representative',
        'sqlite_audit': integrity,
        'sqlite_counts': counts,
        'claims': ['Complete KEV downloaded for one-time validation; no CISA KEV state written to Git.',
                   'Only selected CVE JSON documents fetched; no full CVE backfill or live alerts.',
                   'Failed CVE fetches are explicit and do not imply an issue is not real.'],
    }
    (output / 'pilot-manifest.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description='Read-only bounded KEV/CVE official-data pilot')
    parser.add_argument('--kev-json', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--limit', type=int, choices=(10, 25, 50), default=10)
    args = parser.parse_args()
    data = run_pilot(args.kev_json, args.out, limit=args.limit)
    print(json.dumps({k: v for k, v in data.items() if k not in ('sqlite_audit', 'sqlite_counts')}, indent=2))
    if data['cve_records_imported'] == 0:
        raise SystemExit('No official CVE source records verified; check CSV errors before retry')


if __name__ == '__main__':
    main()
