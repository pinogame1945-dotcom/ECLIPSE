"""Evidence-preserving KEV -> SQLite -> customer-filtered PowerPoint.

Manual execution only in v0.3; no persistent DB is implied by ephemeral CI runners.
"""
from __future__ import annotations

import argparse
from contextlib import closing
import hashlib
import json
from datetime import date, datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

from eclipse_l0.core import connect, export_kev_catalog, ingest_kev_json, audit
from eclipse_reports.daily import render


def build(kev_path: Path, db_path: Path, customer_path: Path, output_path: Path,
          start: date, end: date, *, demo: bool = False, min_records: int = 1000) -> dict:
    """Generate a report from the L0-validated, recorded catalog, not a loose JSON file."""
    if end < start:
        raise ValueError('Report start date must not exceed end date')
    digest = hashlib.sha256(kev_path.read_bytes()).hexdigest()
    # Include full checksum to prevent two different feeds from sharing one source run label.
    label = 'cisa-kev-' + digest
    normalized = output_path.parent / '.validated-cisa-kev.json'
    with closing(connect(db_path)) as con:
        ingestion = ingest_kev_json(con, kev_path, label, min_records=min_records)
        checks = audit(con)
        if checks['kev_present'] < min_records:
            raise ValueError('L0 KEV validation failed')
        snapshot = export_kev_catalog(con, normalized)
        if snapshot['sha256'] != digest:
            raise RuntimeError('Catalog hash mismatch after writing to SQLite')
    try:
        manifest = render(normalized, customer_path, output_path, start, end, demo=demo)
    finally:
        normalized.unlink(missing_ok=True)
    manifest.update({
        'l0_ingestion': ingestion,
        'l0_snapshot': snapshot,
        'l0_sqlite_audit': checks['sqlite_quick_check'],
        'data_scope': 'CISA KEV dateAdded only; no manufacturer notices or AI analysis',
    })
    manifest_path = output_path.with_suffix('.manifest.json')
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding='utf-8')
    return manifest


def main() -> None:
    p = argparse.ArgumentParser(description='L0-validated customer KEV briefing')
    p.add_argument('--kev-json', required=True, type=Path)
    p.add_argument('--db', type=Path, default=Path('state/eclipse.sqlite3'))
    p.add_argument('--customer', required=True, type=Path)
    p.add_argument('--output', required=True, type=Path)
    p.add_argument('--end-date', type=date.fromisoformat,
                   default=None, help='KEV registration end date YYYY-MM-DD (default: yesterday JST)')
    p.add_argument('--days', type=int, default=1, help='1 to 31 calendar days (inclusive)')
    p.add_argument('--demo', action='store_true', help='Mark all slides as synthetic samples')
    args = p.parse_args()
    if not 1 <= args.days <= 31:
        p.error('--days must be 1..31')
    end = args.end_date or (datetime.now(ZoneInfo('Asia/Tokyo')).date() - timedelta(days=1))
    start = end - timedelta(days=args.days - 1)
    result = build(args.kev_json, args.db, args.customer, args.output, start, end,
                   demo=args.demo, min_records=1 if args.demo else 1000)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
