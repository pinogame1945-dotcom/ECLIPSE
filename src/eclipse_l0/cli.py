"""Run via: PYTHONPATH=src python -m eclipse_l0.cli <command>"""
import argparse
import json
from pathlib import Path
from .core import audit, connect, export_current, ingest_cve_zip, ingest_kev_json, report
from .network import fetch_sources


def main() -> None:
    parser = argparse.ArgumentParser(description='PROJECT ECLIPSE L0 — CVE / KEV evidence collector')
    parser.add_argument('--db', type=Path, default=Path('state/eclipse.sqlite3'))
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('ingest-cve', help='Import a full CVE baseline ZIP')
    p.add_argument('zip', type=Path)
    p.add_argument('--source-label', required=True)
    p.add_argument('--min-records', type=int, default=100000)
    p = sub.add_parser('ingest-kev', help='Import complete CISA KEV JSON')
    p.add_argument('json', type=Path)
    p.add_argument('--source-label', required=True)
    p.add_argument('--min-records', type=int, default=1000)
    p = sub.add_parser('sync-official', help='Download latest full baseline + KEV and ingest')
    p.add_argument('--workdir', type=Path, default=Path('downloads'))
    p.add_argument('--max-zip-mb', type=int, default=1100)
    sub.add_parser('report')
    sub.add_parser('audit', help='Check SQLite integrity and source coverage')
    p = sub.add_parser('export-csv')
    p.add_argument('output', type=Path)
    args = parser.parse_args()
    if args.command == 'sync-official':
        cve, kev, label = fetch_sources(args.workdir, args.max_zip_mb)
        with connect(args.db) as con:
            a = ingest_cve_zip(con, cve, source_label_safe(label))
            b = ingest_kev_json(con, kev, source_label_safe('kev-' + _sha8(kev)))
            print(json.dumps({'cve': a, 'kev': b, 'report': report(con)}, ensure_ascii=False, indent=2))
    else:
        with connect(args.db) as con:
            if args.command == 'ingest-cve':
                out = ingest_cve_zip(con, args.zip, args.source_label, args.min_records)
            elif args.command == 'ingest-kev':
                out = ingest_kev_json(con, args.json, args.source_label, args.min_records)
            elif args.command == 'audit':
                out = audit(con)
            elif args.command == 'export-csv':
                out = {'exported': export_current(con, args.output), 'output': str(args.output)}
            else:
                out = report(con)
            print(json.dumps(out, ensure_ascii=False, indent=2))


def source_label_safe(label: str) -> str:
    return label.replace(' ', '_')


def _sha8(path: Path) -> str:
    from .core import file_sha256
    return file_sha256(path)[:16]


if __name__ == '__main__':
    main()
