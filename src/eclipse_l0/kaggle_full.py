"""Private Kaggle transport: entire byte-exact official CVE source snapshot.

Stages shards in the dataset root with .cvepack extension to prevent provider
ZIP auto-extraction. No secrets, Kaggle SDK or network code is used here.
An upload is only accepted after every shard has been read back and checked.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sqlite3
import zipfile
from pathlib import Path

from .full_baseline import CVE, sha, write_json
from .core import connect, _upsert_cve, audit

HEX = re.compile(r'^[0-9a-f]{64}$')
SHARD = re.compile(r'^\d{6}-\d{6}\.cvepack$')
INDEX_FILE = 'archive-index.json'
SCHEMA = 1
MAX_SHARDS = 1000
MAX_SHARD_BYTES = 200 * 1024 * 1024
MAX_RECORD_BYTES = 16 * 1024 * 1024


def prepare(stage: Path) -> dict:
    """Seal a full-source staging directory; refuse partial / bounded stages."""
    mf = stage / 'manifest.json'
    m = json.loads(mf.read_text(encoding='utf-8'))
    if (m.get('status') != 'VERIFIED_FULL_SOURCE_BYTES_STAGED_NOT_KAGGLE_VERIFIED'
            or m.get('limit') is not None or not isinstance(m.get('shards'), list)
            or not 1 <= len(m['shards']) <= MAX_SHARDS
            or m.get('records_staged') != m.get('cve_member_count')
            or not isinstance(m.get('records_staged'), int)
            or m['records_staged'] < 1000 or not HEX.fullmatch(m.get('archive_sha256', ''))):
        raise ValueError('Not a verified complete source manifest')
    files = {}
    seen = set()
    total = 0
    for s in m['shards']:
        name = s.get('file')
        if not isinstance(name, str) or not SHARD.fullmatch(name) or name in seen:
            raise ValueError('Invalid/duplicate source shard filename')
        seen.add(name)
        path = stage / name
        if (not path.is_file() or not isinstance(s.get('bytes'), int)
                or not 0 < s['bytes'] <= MAX_SHARD_BYTES
                or path.stat().st_size != s['bytes']
                or sha(path) != s['sha256']):
            raise ValueError('Staged shard incomplete or hash mismatch: ' + name)
        files[name] = {'sha256': s['sha256'], 'bytes': s['bytes'], 'records': s['records']}
        total += s['records']
    if total != m['records_staged']:
        raise ValueError('Shard count != complete source member count')
    index = {
        'schema_version': SCHEMA, 'scope': 'OFFICIAL_CVE_V5_FULL_SNAPSHOT',
        'source_sha256': m['archive_sha256'], 'source_archive_bytes': m['archive_bytes'],
        'source_filename': m['archive_filename'], 'record_count': total,
        'shard_count': len(files), 'manifest_sha256': sha(mf), 'files': files,
        'recovery': 'Each .cvepack is a standard ZIP file with unchanged CVE JSON bytes.',
    }
    dest = stage / INDEX_FILE
    if dest.exists() and json.loads(dest.read_text()) != index:
        raise ValueError('Archive index changed on resume; refuse silent overwrite')
    write_json(dest, index)
    return index


def verify(download: Path, recovered: Path, expected_index_sha256: str,
           *, min_records: int = 1000) -> dict:
    """Full file-level roundtrip + member coverage + independent SQLite sample.

    Full-body source equality is established at staging by full_baseline.process;
    every stored shard MUST be byte-identical on provider readback.
    """
    if not HEX.fullmatch(expected_index_sha256):
        raise ValueError('Trusted expected SHA256 is required')
    idx_file = download / INDEX_FILE
    if not idx_file.is_file() or sha(idx_file) != expected_index_sha256:
        raise ValueError('Kaggle index differs from trusted pre-upload digest')
    index = json.loads(idx_file.read_text(encoding='utf-8'))
    if (index.get('schema_version') != SCHEMA or index.get('scope') != 'OFFICIAL_CVE_V5_FULL_SNAPSHOT'
            or not HEX.fullmatch(index.get('source_sha256',''))
            or type(index.get('record_count')) is not int or index['record_count'] < min_records
            or type(index.get('shard_count')) is not int
            or not 1 <= index['shard_count'] <= MAX_SHARDS):
        raise ValueError('Kaggle full-source index invalid')
    mf = download / 'manifest.json'
    if not mf.is_file() or sha(mf) != index.get('manifest_sha256'):
        raise ValueError('Kaggle manifest differs from trusted source')
    manifest = json.loads(mf.read_text())
    if (manifest.get('archive_sha256') != index['source_sha256']
            or manifest.get('records_staged') != index['record_count']
            or manifest.get('status') != 'VERIFIED_FULL_SOURCE_BYTES_STAGED_NOT_KAGGLE_VERIFIED'
            or manifest.get('limit') is not None):
        raise ValueError('Kaggle manifest does not describe complete source')
    specs = index.get('files')
    if not isinstance(specs, dict) or len(specs) != index['shard_count']:
        raise ValueError('Unexpected archive shard manifest')
    if set(specs) != {item['file'] for item in manifest['shards']}:
        raise ValueError('Shard list differs between index and verified manifest')
    if recovered.exists() and any(recovered.iterdir()):
        raise ValueError('SQLite recovery must use a fresh directory')
    recovered.mkdir(parents=True, exist_ok=True)
    con = connect(recovered / 'sample-recovery.sqlite3')
    records = 0
    unique = set()
    samples = 0
    try:
        for name, spec in sorted(specs.items()):
            if not SHARD.fullmatch(name) or not isinstance(spec, dict):
                raise ValueError('Unsafe filename or malformed shard metadata')
            size = spec.get('bytes')
            if (type(size) is not int or not 0 < size <= MAX_SHARD_BYTES
                    or type(spec.get('records')) is not int or not 1 <= spec['records'] <= 2500
                    or not HEX.fullmatch(spec.get('sha256', ''))):
                raise ValueError('Malformed shard sizes/digest')
            p = download / name
            if not p.is_file() or p.stat().st_size != size or sha(p) != spec['sha256']:
                raise ValueError('Missing/modified private Kaggle shard: ' + name)
            with zipfile.ZipFile(p) as z:
                entries = z.infolist()
                if len(entries) != spec['records']:
                    raise ValueError('Shard record count mismatch: ' + name)
                for info in entries:
                    cve_id = info.filename[:-5] if info.filename.endswith('.json') else ''
                    if (not CVE.fullmatch(cve_id) or info.filename != cve_id + '.json'
                            or info.file_size == 0 or info.file_size > MAX_RECORD_BYTES
                            or cve_id in unique):
                        raise ValueError('Unexpected or duplicate member: ' + info.filename)
                    unique.add(cve_id)
                # Check full ZIP integrity, not merely the ZIP container digest.
                bad = z.testzip()
                if bad:
                    raise ValueError('ZIP member CRC failure: ' + bad)
                # Independently reconstruct one record per shard into SQLite.
                first = entries[0]
                raw = z.read(first)
                body = json.loads(raw)
                if (body.get('cveMetadata') or {}).get('cveId') != first.filename[:-5]:
                    raise ValueError('SQLite reconstruction CVE ID mismatch')
                _upsert_cve(con, body, raw, 'private-Kaggle-recovery-sample')
                samples += 1
                records += len(entries)
        con.commit()
        sql = audit(con)
        if (records != index['record_count'] or len(unique) != records or
                samples != index['shard_count'] or sql['cve_total'] != samples or
                sql['sqlite_quick_check'] != 'ok'):
            raise ValueError('Incomplete CVE count or SQLite recovery failure')
    finally:
        con.close()
    return {
        'result': 'KAGGLE_PRIVATE_FULL_SOURCE_SHARD_ROUNDTRIP_VERIFIED',
        'source_sha256': index['source_sha256'],
        'index_sha256': expected_index_sha256,
        'records_checked': records, 'shards_checked': len(specs),
        'sqlite_sample_count': samples, 'sqlite_quick_check': sql['sqlite_quick_check'],
        'complete_sqlite_backfill': False, 'kaggle_visibility_confirmed_via_api': False,
    }


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest='command', required=True)
    s = sub.add_parser('prepare')
    s.add_argument('--stage', type=Path, required=True)
    v = sub.add_parser('verify')
    v.add_argument('--download', type=Path, required=True)
    v.add_argument('--recovered', type=Path, required=True)
    v.add_argument('--expected-index-sha256', required=True)
    args = p.parse_args()
    out = prepare(args.stage) if args.command == 'prepare' else verify(
        args.download, args.recovered, args.expected_index_sha256)
    print(json.dumps(out, ensure_ascii=False, sort_keys=True))


if __name__ == '__main__':
    main()
