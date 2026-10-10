"""Lossless Kaggle transport for the audited 100-record public CVE source seed.

Kaggle private dataset creation and retrieval are done by an authenticated CI
workflow. This module deals ONLY in untrusted bytes, checksum and SQL replay;
it never accesses credentials or automatically publishes customer information.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import zipfile
from pathlib import Path

from .cve_seed import audit_seed

SCHEMA = 1
BUNDLE_NAME = 'eclipse-cve-source-seed.zip'
INDEX_NAME = 'archive-index.json'
MAX_BUNDLE_BYTES = 15 * 1024 * 1024
MAX_MEMBERS = 12
SHA = re.compile(r'^[0-9a-f]{64}$')


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _load(path: Path) -> dict:
    v = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(v, dict):
        raise ValueError('Index must be JSON object')
    return v


def _members(state_dir: Path) -> dict[str, Path]:
    folder = state_dir / 'cve-seed'
    manifest = _load(folder / 'manifest.json')
    if not isinstance(manifest.get('shards'), list):
        raise ValueError('Seed manifest has no shard list')
    files = {
        'cohort.json': folder / 'cohort.json',
        'manifest.json': folder / 'manifest.json',
    }
    for sh in manifest['shards']:
        name = sh.get('file')
        if not isinstance(name, str) or not re.fullmatch(r'\d{4}-\d{4}\.jsonl', name):
            raise ValueError('Unsafe original CVE shard filename')
        files[f'shards/{name}'] = folder / 'shards' / name
    if len(files) > MAX_MEMBERS:
        raise ValueError('Archive file-count safety bound exceeded')
    return files


def prepare(state_dir: Path, output_dir: Path, *, expected_records: int = 100) -> dict:
    """Create deterministic binary archive only after the full source audit."""
    report = audit_seed(state_dir)
    if report['integrity'] != 'ok' or report['archived_cve_count'] != expected_records:
        raise ValueError('Original CVE seed must be fully audited at approved record count')
    if output_dir.exists() and any(output_dir.iterdir()):
        raise ValueError('Refusing to reuse staged Kaggle upload directory')
    output_dir.mkdir(parents=True, exist_ok=True)
    paths = _members(state_dir)
    member_meta = {}
    packed = output_dir / BUNDLE_NAME
    with zipfile.ZipFile(packed, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        for name, path in sorted(paths.items()):
            data = path.read_bytes()
            member_meta[name] = {'sha256': digest(data), 'bytes': len(data)}
            zi = zipfile.ZipInfo(name, (2020, 1, 1, 0, 0, 0))
            zi.compress_type = zipfile.ZIP_DEFLATED
            zi.external_attr = 0o444 << 16
            z.writestr(zi, data)
    if packed.stat().st_size > MAX_BUNDLE_BYTES:
        packed.unlink()
        raise ValueError('Kaggle source bundle exceeds approved 15 MiB cap')
    index = {
        'schema_version': SCHEMA,
        'source': 'CVEProject/cvelistV5 selected public KEV-linked CVE bodies',
        'scope': '100 KEV-linked CVEs only, NOT historical CVE full archive',
        'record_count': report['archived_cve_count'],
        'shard_count': report['completed_shards'],
        'bundle': BUNDLE_NAME,
        'bundle_sha256': digest(packed.read_bytes()),
        'bundle_bytes': packed.stat().st_size,
        'members': member_meta,
        'manifest_sha256': report['manifest_sha256'],
        'cohort_sha256': report['cohort_sha256'],
        'original_source_audit': report,
    }
    (output_dir / INDEX_NAME).write_text(json.dumps(index, sort_keys=True, indent=2)+'\n', encoding='utf-8')
    return index


def verify(download_dir: Path, recovery_dir: Path, *, expected_records: int = 100,
           expected_index_sha256: str | None = None) -> dict:
    """Read back downloaded files, verify every byte, rebuild SQLite from scratch."""
    index_path = download_dir / INDEX_NAME
    bundle = download_dir / BUNDLE_NAME
    if not index_path.is_file():
        raise ValueError('Kaggle retrieval missing archive index')
    index_raw = index_path.read_bytes()
    if expected_index_sha256 and digest(index_raw) != expected_index_sha256:
        raise ValueError('Kaggle index does not match prepared snapshot')
    index = _load(index_path)
    if (index.get('schema_version') != SCHEMA or index.get('bundle') != BUNDLE_NAME
            or index.get('record_count') != expected_records):
        raise ValueError('Unexpected Kaggle archive schema/scope/count')
    members = index.get('members')
    if not isinstance(members, dict) or not 2 <= len(members) <= MAX_MEMBERS:
        raise ValueError('Invalid archive member manifest')
    # Kaggle's server sometimes AUTO-EXTRACTS uploaded *.zip files and
    # serves the original members under a stem-named folder. Never mistake
    # that for lost source data. Verify each member SHA and repack with the
    # exact same deterministic ZIP metadata, then compare to the original
    # archive's *byte-identical* signed-in-the-manifest SHA-256.
    transport = 'ORIGINAL_ZIP_DOWNLOADED'
    if not bundle.is_file():
        extracted = download_dir / Path(BUNDLE_NAME).stem
        if not extracted.is_dir():
            raise ValueError('Kaggle retrieval has neither ZIP nor extracted source folder')
        files = {p.relative_to(extracted).as_posix():p for p in extracted.rglob('*') if p.is_file()}
        if set(files) != set(members):
            raise ValueError('Kaggle auto-extraction contains extra/missing source files')
        with zipfile.ZipFile(bundle, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as z:
            for name, path in sorted(files.items()):
                spec = members[name]
                if not isinstance(spec, dict) or not isinstance(spec.get('sha256'), str):
                    raise ValueError('Invalid extracted member metadata')
                raw = path.read_bytes()
                if len(raw) != spec['bytes'] or digest(raw) != spec['sha256']:
                    raise ValueError('Kaggle auto-extracted raw member checksum mismatch')
                zi = zipfile.ZipInfo(name, (2020, 1, 1, 0, 0, 0))
                zi.compress_type = zipfile.ZIP_DEFLATED
                zi.external_attr = 0o444 << 16
                z.writestr(zi, raw)
        transport = 'KAGGLE_AUTO_EXTRACTED_MEMBERS_BYTE_EXACT_REPACK'
    if (bundle.stat().st_size > MAX_BUNDLE_BYTES
            or bundle.stat().st_size != index.get('bundle_bytes')
            or digest(bundle.read_bytes()) != index.get('bundle_sha256')):
        raise ValueError('Kaggle download altered the original compressed archive bytes')
    if recovery_dir.exists() and any(recovery_dir.iterdir()):
        raise ValueError('Recover into a new empty directory to avoid stale data')
    if set(members) != {'cohort.json', 'manifest.json'} | {
            p for p in members if re.fullmatch(r'shards/\d{4}-\d{4}\.jsonl', p)}:
        raise ValueError('Unsafe Kaggle archive member name')
    restored_root = recovery_dir / 'data' / 'cve-seed'
    with zipfile.ZipFile(bundle) as z:
        if set(z.namelist()) != set(members) or len(z.namelist()) != len(set(members)):
            raise ValueError('Kaggle archive contains missing/extra/duplicate entries')
        for name, spec in members.items():
            if not isinstance(spec, dict) or set(spec) != {'sha256', 'bytes'}:
                raise ValueError('Corrupt member metadata')
            if type(spec['bytes']) is not int or spec['bytes'] < 0 or spec['bytes'] > 3*1024*1024:
                raise ValueError('Unsafe archive member byte size')
            if not isinstance(spec['sha256'], str) or not SHA.fullmatch(spec['sha256']):
                raise ValueError('Unsafe archive member digest')
            if z.getinfo(name).file_size != spec['bytes']:
                raise ValueError('Archive member size mismatch')
            raw = z.read(name)
            if len(raw) != spec['bytes'] or digest(raw) != spec['sha256']:
                raise ValueError('Archive member checksum mismatch: '+name)
            out = restored_root / name
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(raw)
    sqlite_path = recovery_dir / 'restored.sqlite3'
    result = audit_seed(recovery_dir / 'data', export_sqlite=sqlite_path)
    if (result['archived_cve_count'] != expected_records
            or result.get('sqlite_cve_count') != expected_records
            or result.get('sqlite_quick_check') != 'ok'
            or result['manifest_sha256'] != index['manifest_sha256']
            or result['cohort_sha256'] != index['cohort_sha256']):
        raise ValueError('Kaggle restore inconsistent with original validated CVE seed')
    return {
        'status': 'VERIFIED_KAGGLE_DOWNLOAD_AND_SQLITE_RESTORE',
        'transport': transport,
        'cve_records': expected_records,
        'archive_sha256': index['bundle_sha256'],
        'index_sha256': digest(index_raw),
        'sqlite_quick_check': 'ok',
        'sqlite_cve_count': result['sqlite_cve_count'],
        'scope': index['scope'],
    }


def main() -> None:
    p = argparse.ArgumentParser(description='Prepare/verify Kaggle private-source seed dataset payload')
    sub = p.add_subparsers(dest='command', required=True)
    create = sub.add_parser('prepare')
    create.add_argument('--state-dir', type=Path, required=True)
    create.add_argument('--out-dir', type=Path, required=True)
    read = sub.add_parser('verify')
    read.add_argument('--download-dir', type=Path, required=True)
    read.add_argument('--recovery-dir', type=Path, required=True)
    read.add_argument('--expected-index-sha256')
    args = p.parse_args()
    out=(prepare(args.state_dir,args.out_dir) if args.command=='prepare' else
         verify(args.download_dir,args.recovery_dir,expected_index_sha256=args.expected_index_sha256))
    print(json.dumps(out,ensure_ascii=False,indent=2))

if __name__=='__main__':
    main()
