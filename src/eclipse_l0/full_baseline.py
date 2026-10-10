"""Bounded, auditable CVEProject snapshot sampler. NEVER writes to public Git state.

A sampling gate for private archive storage, NOT a complete CVE mirror. Verbatim
record bodies are retained in deterministic ZIP shards; no arbitrary extraction.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import tempfile
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath

from .network import GITHUB_RELEASES, _request

CVE = re.compile(r'CVE-\d{4}-\d{4,}')
ASSET = re.compile(r'(\d{4}-\d{2}-\d{2})_all_CVEs_at_midnight\.zip(?:\.zip)?')
GITHUB_PREFIX = 'https://github.com/CVEProject/cvelistV5/releases/download/'
ALLOWED = {1000, 10000, 50000}
MAX_SOURCE_BYTES = 800 * 1024 * 1024
MAX_INNER_BYTES = 2 * 1024 * 1024 * 1024
MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_TOTAL_UNCOMPRESSED = 24 * 1024 * 1024 * 1024


def sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as f:
        for b in iter(lambda: f.read(4 * 1024 * 1024), b''):
            digest.update(b)
    return digest.hexdigest()


def write_json(path: Path, doc: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + '.tmp')
    try:
        tmp.write_text(json.dumps(doc, sort_keys=True, ensure_ascii=False, indent=2) + '\n')
        tmp.replace(path)
    finally:
        tmp.unlink(missing_ok=True)


def select_asset(releases: list[dict], max_bytes: int = MAX_SOURCE_BYTES) -> dict:
    """Choose newest dated, size-checked official full baseline (not hourly delta)."""
    candidates = []
    for release in releases:
        tag = release.get('tag_name', '')
        if not isinstance(tag, str) or not tag.startswith('cve_'):
            continue
        for item in release.get('assets', []):
            name = item.get('name', '')
            match = ASSET.fullmatch(name) if isinstance(name, str) else None
            url = item.get('browser_download_url', '')
            size = item.get('size')
            if not match or not isinstance(url, str) or not url.startswith(GITHUB_PREFIX):
                continue
            if not url.endswith('/' + name):
                continue
            if not isinstance(size, int) or isinstance(size, bool) or not (1024 * 1024 <= size <= max_bytes):
                raise ValueError('Invalid/oversize official baseline asset')
            if not isinstance(item.get('id'), int):
                raise ValueError('Official baseline asset ID missing')
            candidates.append(dict(date=match.group(1), name=name, url=url,
                                   bytes=size, asset_id=item['id'], tag=tag,
                                   created_at=item.get('created_at')))
    if not candidates:
        raise ValueError('No size-checked official full-baseline asset in release window')
    return max(candidates, key=lambda x: (x['date'], x['created_at'] or '', x['asset_id']))


def latest_asset() -> dict:
    with urllib.request.urlopen(_request(GITHUB_RELEASES), timeout=35) as res:
        data = json.load(res)
    if not isinstance(data, list):
        raise ValueError('Unexpected GitHub releases API response')
    return select_asset(data)


def acquire(asset: dict, dest: Path, opener=urllib.request.urlopen) -> Path:
    """Restartable HTTP Range download, pinned to a single asset id/size.

    Refuse ignored/mismatched Range replies. No partial file is ever treated as valid.
    """
    dest.mkdir(parents=True, exist_ok=True)
    target = dest / asset['name']
    part = dest / (asset['name'] + '.part')
    control = dest / (asset['name'] + '.source.json')
    key = {k: asset[k] for k in ('name', 'url', 'bytes', 'asset_id', 'tag')}
    if control.exists() and json.loads(control.read_text()) != key:
        raise ValueError('Source asset identity changed: separate source directory required')
    if target.exists():
        if not control.exists() or target.stat().st_size != asset['bytes']:
            raise ValueError('Existing final archive is not bound to requested source')
        if not zipfile.is_zipfile(target):
            raise ValueError('Completed archive is not a ZIP')
        return target
    if not control.exists():
        if part.exists():
            raise ValueError('Orphan partial archive: refuse unsafe resume')
        write_json(control, key)
    offset = part.stat().st_size if part.exists() else 0
    if offset > asset['bytes']:
        raise ValueError('Partial download exceeds declared asset length')
    if offset < asset['bytes']:
        req = _request(asset['url'])
        if offset:
            req.add_header('Range', f'bytes={offset}-')
        with opener(req, timeout=120) as res:
            status = getattr(res, 'status', res.getcode())
            if offset:
                expected = f'bytes {offset}-{asset["bytes"]-1}/{asset["bytes"]}'
                if status != 206 or res.headers.get('Content-Range') != expected:
                    raise ValueError('Origin ignored/misreported HTTP byte-range resume')
            elif status != 200:
                raise ValueError('Unexpected initial HTTP response status')
            with part.open('ab' if offset else 'wb') as out:
                total = offset
                for data in iter(lambda: res.read(1024 * 1024), b''):
                    total += len(data)
                    if total > asset['bytes']:
                        raise ValueError('Official archive longer than pinned asset size')
                    out.write(data)
    if part.stat().st_size != asset['bytes'] or not zipfile.is_zipfile(part):
        raise ValueError('Incomplete/broken official ZIP retained for retry')
    part.replace(target)
    return target


def members(zf: zipfile.ZipFile) -> tuple[list[zipfile.ZipInfo], dict]:
    found, seen = [], set()
    total = 0
    for info in zf.infolist():
        name = info.filename
        p = PurePosixPath(name)
        if (not name or '\\' in name or name.startswith('/') or
                any(s in ('.', '..') for s in name.split('/')) or
                name in seen or (info.external_attr >> 16 & 0o170000) == 0o120000):
            raise ValueError('Unsafe, duplicate or symlink ZIP member')
        seen.add(name)
        if info.is_dir():
            continue
        total += info.file_size
        if total > MAX_TOTAL_UNCOMPRESSED:
            raise ValueError('ZIP uncompressed budget exceeded')
        if p.suffix == '.json' and CVE.fullmatch(p.stem):
            if info.file_size > MAX_JSON_BYTES or info.file_size == 0:
                raise ValueError('Oversize/empty CVE JSON member')
            found.append(info)
    ids = [PurePosixPath(x.filename).stem for x in found]
    if len(ids) != len(set(ids)):
        raise ValueError('Duplicate CVE ID in official ZIP')
    return sorted(found, key=lambda info: hashlib.sha256(PurePosixPath(info.filename).stem.encode('ascii')).digest()), {
        'cve_member_count': len(found), 'zip_member_count': len(seen),
        'uncompressed_bytes_claimed': total}


def process(archive: Path, stage: Path, limit: int, shard_size: int = 500) -> dict:
    if limit not in ALLOWED or not 1 <= shard_size <= 1000:
        raise ValueError('Only approved bounded sampling gates are allowed')
    stage.mkdir(parents=True, exist_ok=True)
    source_digest = sha(archive)
    source = {'archive_filename': archive.name, 'archive_bytes': archive.stat().st_size,
              'archive_sha256': source_digest, 'limit': limit, 'shard_size': shard_size}
    control = stage / 'source.json'
    if control.exists() and json.loads(control.read_text()) != source:
        raise ValueError('Staging source/count changed: use a fresh output directory')
    if not control.exists():
        if any(stage.iterdir()):
            raise ValueError('Unbound staging content already exists')
        write_json(control, source)
    with tempfile.TemporaryDirectory(prefix='eclipse-cve-inner-') as temp:
        active = archive
        with zipfile.ZipFile(archive) as top:
            selected, stats = members(top)
            if not selected:
                files = [x for x in top.infolist() if not x.is_dir()]
                if len(files) != 1 or not files[0].filename.endswith('.zip') or files[0].file_size > MAX_INNER_BYTES:
                    raise ValueError('Unrecognized CVE archive layout (neither direct JSON nor single inner ZIP)')
                active = Path(temp) / 'inner.zip'
                with top.open(files[0]) as src, active.open('wb') as dst:
                    shutil.copyfileobj(src, dst, 1024 * 1024)
                if not zipfile.is_zipfile(active):
                    raise ValueError('Nested member is not a ZIP')
        with zipfile.ZipFile(active) as zf:
            selected, stats = members(zf)
            if len(selected) < limit:
                raise ValueError(f'Snapshot contains {len(selected)} CVE records, fewer than {limit}')
            shard_docs = []
            for start in range(0, limit, shard_size):
                batch = selected[start:min(limit, start + shard_size)]
                name = f'{start:06d}-{start + len(batch) - 1:06d}.zip'
                dest = stage / 'shards' / name
                if dest.exists():
                    # Don't silently reuse a modified shard. Re-validate below after full pass.
                    pass
                else:
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    tmp = dest.with_suffix('.zip.tmp')
                    try:
                        with zipfile.ZipFile(tmp, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as out:
                            for info in batch:
                                raw = zf.read(info)
                                cve_id = PurePosixPath(info.filename).stem
                                body = json.loads(raw)
                                if (body.get('cveMetadata') or {}).get('cveId') != cve_id:
                                    raise ValueError('CVE record filename/metadata mismatch: ' + cve_id)
                                zi = zipfile.ZipInfo(cve_id + '.json', (1980, 1, 1, 0, 0, 0))
                                zi.compress_type = zipfile.ZIP_DEFLATED
                                out.writestr(zi, raw, compress_type=zipfile.ZIP_DEFLATED, compresslevel=6)
                        tmp.replace(dest)
                    finally:
                        tmp.unlink(missing_ok=True)
                # Audit retained verbatim records against THIS baseline even when resuming.
                with zipfile.ZipFile(dest) as check:
                    expected = {PurePosixPath(i.filename).stem: i for i in batch}
                    if set(check.namelist()) != {i + '.json' for i in expected}:
                        raise ValueError('Shard record set mismatch: ' + name)
                    for cve_id, original in expected.items():
                        baseline_raw = zf.read(original)
                        if check.read(cve_id + '.json') != baseline_raw:
                            raise ValueError('Shard body differs from official archive: ' + cve_id)
                shard_docs.append({'file': 'shards/' + name, 'records': len(batch),
                                   'bytes': dest.stat().st_size, 'sha256': sha(dest)})
    # Distinct entry count is based on fully verified source-selected members.
    manifest = {**source, **stats, 'records_staged': limit,
                'shards': shard_docs, 'layout': 'direct_or_single_nested_zip',
                'selection': 'DETERMINISTIC_SHA256_CVE_ID_SAMPLE_NOT_STATISTICALLY_VALIDATED',
                'status': 'VERIFIED_BOUNDED_SAMPLE_NOT_FULL_BACKFILL'}
    write_json(stage / 'manifest.json', manifest)
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--workdir', type=Path, required=True)
    parser.add_argument('--limit', type=int, choices=sorted(ALLOWED), required=True)
    parser.add_argument('--release-json', type=Path)
    args = parser.parse_args()
    if args.release_json:
        asset = select_asset(json.loads(args.release_json.read_text()))
    else:
        asset = latest_asset()
    print(json.dumps({k: v for k, v in asset.items() if k != 'url'}, sort_keys=True), flush=True)
    archive = acquire(asset, args.workdir / 'download')
    result = process(archive, args.workdir / 'staged', args.limit)
    print(json.dumps({'result': result['status'], 'rows': result['records_staged'],
                      'archive_sha256': result['archive_sha256'],
                      'source_member_count': result['cve_member_count'],
                      'shards': len(result['shards'])}, sort_keys=True))


if __name__ == '__main__':
    main()
