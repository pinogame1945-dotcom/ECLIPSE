"""Bounded, restartable CVE source archive seeded from the PUBLIC CISA KEV watchlist.

This is deliberately NOT a complete historical CVE database. A fixed, documented
cohort plus immutable per-batch JSONL shards are the durable source records.
SQLite is a reproducible materialized view, never the only copy of source data.

Git transaction: run one batch -> audit -> commit/push the whole data/ folder.
A failed fetch is atomic *for the local batch*: cursor/shard remains unchanged.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from contextlib import closing
from datetime import date, datetime, timezone
from pathlib import Path

from .core import CVE_ID, _upsert_cve, audit as sqlite_audit, connect
from .kev_monitor import _atomic_text, _dump
from .pilot import MAX_CVE_BYTES, cve_url, fetch_record

SCHEMA = 1
ABSOLUTE_CVE_CAP = 100       # require explicit source review before raising
MAX_SHARD_BYTES = 3 * 1024 * 1024
MAX_ARCHIVE_BYTES = 12 * 1024 * 1024
BASE_DIR = 'cve-seed'
MANIFEST_NAME = 'manifest.json'
COHORT_NAME = 'cohort.json'


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical(obj: object) -> bytes:
    return _dump(obj).encode('utf-8')


def _read(path: Path) -> dict:
    obj = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(obj, dict):
        raise ValueError('Unexpected JSON document (expected object): ' + str(path))
    return obj


def _validate_public_kev(path: Path) -> dict:
    state = _read(path)
    rows = state.get('records')
    if state.get('schema_version') != 1 or not isinstance(rows, dict) or len(rows) < 1000:
        raise ValueError('Full official KEV baseline is required to seed CVE')
    for cve, entry in rows.items():
        if not isinstance(cve, str) or not CVE_ID.fullmatch(cve) or not isinstance(entry, dict) or entry.get('cveID') != cve:
            raise ValueError('Corrupt KEV watchlist identity')
        date.fromisoformat(entry['dateAdded'])
    return state


def _plan(state: dict) -> dict:
    ordered = sorted(state['records'].values(),
                     key=lambda r: (r['dateAdded'], r['cveID']), reverse=True)
    return {
        'schema_version': SCHEMA,
        'cohort_source': 'CISA KEV official public-state snapshot',
        'kev_sha256_when_frozen': state['source_sha256'],
        'selection': 'dateAdded desc, CVE ID desc; biased toward KEV (not general CVE population)',
        'items': [{'cve_id': r['cveID'], 'kev_date_added': r['dateAdded']} for r in ordered],
    }


def _check_cohort(plan: dict) -> list[dict]:
    items = plan.get('items')
    if plan.get('schema_version') != SCHEMA or not isinstance(items, list) or len(items) < 1000:
        raise ValueError('Invalid frozen CVE source cohort')
    keys = set()
    last = None
    for r in items:
        if not isinstance(r, dict) or set(r) != {'cve_id', 'kev_date_added'}:
            raise ValueError('Invalid cohort row shape')
        cve = r['cve_id']
        if not isinstance(cve, str) or not CVE_ID.fullmatch(cve) or cve in keys:
            raise ValueError('Duplicate/invalid cohort CVE ID')
        date.fromisoformat(r['kev_date_added'])
        key = (r['kev_date_added'], cve)
        if last is not None and key > last:
            raise ValueError('Frozen cohort order is not deterministic')
        last = key
        keys.add(cve)
    return items


def _verify_entry(row: dict, cve: str) -> bytes:
    if row.get('cve_id') != cve or row.get('source_url') != cve_url(cve):
        raise ValueError('Archive entry identity or upstream source URL mismatch')
    body = row.get('body_utf8')
    if not isinstance(body, str):
        raise ValueError('Archived CVE record has no original UTF-8 bytes')
    raw = body.encode('utf-8')
    if len(raw) > MAX_CVE_BYTES or sha256(raw) != row.get('source_sha256'):
        raise ValueError('Archived CVE record checksum/size mismatch')
    doc = json.loads(raw)
    if not isinstance(doc, dict) or (doc.get('cveMetadata') or {}).get('cveId') != cve:
        raise ValueError('Official CVE source body ID mismatch')
    return raw


def audit_seed(state_dir: Path, *, export_sqlite: Path | None = None) -> dict:
    """Independently verify every shard & rebuild exact immutable source archive."""
    root = Path(state_dir) / BASE_DIR
    manifest_path, cohort_path = root / MANIFEST_NAME, root / COHORT_NAME
    if not manifest_path.is_file() or not cohort_path.is_file():
        raise ValueError('No completed CVE seed manifest/cohort to audit')
    cohort_raw = cohort_path.read_bytes()
    cohort = _read(cohort_path)
    items = _check_cohort(cohort)
    meta = _read(manifest_path)
    if (meta.get('schema_version') != SCHEMA or
        meta.get('cohort_sha256') != sha256(cohort_raw) or
        not isinstance(meta.get('shards'), list) or
        type(meta.get('next_index')) is not int or
        meta['next_index'] < 0 or meta['next_index'] > min(len(items), ABSOLUTE_CVE_CAP)):
        raise ValueError('Invalid seed manifest or frozen cohort checksum')
    if meta.get('scope') != 'PUBLIC_KEV_SELECTED_CVE_NOT_FULL_BACKFILL':
        raise ValueError('Unsafe CVE data scope')
    index = 0
    all_raw: list[tuple[str, bytes]] = []
    total_size = 0
    for sh in meta['shards']:
        if not isinstance(sh, dict) or set(sh) != {'file','start','end','sha256','records','bytes'}:
            raise ValueError('Invalid CVE shard manifest shape')
        if type(sh['start']) is not int or type(sh['end']) is not int or sh['start'] != index or sh['end'] <= index:
            raise ValueError('Missing/overlapping CVE shard index')
        name = f"{sh['start']:04d}-{sh['end']-1:04d}.jsonl"
        if sh['file'] != name or sh['records'] != sh['end']-sh['start']:
            raise ValueError('CVE shard filename/count mismatch')
        path = root / 'shards' / name
        if not path.is_file():
            raise ValueError('Missing persisted CVE shard: ' + name)
        data = path.read_bytes()
        if len(data) > MAX_SHARD_BYTES or len(data) != sh['bytes'] or sha256(data) != sh['sha256']:
            raise ValueError('CVE shard integrity/checksum failed: ' + name)
        total_size += len(data)
        if total_size > MAX_ARCHIVE_BYTES:
            raise ValueError('CVE seed exceeds explicit public Git storage budget')
        rows = data.splitlines()
        if len(rows) != sh['records']:
            raise ValueError('CVE shard count does not match lines')
        for offset, line in enumerate(rows):
            cve = items[index+offset]['cve_id']
            record = json.loads(line)
            all_raw.append((cve, _verify_entry(record, cve)))
        index = sh['end']
    if index != meta['next_index']:
        raise ValueError('CVE seed manifest cursor does not match immutable shards')
    # Any unindexed JSONL files are suspicious (crash/uncommitted garbage).
    known = {sh['file'] for sh in meta['shards']}
    if any(f.name not in known for f in (root / 'shards').glob('*.jsonl')):
        raise ValueError('Untracked CVE source shard found')
    result = {
        'schema_version': SCHEMA,
        'scope': meta['scope'],
        'frozen_cohort_size': len(items),
        'archived_cve_count': index,
        'archive_jsonl_bytes': total_size,
        'completed_shards': len(meta['shards']),
        'cohort_sha256': meta['cohort_sha256'],
        'manifest_sha256': sha256(manifest_path.read_bytes()),
        'integrity': 'ok',
        'full_historical_cve_backfill': False,
    }
    if export_sqlite is not None:
        out = Path(export_sqlite)
        if out.exists():
            out.unlink()
        with closing(connect(out)) as con:
            for cve, raw in all_raw:
                _upsert_cve(con, json.loads(raw), raw, 'verified-kev-selected-cve-seed')
            con.commit()
            check = sqlite_audit(con)
            if check['sqlite_quick_check'] != 'ok' or check['cve_total'] != index:
                raise ValueError('Rebuilt SQLite CVE master-view integrity failure')
            result['sqlite_quick_check'] = check['sqlite_quick_check']
            result['sqlite_cve_count'] = check['cve_total']
        # Prevent a stale leftover write-ahead log from escaping the workspace.
    return result


def run_batch(state_dir: Path, *, batch_size: int = 25, max_total: int = 50,
              fetcher=fetch_record, observed_at: datetime | None = None) -> dict:
    """Append at most one verified, immutable shard; no cursor advance on failure."""
    if type(batch_size) is not int or type(max_total) is not int or not 1 <= batch_size <= 25 or not 1 <= max_total <= ABSOLUTE_CVE_CAP:
        raise ValueError('CVE seed out of bounded fetch or Git storage limits')
    now = observed_at or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError('observed_at must be timezone-aware')
    root = Path(state_dir) / BASE_DIR
    manifest_path, cohort_path = root / MANIFEST_NAME, root / COHORT_NAME
    if manifest_path.is_file() != cohort_path.is_file():
        raise ValueError('Partial persisted CVE seed state; manual investigation required')
    if manifest_path.exists():
        existing = audit_seed(state_dir)
        meta = _read(manifest_path)
        plan = _read(cohort_path)
        items = _check_cohort(plan)
    else:
        kev = _validate_public_kev(Path(state_dir) / 'kev-current.json')
        plan = _plan(kev)
        items = _check_cohort(plan)
        meta = {'schema_version': SCHEMA,
                'scope': 'PUBLIC_KEV_SELECTED_CVE_NOT_FULL_BACKFILL',
                'cohort_sha256': sha256(_canonical(plan)),
                'frozen_at_utc': now.astimezone(timezone.utc).isoformat(timespec='seconds'),
                'next_index': 0, 'shards': []}
        existing = {'archived_cve_count': 0, 'archive_jsonl_bytes': 0}
    start = meta['next_index']
    allowed = min(max_total, len(items), ABSOLUTE_CVE_CAP)
    stop = min(start+batch_size, allowed)
    if start >= allowed:
        result = dict(existing, status='already_at_limit', selected_cap=allowed,
                      no_op=True, new_cve_records=0)
        return result
    lines = []
    for item in items[start:stop]:
        cve = item['cve_id']
        url = cve_url(cve)
        raw = fetcher(url)
        if not isinstance(raw, bytes) or len(raw) > MAX_CVE_BYTES:
            raise ValueError('Official CVE source returned non-bytes or oversized body')
        body = raw.decode('utf-8')
        row = {'cve_id': cve,'source_url': url,'source_sha256': sha256(raw),
               'body_utf8': body}
        _verify_entry(row,cve)
        lines.append(_dump(row))
    shard = ''.join(lines).encode('utf-8')
    if len(shard) > MAX_SHARD_BYTES or existing['archive_jsonl_bytes']+len(shard)>MAX_ARCHIVE_BYTES:
        raise ValueError('CVE source shard exceeds bounded Git-state storage quota')
    name = f'{start:04d}-{stop-1:04d}.jsonl'
    shard_path = root/'shards'/name
    if shard_path.exists():
        raise ValueError('Refusing to overwrite existing source shard')
    newmeta = dict(meta)
    newmeta['next_index'] = stop
    newmeta['shards'] = meta['shards'] + [{
        'file': name, 'start': start,'end': stop,'sha256': sha256(shard),
        'records': stop-start,'bytes': len(shard),
    }]
    # Local transaction: build bytes and validate before writing; remote atomic
    # boundary is a single Git commit containing shard+cursor+cohort.
    root.mkdir(parents=True,exist_ok=True)
    if not cohort_path.exists():
        _atomic_text(cohort_path,_dump(plan))
    _atomic_text(shard_path,shard.decode('utf-8'))
    _atomic_text(manifest_path,_dump(newmeta))
    audit_result = audit_seed(state_dir)
    if audit_result['archived_cve_count'] != stop:
        raise ValueError('Post-write CVE audit failed; do not commit these files')
    return dict(audit_result, status='batch_saved_locally', no_op=False,
                selected_cap=allowed, new_cve_records=stop-start,
                source_note='KEV-linked selected CVEs only; not all CVE IDs')


def main() -> None:
    p = argparse.ArgumentParser(description='Quota-bounded durable official CVE source seed')
    p.add_argument('--state-dir',required=True,type=Path)
    p.add_argument('--out',type=Path,required=True)
    p.add_argument('--batch-size',type=int,default=25)
    p.add_argument('--max-total',type=int,default=50)
    p.add_argument('--audit-only',action='store_true')
    p.add_argument('--export-sqlite',type=Path)
    args=p.parse_args()
    result=(audit_seed(args.state_dir,export_sqlite=args.export_sqlite)
            if args.audit_only else run_batch(args.state_dir,batch_size=args.batch_size,max_total=args.max_total))
    _atomic_text(args.out,_dump(result))
    print(json.dumps(result,ensure_ascii=False,indent=2))


if __name__=='__main__':
    main()
