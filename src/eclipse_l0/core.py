"""PROJECT ECLIPSE L0 — evidence-preserving CVE + CISA KEV collector.

Python standard library only. No scanning, exploitation, or external AI calls.
"""
from __future__ import annotations

import csv
import hashlib
import json
import re
import sqlite3
import zlib
from datetime import datetime, timezone
from pathlib import Path
from zipfile import ZipFile

CVE_ID = re.compile(r'^CVE-\d{4}-\d{4,}$')


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        while chunk := handle.read(4 * 1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def stable_json_hash(obj: object) -> str:
    # Semantic hash: whitespace changes do not create false vulnerability events.
    payload = json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf8')
    return hashlib.sha256(payload).hexdigest()


def connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(db_path), timeout=90)
    con.row_factory = sqlite3.Row
    con.execute('PRAGMA journal_mode=WAL')
    con.execute('PRAGMA foreign_keys=ON')
    con.execute('PRAGMA busy_timeout=90000')
    con.execute('PRAGMA synchronous=FULL')
    con.executescript('''
    CREATE TABLE IF NOT EXISTS objects (
      hash TEXT PRIMARY KEY, payload_zlib BLOB NOT NULL, original_size INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS cve_current (
      cve_id TEXT PRIMARY KEY, record_state TEXT NOT NULL,
      hash TEXT NOT NULL REFERENCES objects(hash),
      date_published TEXT, date_updated TEXT, last_seen TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS cve_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT, cve_id TEXT NOT NULL,
      old_hash TEXT, new_hash TEXT NOT NULL REFERENCES objects(hash),
      observed_at TEXT NOT NULL, source_label TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS ix_cve_events_key ON cve_events(cve_id, id);
    CREATE TABLE IF NOT EXISTS kev_current (
      cve_id TEXT PRIMARY KEY, hash TEXT NOT NULL REFERENCES objects(hash),
      date_added TEXT, present INTEGER NOT NULL CHECK(present IN (0,1)),
      last_seen TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS kev_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT, cve_id TEXT NOT NULL,
      kind TEXT NOT NULL CHECK(kind IN ('added','updated','removed','restored')),
      old_hash TEXT, new_hash TEXT, observed_at TEXT NOT NULL,
      source_label TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS ix_kev_events_key ON kev_events(cve_id, id);
    CREATE TABLE IF NOT EXISTS source_runs (
      source_label TEXT PRIMARY KEY, source_kind TEXT NOT NULL,
      content_sha256 TEXT NOT NULL, started_at TEXT NOT NULL,
      finished_at TEXT, status TEXT NOT NULL, items INTEGER NOT NULL DEFAULT 0
    );
    ''')
    con.commit()
    return con


def _save_object(con: sqlite3.Connection, digest: str, raw: bytes) -> None:
    con.execute('INSERT OR IGNORE INTO objects VALUES (?,?,?)',
                (digest, sqlite3.Binary(zlib.compress(raw, 6)), len(raw)))


def _guard_snapshot_order(con: sqlite3.Connection, label: str, kind: str) -> None:
    """Reject older dated CVE baselines after a newer completed snapshot."""
    if kind != 'cve_full_baseline':
        return
    match = re.search(r'(?<!\d)(\d{4}-\d{2}-\d{2})(?!\d)', label)
    if not match:
        return
    dates = []
    for row in con.execute("SELECT source_label FROM source_runs WHERE source_kind=? AND status='completed'", (kind,)):
        old = re.search(r'(?<!\d)(\d{4}-\d{2}-\d{2})(?!\d)', row['source_label'])
        if old:
            dates.append(old.group(1))
    if dates and match.group(1) < max(dates):
        raise ValueError('Refusing older CVE full baseline after newer completed snapshot')


def _start_run(con: sqlite3.Connection, label: str, kind: str, digest: str) -> bool:
    _guard_snapshot_order(con, label, kind)
    prev = con.execute('SELECT status, content_sha256 FROM source_runs WHERE source_label=?',
                       (label,)).fetchone()
    if prev and prev['status'] == 'completed':
        if prev['content_sha256'] != digest:
            raise ValueError('Source label reused with different content: ' + label)
        return False
    if prev and prev['content_sha256'] != digest:
        raise ValueError('Incomplete source label reused with different content: ' + label)
    con.execute('''INSERT INTO source_runs(source_label,source_kind,content_sha256,started_at,status)
                   VALUES (?,?,?,?, 'running') ON CONFLICT(source_label)
                   DO UPDATE SET started_at=excluded.started_at,status='running' ''',
                (label, kind, digest, utcnow()))
    con.commit()
    return True


def _finish_run(con: sqlite3.Connection, label: str, count: int) -> None:
    con.execute('UPDATE source_runs SET status=?,finished_at=?,items=? WHERE source_label=?',
                ('completed', utcnow(), count, label))
    con.commit()


def _text_description(record: dict) -> str:
    descriptions = ((record.get('containers') or {}).get('cna') or {}).get('descriptions') or []
    for entry in descriptions:
        if isinstance(entry, dict) and entry.get('lang', '').lower().startswith('en'):
            return entry.get('value', '')
    return ''


def _upsert_cve(con: sqlite3.Connection, record: dict, raw: bytes, label: str) -> bool:
    meta = record.get('cveMetadata') or {}
    cve_id = meta.get('cveId', '')
    if not CVE_ID.fullmatch(cve_id):
        raise ValueError('Invalid or missing CVE identifier')
    digest = stable_json_hash(record)
    existing = con.execute('SELECT hash FROM cve_current WHERE cve_id=?', (cve_id,)).fetchone()
    state = str(meta.get('state') or 'UNKNOWN')
    published = meta.get('datePublished')
    updated = meta.get('dateUpdated')
    now = utcnow()
    if existing and existing['hash'] == digest:
        # last_seen reflects collection time, but it is not a vulnerability change.
        con.execute('UPDATE cve_current SET last_seen=? WHERE cve_id=?', (now, cve_id))
        return False
    _save_object(con, digest, raw)
    con.execute('''INSERT INTO cve_current VALUES(?,?,?,?,?,?)
                   ON CONFLICT(cve_id) DO UPDATE SET record_state=excluded.record_state,
                   hash=excluded.hash,date_published=excluded.date_published,
                   date_updated=excluded.date_updated,last_seen=excluded.last_seen''',
                (cve_id, state, digest, published, updated, now))
    con.execute('INSERT INTO cve_events(cve_id,old_hash,new_hash,observed_at,source_label) VALUES(?,?,?,?,?)',
                (cve_id, existing['hash'] if existing else None, digest, now, label))
    return True


def ingest_cve_zip(con: sqlite3.Connection, archive: Path, label: str,
                   min_records: int = 100000, batch_size: int = 500,
                   max_entry_bytes: int = 16 * 1024 * 1024) -> dict:
    """Import a FULL CVE baseline ZIP. Idempotent and restartable after interruption.

    Does not interpret missing ZIP members as CVE deletions. CVE reject state is retained.
    """
    archive = Path(archive)
    with ZipFile(archive) as zf:
        entries = [zi for zi in zf.infolist() if CVE_ID.fullmatch(Path(zi.filename).stem)
                   and zi.filename.endswith('.json') and not zi.is_dir()]
        if len(entries) < min_records:
            raise ValueError(f'Baseline too small ({len(entries)} < {min_records}); refusing ingestion')
        oversized = [zi.filename for zi in entries if zi.file_size > max_entry_bytes]
        if oversized:
            raise ValueError('Oversized CVE JSON entry: ' + oversized[0])
        digest = file_sha256(archive)
        if not _start_run(con, label, 'cve_full_baseline', digest):
            return {'status': 'already_completed', 'entries': len(entries), 'changes': 0}
        count, changes = 0, 0
        try:
            for info in entries:
                raw = zf.read(info)
                record = json.loads(raw)
                if Path(info.filename).stem != (record.get('cveMetadata') or {}).get('cveId'):
                    raise ValueError('CVE file name disagrees with CVE identifier: ' + info.filename)
                changes += bool(_upsert_cve(con, record, raw, label))
                count += 1
                if count % batch_size == 0:
                    con.commit()
            con.commit()
            _finish_run(con, label, count)
        except Exception:
            con.rollback()
            # Previously committed batches remain; re-running replays them idempotently.
            raise
        return {'status': 'completed', 'entries': count, 'changes': changes}


def ingest_kev_json(con: sqlite3.Connection, path: Path, label: str,
                    min_records: int = 1000, max_removed_fraction: float = 0.05) -> dict:
    """Synchronize an entire authoritative KEV catalog, preserving removals as events.

    A sharp reduction in item count is rejected rather than marking everyone removed.
    """
    path = Path(path)
    raw_catalog = path.read_bytes()
    content = json.loads(raw_catalog)
    rows = content.get('vulnerabilities')
    if not isinstance(rows, list) or len(rows) < min_records:
        raise ValueError('KEV catalog missing or suspiciously small')
    if content.get('count') is not None and content['count'] != len(rows):
        raise ValueError('KEV reported count disagrees with vulnerabilities list')
    found = {}
    for row in rows:
        cve_id = row.get('cveID', '') if isinstance(row, dict) else ''
        if not CVE_ID.fullmatch(cve_id) or cve_id in found:
            raise ValueError('Duplicate / malformed KEV entry: ' + str(cve_id))
        found[cve_id] = row
    existing_present = con.execute('SELECT COUNT(*) FROM kev_current WHERE present=1').fetchone()[0]
    # Avoid the SQLite host-variable limit; compute removed IDs on the application side.
    existing_ids = {r['cve_id'] for r in con.execute('SELECT cve_id FROM kev_current WHERE present=1')}
    removed_ids = existing_ids - set(found)
    if existing_present and len(removed_ids) > max(1, int(existing_present * max_removed_fraction)):
        raise ValueError(f'KEV shrank by {len(removed_ids)} entries: rejecting mass removal')
    digest = hashlib.sha256(raw_catalog).hexdigest()
    if not _start_run(con, label, 'kev_full_catalog', digest):
        return {'status': 'already_completed', 'entries': len(found), 'changes': 0}
    changes = 0
    now = utcnow()
    try:
        # Preserve the source catalog as evidence even when its content is only minimally changed.
        _save_object(con, digest, raw_catalog)
        for cve_id, row in found.items():
            raw = json.dumps(row, ensure_ascii=False, sort_keys=True).encode('utf8')
            row_hash = stable_json_hash(row)
            old = con.execute('SELECT hash,present FROM kev_current WHERE cve_id=?',
                              (cve_id,)).fetchone()
            if old and old['hash'] == row_hash and old['present']:
                con.execute('UPDATE kev_current SET last_seen=? WHERE cve_id=?', (now, cve_id))
                continue
            kind = 'added' if not old else ('restored' if not old['present'] else 'updated')
            _save_object(con, row_hash, raw)
            con.execute('''INSERT INTO kev_current VALUES(?,?,?,?,?)
                           ON CONFLICT(cve_id) DO UPDATE SET hash=excluded.hash,
                           date_added=excluded.date_added,present=1,last_seen=excluded.last_seen''',
                        (cve_id, row_hash, row.get('dateAdded'), 1, now))
            con.execute('''INSERT INTO kev_events(cve_id,kind,old_hash,new_hash,observed_at,source_label)
                           VALUES(?,?,?,?,?,?)''',
                        (cve_id, kind, old['hash'] if old else None, row_hash, now, label))
            changes += 1
        for cve_id in removed_ids:
            old_hash = con.execute('SELECT hash FROM kev_current WHERE cve_id=?',
                                   (cve_id,)).fetchone()['hash']
            con.execute('UPDATE kev_current SET present=0,last_seen=? WHERE cve_id=?', (now, cve_id))
            con.execute('''INSERT INTO kev_events(cve_id,kind,old_hash,new_hash,observed_at,source_label)
                           VALUES(?,?,?,?,?,?)''', (cve_id, 'removed', old_hash, None, now, label))
            changes += 1
        con.commit()
        _finish_run(con, label, len(found))
    except Exception:
        con.rollback()
        raise
    return {'status': 'completed', 'entries': len(found), 'changes': changes}


def report(con: sqlite3.Connection) -> dict:
    one = lambda sql: con.execute(sql).fetchone()[0]
    return {
        'cve_total': one('SELECT COUNT(*) FROM cve_current'),
        'cve_published': one("SELECT COUNT(*) FROM cve_current WHERE record_state='PUBLISHED'"),
        'cve_rejected': one("SELECT COUNT(*) FROM cve_current WHERE record_state='REJECTED'"),
        'cve_versions': one('SELECT COUNT(*) FROM cve_events'),
        'kev_present': one('SELECT COUNT(*) FROM kev_current WHERE present=1'),
        'kev_versions': one('SELECT COUNT(*) FROM kev_events'),
        'kev_missing_from_cve': one('''SELECT COUNT(*) FROM kev_current k LEFT JOIN cve_current c
                                      ON c.cve_id=k.cve_id WHERE k.present=1 AND c.cve_id IS NULL'''),
        'source_runs_finished': one("SELECT COUNT(*) FROM source_runs WHERE status='completed'"),
        'source_runs_incomplete': one("SELECT COUNT(*) FROM source_runs WHERE status!='completed'"),
    }


def export_current(con: sqlite3.Connection, output_path: Path) -> int:
    """Operational TSV-free CSV. No risk decisions are fabricated in L0."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    query = '''SELECT c.cve_id,c.record_state,c.date_published,c.date_updated,c.hash,
                coalesce(k.present,0) AS kev_present,k.date_added AS kev_date_added
               FROM cve_current c LEFT JOIN kev_current k ON c.cve_id=k.cve_id ORDER BY c.cve_id'''
    count = 0
    with output_path.open('w', newline='', encoding='utf-8-sig') as handle:
        writer = csv.writer(handle)
        writer.writerow(['cve_id','state','date_published','date_updated','content_hash','kev_present','kev_date_added'])
        for row in con.execute(query):
            writer.writerow(list(row))
            count += 1
    return count


def get_original(con: sqlite3.Connection, object_hash: str) -> bytes:
    row = con.execute('SELECT payload_zlib FROM objects WHERE hash=?', (object_hash,)).fetchone()
    if not row:
        raise KeyError(object_hash)
    return zlib.decompress(row[0])


def audit(con: sqlite3.Connection) -> dict:
    """Structural integrity; not an independent source reconciliation."""
    integrity = con.execute('PRAGMA quick_check').fetchone()[0]
    results = report(con)
    results.update({
        'sqlite_quick_check': integrity,
        'missing_cve_objects': con.execute('SELECT COUNT(*) FROM cve_current c LEFT JOIN objects o ON c.hash=o.hash WHERE o.hash IS NULL').fetchone()[0],
        'missing_kev_objects': con.execute('SELECT COUNT(*) FROM kev_current k LEFT JOIN objects o ON k.hash=o.hash WHERE o.hash IS NULL').fetchone()[0]
    })
    if integrity != 'ok' or results['missing_cve_objects'] or results['missing_kev_objects']:
        raise RuntimeError('Database structural audit failed: ' + json.dumps(results))
    return results


def export_kev_catalog(con: sqlite3.Connection, output_path: Path) -> dict:
    """Export the most recent *completed* authoritative raw CISA catalog.

    Retains the official bytes and metadata for reproducible report manifests.
    """
    row = con.execute(
        "SELECT content_sha256, source_label FROM source_runs "
        "WHERE source_kind='kev_full_catalog' AND status='completed' "
        "ORDER BY rowid DESC LIMIT 1"
    ).fetchone()
    if not row:
        raise ValueError('No completed KEV source run; cannot produce report')
    content = get_original(con, row['content_sha256'])
    if hashlib.sha256(content).hexdigest() != row['content_sha256']:
        raise RuntimeError('Corrupt KEV original catalog hash')
    parsed = json.loads(content)
    if len(parsed.get('vulnerabilities') or []) != con.execute(
        'SELECT COUNT(*) FROM kev_current WHERE present=1').fetchone()[0]:
        raise RuntimeError('KEV catalog / current-table count mismatch')
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(content)
    return {'sha256': row['content_sha256'], 'source_label': row['source_label'],
            'count': len(parsed['vulnerabilities'])}
