"""Complete, restartable CVE SQLite warehouse built from a pinned PRIVATE Kaggle archive.

No customer information. Preserves the original JSON bodies and source provenance.
KEV and EPSS are distinct evidence sources, not proof of customer compromise.
"""
from __future__ import annotations

import argparse
import subprocess
import time
import csv
import gzip
import hashlib
import io
import json
import math
import re
import sqlite3
import urllib.request
import zipfile
from datetime import datetime, timezone
from itertools import chain
from pathlib import Path

from .core import CVE_ID, _upsert_cve, audit, connect, ingest_kev_json, report
from .full_baseline import sha, write_json
from .kaggle_full import SHARD, INDEX_FILE

# Pinned and independently read-back verified on 2026-10-10. No mutable 'latest'.
SOURCE_INDEX_SHA256 = '1b19b50fedb034390463a68222948b365f6b6dc39dcd1904218dd880abe504d2'
SOURCE_SHA256 = '727c63047df02ffb00c63812c82dcae20512c42c786be4b36c7630be30cb79c1'
SOURCE_COUNT = 403696
SOURCE_SHARDS = 162
KEV_URL = 'https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json'
EPSS_URL = 'https://epss.empiricalsecurity.com/epss_scores-current.csv.gz'
DB_PART_SIZE = 64 * 1024 * 1024
MAX_SHARD_BYTES = 200 * 1024 * 1024
MAX_CVE_BYTES = 16 * 1024 * 1024
MAX_DB_SIZE = 9 * 1024 * 1024 * 1024


def check_index(root: Path, expected_sha: str = SOURCE_INDEX_SHA256,
                expected_count: int = SOURCE_COUNT, expected_shards: int = SOURCE_SHARDS,
                expected_source: str = SOURCE_SHA256) -> dict:
    """Trusted Git-pinned digest, NOT a hash obtained from the Kaggle server itself."""
    p = root / INDEX_FILE
    if not p.is_file() or sha(p) != expected_sha:
        raise ValueError('CVE index does not match independent trusted digest')
    index = json.loads(p.read_text(encoding='utf-8'))
    specs = index.get('files')
    if (index.get('schema_version') != 1 or index.get('scope') != 'OFFICIAL_CVE_V5_FULL_SNAPSHOT'
            or index.get('source_sha256') != expected_source or index.get('record_count') != expected_count
            or index.get('shard_count') != expected_shards or not isinstance(specs, dict)
            or len(specs) != expected_shards):
        raise ValueError('Pinned CVE source/coverage mismatch')
    for name, info in specs.items():
        if (not SHARD.fullmatch(name) or not isinstance(info, dict)
                or type(info.get('records')) is not int or not 1 <= info['records'] <= 2500
                or type(info.get('bytes')) is not int or not 0 < info['bytes'] <= MAX_SHARD_BYTES
                or not isinstance(info.get('sha256'), str) or not re.fullmatch('[0-9a-f]{64}', info['sha256'])):
            raise ValueError('Malformed source shard specification')
    if sum(s['records'] for s in specs.values()) != expected_count:
        raise ValueError('Incorrect source member coverage')
    m = root / 'manifest.json'
    if not m.exists() or sha(m) != index.get('manifest_sha256'):
        raise ValueError('Original source manifest missing or changed')
    manifest = json.loads(m.read_text(encoding='utf-8'))
    if (manifest.get('status') != 'VERIFIED_FULL_SOURCE_BYTES_STAGED_NOT_KAGGLE_VERIFIED'
            or manifest.get('limit') is not None
            or manifest.get('cve_member_count') != expected_count
            or {s['file'] for s in manifest['shards']} != set(specs)):
        raise ValueError('Source was not complete as verified')
    return index


def _english(record: dict) -> tuple[str | None, str | None]:
    cna = (record.get('containers') or {}).get('cna') or {}
    title = cna.get('title') if isinstance(cna.get('title'), str) else None
    for desc in cna.get('descriptions') or []:
        if isinstance(desc, dict) and str(desc.get('lang','')).lower().startswith('en'):
            text = desc.get('value')
            if isinstance(text, str):
                return title, text
    return title, None


def _score(record: dict) -> tuple[float | None, str | None, str | None]:
    # CNA-only CVSS assertion, never synthesise severity from an EPSS score.
    cna = (record.get('containers') or {}).get('cna') or {}
    for metric in cna.get('metrics') or []:
        if not isinstance(metric, dict):
            continue
        for key in ('cvssV4_0','cvssV3_1','cvssV3_0','cvssV2_0'):
            obj = metric.get(key)
            if not isinstance(obj, dict):
                continue
            try:
                score = float(obj['baseScore'])
            except (KeyError, ValueError, TypeError):
                continue
            if math.isfinite(score) and 0 <= score <= 10:
                return score, key, obj.get('baseSeverity') if isinstance(obj.get('baseSeverity'), str) else None
    return None, None, None


def _affected(record: dict):
    containers = record.get('containers') or {}
    for source, obj in [('cna', containers.get('cna'))] + [
            (f'adp:{i}', v) for i, v in enumerate(containers.get('adp') or [])]:
        if not isinstance(obj, dict):
            continue
        for ordinal, row in enumerate(obj.get('affected') or []):
            if not isinstance(row, dict):
                continue
            vendor = row.get('vendor') if isinstance(row.get('vendor'), str) else None
            product = row.get('product') if isinstance(row.get('product'), str) else None
            # Preserve upstream version predicates unaltered, including versionType/lessThan.
            versions = row.get('versions')
            yield (source, ordinal, vendor, product,
                   vendor.strip().casefold() if vendor else None,
                   product.strip().casefold() if product else None,
                   row.get('defaultStatus') if isinstance(row.get('defaultStatus'), str) else None,
                   json.dumps(versions, ensure_ascii=False, separators=(',', ':')) if versions is not None else None)


def _schema(con: sqlite3.Connection) -> None:
    con.executescript('''
    CREATE TABLE IF NOT EXISTS warehouse_shard_progress (
        shard TEXT PRIMARY KEY, sha256 TEXT NOT NULL, rows INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS warehouse_summary (
        cve_id TEXT PRIMARY KEY REFERENCES cve_current(cve_id), title TEXT,
        description_en TEXT, cvss_score REAL, cvss_kind TEXT, cvss_severity TEXT);
    CREATE TABLE IF NOT EXISTS warehouse_affected (
        cve_id TEXT NOT NULL REFERENCES cve_current(cve_id), container TEXT NOT NULL,
        ordinal INTEGER NOT NULL, vendor TEXT, product TEXT,
        vendor_norm TEXT, product_norm TEXT, default_status TEXT, versions_json TEXT,
        PRIMARY KEY (cve_id,container,ordinal));
    CREATE INDEX IF NOT EXISTS ix_warehouse_vendor_product ON warehouse_affected(vendor_norm,product_norm,cve_id);
    CREATE INDEX IF NOT EXISTS ix_warehouse_product ON warehouse_affected(product_norm,cve_id);
    CREATE INDEX IF NOT EXISTS ix_cve_publish ON cve_current(date_published);
    CREATE INDEX IF NOT EXISTS ix_cve_update ON cve_current(date_updated);
    CREATE TABLE IF NOT EXISTS warehouse_epss (
        cve_id TEXT PRIMARY KEY, probability REAL NOT NULL CHECK(probability BETWEEN 0 AND 1),
        percentile REAL NOT NULL CHECK(percentile BETWEEN 0 AND 1));
    CREATE TABLE IF NOT EXISTS warehouse_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
    ''')
    con.commit()


def _meta(con: sqlite3.Connection, key: str, value: object) -> None:
    con.execute('INSERT OR REPLACE INTO warehouse_metadata VALUES (?,?)',
                (key, json.dumps(value, ensure_ascii=False, sort_keys=True)))


def ingest_verified_shards(root: Path, db_path: Path, *,
                          expected_index_sha: str = SOURCE_INDEX_SHA256,
                          expected_count: int = SOURCE_COUNT,
                          expected_shards: int = SOURCE_SHARDS,
                          expected_source: str = SOURCE_SHA256,
                          progress=None) -> dict:
    index = check_index(root, expected_index_sha, expected_count, expected_shards, expected_source)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    con = connect(db_path)
    try:
        _schema(con)
        _meta(con,'source_index_sha256',expected_index_sha)
        _meta(con,'source_archive_sha256',expected_source)
        _meta(con,'expected_cve_count',expected_count)
        con.commit()
        # One shard is a single atomic transaction. Resume skips ONLY complete shards.
        for n,(name,spec) in enumerate(sorted(index['files'].items()),1):
            p=root/name
            if not p.is_file() or p.stat().st_size != spec['bytes'] or sha(p)!=spec['sha256']:
                raise ValueError('Absent or corrupt CVE shard: '+name)
            old=con.execute('SELECT sha256,rows FROM warehouse_shard_progress WHERE shard=?',(name,)).fetchone()
            if old:
                if old['sha256'] != spec['sha256'] or old['rows'] != spec['records']:
                    raise ValueError('Shard checkpoint mismatch: '+name)
                if progress: progress(n,name,True)
                continue
            with zipfile.ZipFile(p) as z:
                infos=z.infolist()
                if len(infos)!=spec['records']:
                    raise ValueError('ZIP member count differs: '+name)
                seen=set()
                con.execute('BEGIN IMMEDIATE')
                try:
                    for info in infos:
                        cve=info.filename[:-5] if info.filename.endswith('.json') else ''
                        if (not CVE_ID.fullmatch(cve) or info.filename!=cve+'.json'
                                or cve in seen or not 0 < info.file_size <= MAX_CVE_BYTES):
                            raise ValueError('Unsafe, duplicate, or missing CVE in '+name)
                        seen.add(cve)
                        raw=z.read(info)  # zip CRC verified by read
                        record=json.loads(raw)
                        if (record.get('cveMetadata') or {}).get('cveId')!=cve:
                            raise ValueError('Record does not match filename: '+cve)
                        _upsert_cve(con,record,raw,'OFFICIAL_CVE_2026-10-10_PINNED')
                        title,description=_english(record)
                        score,kind,severity=_score(record)
                        con.execute('''INSERT OR REPLACE INTO warehouse_summary VALUES (?,?,?,?,?,?)''',
                                    (cve,title,description,score,kind,severity))
                        for row in _affected(record):
                            con.execute('INSERT OR REPLACE INTO warehouse_affected VALUES (?,?,?,?,?,?,?,?,?)',
                                        (cve,*row))
                    con.execute('INSERT INTO warehouse_shard_progress VALUES (?,?,?)',
                                (name,spec['sha256'],len(seen)))
                    con.commit()
                except BaseException:
                    con.rollback()
                    raise
            if n%10==0:
                con.execute('PRAGMA wal_checkpoint(TRUNCATE)')
            if progress: progress(n,name,False)
        counts=report(con)
        coverage=con.execute('SELECT COUNT(*),COALESCE(SUM(rows),0) FROM warehouse_shard_progress').fetchone()
        if (counts['cve_total']!=expected_count or counts['cve_versions']!=expected_count
                or tuple(coverage)!=(expected_shards,expected_count)
                or con.execute('SELECT COUNT(*) FROM warehouse_summary').fetchone()[0]!=expected_count):
            raise ValueError('Full CVE coverage/checkpoints differ from trusted source')
        audited=audit(con)
        if audited['sqlite_quick_check']!='ok':
            raise ValueError('SQLite consistency failed')
        _meta(con,'cve_full_ingest_verified',True)
        con.commit()
        return {'cve_count':expected_count,'shards':expected_shards,
                'summary_count':expected_count,'affected_rows':con.execute('SELECT COUNT(*) FROM warehouse_affected').fetchone()[0],
                'sqlite_quick_check':audited['sqlite_quick_check']}
    finally:
        con.close()


def bounded_download(url: str, dest: Path, max_bytes: int) -> str:
    allowed={KEV_URL,EPSS_URL}
    if url not in allowed:
        raise ValueError('Non-authoritative source URL')
    dest.parent.mkdir(parents=True,exist_ok=True)
    tmp=dest.with_suffix(dest.suffix+'.part')
    digest=hashlib.sha256()
    try:
        req=urllib.request.Request(url,headers={'User-Agent':'PROJECT-ECLIPSE-WAREHOUSE/1.0'})
        with urllib.request.urlopen(req,timeout=90) as inp, tmp.open('wb') as out:
            n=0
            while chunk:=inp.read(1024*1024):
                n+=len(chunk)
                if n>max_bytes: raise ValueError('Source exceeds approved byte budget')
                digest.update(chunk)
                out.write(chunk)
        tmp.replace(dest)
    finally:
        tmp.unlink(missing_ok=True)
    return digest.hexdigest()


def enrich_kev(con: sqlite3.Connection, path: Path) -> dict:
    res=ingest_kev_json(con,path,'CISA-KEV-'+sha(path)[:16],min_records=1000)
    _meta(con,'kev_source_sha256',sha(path))
    _meta(con,'kev_source_record_count',res['entries'])
    con.commit()
    return {'source_sha256':sha(path),'feed_rows':res['entries'],'cve_join_rows':con.execute('''
        SELECT COUNT(*) FROM kev_current k JOIN cve_current c ON c.cve_id=k.cve_id WHERE k.present=1''').fetchone()[0],
        'feed_missing_from_cve':con.execute('''
        SELECT COUNT(*) FROM kev_current k LEFT JOIN cve_current c ON c.cve_id=k.cve_id
        WHERE k.present=1 AND c.cve_id IS NULL''').fetchone()[0]}


def enrich_epss(con: sqlite3.Connection, gz_path: Path, min_rows: int=200000) -> dict:
    """Snapshot ALL official EPSS rows (including CVEs not in the pinned CVE archive)."""
    feed_hash=sha(gz_path)
    rows=0
    seen=set()
    timestamp=None
    con.execute('BEGIN IMMEDIATE')
    try:
        con.execute('DELETE FROM warehouse_epss')
        with gzip.open(gz_path,'rt',encoding='utf-8-sig',newline='') as f:
            comments=[]
            while True:
                line=f.readline()
                if not line: raise ValueError('Missing EPSS CSV header')
                if not line.startswith('#'): break
                comments.append(line)
            reader=csv.DictReader(chain([line],f))
            if not {'cve','epss','percentile'} <= set(reader.fieldnames or []):
                raise ValueError('EPSS schema changed')
            for row in reader:
                cve=row.get('cve','')
                if not CVE_ID.fullmatch(cve) or cve in seen:
                    raise ValueError('Malformed or duplicate EPSS CVE')
                seen.add(cve)
                try:
                    prob=float(row['epss']);pct=float(row['percentile'])
                except (TypeError,ValueError) as exc:
                    raise ValueError('Non-numeric EPSS') from exc
                if not(math.isfinite(prob) and math.isfinite(pct) and 0<=prob<=1 and 0<=pct<=1):
                    raise ValueError('EPSS value out of range')
                con.execute('INSERT INTO warehouse_epss VALUES (?,?,?)',(cve,prob,pct))
                rows+=1
            meta={}
            for item in comments:
                for entry in item.lstrip('#').split(','):
                    key,sep,val=entry.strip().partition(':')
                    if sep and key.strip().lower() in ('score_date','model_version'):
                        meta[key.strip().lower()]=val.strip()
            timestamp=meta.get('score_date')
            if not timestamp:
                raise ValueError('EPSS score_date missing')
            d=datetime.fromisoformat(timestamp.replace('Z','+00:00'))
            if d.tzinfo is None or d > datetime.now(timezone.utc).replace(hour=23,minute=59,second=59):
                raise ValueError('EPSS score date invalid or in future')
            if rows<min_rows: raise ValueError('EPSS feed appears truncated')
            _meta(con,'epss_source_sha256',feed_hash)
            _meta(con,'epss_score_date',timestamp)
            _meta(con,'epss_model_version',meta.get('model_version'))
            _meta(con,'epss_feed_count',rows)
        con.commit()
    except BaseException:
        con.rollback()
        raise
    return {'source_sha256':feed_hash,'score_date':timestamp,'feed_rows':rows,
            'cve_join_rows':con.execute('SELECT COUNT(*) FROM warehouse_epss e JOIN cve_current c USING(cve_id)').fetchone()[0]}


def verify_database(path: Path, index: dict | None=None, *, expected_count: int=SOURCE_COUNT) -> dict:
    con=sqlite3.connect(f'file:{path.as_posix()}?mode=ro',uri=True)
    try:
        complete=con.execute('PRAGMA integrity_check').fetchone()[0]
        foreign=con.execute('PRAGMA foreign_key_check').fetchall()
        counts={
          'cve':con.execute('SELECT COUNT(*) FROM cve_current').fetchone()[0],
          'events':con.execute('SELECT COUNT(*) FROM cve_events').fetchone()[0],
          'summary':con.execute('SELECT COUNT(*) FROM warehouse_summary').fetchone()[0],
          'shards':con.execute('SELECT COUNT(*) FROM warehouse_shard_progress').fetchone()[0],
          'shard_rows':con.execute('SELECT SUM(rows) FROM warehouse_shard_progress').fetchone()[0],
          'affected':con.execute('SELECT COUNT(*) FROM warehouse_affected').fetchone()[0],
          'kev':con.execute('SELECT COUNT(*) FROM kev_current WHERE present=1').fetchone()[0],
          'epss':con.execute('SELECT COUNT(*) FROM warehouse_epss').fetchone()[0],
        }
        meta={k:json.loads(v) for k,v in con.execute('SELECT key,value FROM warehouse_metadata')}
        if (complete!='ok' or foreign or counts['cve']!=expected_count or
            counts['events']!=expected_count or counts['summary']!=expected_count or
            counts['shard_rows']!=expected_count or not meta.get('cve_full_ingest_verified') or
            (expected_count==SOURCE_COUNT and meta.get('source_archive_sha256')!=SOURCE_SHA256)):
            raise ValueError('Warehouse integrity / source coverage mismatch')
        if index and (counts!=index['table_counts'] or
                meta['source_index_sha256']!=index['source_index_sha256'] or
                meta.get('kev_source_sha256')!=index['kev_source_sha256'] or
                meta.get('epss_source_sha256')!=index['epss_source_sha256']):
            raise ValueError('Returned warehouse metadata differs from trusted index')
        return {'integrity_check':complete,'foreign_key_errors':len(foreign),
                'table_counts':counts,'source_index_sha256':meta['source_index_sha256'],
                'kev_source_sha256':meta.get('kev_source_sha256'),
                'epss_source_sha256':meta.get('epss_source_sha256'),
                'epss_score_date':meta.get('epss_score_date')}
    finally:
        con.close()


def split_sqlite(db: Path, out: Path, info: dict, *, part_bytes: int=DB_PART_SIZE) -> dict:
    if not 1024 <= part_bytes <= 128*1024*1024 or db.stat().st_size>MAX_DB_SIZE:
        raise ValueError('SQLite file exceeds safe packaging bounds')
    # A successful query against WAL-backed SQLite does NOT mean the main .sqlite
    # bytes include recent committed rows. Checkpoint before splitting raw bytes.
    checkpoint=sqlite3.connect(db)
    try:
        state=checkpoint.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone()
        if state[0]!=0 or state[1]!=state[2]:
            raise ValueError('Unable to checkpoint SQLite WAL before export')
    finally:
        checkpoint.close()
    if db.with_name(db.name+'-wal').exists() and db.with_name(db.name+'-wal').stat().st_size:
        raise ValueError('SQLite WAL is not empty at packaging')
    out.mkdir(parents=True,exist_ok=True)
    parts=[];total=0;h=hashlib.sha256()
    with db.open('rb') as f:
        i=0
        while chunk:=f.read(part_bytes):
            name=f'part-{i:04d}.dbpart'
            p=out/name
            p.write_bytes(chunk)
            digest=hashlib.sha256(chunk).hexdigest()
            parts.append({'name':name,'bytes':len(chunk),'sha256':digest})
            h.update(chunk);total+=len(chunk);i+=1
    idx={'schema_version':1,'scope':'ECLIPSE_CVE_SQLITE_20261010',
         'source_index_sha256':SOURCE_INDEX_SHA256,
         'source_sha256':SOURCE_SHA256,'sqlite_sha256':h.hexdigest(),
         'sqlite_bytes':total,'part_count':len(parts),'parts':parts,
         'table_counts':info['table_counts'],
         'kev_source_sha256':info['kev_source_sha256'],
         'epss_source_sha256':info['epss_source_sha256'],
         'epss_score_date':info['epss_score_date'],
         'evidence_files':{}}
    if not (parts and total==db.stat().st_size):raise ValueError('Missing SQLite parts')
    write_json(out/'warehouse-index.json',idx)
    return idx


def restore_parts(root: Path, dest: Path, trusted: dict,
                  *, expected_count: int=SOURCE_COUNT) -> dict:
    parts=trusted['parts']
    if (trusted.get('schema_version')!=1 or trusted.get('scope')!='ECLIPSE_CVE_SQLITE_20261010'
            or trusted.get('source_index_sha256')!=SOURCE_INDEX_SHA256
            or trusted.get('source_sha256')!=SOURCE_SHA256
            or len(parts)!=trusted.get('part_count')
            or not 1 <= len(parts) <= 300):
        raise ValueError('Untrusted warehouse index schema')
    if dest.exists():raise ValueError('Refuse to overwrite restored SQLite')
    evidence=trusted.get('evidence_files')
    if not isinstance(evidence,dict) or set(evidence)!={'kev-original.payload','epss-original.payload'}:
        raise ValueError('Provenance source file manifest is missing')
    for name,info in evidence.items():
        p=root/name
        if (not p.is_file() or p.is_symlink() or p.stat().st_size!=info['bytes']
                or sha(p)!=info['sha256']):
            raise ValueError('Failed authoritative source evidence validation: '+name)
    if evidence['kev-original.payload']['sha256']!=trusted['kev_source_sha256'] or evidence['epss-original.payload']['sha256']!=trusted['epss_source_sha256']:
        raise ValueError('Evidence SHA differs from warehouse metadata')
    dest.parent.mkdir(parents=True,exist_ok=True)
    h=hashlib.sha256();written=0
    try:
        with dest.open('xb') as out:
            for i,part in enumerate(parts):
                name=part.get('name')
                if name!=f'part-{i:04d}.dbpart':raise ValueError('Parts out of order')
                p=root/name
                if (not p.is_file() or p.is_symlink() or p.stat().st_size!=part['bytes']
                        or sha(p)!=part['sha256']):
                    raise ValueError('Missing/altered restored warehouse part: '+name)
                with p.open('rb') as inp:
                    while chunk:=inp.read(1024*1024):
                        written+=len(chunk);h.update(chunk);out.write(chunk)
        if written!=trusted['sqlite_bytes'] or h.hexdigest()!=trusted['sqlite_sha256']:
            raise ValueError('Restored SQLite differs from trusted digest')
        return verify_database(dest,trusted,expected_count=expected_count)
    except BaseException:
        dest.unlink(missing_ok=True)
        raise



def _fetch_small_metadata(ref: str, dest: Path, name: str, digest: str, max_size: int=2*1024*1024) -> None:
    """Read exactly one small file from Kaggle, without trusting server-provided checksums."""
    if name not in (INDEX_FILE,'manifest.json','kev-original.payload','epss-original.payload') or not re.fullmatch('[0-9a-f]{64}',digest):
        raise ValueError('Untrusted Kaggle metadata request')
    dest.mkdir(parents=True,exist_ok=True)
    p=dest/name
    if p.is_file() and p.stat().st_size<=max_size and sha(p)==digest:
        return
    if p.exists():p.unlink()
    for attempt in range(4):
        try:
            res=subprocess.run(['kaggle','datasets','download',ref,'--file',name,
                      '--path',str(dest),'--unzip','--force','--quiet'],
                      capture_output=True,text=True,timeout=120)
            if res.returncode==0 and p.is_file() and not p.is_symlink() and 0<p.stat().st_size<=max_size:
                if sha(p)!=digest:
                    raise ValueError('Kaggle metadata hash differs from pinned checksum')
                return
        except subprocess.TimeoutExpired:
            pass
        if p.exists():p.unlink()
        if attempt<3:time.sleep((3,8,15)[attempt])
    raise RuntimeError('Kaggle targeted metadata download failed: '+name)


def download_cve_source(ref: str, dest: Path) -> dict:
    """New runner rebuild: GET every recorded shard from PRIVATE source Kaggle dataset."""
    from .kaggle_readback import check_ref, fetch_one
    check_ref(ref)
    _fetch_small_metadata(ref,dest,INDEX_FILE,SOURCE_INDEX_SHA256)
    index=json.loads((dest/INDEX_FILE).read_text(encoding='utf-8'))
    manifest_hash=index.get('manifest_sha256','')
    _fetch_small_metadata(ref,dest,'manifest.json',manifest_hash)
    check_index(dest)
    for i,(name,spec) in enumerate(sorted(index['files'].items()),1):
        fetch_one(ref,name,spec['sha256'],spec['bytes'],dest)
        if i%25==0 or i==len(index['files']):
            print(f'KAGGLE_CVE_SHARDS_DOWNLOADED={i}/{len(index["files"])}',flush=True)
    return index


def download_warehouse_parts(ref: str, dest: Path, trusted: dict) -> None:
    if not re.fullmatch('[A-Za-z0-9_-]+/eclipse-cve-warehouse-20261010-v1',ref):
        raise ValueError('Unexpected warehouse dataset reference')
    if len(trusted.get('parts',[]))!=trusted.get('part_count') or not 1<=trusted['part_count']<=300:
        raise ValueError('Unexpected trusted parts index')
    dest.mkdir(parents=True,exist_ok=True)
    for name,info in trusted['evidence_files'].items():
        if name not in ('kev-original.payload','epss-original.payload'):
            raise ValueError('Untrusted evidence filename')
        _fetch_small_metadata(ref,dest,name,info['sha256'],max_size=100*1024*1024)
    for i,spec in enumerate(trusted['parts']):
        name=spec.get('name')
        if name!=f'part-{i:04d}.dbpart' or spec.get('bytes',0)>DB_PART_SIZE:
            raise ValueError('Unsafe database part description')
        p=dest/name
        for attempt in range(4):
            try:
                cmd=['kaggle','datasets','download',ref,'--file',name,'--path',str(dest),
                     '--unzip','--force','--quiet']
                r=subprocess.run(cmd,capture_output=True,text=True,timeout=150)
                if (r.returncode==0 and p.is_file() and not p.is_symlink()
                        and p.stat().st_size==spec['bytes'] and sha(p)==spec['sha256']):
                    break
                if p.exists() and p.stat().st_size==spec['bytes'] and sha(p)!=spec['sha256']:
                    raise ValueError('Corrupt Kaggle SQLite part: '+name)
            except subprocess.TimeoutExpired:
                pass
            if p.exists():p.unlink()
            if attempt==3:raise RuntimeError('Kaggle part unavailable: '+name)
            time.sleep((3,8,15)[attempt])
        if (i+1)%20==0 or i+1==len(trusted['parts']):
            print(f'SQLITE_PARTS_READ_BACK={i+1}/{len(trusted["parts"])}',flush=True)

def main():
    p=argparse.ArgumentParser()
    sub=p.add_subparsers(dest='command',required=True)
    b=sub.add_parser('build')
    b.add_argument('--source-dir',type=Path,required=True)
    b.add_argument('--workdir',type=Path,required=True)
    b.add_argument('--source-ref',required=False)
    v=sub.add_parser('restore')
    v.add_argument('--parts-dir',type=Path,required=True)
    v.add_argument('--out',type=Path,required=True)
    v.add_argument('--trusted-index',type=Path,required=True)
    v.add_argument('--dataset-ref',required=False)
    args=p.parse_args()
    if args.command=='build':
        if args.source_ref:
            download_cve_source(args.source_ref,args.source_dir)
        db=args.workdir/'warehouse.sqlite3'
        def progress(n,name,resumed):
            if n%20==0 or n==SOURCE_SHARDS:print(f'SQLITE_SHARDS_VERIFIED={n}/{SOURCE_SHARDS}',flush=True)
        out=ingest_verified_shards(args.source_dir,db,progress=progress)
        kev=args.workdir/'kev-official.json'
        epss=args.workdir/'epss-official.csv.gz'
        bounded_download(KEV_URL,kev,25*1024*1024)
        bounded_download(EPSS_URL,epss,100*1024*1024)
        con=connect(db)
        try:
            kr=enrich_kev(con,kev)
            er=enrich_epss(con,epss)
            con.execute('PRAGMA wal_checkpoint(TRUNCATE)')
        finally:con.close()
        proof=verify_database(db)
        idx=split_sqlite(db,args.workdir/'upload',proof)
        # Preserve the exact KEV/EPSS input bytes as opaque payloads as well.
        import shutil
        for key,src,name in [('kev',kev,'kev-original.payload'),
                             ('epss',epss,'epss-original.payload')]:
            dest=args.workdir/'upload'/name
            shutil.copyfile(src,dest)
            idx['evidence_files'][name]={'bytes':dest.stat().st_size,'sha256':sha(dest)}
        write_json(args.workdir/'upload/warehouse-index.json',idx)
        write_json(args.workdir/'build-receipt.json',{'result':'FULL_CVE_SQLITE_BUILT_NOT_YET_STORED',
                   **proof,'source_cve_count':out['cve_count'],
                   'source_shards':out['shards'],'warehouse_index_sha256':sha(args.workdir/'upload/warehouse-index.json'),
                   'sqlite_bytes':idx['sqlite_bytes']})
        print(json.dumps({'result':'FULL_CVE_SQLITE_BUILT_NOT_YET_STORED',
                          'counts':proof['table_counts'],'sqlite_bytes':idx['sqlite_bytes'],
                          'parts':idx['part_count']},sort_keys=True))
    else:
        trusted=json.loads(args.trusted_index.read_text(encoding='utf-8'))
        if args.dataset_ref:
            download_warehouse_parts(args.dataset_ref,args.parts_dir,trusted)
        proof=restore_parts(args.parts_dir,args.out,trusted)
        print(json.dumps({'result':'INDEPENDENT_SQLITE_RESTORE_VERIFIED',**proof},sort_keys=True))

if __name__=='__main__':main()
