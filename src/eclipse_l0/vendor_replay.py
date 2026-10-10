"""Verify and restore short-lived GitHub Actions vendor pilot state across runs.

This is NOT durable storage: Actions artifacts expire after 7 days. Missing prior
state MUST fail closed instead of silently creating a second 'first' baseline.
Keep this independent of the separate CVE/Kaggle database and customers.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
from urllib.parse import urlsplit

from .vendor_registry import load_registry

MAX_DB_BYTES = 50 * 1024 * 1024
MAX_ROWS = 10000
HEX = re.compile(r"^[0-9a-f]{64}$")


def _sha(path: Path) -> str:
    digest=hashlib.sha256()
    with Path(path).open("rb") as handle:
        while block:=handle.read(1024*1024):
            digest.update(block)
    return digest.hexdigest()


def inspect_db(path: Path, registry: dict) -> dict:
    """Read-only integrity/provenance audit. Never modifies incoming DB."""
    file=Path(path)
    if not file.is_file() or file.is_symlink() or not (1 <= file.stat().st_size <= MAX_DB_BYTES):
        raise ValueError("Missing, symlinked or oversized previous vendor SQLite state")
    known={row["source_id"]:row for row in registry["sources"]
           if row["verification_status"]=="read_parse_verified"}
    uri=file.resolve().as_uri()+"?mode=ro"
    db=sqlite3.connect(uri,uri=True)
    db.row_factory=sqlite3.Row
    try:
        db.execute("PRAGMA query_only=ON")
        db.execute("PRAGMA foreign_keys=ON")
        check=db.execute("PRAGMA quick_check").fetchone()
        if not check or check[0]!="ok":
            raise ValueError("SQLite integrity check failed")
        if db.execute("PRAGMA foreign_key_check").fetchone():
            raise ValueError("SQLite foreign key validation failed")
        tables={row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        required={"vendor_documents","vendor_document_versions","vendor_document_events"}
        if not required.issubset(tables):
            raise ValueError("Previous vendor state missing required ledger tables")
        dcount=db.execute("SELECT COUNT(*) FROM vendor_documents").fetchone()[0]
        vcount=db.execute("SELECT COUNT(*) FROM vendor_document_versions").fetchone()[0]
        ecount=db.execute("SELECT COUNT(*) FROM vendor_document_events").fetchone()[0]
        if not (0 <= dcount <= vcount <= MAX_ROWS and 0 <= ecount <= MAX_ROWS):
            raise ValueError("Impossible ledger counts")
        sources={}
        for row in db.execute("""SELECT source_id,advisory_id,source_url,current_facts_sha,
                         current_source_sha,first_observed_utc,last_observed_utc
                         FROM vendor_documents"""):
            sid=row["source_id"]
            item=known.get(sid)
            if item is None:
                raise ValueError("Previous database contains unverified publisher source")
            p=urlsplit(row["source_url"])
            if p.scheme!="https" or p.hostname not in item["allowed_hosts"] or p.username or p.password:
                raise ValueError("Previous database contains nonofficial publisher URL")
            for field in ("current_facts_sha","current_source_sha"):
                if not HEX.fullmatch(row[field]):
                    raise ValueError("Invalid source/facts hash in previous database")
            latest=db.execute("""SELECT facts_sha256,source_sha256,version,observed_utc FROM
                vendor_document_versions WHERE source_id=? AND advisory_id=?
                ORDER BY version DESC LIMIT 1""",(sid,row["advisory_id"])).fetchone()
            if latest is None or latest["facts_sha256"]!=row["current_facts_sha"] or latest["source_sha256"]!=row["current_source_sha"]:
                raise ValueError("Latest advisory version disagrees with current source")
            if latest["observed_utc"]!=row["last_observed_utc"]:
                raise ValueError("Last observation disagrees with last saved version")
            sources[sid]=sources.get(sid,0)+1
        # Verify content-addressed fact payloads; do not trust artifact summary alone.
        for row in db.execute("SELECT facts_json,facts_sha256,source_sha256 FROM vendor_document_versions"):
            try:
                value=json.loads(row["facts_json"])
                canonical=json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(",",":"))
            except (TypeError,ValueError) as exc:
                raise ValueError("Unreadable saved vendor facts") from exc
            if hashlib.sha256(canonical.encode("utf-8")).hexdigest()!=row["facts_sha256"]:
                raise ValueError("Saved facts payload hash mismatch")
            if not HEX.fullmatch(row["source_sha256"]):
                raise ValueError("Invalid version source digest")
        if vcount!=ecount:
            raise ValueError("Every stored version must have one event (ledger not synchronized)")
        return {"advisories":dcount,"versions":vcount,"events":ecount,
                "integrity":"ok","source_counts":sources,"sqlite_sha256":_sha(file)}
    finally:
        db.close()


def restore(previous_dir: Path, dest: Path, registry: dict, *, run_id: int) -> dict:
    """Restore an independently generated run, rejecting loss/corruption.

    The workflow must select an earlier successful run of THIS workflow in THIS
    repo+branch. Its artifact ID is checked by the GitHub API outside this module.
    """
    if not isinstance(run_id,int) or run_id<=0:
        raise ValueError("Restoring state requires verified prior GitHub run ID")
    previous_dir=Path(previous_dir)
    source=previous_dir/"vendor-evidence.sqlite3"
    manifest_path=previous_dir/"vendor-evidence-manifest.json"
    if not manifest_path.is_file():
        raise ValueError("Prior successful artifact lacks collection manifest; refusing baseline reset")
    manifest=json.loads(manifest_path.read_text("utf-8"))
    if manifest.get("mode")!="ONE_SHOT_OFFICIAL_UNREVIEWED_PILOT":
        raise ValueError("Prior state manifest is not a known vendor-only collector")
    expected=manifest.get("db_counts")
    if not isinstance(expected,dict) or expected.get("integrity")!="ok":
        raise ValueError("Prior collector manifest lacks verified SQLite result")
    result=inspect_db(source,registry)
    for k in ("advisories","versions","events"):
        if result[k]!=expected.get(k):
            raise ValueError("Prior artifact count mismatch for "+k)
    if manifest.get("sources_failed",0)>0:
        # The artifact may contain a partial result: do not conflate a run with
        # verified complete coverage even when the workflow itself was green.
        raise ValueError("Prior collection had failed vendor sources; manual intervention needed")
    dest=Path(dest)
    if dest.exists():
        raise ValueError("Refusing to overwrite pre-existing current vendor DB")
    dest.parent.mkdir(parents=True,exist_ok=True)
    tmp=dest.with_name(dest.name+".restore-incomplete")
    if tmp.exists():
        raise ValueError("Incomplete restore already exists")
    try:
        shutil.copy2(source,tmp)
        if _sha(tmp)!=result["sqlite_sha256"]:
            raise ValueError("Restore copy hash mismatch")
        os.replace(tmp,dest)
        checked=inspect_db(dest,registry)
        if checked["sqlite_sha256"]!=result["sqlite_sha256"]:
            raise ValueError("Restored SQLite digest mismatch")
    finally:
        if tmp.exists():
            tmp.unlink()
    return {"state":"RESTORED_PRIOR_SHORT_LIVED_ARTIFACT","previous_run_id":run_id,
            "previous_sqlite_sha256":result["sqlite_sha256"],
            "counts":{k:result[k] for k in ("advisories","versions","events")},
            "source_counts":result["source_counts"],
            "guarantees":"Cross-run restoration only while GitHub artifact exists; not durable storage."}


def initialize(dest: Path) -> dict:
    """Use ONLY when no previous successful run ever existed on the pilot branch."""
    if Path(dest).exists():
        raise ValueError("Cannot bootstrap on top of existing vendor state")
    return {"state":"FIRST_BASELINE_NO_PRIOR_SUCCESSFUL_RUN",
            "previous_run_id":None,
            "guarantees":"New baseline, not new vulnerabilities; 7-day artifact is not durable."}


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--registry",type=Path,required=True)
    p.add_argument("--dest",type=Path,required=True)
    p.add_argument("--report",type=Path,required=True)
    choice=p.add_mutually_exclusive_group(required=True)
    choice.add_argument("--bootstrap",action="store_true")
    choice.add_argument("--previous-run-id",type=int)
    p.add_argument("--previous-dir",type=Path)
    args=p.parse_args()
    registry=load_registry(args.registry)
    if args.bootstrap:
        if args.previous_dir is not None:
            p.error("--bootstrap cannot use a previous directory")
        result=initialize(args.dest)
    else:
        if args.previous_dir is None:
            p.error("--previous-run-id requires --previous-dir")
        result=restore(args.previous_dir,args.dest,registry,run_id=args.previous_run_id)
    args.report.parent.mkdir(parents=True,exist_ok=True)
    args.report.write_text(json.dumps(result,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    print(json.dumps(result,ensure_ascii=False,indent=2))


if __name__=="__main__":
    main()
