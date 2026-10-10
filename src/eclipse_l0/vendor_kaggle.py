"""Independent PRIVATE Kaggle transport for ECLIPSE vendor evidence snapshots.

Separate from the CVE warehouse dataset and independent of CVE/Kaggle updates.
Only normalized, UNREVIEWED publisher facts, source URLs + digests and history
are stored. Original full vendor HTML/JSON is NOT present.
Stage is immutable create-only; restore compares a *trusted* pre-upload index,
never a checksum supplied solely by the Kaggle download.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shutil

from .vendor_registry import load_registry
from .vendor_replay import inspect_db

SCOPE = "ECLIPSE_VENDOR_EVIDENCE_PRIVATE_SNAPSHOT_V1"
INDEX_NAME = "vendor-evidence-index.json"
PART_NAME = "part-0000.dbpart"
SOURCE_DB_NAME = "vendor-evidence.sqlite3"
SOURCE_MANIFEST_NAME = "vendor-evidence-manifest.json"
MAX_SNAPSHOT_BYTES = 50 * 1024 * 1024
EXPECTED_SOURCE_RUN = 38051672457
EXPECTED_SOURCE_DIGEST = "cfe17acc36b4be9e449c6dd6c800b709433052da51e1c8a0edb0430cc892d00c"
DATASET_SLUG = "eclipse-vendor-evidence-20261010-v1"
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as source:
        while chunk := source.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def json_bytes(document: dict) -> bytes:
    return (json.dumps(document, sort_keys=True, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def _check_source(source: Path, registry: dict, source_manifest: Path, run_id: int,
                  expected_sha256: str) -> dict:
    if run_id != EXPECTED_SOURCE_RUN:
        raise ValueError("Source run ID not pinned to audited completed GitHub Actions run")
    if expected_sha256 != EXPECTED_SOURCE_DIGEST or not HEX64.fullmatch(expected_sha256):
        raise ValueError("Unexpected source digest: cannot authorize Kaggle upload")
    result = inspect_db(source, registry)
    if result["sqlite_sha256"] != expected_sha256:
        raise ValueError("Source SQLite SHA256 differs from audited successful run")
    if result["advisories"] != 125 or result["versions"] != 202 or result["events"] != 202:
        raise ValueError("Pinned vendor state counts mismatch")
    manifest = json.loads(Path(source_manifest).read_text("utf-8"))
    if manifest.get("mode") != "ONE_SHOT_OFFICIAL_UNREVIEWED_PILOT":
        raise ValueError("Unexpected source manifest or dataset scope")
    expected = manifest.get("db_counts", {})
    for field, name in [("advisories", "advisories"), ("versions", "versions"),
                        ("events", "events")]:
        if expected.get(name) != result[field]:
            raise ValueError("Source manifest contradicts SQLite: " + field)
    if expected.get("integrity") != "ok":
        raise ValueError("Source manifest integrity was not verified")
    if manifest.get("sources_pass") != 9 or manifest.get("sources_partial") != 0 or manifest.get("sources_failed") != 0:
        raise ValueError("Not all verified publisher sources passed in source run")
    return result


def stage(*, source: Path, source_manifest: Path, registry: dict, dest: Path,
          source_run: int = EXPECTED_SOURCE_RUN,
          expected_sha256: str = EXPECTED_SOURCE_DIGEST) -> dict:
    """Build a bounded, new immutable Kaggle upload directory."""
    checked = _check_source(source, registry, source_manifest, source_run, expected_sha256)
    dest = Path(dest)
    if dest.exists():
        if any(dest.iterdir()):
            raise ValueError("Refusing nonempty Kaggle stage dir")
    else:
        dest.mkdir(parents=True)
    part = dest / PART_NAME
    with part.open("xb") as target, Path(source).open("rb") as original:
        shutil.copyfileobj(original, target, 1024 * 1024)
    if (part.stat().st_size > MAX_SNAPSHOT_BYTES or part.stat().st_size == 0
            or sha256(part) != checked["sqlite_sha256"]):
        part.unlink(missing_ok=True)
        raise ValueError("Staged SQLite failed byte-exact verification")
    index = {
        "schema_version": 1,
        "scope": SCOPE,
        "content_status": "UNREVIEWED_NORMALIZED_VENDOR_FACTS_ONLY",
        "publisher_rights": "NOT_APPROVED_FOR_EXTERNAL_REDISTRIBUTION",
        "customer_data": False,
        "raw_vendor_publisher_bodies_included": False,
        "source_repository": "pinogame1945-dotcom/ECLIPSE",
        "source_run_id": source_run,
        "source_run_url": f"https://github.com/pinogame1945-dotcom/ECLIPSE/actions/runs/{source_run}",
        "source_manifest_sha256": sha256(source_manifest),
        "sqlite_sha256": checked["sqlite_sha256"],
        "sqlite_bytes": part.stat().st_size,
        "part_name": PART_NAME,
        "dataset_slug": DATASET_SLUG,
        "counts": {name: checked[name] for name in ("advisories", "versions", "events")},
        "source_counts": checked["source_counts"],
        "collection_scope": "9 official vendor source representatives; no full-coverage claim",
        "index_generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "cve_warehouse_independent": True,
    }
    idx_file = dest / INDEX_NAME
    idx_file.write_bytes(json_bytes(index))
    return {"status": "STAGED_UNPUBLISHED_FOR_PRIVATE_KAGGLE",
            "index_sha256": sha256(idx_file), "sqlite_sha256": checked["sqlite_sha256"],
            "source_run_id": source_run, "counts": index["counts"]}


def validate_index(index: dict) -> None:
    if (index.get("schema_version") != 1 or index.get("scope") != SCOPE
            or index.get("part_name") != PART_NAME or index.get("dataset_slug") != DATASET_SLUG
            or index.get("source_run_id") != EXPECTED_SOURCE_RUN
            or index.get("sqlite_sha256") != EXPECTED_SOURCE_DIGEST
            or index.get("customer_data") is not False
            or index.get("raw_vendor_publisher_bodies_included") is not False
            or index.get("content_status") != "UNREVIEWED_NORMALIZED_VENDOR_FACTS_ONLY"
            or index.get("cve_warehouse_independent") is not True):
        raise ValueError("Untrusted vendor snapshot index")
    if (index.get("counts") != {"advisories":125,"versions":202,"events":202}
            or not isinstance(index.get("source_counts"),dict)
            or sum(index["source_counts"].values()) != 125):
        raise ValueError("Vendor snapshot index has incorrect coverage or counts")
    if not 0 < index.get("sqlite_bytes",0) <= MAX_SNAPSHOT_BYTES:
        raise ValueError("Invalid vendor snapshot bytes")
    if not isinstance(index.get("source_manifest_sha256"),str) or not HEX64.fullmatch(index["source_manifest_sha256"]):
        raise ValueError("Malformed source evidence hash")


def restore(*, trusted_index: Path, downloaded: Path, out: Path, registry: dict) -> dict:
    """Verify provider copy using a trusted index delivered independently."""
    trusted_bytes = Path(trusted_index).read_bytes()
    index = json.loads(trusted_bytes)
    validate_index(index)
    downloaded = Path(downloaded)
    returned_index = downloaded / INDEX_NAME
    part = downloaded / PART_NAME
    if not returned_index.is_file() or returned_index.is_symlink() or returned_index.read_bytes() != trusted_bytes:
        raise ValueError("Kaggle returned index differs from pre-upload trusted index")
    if (not part.is_file() or part.is_symlink()
            or part.stat().st_size != index["sqlite_bytes"] or sha256(part) != index["sqlite_sha256"]):
        raise ValueError("Kaggle returned SQLite bytes differ from pinned original")
    out = Path(out)
    if out.exists():
        raise ValueError("Refusing to overwrite restored vendor database")
    out.parent.mkdir(parents=True, exist_ok=True)
    try:
        with out.open("xb") as target, part.open("rb") as body:
            shutil.copyfileobj(body,target,1024*1024)
        if sha256(out) != index["sqlite_sha256"]:
            raise ValueError("Restoration corrupted original vendor DB")
        verified=inspect_db(out,registry)
        if (verified["advisories"] != index["counts"]["advisories"]
                or verified["versions"] != index["counts"]["versions"]
                or verified["events"] != index["counts"]["events"]
                or verified["source_counts"] != index["source_counts"]):
            raise ValueError("Restored vendor evidence counts do not match trusted index")
        return {"result":"INDEPENDENT_PRIVATE_KAGGLE_VENDOR_SQLITE_RESTORE_VERIFIED",
                "source_run_id":index["source_run_id"],
                "counts":index["counts"],"source_counts":verified["source_counts"],
                "sqlite_sha256":verified["sqlite_sha256"],
                "sqlite_quick_check":verified["integrity"],
                "source_index_sha256":sha256(trusted_index),
                "vendor_data_scope":"UNREVIEWED_NON_CUSTOMER",
                "cve_warehouse_untouched":True}
    except BaseException:
        out.unlink(missing_ok=True)
        raise


def main():
    p=argparse.ArgumentParser()
    sub=p.add_subparsers(dest="command",required=True)
    a=sub.add_parser("stage")
    a.add_argument("--db",type=Path,required=True)
    a.add_argument("--source-manifest",type=Path,required=True)
    a.add_argument("--registry",type=Path,required=True)
    a.add_argument("--dest",type=Path,required=True)
    b=sub.add_parser("restore")
    b.add_argument("--trusted-index",type=Path,required=True)
    b.add_argument("--downloaded",type=Path,required=True)
    b.add_argument("--out",type=Path,required=True)
    b.add_argument("--registry",type=Path,required=True)
    args=p.parse_args()
    registry=load_registry(args.registry)
    if args.command=="stage":
        print(json.dumps(stage(source=args.db,source_manifest=args.source_manifest,
               registry=registry,dest=args.dest),ensure_ascii=False,indent=2))
    else:
        print(json.dumps(restore(trusted_index=args.trusted_index,downloaded=args.downloaded,
             out=args.out,registry=registry),ensure_ascii=False,indent=2))


if __name__=="__main__":
    main()
