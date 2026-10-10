"""Read back a PRIVATE Kaggle CVE snapshot one exact file at a time.

Kaggle's bulk dataset export may fail even though individual files are healthy.
Never accept a response until its bytes match the trusted local manifest.
No Kaggle owner, token, raw errors, or private dataset URL is printed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import time
from pathlib import Path

from .full_baseline import sha
from .kaggle_full import INDEX_FILE, SHARD

ALLOWED_META = ("archive-index.json", "manifest.json")


def check_ref(ref: str) -> None:
    if not re.fullmatch(r"[A-Za-z0-9_-]+/eclipse-cve-full-20261010-v1", ref):
        raise ValueError("Unexpected private Kaggle dataset identifier")


def files_to_fetch(stage: Path) -> list[tuple[str, str, int]]:
    """Only trust filenames and SHA256 recorded in the locally verified stage."""
    index_path = stage / INDEX_FILE
    index = json.loads(index_path.read_text(encoding="utf-8"))
    if not isinstance(index.get("files"), dict) or not index["files"]:
        raise ValueError("Missing expected CVE shard index")
    if index.get("record_count") != 403696 or index.get("shard_count") != 162:
        raise ValueError("Unexpected pinned full-source size")
    if index.get("source_sha256") != "727c63047df02ffb00c63812c82dcae20512c42c786be4b36c7630be30cb79c1":
        raise ValueError("Source baseline changed")
    manifest = stage / "manifest.json"
    if sha(manifest) != index.get("manifest_sha256"):
        raise ValueError("Source manifest mutated before readback")
    ret = [
        (INDEX_FILE, sha(index_path), index_path.stat().st_size),
        ("manifest.json", sha(manifest), manifest.stat().st_size)
    ]
    for name, spec in sorted(index["files"].items()):
        if not SHARD.fullmatch(name) or type(spec) is not dict:
            raise ValueError("Invalid Kaggle member filename")
        digest = spec.get("sha256")
        size = spec.get("bytes")
        if (not isinstance(digest, str) or not re.fullmatch("[0-9a-f]{64}", digest)
                or type(size) is not int or not 0 < size <= 200*1024*1024):
            raise ValueError("Invalid shard integrity metadata")
        if (stage / name).stat().st_size != size or sha(stage / name) != digest:
            raise ValueError("Local shard integrity changed before readback")
        ret.append((name, digest, size))
    return ret


def fetch_one(ref: str, name: str, expected_sha: str, expected_size: int,
              directory: Path, *, runner=subprocess.run, sleeper=time.sleep,
              attempts: int = 4) -> None:
    """Never use a dataset-wide export. Targeted downloads are supported by Kaggle CLI."""
    if name not in ALLOWED_META and not SHARD.fullmatch(name):
        raise ValueError("Untrusted filename")
    directory.mkdir(parents=True, exist_ok=True)
    dest = directory / name
    if dest.is_symlink():
        raise ValueError("Unsafe destination file type")
    if dest.is_file() and dest.stat().st_size == expected_size and sha(dest) == expected_sha:
        return
    for attempt in range(attempts):
        # Kaggle CLI wraps some single files in a transport ZIP; --unzip extracts
        # that envelope, NOT our opaque .cvepack file contents.
        cmd = ["kaggle", "datasets", "download", ref, "--file", name,
               "--path", str(directory), "--unzip", "--force", "--quiet"]
        try:
            p = runner(cmd, capture_output=True, text=True, timeout=150)
            success = p.returncode == 0
        except subprocess.TimeoutExpired:
            success = False
        if (success and dest.is_file() and not dest.is_symlink()
                and dest.stat().st_size == expected_size and sha(dest) == expected_sha):
            return
        # Do not log provider error text, which can contain the private ref.
        if dest.is_symlink():
            raise ValueError("Unsafe Kaggle response file type")
        if dest.is_file():
            # Readback integrity mismatch: fail closed, do not accept a retry as valid.
            if dest.stat().st_size == expected_size and sha(dest) != expected_sha:
                raise ValueError("Provider file hash differs from trusted SHA256: " + name)
            dest.unlink()
        if attempt + 1 < attempts:
            sleeper([3, 8, 20][min(attempt, 2)])
    raise RuntimeError("Bounded targeted Kaggle readback unavailable for: " + name)


def readback(stage: Path, download: Path, ref: str, *, runner=subprocess.run,
             sleeper=time.sleep) -> dict:
    check_ref(ref)
    specs = files_to_fetch(stage)
    download.mkdir(parents=True, exist_ok=True)
    for i, (name, digest, size) in enumerate(specs, 1):
        fetch_one(ref, name, digest, size, download, runner=runner, sleeper=sleeper)
        if i % 25 == 0:
            print(f"KAGGLE_PRIVATE_READBACK_VERIFIED_FILES={i}/{len(specs)}", flush=True)
    return {"downloaded_and_verified_files": len(specs),
            "verified_shards": len(specs)-2, "index_sha256": specs[0][1]}


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--stage", type=Path, required=True)
    p.add_argument("--download", type=Path, required=True)
    p.add_argument("--dataset-ref", required=True)
    args = p.parse_args()
    print(json.dumps(readback(args.stage, args.download, args.dataset_ref), sort_keys=True))


if __name__ == "__main__":
    main()
