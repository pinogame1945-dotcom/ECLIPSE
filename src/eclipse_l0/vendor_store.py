"""Local, append-only evidence ledger for *observed* official vendor advisories.

This module is deliberately not an HTTP collector or a customer exposure engine.
Only explicitly approved sources from the reviewed registry can be recorded.
Original vendor response bodies are not stored by default: store the source URL,
content hash and normalized claims with source-field references instead.
A commercial/raw archive needs a separate rights and private-storage review.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sqlite3
from urllib.parse import urlsplit

CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")
ADVISORY = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._:/-]{0,159}$")
HEX_SHA = re.compile(r"^[0-9a-f]{64}$")


def _canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _utc(value: str) -> str:
    try:
        instant = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise ValueError("Invalid observation timestamp") from exc
    if instant.tzinfo is None:
        raise ValueError("Observation timestamp must include timezone")
    return instant.astimezone(timezone.utc).isoformat(timespec="seconds")


def _source_id(source_id: str) -> str:
    if not isinstance(source_id, str) or not re.fullmatch(r"[a-z][a-z0-9-]{2,79}", source_id):
        raise ValueError("Bad source ID")
    return source_id


def _valid_url(url: str, allowed: list[str]) -> None:
    if not isinstance(url, str):
        raise ValueError("Not a source URL")
    parsed = urlsplit(url)
    if (parsed.scheme != "https" or parsed.hostname not in allowed
            or parsed.username or parsed.password or parsed.port not in (None, 443)
            or parsed.fragment):
        raise ValueError("Source URL not on official registry host allowlist")


def connect(path: Path) -> sqlite3.Connection:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(str(path), timeout=30)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    db.execute("PRAGMA journal_mode=WAL")
    db.executescript("""
      CREATE TABLE IF NOT EXISTS vendor_documents (
        source_id TEXT NOT NULL, advisory_id TEXT NOT NULL,
        source_url TEXT NOT NULL,
        current_facts_sha TEXT NOT NULL, current_source_sha TEXT NOT NULL,
        first_observed_utc TEXT NOT NULL, last_observed_utc TEXT NOT NULL,
        PRIMARY KEY (source_id, advisory_id)
      );
      CREATE TABLE IF NOT EXISTS vendor_document_versions (
        source_id TEXT NOT NULL, advisory_id TEXT NOT NULL,
        version INTEGER NOT NULL,
        facts_sha256 TEXT NOT NULL, source_sha256 TEXT NOT NULL,
        facts_json TEXT NOT NULL, extract_status TEXT NOT NULL,
        observed_utc TEXT NOT NULL, source_url TEXT NOT NULL,
        PRIMARY KEY (source_id, advisory_id, version),
        FOREIGN KEY (source_id, advisory_id)
          REFERENCES vendor_documents(source_id, advisory_id)
      );
      CREATE TABLE IF NOT EXISTS vendor_document_events (
        event_id INTEGER PRIMARY KEY AUTOINCREMENT,
        source_id TEXT NOT NULL, advisory_id TEXT NOT NULL,
        event_kind TEXT NOT NULL CHECK(event_kind IN
          ('baseline','facts_updated','source_changed_only','extraction_revised')),
        observed_utc TEXT NOT NULL, version INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS ix_vendor_document_events
        ON vendor_document_events(source_id, advisory_id, event_id);
    """)
    db.commit()
    _upgrade_legacy_event_constraint(db)
    return db


def _upgrade_legacy_event_constraint(db: sqlite3.Connection) -> None:
    """Transactional migration of the old 3-event CHECK to the 4-event model.

    Existing GitHub Actions pilot databases are restored byte-for-byte first.
    A new parser revision must not fail on yesterday's SQLite schema.
    """
    row = db.execute("""SELECT sql FROM sqlite_master
                        WHERE type='table' AND name='vendor_document_events'""").fetchone()
    if row is None:
        raise ValueError("Missing vendor event schema")
    if "extraction_revised" in row["sql"]:
        return
    if not all(x in row["sql"] for x in ("baseline","facts_updated","source_changed_only")):
        raise ValueError("Unrecognized old vendor event schema; migration blocked")
    with db:
        db.execute("BEGIN IMMEDIATE")
        db.execute("ALTER TABLE vendor_document_events RENAME TO vendor_document_events_legacy")
        db.execute("""CREATE TABLE vendor_document_events (
            event_id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_id TEXT NOT NULL, advisory_id TEXT NOT NULL,
            event_kind TEXT NOT NULL CHECK(event_kind IN
               ('baseline','facts_updated','source_changed_only','extraction_revised')),
            observed_utc TEXT NOT NULL, version INTEGER NOT NULL
        )""")
        db.execute("""INSERT INTO vendor_document_events
            (event_id,source_id,advisory_id,event_kind,observed_utc,version)
            SELECT event_id,source_id,advisory_id,event_kind,observed_utc,version
            FROM vendor_document_events_legacy""")
        db.execute("DROP TABLE vendor_document_events_legacy")
        db.execute("""CREATE INDEX ix_vendor_document_events
            ON vendor_document_events(source_id, advisory_id, event_id)""")


def observe(db: sqlite3.Connection, *, registry: dict, source_id: str,
            advisory_id: str, source_url: str, source_sha256: str,
            facts: dict, observed_utc: str, extract_status: str = "parsed_unreviewed") -> dict:
    """Persist a normalized advisory *observation* and immutable version.

    First source observation is a baseline, never an attack alarm.
    Source-body changes without changed claims are recorded but not vulnerability
    change alerts. All operations use a transaction and are idempotent.
    """
    _source_id(source_id)
    if not isinstance(registry, dict):
        raise ValueError("Missing reviewed registry")
    match = next((s for s in registry.get("sources", []) if s.get("source_id") == source_id), None)
    if match is None or match.get("verification_status") != "read_parse_verified":
        raise ValueError("Source is not read/parse verified in registry")
    if match.get("enabled_for_production", False):
        raise ValueError("This manual ledger must not be used for live production collectors")
    _valid_url(source_url, match.get("allowed_hosts", []))
    if not isinstance(advisory_id, str) or not ADVISORY.fullmatch(advisory_id):
        raise ValueError("Unusable advisory ID")
    if not isinstance(source_sha256, str) or not HEX_SHA.fullmatch(source_sha256):
        raise ValueError("Invalid official source SHA256")
    stamp = _utc(observed_utc)
    if extract_status not in ("parsed_unreviewed", "human_verified"):
        raise ValueError("Unexpected extraction state")
    if not isinstance(facts, dict):
        raise ValueError("Expected normalized facts object")
    if not isinstance(facts.get("title"), str) or not facts["title"].strip():
        raise ValueError("Missing advisory title")
    ids = facts.get("cve_ids", [])
    if not isinstance(ids, list) or any(not isinstance(i, str) or not CVE.fullmatch(i) for i in ids):
        raise ValueError("Invalid CVE list")
    if len(ids) != len(set(ids)):
        raise ValueError("Duplicate CVEs")
    if not isinstance(facts.get("affected", []), list):
        raise ValueError("Affected rows must be an array")
    if not isinstance(facts.get("evidence_fields", []), list) or not facts.get("evidence_fields"):
        raise ValueError("Missing field provenance; cannot verify extracted facts")
    if any(not isinstance(x, str) or not x.strip() for x in facts["evidence_fields"]):
        raise ValueError("Invalid source field citations")
    payload = _canonical(facts)
    facts_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    # Using source_sha256 allows separately tracking updates to the publisher's
    # raw response even if extracted security facts do not change.
    with db:
        old = db.execute("""SELECT current_facts_sha,current_source_sha,
                               first_observed_utc,last_observed_utc
                            FROM vendor_documents WHERE source_id=? AND advisory_id=?""",
                         (source_id, advisory_id)).fetchone()
        if old and stamp < old["last_observed_utc"]:
            raise ValueError("Out-of-order observation; refusing to replace current advisory")
        if old and old["current_facts_sha"] == facts_hash and old["current_source_sha"] == source_sha256:
            db.execute("""UPDATE vendor_documents SET last_observed_utc=?
                          WHERE source_id=? AND advisory_id=?""", (stamp, source_id, advisory_id))
            return {"source_id": source_id, "advisory_id": advisory_id, "event": "unchanged",
                    "version_created": False, "facts_sha256": facts_hash}
        version = db.execute("""SELECT COALESCE(MAX(version),0)+1
                                FROM vendor_document_versions WHERE source_id=? AND advisory_id=?""",
                             (source_id, advisory_id)).fetchone()[0]
        # Claims changed while source bytes did NOT: the extraction changed,
        # not the publisher. Never label this a new vendor security update.
        # A source byte change without changed claims is likewise not a
        # vulnerability update. All extracted claims are unreviewed.
        kind = ("baseline" if old is None else
                "extraction_revised" if old["current_source_sha"] == source_sha256 else
                "source_changed_only" if old["current_facts_sha"] == facts_hash else
                "facts_updated")
        if old is None:
            db.execute("INSERT INTO vendor_documents VALUES (?,?,?,?,?,?,?)",
                       (source_id, advisory_id, source_url, facts_hash, source_sha256, stamp, stamp))
        else:
            db.execute("""UPDATE vendor_documents SET source_url=?,current_facts_sha=?,
                       current_source_sha=?,last_observed_utc=? WHERE source_id=? AND advisory_id=?""",
                       (source_url, facts_hash, source_sha256, stamp, source_id, advisory_id))
        db.execute("""INSERT INTO vendor_document_versions
                   (source_id,advisory_id,version,facts_sha256,source_sha256,facts_json,
                    extract_status,observed_utc,source_url) VALUES (?,?,?,?,?,?,?,?,?)""",
                   (source_id, advisory_id, version, facts_hash, source_sha256,
                    payload, extract_status, stamp, source_url))
        db.execute("""INSERT INTO vendor_document_events
                   (source_id,advisory_id,event_kind,observed_utc,version) VALUES (?,?,?,?,?)""",
                   (source_id, advisory_id, kind, stamp, version))
    return {"source_id": source_id, "advisory_id": advisory_id, "event": kind,
            "version_created": True, "version": version, "facts_sha256": facts_hash}


def facts_history(db: sqlite3.Connection, source_id: str, advisory_id: str) -> list[dict]:
    _source_id(source_id)
    if not ADVISORY.fullmatch(advisory_id):
        raise ValueError("Invalid advisory ID")
    return [
        {"version": row["version"], "source_sha256": row["source_sha256"],
         "facts_sha256": row["facts_sha256"], "observed_utc": row["observed_utc"],
         "source_url": row["source_url"], "extract_status": row["extract_status"],
         "facts": json.loads(row["facts_json"])}
        for row in db.execute("""SELECT * FROM vendor_document_versions
                                WHERE source_id=? AND advisory_id=? ORDER BY version""",
                              (source_id, advisory_id))
    ]
