"""Vendor SQLite schema migrations must preserve historic event records."""
import sqlite3
from pathlib import Path
import tempfile
import unittest
from eclipse_l0.vendor_store import connect


class EventMigrationTest(unittest.TestCase):
    def test_old_three_event_table_can_upgrade_without_dropping_history(self):
        with tempfile.TemporaryDirectory() as dirname:
            dbpath=Path(dirname)/"old.sqlite3"
            with sqlite3.connect(dbpath) as db:
                db.executescript("""
                CREATE TABLE vendor_document_events (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_id TEXT NOT NULL, advisory_id TEXT NOT NULL,
                    event_kind TEXT NOT NULL CHECK(event_kind IN
                      ('baseline','facts_updated','source_changed_only')),
                    observed_utc TEXT NOT NULL, version INTEGER NOT NULL
                );
                CREATE INDEX ix_vendor_document_events ON vendor_document_events
                    (source_id,advisory_id,event_id);
                INSERT INTO vendor_document_events
                    (event_id,source_id,advisory_id,event_kind,observed_utc,version)
                VALUES (75,'siemens-csaf','SSA-001','baseline','2026-10-10T11:00:00+00:00',1);
                INSERT INTO vendor_document_events
                    (event_id,source_id,advisory_id,event_kind,observed_utc,version)
                VALUES (76,'siemens-csaf','SSA-001','source_changed_only','2026-10-10T11:15:00+00:00',2);
                """)
            for run in (1,2):
                db=connect(dbpath)
                try:
                    got=list(db.execute("SELECT event_id,event_kind,version FROM vendor_document_events ORDER BY event_id"))
                    expected = [(75,"baseline",1),(76,"source_changed_only",2)]
                    if run == 2:
                        expected.append((77,"extraction_revised",3))
                    self.assertEqual([(x[0],x[1],x[2]) for x in got], expected)
                    db.execute("""INSERT INTO vendor_document_events
                       (source_id,advisory_id,event_kind,observed_utc,version)
                       VALUES ('siemens-csaf','SSA-001','extraction_revised',
                       '2026-10-10T12:00:00+00:00',3)""") if run==1 else None
                    db.commit()
                    if run==2:
                        self.assertEqual(db.execute("SELECT COUNT(*) FROM vendor_document_events").fetchone()[0],3)
                    self.assertEqual(db.execute("PRAGMA quick_check").fetchone()[0],"ok")
                finally:
                    db.close()
