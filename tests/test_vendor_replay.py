"""Cross-run artifact restoration and true version changes, fully offline."""
from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from eclipse_l0.vendor_replay import inspect_db, restore, initialize
from eclipse_l0.vendor_pilot import ingest_source
from eclipse_l0.vendor_registry import load_registry
from eclipse_l0.vendor_store import connect, facts_history

ROOT=Path(__file__).resolve().parents[1]
REGISTRY=load_registry(ROOT/"config/vendor_source_registry.json")


class MemoryFetcher:
    def __init__(self, src, feed, body):
        self.data={src["discovery_url"]:feed,
                  "https://fortiguard.fortinet.com/psirt/FG-IR-26-123":body}
    def get(self,url,limit=None):
        return self.data[url]


def evidence(html_versions: str) -> bytes:
    return ("""<html><body><h1>SYNTHETIC test CVE-2026-12345</h1>
      <p>Version impact demonstration is synthetic and not from Fortinet.</p>
      <table><tr><td>FortiMail 7.6</td><td>"""+html_versions+
      """</td><td>Upgrade to 7.6.3 or above</td></tr></table></body></html>""").encode()


class ReplayAcrossSeparateRunsTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.src=next(s for s in REGISTRY["sources"] if s["source_id"]=="fortinet-psirt")
        self.feed=b"""<rss version="2.0"><channel><item>
          <title>SYNTHETIC CVE-2026-12345</title>
          <link>https://fortiguard.fortinet.com/psirt/FG-IR-26-123</link>
          <description>fixture only</description>
          </item></channel></rss>"""
        self.previous=self.root/"previous"
        self.previous.mkdir()
        self.db=self.previous/"vendor-evidence.sqlite3"

    def first_run(self):
        first=ingest_source(REGISTRY,self.src,self.db,1,
                            MemoryFetcher(self.src,self.feed,evidence("7.6.0 through 7.6.2")))
        self.assertEqual(first["status"],"PASS")
        prior=inspect_db(self.db,REGISTRY)
        summary={"mode":"ONE_SHOT_OFFICIAL_UNREVIEWED_PILOT",
                 "db_counts":{k:prior[k] for k in ("advisories","versions","events","integrity")},
                 "sources_failed":0}
        (self.previous/"vendor-evidence-manifest.json").write_text(json.dumps(summary),encoding="utf-8")
        return prior

    def test_restore_replay_change_and_unchanged_across_runs(self):
        before=self.first_run()
        now=self.root/"current"/"vendor-evidence.sqlite3"
        restored=restore(self.previous,now,REGISTRY,run_id=321)
        self.assertEqual(restored["state"],"RESTORED_PRIOR_SHORT_LIVED_ARTIFACT")
        self.assertEqual(restored["counts"]["advisories"],1)
        second=ingest_source(REGISTRY,self.src,now,1,
                             MemoryFetcher(self.src,self.feed,evidence("7.6.0 through 7.6.2")))
        self.assertEqual(second["status"],"PASS")
        self.assertEqual(second["baseline"],0)
        self.assertEqual(second["replay_unchanged"],1)
        self.assertEqual(inspect_db(now,REGISTRY)["versions"],1)
        third=ingest_source(REGISTRY,self.src,now,1,
                            MemoryFetcher(self.src,self.feed,evidence("7.6.0 through 7.6.4")))
        self.assertEqual(third["updates"],1)
        self.assertEqual(inspect_db(now,REGISTRY)["versions"],2)
        with connect(now) as db:
            history=facts_history(db,"fortinet-psirt","FG-IR-26-123")
        self.assertEqual([x["facts"]["affected"][0]["affected_versions_raw"] for x in history],
                         ["7.6.0 through 7.6.2","7.6.0 through 7.6.4"])

    def test_fails_closed_on_expired_artifact_or_mismatch(self):
        self.first_run()
        (self.previous/"vendor-evidence.sqlite3").unlink()
        with self.assertRaisesRegex(ValueError,"Missing"):
            restore(self.previous,self.root/"new.sqlite3",REGISTRY,run_id=321)

    def test_fails_closed_on_corrupt_ledger(self):
        self.first_run()
        with sqlite3.connect(self.db) as db:
            db.execute("UPDATE vendor_document_versions SET facts_json='{}'")
        with self.assertRaisesRegex(ValueError,"hash mismatch"):
            restore(self.previous,self.root/"new.sqlite3",REGISTRY,run_id=321)

    def test_prevent_overwriting_existing_state(self):
        self.first_run()
        with self.assertRaisesRegex(ValueError,"overwrite"):
            restore(self.previous,self.db,REGISTRY,run_id=321)
        with self.assertRaisesRegex(ValueError,"existing"):
            initialize(self.db)

    def test_synthetic_bootstrap_not_called_while_old_state_is_present(self):
        value=initialize(self.root/"fresh.sqlite3")
        self.assertEqual(value["state"],"FIRST_BASELINE_NO_PRIOR_SUCCESSFUL_RUN")


if __name__=="__main__":
    unittest.main()
