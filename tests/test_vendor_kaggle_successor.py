"""Synthetic successor Kaggle snapshot chain, no network or Kaggle credentials."""
import json
import shutil
from pathlib import Path
from unittest.mock import patch
import unittest

from test_vendor_kaggle import KaggleVendorSnapshotTest
from eclipse_l0.vendor_kaggle import INDEX_NAME
from eclipse_l0.vendor_kaggle_successor import stage,restore,prove_chain,INDEX
from eclipse_l0.vendor_replay import inspect_db
from eclipse_l0.vendor_store import connect,observe


class VendorSuccessorTest(unittest.TestCase):
    def setUp(self):
        self.fixture=KaggleVendorSnapshotTest("test_roundtrip_byte_exact_and_source_counts")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root=self.fixture.root
        self.registry=self.fixture.registry
        self.parent=self.fixture.source
        with patch("eclipse_l0.vendor_kaggle.EXPECTED_SOURCE_DIGEST",self.fixture.digest):
            self.fixture._stage()
        self.idx=self.root/"upload"/INDEX_NAME
        self.child=self.root/"child.sqlite3"
        shutil.copy2(self.parent,self.child)
        with connect(self.child) as db:
            observe(db,registry=self.registry,source_id="fortinet-psirt",
                advisory_id="SYNTHETIC-NEW-999",source_url=
                "https://fortiguard.fortinet.com/psirt/FG-IR-26-175",
                source_sha256="d"*64,observed_utc="2026-10-10T14:00:00Z",
                facts={"title":"Fixture new notice","cve_ids":[],"affected":[],
                       "evidence_fields":["fixture"]})
        db.close()
        details=inspect_db(self.child,self.registry)
        self.manifest=self.root/"collect.json"
        self.manifest.write_text(json.dumps({
           "mode":"ONE_SHOT_OFFICIAL_UNREVIEWED_PILOT","sources_pass":9,
           "sources_partial":0,"sources_failed":0,"db_counts":details
        }),encoding="utf-8")
        self.patch=patch("eclipse_l0.vendor_kaggle.EXPECTED_SOURCE_DIGEST",self.fixture.digest)
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def _stage(self):
        return stage(self.parent,self.child,self.idx,self.manifest,self.root/"v2",self.registry)

    def test_immutable_history_across_generations(self):
        receipt=self._stage()
        self.assertEqual(receipt["counts"],{"advisories":126,"versions":203,"events":203})
        self.assertEqual(receipt["new_documents"],1)
        dst=self.root/"kaggle-sim"
        dst.mkdir()
        for f in (INDEX,"part-0000.dbpart"):
            shutil.copy2(self.root/"v2"/f,dst/f)
        audit=restore(self.root/"v2"/INDEX,self.idx,dst,self.root/"v2-restored.db",
                      self.registry)
        self.assertEqual(audit["counts"]["advisories"],126)
        self.assertTrue(audit["prior_history_unchanged"])

    def test_rejects_existing_history_deletion_even_if_counts_grow(self):
        from sqlite3 import connect as sqlite_connect
        with sqlite_connect(self.child) as db:
            db.execute("""UPDATE vendor_document_versions SET facts_json='{}'
                          WHERE source_id='fortinet-psirt' AND advisory_id='SYNTH-0000'""")
        with self.assertRaisesRegex(ValueError,"hash mismatch|history"):
            self._stage()

    def test_rejects_incomplete_collector(self):
        doc=json.loads(self.manifest.read_text())
        doc["sources_failed"]=1
        self.manifest.write_text(json.dumps(doc))
        with self.assertRaisesRegex(ValueError,"Incomplete"):
            self._stage()

    def test_rejects_provider_mutated_successor(self):
        self._stage()
        dst=self.root/"kaggle-sim"
        dst.mkdir()
        for name in (INDEX,"part-0000.dbpart"):
            shutil.copy2(self.root/"v2"/name,dst/name)
        with (dst/"part-0000.dbpart").open("ab") as file:
            file.write(b"unsafe-change")
        with self.assertRaisesRegex(ValueError,"altered"):
            restore(self.root/"v2"/INDEX,self.idx,dst,self.root/"bad.db",self.registry)


if __name__=="__main__":
    unittest.main()
