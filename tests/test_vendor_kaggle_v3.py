"""Offline V3 immutable parent and Byzantine/Kaggle tampering tests."""
import hashlib,json,shutil,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from test_vendor_kaggle import KaggleVendorSnapshotTest
from eclipse_l0 import vendor_kaggle_v3 as v3
from eclipse_l0.vendor_store import connect,observe
from eclipse_l0.vendor_replay import inspect_db

class VendorV3Tests(unittest.TestCase):
    def setUp(self):
        fixture=KaggleVendorSnapshotTest("test_roundtrip_byte_exact_and_source_counts")
        fixture.setUp();self.addCleanup(fixture.doCleanups)
        self.root=fixture.root;self.registry=fixture.registry;self.parent=fixture.source
        self.child=self.root/"child.sqlite3"
        shutil.copy2(self.parent,self.child)
        self.before=inspect_db(self.parent,self.registry)
        self.ids=v3.EXPECTED_SOURCE_IDS
        self.passed=self.ids[:12]
        lookup={s["source_id"]:s for s in self.registry["sources"]}
        with connect(self.child) as db:
            for sid in self.passed:
                source=lookup[sid]
                self.assertEqual(source["verification_status"],"read_parse_verified")
                id="SYNTH-V3-"+sid
                kw=dict(registry=self.registry,source_id=sid,
                    advisory_id=id,source_url=source["detail_sample_url"],
                    source_sha256=hashlib.sha256(("fixture-"+sid).encode()).hexdigest(),
                    observed_utc="2026-10-11T00:00:00Z",
                    facts={"title":"Synthetic immutable v3 test "+sid,"cve_ids":[],
                           "affected":[],"evidence_fields":["offline identity evidence"]})
                f=observe(db,**kw)
                self.assertEqual(f["event"],"baseline")
                self.assertEqual(observe(db,**kw)["event"],"unchanged")
        db.close()
        self.after=inspect_db(self.child,self.registry)
        self.fake_v1=self.root/"v1-index.json";self.fake_v1.write_text("{}")
        self.fake_v2=self.root/"v2-index.json";self.fake_v2.write_text("{}")
        self.trusted={"schema_version":2,"scope":"ECLIPSE_VENDOR_PRIVATE_GENERATION_2",
                      "dataset_slug":v3.PARENT_SLUG,"sqlite_sha256":self.before["sqlite_sha256"],
                      "counts":{k:self.before[k] for k in ("advisories","versions","events")}}
        self.manifest=self.root/"receipt.json"
        self.manifest.write_text(json.dumps({
            "mode":"ONE_SHOT_OFFICIAL_UNREVIEWED_PILOT",
            "source_results":[
                {"source_id":sid,"status":"PASS" if sid in self.passed else "FAIL",
                 "saved":1 if sid in self.passed else 0,
                 "replay_unchanged":1 if sid in self.passed else 0,
                 "errors":[] if sid in self.passed else ["fixture official publisher unavailable"]}
                for sid in self.ids
            ],
            "sources_pass":12,"sources_failed":3,"sources_partial":0,
            "sources_degraded":0,"db_counts":self.after,
            "requested_max_items_per_source":1
        }))
        self.guard=patch.object(v3,"trusted_parent",return_value=self.trusted)
        self.guard.start();self.addCleanup(self.guard.stop)

    def run_stage(self,where="stage"):
        return v3.stage(self.parent,self.child,self.fake_v2,self.fake_v1,
            self.manifest,self.root/where,self.registry)

    def test_append_only_stage_and_independent_restore(self):
        result=self.run_stage()
        self.assertEqual(result["sampling"]["passed"],12)
        self.assertEqual(result["sampling"]["failed"],3)
        self.assertEqual(result["new_advisories"],12)
        folder=self.root/"download";folder.mkdir()
        for f in (v3.INDEX,v3.PART_NAME):
            shutil.copy2(self.root/"stage"/f,folder/f)
        restored=v3.restore(self.root/"stage"/v3.INDEX,self.fake_v2,self.fake_v1,
                            folder,self.root/"restored.sqlite3",self.registry)
        self.assertEqual(restored["result"],"PRIVATE_VENDOR_V3_INDEPENDENT_READBACK_VERIFIED")
        self.assertEqual(restored["counts"]["advisories"],137)
        self.assertEqual(len(restored["failures_not_hidden"]),3)

    def test_rejects_silent_failed_vendor_and_partial_source(self):
        m=json.loads(self.manifest.read_text())
        m["source_results"][-1]["errors"]=[]
        self.manifest.write_text(json.dumps(m))
        with self.assertRaisesRegex(ValueError,"error"):self.run_stage()
        m["source_results"][-1]["errors"]=["publisher timeout"]
        m["source_results"][0]["status"]="PARTIAL"
        self.manifest.write_text(json.dumps(m))
        with self.assertRaisesRegex(ValueError,"failed, partial"):self.run_stage()

    def test_rejects_ancestor_mutation_even_if_parent_count_preserved(self):
        import sqlite3
        with sqlite3.connect(self.child) as db:
            db.execute("UPDATE vendor_document_versions SET source_sha256=? WHERE source_id=? AND advisory_id=? AND version=1",
                       ("a"*64,"fortinet-psirt","SYNTH-0000"))
        with self.assertRaisesRegex(ValueError,"hash mismatch|immutable|Previous database"):
            self.run_stage()

    def test_rejects_modified_provider_bytes_and_index(self):
        self.run_stage()
        download=self.root/"download";download.mkdir()
        for f in (v3.INDEX,v3.PART_NAME):shutil.copy2(self.root/"stage"/f,download/f)
        with (download/v3.PART_NAME).open("ab") as file:file.write(b"altered")
        with self.assertRaisesRegex(ValueError,"differs"):
            v3.restore(self.root/"stage"/v3.INDEX,self.fake_v2,self.fake_v1,
                       download,self.root/"bad.sqlite3",self.registry)
        self.assertFalse((self.root/"bad.sqlite3").exists())
        download.joinpath(v3.PART_NAME).write_bytes((self.root/"stage"/v3.PART_NAME).read_bytes())
        obj=json.loads((download/v3.INDEX).read_text())
        obj["weekly_source_coverage_assured"]=True
        (download/v3.INDEX).write_text(json.dumps(obj))
        with self.assertRaisesRegex(ValueError,"index differs"):
            v3.restore(self.root/"stage"/v3.INDEX,self.fake_v2,self.fake_v1,
                       download,self.root/"bad.sqlite3",self.registry)

    def test_rejects_unauthorized_trusted_index_coverage_claims(self):
        self.run_stage()
        idx=self.root/"stage"/v3.INDEX
        obj=json.loads(idx.read_text())
        obj["weekly_source_coverage_assured"]=True
        idx.write_text(json.dumps(obj))
        with self.assertRaisesRegex(ValueError,"unapproved claims"):
            v3.restore(idx,self.fake_v2,self.fake_v1,
                       self.root/"stage",self.root/"bad.sqlite3",self.registry)

if __name__=="__main__":unittest.main()
