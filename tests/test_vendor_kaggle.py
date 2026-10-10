"""No-network tests of private vendor transport with a synthetic 125/202 SQLite.

Provider-supplied manifest is never trusted independently of the pinned source
digest delivered through an independent GitHub Actions artifact.
"""
from pathlib import Path
import hashlib
import json
import shutil
import tempfile
from unittest.mock import patch
import unittest

from eclipse_l0.vendor_registry import load_registry
from eclipse_l0.vendor_store import connect, observe
from eclipse_l0.vendor_replay import inspect_db
from eclipse_l0 import vendor_kaggle as vk


class KaggleVendorSnapshotTest(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)
        self.registry=load_registry(Path(__file__).resolve().parents[1]/"config/vendor_source_registry.json")
        self.source=self.root/"prior"/"vendor-evidence.sqlite3"
        self.source.parent.mkdir(parents=True)
        sources=[x for x in self.registry["sources"] if x["verification_status"]=="read_parse_verified"]
        with connect(self.source) as db:
            for i in range(125):
                source=sources[i%len(sources)]
                fields=dict(registry=self.registry, source_id=source["source_id"],
                   advisory_id=f"SYNTH-{i:04d}",
                   source_url=source["detail_sample_url"],
                   source_sha256=hashlib.sha256(f"synthetic-body-{i}".encode()).hexdigest(),
                   observed_utc="2026-10-10T12:00:00Z",
                   facts={"title":f"FAKE fixture advisory {i}",
                          "cve_ids":[],"affected":[],
                          "evidence_fields":["synthetic fixture source path"]})
                observe(db,**fields)
                if i<77:
                    fields["source_sha256"]=hashlib.sha256(f"synthetic-new-{i}".encode()).hexdigest()
                    fields["observed_utc"]="2026-10-10T13:00:00Z"
                    fields["facts"]["title"]=f"SYNTHETIC revision {i}"
                    observe(db,**fields)
        a=inspect_db(self.source,self.registry)
        self.assertEqual((a["advisories"],a["versions"],a["events"]),(125,202,202))
        self.digest=a["sqlite_sha256"]
        self.manifest=self.source.parent/"vendor-evidence-manifest.json"
        self.manifest.write_text(json.dumps({
          "mode":"ONE_SHOT_OFFICIAL_UNREVIEWED_PILOT",
          "sources_pass":9,"sources_partial":0,"sources_failed":0,
          "db_counts":{"advisories":125,"versions":202,"events":202,"integrity":"ok"}
        }),encoding="utf-8")

    def _stage(self):
        with patch.object(vk,"EXPECTED_SOURCE_DIGEST",self.digest):
            return vk.stage(source=self.source,source_manifest=self.manifest,
                   registry=self.registry,dest=self.root/"upload",
                   expected_sha256=self.digest)

    def test_roundtrip_byte_exact_and_source_counts(self):
        st=self._stage()
        self.assertEqual(st["counts"]["advisories"],125)
        # Independent downloaded folder (no Kaggle mock used to assert live connectivity).
        dst=self.root/"download"
        dst.mkdir()
        for file in (vk.PART_NAME,vk.INDEX_NAME):
            shutil.copy2(self.root/"upload"/file,dst/file)
        with patch.object(vk,"EXPECTED_SOURCE_DIGEST",self.digest):
            receipt=vk.restore(trusted_index=self.root/"upload"/vk.INDEX_NAME,
                  downloaded=dst,out=self.root/"restored.sqlite3",registry=self.registry)
        self.assertEqual(receipt["sqlite_sha256"],self.digest)
        self.assertEqual(receipt["counts"]["versions"],202)
        self.assertEqual(receipt["sqlite_quick_check"],"ok")

    def test_rejects_tampered_kaggle_bytes(self):
        self._stage()
        dst=self.root/"download"
        dst.mkdir()
        for name in (vk.PART_NAME,vk.INDEX_NAME):
            shutil.copy2(self.root/"upload"/name,dst/name)
        with (dst/vk.PART_NAME).open("ab") as f:
            f.write(b"tampered")
        with patch.object(vk,"EXPECTED_SOURCE_DIGEST",self.digest):
            with self.assertRaisesRegex(ValueError,"Kaggle returned SQLite"):
                vk.restore(trusted_index=self.root/"upload"/vk.INDEX_NAME,
                           downloaded=dst,out=self.root/"restored.sqlite3",registry=self.registry)
        self.assertFalse((self.root/"restored.sqlite3").exists())

    def test_no_unpinned_source_can_enter_kaggle(self):
        with self.assertRaisesRegex(ValueError,"Unexpected source digest"):
            vk.stage(source=self.source,source_manifest=self.manifest,
                     registry=self.registry,dest=self.root/"upload",
                     expected_sha256=self.digest)

    def test_fail_closed_tampered_trusted_index(self):
        self._stage()
        p=self.root/"upload"/vk.INDEX_NAME
        content=json.loads(p.read_text())
        content["counts"]["advisories"]=124
        p.write_bytes(vk.json_bytes(content))
        with patch.object(vk,"EXPECTED_SOURCE_DIGEST",self.digest):
            with self.assertRaisesRegex(ValueError,"incorrect coverage"):
                vk.restore(trusted_index=p,downloaded=self.root/"upload",
                    out=self.root/"restore.sqlite3",registry=self.registry)

    def test_incomplete_collection_cannot_be_staged(self):
        doc=json.loads(self.manifest.read_text())
        doc["sources_partial"]=1
        doc["sources_pass"]=8
        self.manifest.write_text(json.dumps(doc))
        with patch.object(vk,"EXPECTED_SOURCE_DIGEST",self.digest):
            with self.assertRaisesRegex(ValueError,"Not all verified"):
                vk.stage(source=self.source,source_manifest=self.manifest,
                         registry=self.registry,dest=self.root/"upload",
                         expected_sha256=self.digest)


if __name__=="__main__":
    unittest.main()
