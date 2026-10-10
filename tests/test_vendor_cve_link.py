"""Synthetic independent vendor/CVE database linking; never alters source DBs."""
from pathlib import Path
import sqlite3
import json
import tempfile
import unittest

from eclipse_l0.vendor_registry import load_registry
from eclipse_l0.vendor_store import connect, observe
from eclipse_l0.vendor_cve_link import link_audit


class VendorCVEInteroperabilityTest(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)
        self.registry=load_registry(Path(__file__).resolve().parents[1]/"config/vendor_source_registry.json")
        self.vendor=self.root/"vendor.sqlite3"
        self.cve=self.root/"warehouse.sqlite3"
        source="fortinet-psirt"
        with connect(self.vendor) as db:
            for i,cves in enumerate([["CVE-2026-100001","CVE-2026-100002","CVE-2026-100003"],[]]):
                observe(db,registry=self.registry,source_id=source,
                        advisory_id=f"FG-IR-26-TEST{i}",
                        source_url="https://fortiguard.fortinet.com/psirt/FG-IR-26-175",
                        source_sha256=(f"{i+1:064x}"),
                        facts={"title":f"SYNTHETIC vendor notice {i}","cve_ids":cves,
                               "affected":[],"evidence_fields":["test fixture.official reference"]},
                        observed_utc="2026-10-10T12:00:00Z")
        db.close()
        with sqlite3.connect(self.cve) as db:
            db.executescript("""
            CREATE TABLE cve_current(cve_id TEXT PRIMARY KEY, record_state TEXT, hash TEXT);
            CREATE TABLE warehouse_metadata(key TEXT PRIMARY KEY, value TEXT);
            """)
            db.executemany("INSERT INTO cve_current VALUES (?,?,?)",
                           [("CVE-2026-100001","PUBLISHED","a"*64),
                            ("CVE-2026-100002","REJECTED","b"*64)])
            db.executemany("INSERT INTO warehouse_metadata VALUES (?,?)",
                           [("source_index_sha256",json.dumps("c"*64)),
                            ("source_archive_sha256",json.dumps("d"*64))])

    def test_matched_rejected_pending_and_unassigned(self):
        result=link_audit(self.vendor,self.cve,self.registry)
        self.assertEqual(result["vendor_snapshot"]["advisories"],2)
        self.assertEqual(result["counts"],{
            "MATCHED_PUBLISHED":1,"MATCHED_REJECTED":1,
            "UNASSIGNED":1,"UNMATCHED_SNAPSHOT":1})
        self.assertEqual(len(result["links"]),3)
        self.assertEqual(result["cve_snapshot"]["source_index_sha256"],"c"*64)
        self.assertTrue(result["policy"]["writes_performed"] is False)
        self.assertTrue(all(link["link_confidence"]=="EXTRACTED_UNREVIEWED"
                            for link in result["links"]))

    def test_cannot_claim_full_cve_snapshot_when_not_full(self):
        with self.assertRaisesRegex(ValueError,"403,696"):
            link_audit(self.vendor,self.cve,self.registry,check_full_cve_count=True)

    def test_rejects_missing_source_provenance(self):
        with sqlite3.connect(self.cve) as db:
            db.execute("DELETE FROM warehouse_metadata WHERE key='source_index_sha256'")
        with self.assertRaisesRegex(ValueError,"hashes missing"):
            link_audit(self.vendor,self.cve,self.registry)

    def test_never_changes_the_two_source_databases(self):
        before=(self.vendor.read_bytes(),self.cve.read_bytes())
        link_audit(self.vendor,self.cve,self.registry)
        self.assertEqual((self.vendor.read_bytes(),self.cve.read_bytes()),before)


if __name__=="__main__":
    unittest.main()
