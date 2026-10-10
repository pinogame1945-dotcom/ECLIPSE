"""Offline product/version cross-source comparison safety fixtures."""
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from eclipse_l0.vendor_registry import load_registry
from eclipse_l0.vendor_store import connect, observe
from eclipse_l0.vendor_content_audit import content_audit,name_key,literal_exact_versions

REGISTRY=load_registry(Path(__file__).resolve().parents[1]/"config/vendor_source_registry.json")
SOURCES={x["source_id"]:x for x in REGISTRY["sources"]}


class ContentAuditTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir=Path(tmp.name)
        self.vendor=self.dir/"vendor.sqlite3"
        self.cve=self.dir/"cve.sqlite3"
        with sqlite3.connect(self.cve) as db:
            db.executescript("""
            CREATE TABLE cve_current(cve_id TEXT PRIMARY KEY,record_state TEXT,hash TEXT);
            CREATE TABLE warehouse_metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);
            CREATE TABLE warehouse_affected(
              cve_id TEXT, container TEXT,ordinal INTEGER,vendor TEXT,
              product TEXT,versions_json TEXT,default_status TEXT);
            """)
            db.executemany("INSERT INTO warehouse_metadata VALUES(?,?)",[
                ("source_index_sha256",json.dumps("a"*64)),
                ("source_archive_sha256",json.dumps("b"*64))])
            db.executemany("INSERT INTO cve_current VALUES(?,?,?)",[
                (f"CVE-2026-{i:05d}","REJECTED" if i==6 else "PUBLISHED","a"*64)
                for i in range(1,7)])
            db.executemany("INSERT INTO warehouse_affected VALUES(?,?,?,?,?,?,?)",[
                ("CVE-2026-00001","cna",0,"Palo Alto Networks","PAN-OS",
                 json.dumps([{"version":"11.0.2","status":"affected"},
                             {"version":"11.0.3","status":"unaffected"}]),None),
                ("CVE-2026-00002","cna",0,"Palo Alto Networks","PAN-OS",
                 json.dumps([{"version":"11.0.2","status":"affected"}]),None),
                ("CVE-2026-00003","cna",0,"Palo Alto Networks","Other Firewall",
                 json.dumps([{"version":"1.0","status":"affected"}]),None),
                ("CVE-2026-00004","cna",0,"Siemens","Controller 1.0",
                 json.dumps([{"version":"1.0","status":"affected"}]),None),
                ("CVE-2026-00005","adp:0",0,"Palo Alto Networks","PAN-OS",
                 json.dumps([{"version":"1.0","status":"affected"}]),None)
            ])
        self.observations=[
            ("paloalto-advisories","CVE-2026-00001",{"cve_ids":["CVE-2026-00001"],
                "affected":[{"vendor":"Palo Alto Networks","product":"PAN-OS",
                             "versions_raw":[{"version":"11.0.2","status":"affected"},
                                             {"version":"11.0.3","status":"unaffected"}]}]}),
            ("paloalto-advisories","CVE-2026-00002",{"cve_ids":["CVE-2026-00002"],
                "affected":[{"vendor":"Palo Alto Networks","product":"PAN-OS",
                             "versions_raw":[{"version":"11.0.2","status":"unaffected"}]}]}),
            ("paloalto-advisories","CVE-2026-00003",{"cve_ids":["CVE-2026-00003"],
                "affected":[{"vendor":"Palo Alto Networks","product":"PAN-OS",
                             "versions_raw":[{"version":"1.0","status":"affected"}]}]}),
            ("siemens-csaf","SSA-SYNTH",{"cve_ids":["CVE-2026-00004"],
                "affected":[],"product_status_claims_unreviewed":[
                    {"cve_id":"CVE-2026-00004","product_name":"Controller 1.0",
                     "status":"known_affected","evidence_path":"vulnerabilities[0].product_status.known_affected"}]}),
            ("fortinet-psirt","FG-IR-SYNTH",{"cve_ids":["CVE-2026-00001"],
                "affected":[{"product_release":"FortiOS 7.0",
                             "affected_versions_raw":"7.0.0 through 7.0.10"}]}),
            ("paloalto-advisories","CVE-2026-00005",{"cve_ids":["CVE-2026-00005"],
                "affected":[{"vendor":"Palo Alto Networks","product":"PAN-OS",
                             "versions_raw":[{"version":"1.0","status":"affected"}]}]}),
            ("paloalto-advisories","CVE-2026-00006",{"cve_ids":["CVE-2026-00006"],
                "affected":[{"vendor":"Palo Alto Networks","product":"PAN-OS",
                             "versions_raw":[{"version":"1.0","status":"affected"}]}]})
        ]
        db=connect(self.vendor)
        try:
            for i,(sid,ident,raw) in enumerate(self.observations):
                observe(db,registry=REGISTRY,source_id=sid,advisory_id=ident,
                    source_url=SOURCES[sid]["detail_sample_url"],
                    source_sha256=f"{i+1:064x}",
                    observed_utc="2026-10-10T14:00:00Z",
                    facts={"title":"Synthetic evidence", "evidence_fields":["fixture"],**raw})
        finally:db.close()

    def test_exact_product_and_literal_mismatch_are_review_only(self):
        result=content_audit(self.vendor,self.cve,REGISTRY)
        counts=result["counts"]
        self.assertEqual(counts["EXACT_VERSION_STATUS_AGREEMENT_FOR_SHARED_LITERALS"],1)
        self.assertEqual(counts["EXACT_VERSION_STATUS_DISAGREEMENT_REVIEW_ONLY"],1)
        self.assertEqual(counts["NO_EXACT_CNA_PRODUCT_NAME_MATCH"],2)  # one unrelated CNA product plus ADP-only claim
        self.assertEqual(counts["PRODUCT_NAME_EXACT_MATCH_CSAF_STATUS_UNMAPPED"],1)
        self.assertEqual(counts["HTML_PAGEWIDE_CVE_LINK_UNVERIFIED"],1)
        self.assertEqual(counts["CLAIM_CVE_NOT_PUBLISHED_IN_SNAPSHOT"],1)
        self.assertEqual(counts["NO_EXACT_CNA_PRODUCT_NAME_MATCH"],2)  # a mismatched CNA product and an ADP-only entry
        self.assertTrue(result["policy"]["no_vendor_product_exposure_certification"])
        self.assertFalse(result["policy"]["customer_delivery_allowed"])
        disputed=result["evidence_samples"]["EXACT_VERSION_STATUS_DISAGREEMENT_REVIEW_ONLY"][0]
        self.assertEqual(disputed["shared_exact_versions"],["11.0.2"])
        self.assertEqual(disputed["cve_evidence_path"],"warehouse_affected(cna,0)")

    def test_detects_missing_published_CNA_product_and_ignores_adp(self):
        result=content_audit(self.vendor,self.cve,REGISTRY)
        self.assertGreaterEqual(result["counts"]["NO_EXACT_CNA_PRODUCT_NAME_MATCH"],1)
        self.assertEqual(result["snapshot"]["cve_source_index_sha256"],"a"*64)

    def test_no_fuzzy_product_alias_or_numeric_version_inference(self):
        self.assertEqual(name_key("  PAN-OS   "), "pan-os")
        self.assertNotEqual(name_key("PAN OS"),name_key("PAN-OS"))
        self.assertEqual(literal_exact_versions([{"version":"11.0","status":"affected",
                                                  "lessThan":"11.2"}]),{})
        self.assertEqual(literal_exact_versions([{"version":"11.*","status":"affected"}]),{})
        self.assertEqual(literal_exact_versions([{"version":"1.0","status":"affected"},
                                                {"version":"1.0","status":"unaffected"}]),{})

    def test_snapshots_never_change(self):
        original=(self.vendor.read_bytes(),self.cve.read_bytes())
        content_audit(self.vendor,self.cve,REGISTRY)
        self.assertEqual((self.vendor.read_bytes(),self.cve.read_bytes()),original)

    def test_full_403696_count_gate(self):
        with self.assertRaisesRegex(ValueError,"403696"):
            content_audit(self.vendor,self.cve,REGISTRY,require_full_cve=True)


if __name__=="__main__":
    unittest.main()
