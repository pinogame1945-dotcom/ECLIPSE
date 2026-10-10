"""Material revision classifier contract: synthetic vendor source pairs, no network."""
from __future__ import annotations

from datetime import date
from pathlib import Path
import json
import sqlite3
import tempfile
import unittest

from eclipse_l0.vendor_registry import load_registry
from eclipse_l0.vendor_store import connect, observe
from eclipse_l0.weekly_material import (
    analyze_vendor_history, verify_report, write_report, _diff, _scoped)

REGISTRY=Path(__file__).resolve().parents[1]/"config/vendor_source_registry.json"


class MaterialVendorDiffTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name)/"vendor.sqlite3"
        self.db=connect(self.path)
        self.addCleanup(self.db.close)
        self.registry=load_registry(REGISTRY)

    def _observe(self, source, ident, body_digest, observed, facts, status="parsed_unreviewed"):
        config=next(x for x in self.registry["sources"] if x["source_id"]==source)
        return observe(self.db,registry=self.registry,source_id=source,advisory_id=ident,
                       source_url=config["detail_sample_url"],
                       source_sha256=body_digest*64,observed_utc=observed,
                       facts=facts,extract_status=status)

    def _facts(self):
        return {"title":"SYNTHETIC NOT A REAL ADVISORY",
                "cve_ids":["CVE-2026-999998"],
                "affected":[{"product":"fictional appliance","versions_raw":["1.0"]}],
                "evidence_fields":["fixtures.cna.affected"],
                "_extractor_revision":"parser-1"}

    def test_strict_important_update_detects_before_after_and_replay(self):
        baseline=self._facts()
        self.assertEqual(self._observe("paloalto-advisories","CVE-2026-999998",
                                        "a","2026-10-01T01:00:00Z",baseline)["event"],"baseline")
        changed=self._facts()
        changed["affected"][0]["versions_raw"]=["1.0","1.1"]
        self.assertEqual(self._observe("paloalto-advisories","CVE-2026-999998",
                                        "b","2026-10-09T01:00:00Z",changed)["event"],"facts_updated")
        result=analyze_vendor_history(self.path,self.registry,start="2026-10-04",end="2026-10-10")
        self.assertEqual(result["event_counts"]["scoped_cve_review_candidates"],1)
        item=result["events"][0]
        self.assertEqual(item["security_claim_change_categories"],
                         ["AFFECTED_PRODUCT_OR_VERSION_CLAIM_CHANGED"])
        self.assertEqual(item["candidate_cve_ids"],["CVE-2026-999998"])
        self.assertTrue(item["eligible_for_weekly_research"])
        self.assertFalse(item["publisher_release_date_confirmed"])
        self.assertFalse(item["safe_for_client_automatic_claims"])
        output=Path(self.temp.name)/"result.json"
        write_report(output,self.path,self.registry,"2026-10-04","2026-10-10")
        self.assertEqual(verify_report(output,self.path,self.registry)["candidate_events"],1)
        payload=json.loads(output.read_text())
        payload["events"][0]["eligible_for_weekly_research"]=False
        output.write_text(json.dumps(payload))
        with self.assertRaisesRegex(ValueError,"reproducible"):
            verify_report(output,self.path,self.registry)

    def test_html_single_cve_never_creates_scoped_publisher_alert(self):
        f=self._facts()
        self._observe("fortinet-psirt","FG-IR-26-175","a","2026-10-01T02:00:00Z",f)
        nxt=self._facts()
        nxt["affected"][0]["versions_raw"]=["2.0"]
        self._observe("fortinet-psirt","FG-IR-26-175","b","2026-10-08T02:00:00Z",nxt)
        result=analyze_vendor_history(self.path,self.registry,start="2026-10-04",end="2026-10-10")
        item=result["events"][0]
        self.assertTrue(item["security_claim_change_categories"])
        self.assertFalse(item["eligible_for_weekly_research"])
        self.assertEqual(item["candidate_cve_ids"],[])
        self.assertEqual(item["cve_link_status"],"MULTI_CVE_OR_PAGEWIDE_LINK_REVIEW_UNSCOPED")

    def test_same_body_extraction_revision_cannot_claim_vendor_update(self):
        old=self._facts()
        self._observe("paloalto-advisories","CVE-2026-999998","a","2026-10-01T02:00:00Z",old)
        new=self._facts()
        new["affected"][0]["versions_raw"]=["2.0"]
        new["_extractor_revision"]="parser-2"
        self._observe("paloalto-advisories","CVE-2026-999998","b","2026-10-08T02:00:00Z",new)
        result=analyze_vendor_history(self.path,self.registry,start="2026-10-04",end="2026-10-10")
        item=result["events"][0]
        self.assertFalse(item["eligible_for_weekly_research"])
        self.assertEqual(item["security_claim_change_categories"],[])
        self.assertEqual(item["change_status"],"NO_CONFIRMED_SECURITY_ASSERTION_DIFF")
        self.assertFalse(result["vendor_weekly_monitoring_complete"])

    def test_source_changed_only_and_cosmetic_order_are_suppressed(self):
        old=self._facts()
        old["affected"]=[{"product":"X","versions_raw":["a"]},
                         {"product":"Y","versions_raw":["b"]}]
        self._observe("paloalto-advisories","CVE-2026-999998","a","2026-10-01T02:00:00Z",old)
        new=self._facts()
        new["affected"]=list(reversed(old["affected"]))
        new["evidence_fields"]=["totally different HTML extraction locator"]
        self._observe("paloalto-advisories","CVE-2026-999998","b","2026-10-08T02:00:00Z",new)
        result=analyze_vendor_history(self.path,self.registry,start="2026-10-04",end="2026-10-10")
        self.assertEqual(result["events"][0]["security_claim_change_categories"],[])
        self.assertFalse(result["events"][0]["eligible_for_weekly_research"])

    def test_multi_cve_csaf_only_changed_scoped_status_associated(self):
        ident="RHSA-2026-999998"
        old={"title":"SYNTHETIC", "cve_ids":["CVE-2026-999998","CVE-2026-999997"],
             "affected":[],"evidence_fields":["document.vulnerabilities"],
             "_extractor_revision":"fixed",
             "product_status_claims_unreviewed":[
               {"cve_id":"CVE-2026-999998","status":"known_affected","product_name":"X"},
               {"cve_id":"CVE-2026-999997","status":"known_affected","product_name":"Y"}]}
        self._observe("redhat-csaf",ident,"a","2026-10-01T01:00:00Z",old)
        nxt=json.loads(json.dumps(old))
        nxt["product_status_claims_unreviewed"][0]["status"]="fixed"
        self._observe("redhat-csaf",ident,"b","2026-10-09T01:00:00Z",nxt)
        result=analyze_vendor_history(self.path,self.registry,start="2026-10-04",end="2026-10-10")
        self.assertEqual(result["events"][0]["candidate_cve_ids"],["CVE-2026-999998"])
        self.assertTrue(result["events"][0]["eligible_for_weekly_research"])

    def test_baseline_is_not_new_announcement(self):
        self._observe("paloalto-advisories","CVE-2026-999998","a","2026-10-09T01:00:00Z",
                      self._facts())
        result=analyze_vendor_history(self.path,self.registry,start="2026-10-04",end="2026-10-10")
        self.assertEqual(len(result["events"]),0)
        self.assertEqual(result["event_counts"]["baseline_not_update"],1)


if __name__=="__main__":
    unittest.main()
