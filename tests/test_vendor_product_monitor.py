"""Private product monitor: scoped CSAF CVE-product-remediation tests, offline."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from eclipse_l0.vendor_csaf import normalize_csaf
from eclipse_l0.vendor_registry import load_registry
from eclipse_l0.vendor_store import connect, observe
from eclipse_l0.vendor_product_monitor import (
    _load_inventory,match_customer_products,product_catalog
)

REGISTRY=load_registry(Path(__file__).resolve().parents[1]/"config/vendor_source_registry.json")
SOURCES={x["source_id"]:x for x in REGISTRY["sources"]}


class StrictInventoryMonitorTest(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir=Path(tmp.name)
        self.db=self.dir/"vendor.sqlite3"
        self.inventory=self.dir/"customer-private.json"
        self._write_inventory([
          {"id":"switch-a","vendor":"Siemens","product":"SIMATIC Field PG M5",
           "installed_version":"customer-reported-1.2"},
          {"id":"server-a","vendor":"Red Hat","product":"Red Hat Enterprise Linux 8.8",
           "csaf_product_id":"RHEL:8.8"},
          {"id":"unseen","vendor":"Siemens","product":"SIMATIC Unseen Product"},
        ])
        self.si=normalize_csaf({
          "document":{"title":"SYNTHETIC Siemens bulletin"},
          "product_tree":{"full_product_names":[
              {"product_id":"SIMATIC:FIELD:5","name":"SIMATIC Field PG M5"},
              {"product_id":"SIMATIC:FIELD:6","name":"SIMATIC Field PG M6"}]},
          "vulnerabilities":[
             {"cve":"CVE-2026-10011",
              "product_status":{"known_affected":["SIMATIC:FIELD:5"],
                                "known_not_affected":["SIMATIC:FIELD:6"]},
              "remediations":[{"category":"vendor_fix","details":"Apply specific vendor fix",
                                "product_ids":["SIMATIC:FIELD:5"]},
                               {"category":"workaround","details":"Group-only workaround",
                                "group_ids":["SIMATIC:GROUP:1"]},
                               {"category":"vendor_fix","details":"NO TARGETS GLOBAL AMBIGUITY"}]},
             {"cve":"CVE-2026-10012",
              "product_status":{"fixed":["SIMATIC:FIELD:5"]},
              "remediations":[{"category":"workaround","details":"Different CVE only",
                                "product_ids":["SIMATIC:FIELD:5"]}]}
          ]},"SYNTHETIC")
        self.rh=normalize_csaf({
          "document":{"title":"SYNTHETIC Red Hat bulletin"},
          "product_tree":{"full_product_names":[
              {"product_id":"RHEL:8.8","name":"Red Hat Enterprise Linux 8.8"},
              {"product_id":"RHEL:8.9","name":"Red Hat Enterprise Linux 8.9"}]},
          "vulnerabilities":[{"cve":"CVE-2026-10011",
             "product_status":{"known_affected":["RHEL:8.8"],"first_fixed":["RHEL:8.9"]}}]
        },"SYNTHETIC")
        db=connect(self.db)
        try:
            for i,(sid,facts) in enumerate([("siemens-csaf",self.si),("redhat-csaf",self.rh)]):
                observe(db,registry=REGISTRY,source_id=sid,
                    advisory_id=f"SYNTH-{i+1:04d}",
                    source_url=SOURCES[sid]["detail_sample_url"],
                    source_sha256=f"{i+1:064x}",observed_utc="2026-10-10T11:45:00Z",
                    facts=facts)
        finally:db.close()

    def _write_inventory(self,rows):
        self.inventory.write_text(json.dumps({
            "schema_version":1,"customer_name":"SYNTHETIC_NOT_A_REAL_CLIENT","products":rows
        },ensure_ascii=False),encoding="utf-8")

    def test_product_id_and_name_matching_scoped_to_publisher_and_cve(self):
        d=match_customer_products(self.db,self.inventory,REGISTRY)
        self.assertEqual(d["coverage"]["monitored_products"],3)
        self.assertEqual(d["coverage"]["candidate_status_rows"],3)
        self.assertEqual(d["coverage"]["distinct_product_cve_candidates"],3)
        self.assertEqual(d["coverage"]["inventory_entries_without_exact_evidence"],1)
        a=[r for r in d["candidate_findings"] if r["inventory_id"]=="switch-a" and r["cve_id"]=="CVE-2026-10011"][0]
        self.assertEqual(a["publisher_product_status_unreviewed"],"known_affected")
        self.assertEqual(a["publisher_product_id"],"SIMATIC:FIELD:5")
        self.assertEqual(a["match_state"],"EXACT_PUBLISHER_NAME_ONE_ID")
        self.assertEqual(a["customer_version_impact"],"NOT_ASSESSED")
        self.assertFalse(a["notification_approved"])
        self.assertEqual(len(a["explicitly_targeted_remediation_texts_unreviewed"]),1)
        self.assertEqual(a["explicitly_targeted_remediation_texts_unreviewed"][0]["publisher_text_unreviewed"],
                         "Apply specific vendor fix")
        fixed=[r for r in d["candidate_findings"] if r["cve_id"]=="CVE-2026-10012"][0]
        self.assertEqual(fixed["publisher_product_status_unreviewed"],"fixed")
        self.assertFalse(fixed["fixed_version_certified"])
        self.assertEqual(len(fixed["explicitly_targeted_remediation_texts_unreviewed"]),1)
        b=[r for r in d["candidate_findings"] if r["inventory_id"]=="server-a"][0]
        self.assertEqual(b["match_state"],"EXACT_PUBLISHER_PRODUCT_ID")
        self.assertEqual(b["publisher_product_name"],"Red Hat Enterprise Linux 8.8")
        self.assertTrue(d["security_policy"]["client_inventory_never_sent_to_github_or_kaggle"])

    def test_remediation_with_unrelated_cve_or_group_only_is_not_applied(self):
        d=match_customer_products(self.db,self.inventory,REGISTRY)
        si=[r for r in d["candidate_findings"] if r["inventory_id"]=="switch-a"]
        self.assertEqual(len(si),2)
        self.assertNotIn("Group-only workaround",json.dumps(si))
        self.assertNotIn("NO TARGETS GLOBAL AMBIGUITY",json.dumps(si))

    def test_catalog_returns_actual_publisher_product_id_candidates(self):
        d=product_catalog(self.db,REGISTRY,"siemens-csaf")
        self.assertEqual(d["known_catalog_ids"],2)
        names={x["publisher_product_id"] for x in d["entries"]}
        self.assertEqual(names,{"SIMATIC:FIELD:5","SIMATIC:FIELD:6"})
        self.assertTrue(all(x["review_state"]=="UNREVIEWED_VENDOR_PRODUCT_TREE" for x in d["entries"]))

    def test_ambiguous_exact_product_name_requires_explicit_id(self):
        db=connect(self.db)
        try:
            facts=normalize_csaf({
              "document":{"title":"SYNTHETIC ambiguous publisher IDs"},
              "product_tree":{"full_product_names":[
                  {"product_id":"A:1","name":"SIMATIC Field PG M5"},
                  {"product_id":"A:2","name":"SIMATIC Field PG M5"}]},
              "vulnerabilities":[{"cve":"CVE-2026-10044",
                  "product_status":{"known_affected":["A:1"],"known_not_affected":["A:2"]}}]
            },"SYNTH")
            observe(db,registry=REGISTRY,source_id="siemens-csaf",
                    advisory_id="SYNTH-AMBIG",source_url=SOURCES["siemens-csaf"]["detail_sample_url"],
                    source_sha256="3"*64,observed_utc="2026-10-10T11:55:00Z",facts=facts)
        finally:db.close()
        rows=[r for r in match_customer_products(self.db,self.inventory,REGISTRY)["candidate_findings"]
              if r["advisory_id"]=="SYNTH-AMBIG"]
        self.assertEqual(len(rows),2)
        self.assertEqual({r["match_state"] for r in rows},{"MULTIPLE_PRODUCT_IDS_REQUIRE_SELECTION"})
        self.assertTrue(all(not r["explicitly_targeted_remediation_texts_unreviewed"] for r in rows))

    def test_cross_vendor_product_name_must_not_match(self):
        self._write_inventory([{"id":"wrong-vendor","vendor":"Red Hat",
                                "product":"SIMATIC Field PG M5"}])
        d=match_customer_products(self.db,self.inventory,REGISTRY)
        self.assertEqual(d["coverage"]["candidate_status_rows"],0)
        self.assertEqual(d["coverage"]["inventory_entries_without_exact_evidence"],1)

    def test_oversized_official_csaf_names_are_skipped_not_privacy_errors(self):
        db=connect(self.db)
        try:
            huge="Hardware bundle "+("device "+40)*7
            facts=normalize_csaf({
              "document":{"title":"SYNTHETIC long officially named product"},
              "product_tree":{"full_product_names":[{"product_id":"LONG:SKU","name":huge}]},
              "vulnerabilities":[{"cve":"CVE-2026-10054",
                  "product_status":{"known_affected":["LONG:SKU"]}}]
            },"fallback")
            observe(db,registry=REGISTRY,source_id="siemens-csaf",
                    advisory_id="SYNTH-LONG-PRODUCT",source_url=SOURCES["siemens-csaf"]["detail_sample_url"],
                    source_sha256="4"*64,observed_utc="2026-10-10T11:56:00Z",facts=facts)
        finally:db.close()
        result=match_customer_products(self.db,self.inventory,REGISTRY)
        self.assertEqual(result["coverage"]["candidate_status_rows"],3)

    def test_never_read_semver_to_claim_customer_is_unaffected(self):
        self._write_inventory([{"id":"switch-a","vendor":"Siemens",
                                "product":"SIMATIC Field PG M5","installed_version":"1.2"}])
        d=match_customer_products(self.db,self.inventory,REGISTRY)
        self.assertEqual(len(d["candidate_findings"]),2)
        self.assertTrue(all(x["customer_version_impact"]=="NOT_ASSESSED" for x in d["candidate_findings"]))

    def test_rejects_unapproved_source_and_never_changes_database(self):
        self._write_inventory([{"id":"x","vendor":"Fortinet","product":"FortiOS"}])
        with self.assertRaisesRegex(ValueError,"Only explicitly scoped"):
            match_customer_products(self.db,self.inventory,REGISTRY)
        self._write_inventory([{"id":"switch-a","vendor":"Siemens","product":"SIMATIC Field PG M5"}])
        initial=self.db.read_bytes()
        match_customer_products(self.db,self.inventory,REGISTRY)
        self.assertEqual(self.db.read_bytes(),initial)

    def test_wrong_explicit_product_id_yields_no_match_not_safety(self):
        self._write_inventory([{"id":"s","vendor":"Siemens","product":"SIMATIC Field PG M5",
                                "csaf_product_id":"WRONG:SKU"}])
        d=match_customer_products(self.db,self.inventory,REGISTRY)
        self.assertFalse(d["candidate_findings"])
        self.assertIn("NOT_PROOF_OF_SAFETY",d["unmatched_inventory_products"][0]["finding"])

    def test_duplicate_id_invalid_and_untrusted_private_inventory_rejected(self):
        self._write_inventory([{"id":"dup","vendor":"Siemens","product":"A"},
                               {"id":"dup","vendor":"Siemens","product":"B"}])
        with self.assertRaisesRegex(ValueError,"duplicate"):
            _load_inventory(self.inventory)


if __name__=="__main__":
    unittest.main()
