"""Deterministic CSAF semantic/provenance tests; no external network."""
import copy
import unittest
from eclipse_l0.vendor_csaf import normalize_csaf


class CsafStructuredClaimsTest(unittest.TestCase):
    def fixture(self):
        return {
          "document":{"title":"SYNTHETIC SSA for explicit affected products"},
          "product_tree":{
            "branches":[{"category":"vendor","name":"ExampleVendor","branches":[
                {"category":"product_name","name":"Example Device","branches":[
                    {"category":"product_version","name":"1.0",
                     "product":{"product_id":"VND:DEVICE:1.0","name":"Example Device 1.0"}},
                    {"category":"product_version","name":"1.1",
                     "product":{"product_id":"VND:DEVICE:1.1","name":"Example Device 1.1"}}
                ]}
            ]}],
            "full_product_names":[{"product_id":"VND:HOTFIX:1.2","name":"Example Device 1.2 fixed"}],
            "relationships":[{"full_product_name":{"product_id":"VND:BUNDLE",
                             "name":"Combined Example Bundle"}}],
          },
          "vulnerabilities":[
             {"cve":"CVE-2026-54321",
              "product_status":{
                  "known_affected":["VND:DEVICE:1.0"],
                  "known_not_affected":["VND:DEVICE:1.1"],
                  "first_fixed":["VND:HOTFIX:1.2"]},
              "remediations":[{
                 "category":"vendor_fix","details":"Use patch 1.2",
                 "product_ids":["VND:DEVICE:1.0"],
                 "url":"https://vendor.example.invalid/patch"
              }]},
             {"cve":"CVE-2026-76543",
              "product_status":{"under_investigation":["UNKNOWN:DEVICE"]},
              "remediations":[{"category":"workaround","details":"Disable feature",
                               "group_ids":["GROUP:1"]}]}
          ]
        }

    def test_resolves_product_tree_but_never_guesses_fixed_range(self):
        f=normalize_csaf(self.fixture(),"fallback")
        self.assertEqual(f["cve_ids"],["CVE-2026-54321","CVE-2026-76543"])
        self.assertEqual(f["product_catalog_size"],4)
        a=f["affected"][0]
        self.assertEqual(a["product_name_from_csaf"],"Example Device 1.0")
        self.assertEqual(a["product_id_unresolved"],"VND:DEVICE:1.0")  # backwards-compatible raw ID
        self.assertIn("product_tree.branches",a["name_evidence_path"])
        status={(x["cve_id"],x["status"]):x for x in f["product_status_claims_unreviewed"]}
        self.assertEqual(status["CVE-2026-54321","known_not_affected"]["product_name"],"Example Device 1.1")
        self.assertEqual(status["CVE-2026-54321","first_fixed"]["product_name"],"Example Device 1.2 fixed")
        self.assertEqual(status["CVE-2026-76543","under_investigation"]["product_name"],None)
        self.assertEqual(f["unresolved_product_ids"],["UNKNOWN:DEVICE"])
        self.assertNotIn("fixed_version",a)
        rem=f["remediations_unreviewed"]
        self.assertEqual(rem[0]["product_ids"],["VND:DEVICE:1.0"])
        self.assertEqual(rem[0]["details_original"],"Use patch 1.2")
        self.assertEqual(rem[1]["group_ids"],["GROUP:1"])
        self.assertTrue(f["evidence_fields"])

    def test_reject_contradictory_known_status_in_same_cve(self):
        doc=self.fixture()
        doc["vulnerabilities"][0]["product_status"]["known_not_affected"].append("VND:DEVICE:1.0")
        with self.assertRaisesRegex(ValueError,"Contradictory"):
            normalize_csaf(doc,"fallback")

    def test_reject_duplicate_different_product_names(self):
        doc=self.fixture()
        doc["product_tree"]["full_product_names"].append(
            {"product_id":"VND:DEVICE:1.0","name":"Misleading product label"})
        with self.assertRaisesRegex(ValueError,"Conflicting CSAF"):
            normalize_csaf(doc,"fallback")

    def test_unresolved_product_stays_unresolved(self):
        doc=self.fixture()
        del doc["product_tree"]
        f=normalize_csaf(doc,"fallback")
        self.assertIsNone(f["affected"][0]["product_name_from_csaf"])
        self.assertIn("VND:DEVICE:1.0",f["unresolved_product_ids"])

    def test_missing_cve_advisory_is_legal(self):
        doc=self.fixture()
        del doc["vulnerabilities"][0]["cve"]
        f=normalize_csaf(doc,"fallback")
        self.assertEqual(f["cve_ids"],["CVE-2026-76543"])
        self.assertEqual(f["affected"][0]["cve_id"],None)

    def test_bad_nested_tree_is_fatal(self):
        doc=self.fixture()
        doc["product_tree"]["branches"][0]["branches"]="UNKNOWN"
        with self.assertRaisesRegex(ValueError,"branches"):
            normalize_csaf(doc,"fallback")


if __name__=="__main__":
    unittest.main()
