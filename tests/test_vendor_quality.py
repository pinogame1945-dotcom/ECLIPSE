"""Field coverage assessments must not convert missing details into claims."""
import unittest
from eclipse_l0.vendor_quality import inspect_facts,summarize_source_quality


class VendorQualityTest(unittest.TestCase):
    def test_structured_csaf_rows_are_present_but_still_unreviewed(self):
        facts={
            "title":"SYNTHETIC CSAF",
            "cve_ids":["CVE-2026-99911"],
            "affected":[{"product_id_unresolved":"abc","product_name_from_csaf":"Device 1.0"}],
            "product_catalog_size":3,
            "product_status_claims_unreviewed":[
                {"status":"known_affected"},
                {"status":"first_fixed"},
                {"status":"under_investigation"}],
            "remediations_unreviewed":[{"details_original":"Update"}],
            "unresolved_product_ids":["def"],
            "evidence_fields":["product_tree.full_product_names","vulnerabilities[0].product_status"]
        }
        q=inspect_facts(facts,"siemens-csaf")
        self.assertFalse(q["quality_assured"])
        self.assertFalse(q["safe_for_customer_facing_auto_claims"])
        self.assertEqual(q["csaf_product_catalog_entries"],3)
        self.assertEqual(q["affected_entries_with_product_label"],1)
        self.assertEqual(q["publisher_marked_fixed_product_status_rows"],1)
        self.assertEqual(q["normalized_fixed_version_ranges_verified"],0)
        self.assertEqual(q["actual_exploitation_state"],"NOT_ASSESSED")
        self.assertIn("no matching product label"," ".join(q["cautions"]))
        qsummary=summarize_source_quality([{"field_quality":q}])
        self.assertEqual(qsummary["sampled_documents"],1)
        self.assertEqual(qsummary["verified_product_exposure_assessments"],0)
        self.assertFalse(qsummary["vendor_wide_coverage_assured"])

    def test_html_navigation_cve_candidates_stay_nonassertive(self):
        facts={"title":"SYNTHETIC notice","cve_ids":[],
               "affected":[],"unreviewed_page_cve_candidates":["CVE-2026-11111"],
               "evidence_fields":["publisher title"]}
        q=inspect_facts(facts,"atlassian-security")
        self.assertEqual(q["cve_ids_provisionally_extracted"],0)
        self.assertEqual(q["detected_html_cve_candidates_unlinked"],1)
        self.assertFalse(q["quality_assured"])
        self.assertIn("navigation"," ".join(q["cautions"]))
