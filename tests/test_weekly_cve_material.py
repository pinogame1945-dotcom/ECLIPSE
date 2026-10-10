"""Synthetic full official-format CVE V5 history diff tests, no network."""
from __future__ import annotations
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from eclipse_l0.weekly_cve_material import compare_pair, analyze_pair_jsonl,write_report,verify_report
from eclipse_l0.weekly_material import canonical


def rec(affected="1.0", meta="2026-10-01T00:00:00Z", description="Synthetic CVE"):
    return {"cveMetadata":{"cveId":"CVE-2026-999998","state":"PUBLISHED","dateUpdated":meta},
            "containers":{"cna":{
                "descriptions":[{"lang":"en","value":description}],
                "affected":[{"vendor":"FICTIONAL","product":"FOOBAR","versions":[{"version":affected,"status":"affected"}]}],
                "metrics":[{"cvssV3_1":{"baseScore":9.8}}],
                "solutions":[{"lang":"en","value":"Synthetic fix"}]
            }}}


def pair(before,after,stamp="2026-10-09T00:00:00Z"):
    h=lambda r:hashlib.sha256(canonical(r).encode()).hexdigest()
    return {"cve_id":"CVE-2026-999998","before":before,"after":after,
            "before_canonical_sha256":h(before),"after_canonical_sha256":h(after),
            "observed_utc":stamp}


class CveRevisionPairTest(unittest.TestCase):
    def test_versions_changed_is_review_not_confirmed_impact(self):
        row=compare_pair(pair(rec(),rec("1.1")))
        self.assertEqual(row["result"],"MATERIAL_CNA_SECURITY_CONTENT_CHANGE_REVIEW")
        self.assertTrue(row["candidate_for_material_security_review"])
        self.assertFalse(row["confirmed_publisher_revision_date"])
        self.assertFalse(row["confirmed_customer_impact"])

    def test_metadata_only_does_not_claim_security_change(self):
        row=compare_pair(pair(rec(),rec(meta="2026-10-09T03:00:00Z")))
        self.assertEqual(row["result"],"CVE_METADATA_ONLY_CHANGE")
        self.assertFalse(row["candidate_for_material_security_review"])

    def test_descriptions_only_are_review_not_automatic_critical(self):
        row=compare_pair(pair(rec(),rec(description="Synthetic revised description")))
        self.assertEqual(row["result"],"DESCRIPTION_OR_WEAKNESS_UPDATED_REVIEW")
        self.assertFalse(row["candidate_for_material_security_review"])

    def test_reordered_affected_is_not_security_change(self):
        a=rec()
        a["containers"]["cna"]["affected"].append({"vendor":"OTHER","product":"BAR","versions":[]})
        b=copy.deepcopy(a)
        b["containers"]["cna"]["affected"].reverse()
        self.assertEqual(compare_pair(pair(a,b))["result"],"NON_SECURITY_FIELD_OR_NO_CHANGE")

    def test_hash_tamper_and_cross_cve_pair_fail_closed(self):
        p=pair(rec(),rec("1.1"))
        p["after_canonical_sha256"]="0"*64
        with self.assertRaisesRegex(ValueError,"hash"):
            compare_pair(p)
        p=pair(rec(),rec("1.1"))
        p["after"]["cveMetadata"]["cveId"]="CVE-2026-999997"
        with self.assertRaisesRegex(ValueError,"ID mismatch"):
            compare_pair(p)

    def test_reproducible_packet_and_observation_window(self):
        with tempfile.TemporaryDirectory() as d:
            source=Path(d)/"pairs.jsonl"
            report=Path(d)/"material.json"
            p=pair(rec(),rec("1.1"))
            source.write_text(canonical(p)+"\n")
            result=write_report(source,report,"2026-10-04","2026-10-10")
            self.assertEqual(result["pairs_compared"],1)
            self.assertEqual(verify_report(source,report)["pairs_compared"],1)
            bad=json.loads(report.read_text())
            bad["events"][0]["candidate_for_material_security_review"]=False
            report.write_text(canonical(bad)+"\n")
            with self.assertRaisesRegex(ValueError,"reproducible"):
                verify_report(source,report)
            with self.assertRaisesRegex(ValueError,"Out-of-window"):
                analyze_pair_jsonl(source.read_bytes(),"2026-10-11","2026-10-11")

    def test_no_prior_version_is_not_comparable(self):
        with self.assertRaisesRegex(ValueError,"Missing"):
            compare_pair({"cve_id":"CVE-2026-999998","after":rec()})


if __name__=="__main__":
    unittest.main()
