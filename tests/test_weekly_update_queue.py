"""Weekly update queue must never claim that metadata date alone is a security update."""
from __future__ import annotations
import hashlib,json,tempfile,unittest,zipfile
from pathlib import Path
from test_weekly_evidence import WeeklyEvidenceTests
from eclipse_l0.weekly_update_queue import compute,create,verify
from eclipse_l0.weekly_evidence import canonical


class UpdateQueueTest(unittest.TestCase):
    def setUp(self):
        fixture=WeeklyEvidenceTests("test_research_handoff_deterministic_and_transparent_about_coverage")
        fixture.setUp();self.addCleanup(fixture.doCleanups)
        self.root=fixture.root
        self.week=self.root/"week.zip"
        fixture._build(self.week)
    def test_date_updated_only_produces_unverified_queue_and_hash_verified_zip(self):
        path=self.root/"queue.zip"
        result=create(self.week,path)
        self.assertEqual(result["original_cves"],4)
        self.assertEqual(result["updated_only"],1)
        self.assertEqual(result["material_review_candidates"],0)
        self.assertEqual(result["unverified_updated"],1)
        self.assertFalse(result["update_weekly_coverage_certified"])
        with zipfile.ZipFile(path) as z:
            self.assertEqual(z.read("source-weekly-evidence.zip"),self.week.read_bytes())
            ledger=[json.loads(x) for x in z.read("updated_cve_decision_ledger.jsonl").splitlines()]
            self.assertEqual(len(ledger),1)
            self.assertEqual(ledger[0]["cve_id"],"CVE-2026-50005")
            self.assertFalse(ledger[0]["selected_for_weekly_report"])
    def test_same_input_produces_byte_deterministic_zip(self):
        first=self.root/"a.zip";second=self.root/"b.zip"
        create(self.week,first);create(self.week,second)
        self.assertEqual(first.read_bytes(),second.read_bytes())
    def test_outside_cve_event_does_not_sneak_into_week(self):
        report={
            "kind":"ECLIPSE_OBSERVED_VENDOR_FACTS_DIFF_REVIEW_ONLY",
            "window":{"start_utc":"2026-10-04","end_utc":"2026-10-10"},
            "vendor_weekly_monitoring_complete":False,
            "events":[{"candidate_cve_ids":["CVE-2099-0001"],"eligible_for_weekly_research":True,
                       "source_id":"synthetic","advisory_id":"fake","source_url":"https://example.invalid",
                       "old_source_sha256":"a"*64,"new_source_sha256":"b"*64,
                       "change_status":"MATERIAL_SOURCE_CONTENT_CHANGE_REVIEW_REQUIRED",
                       "cve_link_status":"PALOALTO_DIRECT_SINGLE_CVE_CNA_SOURCE",
                       "security_claim_change_categories":["AFFECTED_PRODUCT_OR_VERSION_CLAIM_CHANGED"]}]
        }
        result=compute(self.week.read_bytes(),vendor_material=(canonical(report)+"\n").encode())
        summary=json.loads(result["update_review_summary.json"])
        self.assertEqual(summary["supported_material_change_review_candidates"],0)
        self.assertEqual(summary["unverified_or_unmatched_updated_cves"],1)
    def test_review_proof_in_scope_is_not_equivalent_to_publisher_update_date(self):
        item={"source_id":"paloalto-advisories","advisory_id":"synthetic",
              "source_url":"https://security.paloaltonetworks.com/json/CVE-2026-50005",
              "old_source_sha256":"a"*64,"new_source_sha256":"b"*64,
              "change_status":"MATERIAL_SOURCE_CONTENT_CHANGE_REVIEW_REQUIRED",
              "security_claim_change_categories":["AFFECTED_PRODUCT_OR_VERSION_CLAIM_CHANGED"],
              "cve_link_status":"PALOALTO_DIRECT_SINGLE_CVE_CNA_SOURCE",
              "candidate_cve_ids":["CVE-2026-50005"],"eligible_for_weekly_research":True}
        proof={"kind":"ECLIPSE_OBSERVED_VENDOR_FACTS_DIFF_REVIEW_ONLY",
               "window":{"start_utc":"2026-10-04","end_utc":"2026-10-10"},
               "vendor_weekly_monitoring_complete":False,"events":[item]}
        packet=(canonical(proof)+"\n").encode()
        result=compute(self.week.read_bytes(),vendor_material=packet)
        queue=[json.loads(x) for x in result["material_update_review_candidates.jsonl"].splitlines()]
        self.assertEqual([x["cve_id"] for x in queue],["CVE-2026-50005"])
        self.assertFalse(queue[0]["selected_for_weekly_report"])
        self.assertEqual(queue[0]["review_evidence"][0]["time_basis"],
                         "VENDOR_OBSERVED_UTC_NOT_PUBLISHER_UPDATE_DATE")
    def test_tampering_packet_member_is_detected(self):
        path=self.root/"original.zip";create(self.week,path)
        bad=self.root/"altered.zip"
        with zipfile.ZipFile(path) as src:
            files={name:src.read(name) for name in src.namelist()}
        files["updated_cve_decision_ledger.jsonl"]=b""
        manifest=json.loads(files["update_review_manifest.json"])
        manifest["member_sha256"]["updated_cve_decision_ledger.jsonl"]=hashlib.sha256(b"").hexdigest()
        files["update_review_manifest.json"]=(canonical(manifest)+"\n").encode()
        with zipfile.ZipFile(bad,"w") as z:
            for name,data in files.items():z.writestr(name,data)
        with self.assertRaisesRegex(ValueError,"independently reproduced"):
            verify(bad)


if __name__=="__main__": unittest.main()
