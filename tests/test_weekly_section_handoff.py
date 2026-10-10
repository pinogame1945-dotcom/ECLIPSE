"""New-disclosures and existing-CVE content revisions must NEVER share a 50 quota."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import unittest
import zipfile

from eclipse_l0.weekly_evidence import canonical
from eclipse_l0.weekly_section_handoff import create,verify,compute
from eclipse_l0.weekly_important import create as important_create
from eclipse_l0.weekly_update_queue import create as update_create
from test_weekly_evidence import WeeklyEvidenceTests
from test_weekly_important import sample_policy


class TwoSectionTests(unittest.TestCase):
    def setUp(self):
        fixture=WeeklyEvidenceTests("test_research_handoff_deterministic_and_transparent_about_coverage")
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.root=fixture.root
        self.source=self.root/"L1.zip"
        fixture._build(self.source)
        self.policy=self.root/"policy.json"
        self.policy.write_text(canonical(sample_policy())+"\n")
        self.important=self.root/"new.zip"
        self.updated=self.root/"updated.zip"
        important_create(self.source,self.policy,self.important)
        update_create(self.source,self.updated)

    def test_two_sections_independent_and_all_L1_still_present(self):
        out=self.root/"handoff.zip"
        got=create(self.important,self.updated,out)
        self.assertEqual(got["original_l1_cves"],4)
        self.assertEqual(got["new_candidates"],2)
        self.assertEqual(got["new_kev"],1)
        self.assertEqual(got["newly_published_non_kev"],1)
        self.assertEqual(got["update_only_count"],1)
        self.assertEqual(got["material_update_review_candidates"],0)
        self.assertEqual(got["update_unverified_count"],1)
        self.assertFalse(got["report_ready"])
        with zipfile.ZipFile(out) as z:
            summary=json.loads(z.read("weekly_distinct_section_summary.json"))
            news=[json.loads(t) for t in z.read("new_kev_and_disclosures.jsonl").splitlines()]
            revisions=[json.loads(t) for t in z.read("unverified_update_high_risk_watch.jsonl").splitlines()]
            self.assertEqual(len(news),2)
            self.assertEqual(len(revisions),1)
            self.assertEqual(revisions[0]["cve_id"],"CVE-2026-50005")
            self.assertTrue(summary["existing_cve_updates"]["separate_from_new_information"])
            self.assertIsNone(summary["existing_cve_updates"]["fixed_target_or_quota"])
            self.assertFalse(summary["existing_cve_updates"]["material_change_content_verified_as_official_publication"])
            self.assertEqual(z.read("new_cve_candidate_evidence.zip"),self.important.read_bytes())
            self.assertEqual(z.read("existing_cve_update_evidence.zip"),self.updated.read_bytes())

    def test_two_sections_deterministically_reproducible(self):
        a=self.root/"sections-a.zip";b=self.root/"sections-b.zip"
        create(self.important,self.updated,a)
        create(self.important,self.updated,b)
        self.assertEqual(a.read_bytes(),b.read_bytes())

    def test_mismatched_frozen_source_fails_closed(self):
        # Even one extra newline changes the original L1 and cannot be normalized.
        src=self.root/"alt-L1.zip"
        with zipfile.ZipFile(self.source) as old:
            blobs={n:old.read(n) for n in old.namelist()}
        blobs["quality_report.json"]+=b"\n"
        with zipfile.ZipFile(src,"w") as z:
            for name,data in blobs.items():z.writestr(name,data)
        from eclipse_l0.weekly_evidence import sha
        # Independent source verification itself refuses modified source.
        with self.assertRaises((ValueError,AssertionError)):
            update_create(src,self.root/"invalid.zip")

    def test_derived_member_edit_even_with_hash_repair_fails(self):
        out=self.root/"original.zip";create(self.important,self.updated,out)
        files={}
        with zipfile.ZipFile(out) as z:
            for name in z.namelist():files[name]=z.read(name)
        altered=self.root/"altered.zip"
        files["new_kev_and_disclosures.jsonl"]=b""
        manifest=json.loads(files["weekly_section_manifest.json"])
        manifest["member_sha256"]["new_kev_and_disclosures.jsonl"]=hashlib.sha256(b"").hexdigest()
        files["weekly_section_manifest.json"]=(canonical(manifest)+"\n").encode()
        with zipfile.ZipFile(altered,"w") as z:
            for name,body in files.items():z.writestr(name,body)
        with self.assertRaisesRegex(ValueError,"not reproducible"):
            verify(altered)


if __name__=="__main__":
    unittest.main()
