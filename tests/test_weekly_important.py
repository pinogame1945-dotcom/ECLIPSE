"""Synthetic checks for the ~50 review selector. NO real 126-vendor names implied."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

from eclipse_l0.weekly_important import (create, verify, compute, validate_policy,
                                         vendor_key)
from eclipse_l0.weekly_evidence import canonical
from test_weekly_evidence import WeeklyEvidenceTests


def sample_policy():
    # The real 126-row Excel is NOT present in this repository; these are
    # deliberately synthetic fixture names, not a substitute for that Excel.
    return {
        "schema_version": 1,
        "entries": [{"vendor": "Fortinet", "aliases": ["Fortinet Inc."]}]
        + [{"vendor": "SYNTHETIC-PLACEHOLDER-%03d" % i}
           for i in range(125)],
    }


class ImportantReviewTests(unittest.TestCase):
    def setUp(self):
        fixture = WeeklyEvidenceTests("test_research_handoff_deterministic_and_transparent_about_coverage")
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        self.root = fixture.root
        self.source = self.root / "source.zip"
        fixture._build(self.source)
        self.policy = self.root / "vendors.json"
        self.policy.write_text(canonical(sample_policy()) + "\n", encoding="utf-8")

    def _build(self, suffix="one", *, target=50):
        path = self.root / (suffix + ".zip")
        receipt = create(self.source, self.policy, path, target=target)
        return path, receipt

    def test_mandatory_kev_and_cna_vendor_not_cvss_alone(self):
        path, audit = self._build()
        self.assertEqual(audit["l1_total"], 4)
        self.assertEqual(audit["selected"], 2)
        self.assertEqual(audit["mandatory_kev"], 1)
        self.assertEqual(audit["mandatory_vendor_only"], 1)
        self.assertEqual(audit["risk_selected"], 0)
        self.assertEqual(audit["top50"], 2)
        self.assertEqual(audit["top50_vendor"], 1)
        self.assertFalse(audit["weekly_coverage_certified"])
        with zipfile.ZipFile(path) as z:
            self.assertEqual(z.read("source-weekly-evidence.zip"), self.source.read_bytes())
            candidates = [json.loads(s) for s in z.read("important_candidates.jsonl").splitlines()]
            ledger = [json.loads(s) for s in z.read("decision_ledger.jsonl").splitlines()]
            top50 = [json.loads(s) for s in z.read("top50_research_candidates.jsonl").splitlines()]
            quality = json.loads(z.read("important_quality.json"))
        self.assertEqual([x["cve_id"] for x in candidates],
                         ["CVE-2026-50002", "CVE-2026-50001"])
        self.assertEqual(len(ledger), 4)
        self.assertEqual(len(top50), 2)
        self.assertEqual([x["cve_id"] for x in top50],
                         ["CVE-2026-50002","CVE-2026-50001"])
        self.assertIn("WATCH", {x["lane"] for x in ledger})
        self.assertIn("INACTIVE", {x["lane"] for x in ledger})
        self.assertFalse(quality["important_126_vendor_collector_coverage_certified"])
        self.assertTrue(all(x["selected_for_weekly_report"] is False for x in candidates))

    def test_unconditional_overflow_never_silently_cuts_or_loses_l1(self):
        path, audit = self._build(target=1)
        self.assertEqual(audit["selected"], 2)
        self.assertEqual(audit["mandatory_overflow"], 1)
        self.assertEqual(audit["top50"], 1)
        self.assertEqual(verify(path)["l1_total"], 4)

    def test_determinism(self):
        first, _ = self._build("first")
        second, _ = self._build("second")
        self.assertEqual(first.read_bytes(), second.read_bytes())

    def test_only_explicit_approved_alias_matches(self):
        self.assertEqual(vendor_key(" Fortinet, Inc. "), vendor_key("FORTINET INC"))
        self.assertNotEqual(vendor_key("Apple"), vendor_key("Pineapple"))
        policy = sample_policy()
        policy["entries"][1]["aliases"] = ["Fortinet"]
        with self.assertRaisesRegex(ValueError, "Ambiguous aliases"):
            validate_policy(policy)
        policy = sample_policy()
        policy["entries"].pop()
        with self.assertRaisesRegex(ValueError, "exactly 126"):
            validate_policy(policy)

    def test_missing_policy_is_not_silently_inferred_from_13_source_registry(self):
        self.policy.unlink()
        with self.assertRaisesRegex(ValueError, "Missing or unsafe"):
            create(self.source, self.policy, self.root / "bad.zip")

    def test_modified_priority_even_with_rehashed_member_is_rejected(self):
        path, _ = self._build("baseline")
        altered = self.root / "altered.zip"
        with zipfile.ZipFile(path) as source:
            data = {name: source.read(name) for name in source.namelist()}
        selected = [json.loads(s) for s in data["important_candidates.jsonl"].splitlines()]
        selected.pop()
        data["important_candidates.jsonl"] = (
            "".join(canonical(s) + "\n" for s in selected).encode())
        manifest = json.loads(data["important_manifest.json"])
        manifest["member_sha256"]["important_candidates.jsonl"] = hashlib.sha256(
            data["important_candidates.jsonl"]).hexdigest()
        manifest["member_bytes"]["important_candidates.jsonl"] = len(
            data["important_candidates.jsonl"])
        data["important_manifest.json"] = (canonical(manifest) + "\n").encode()
        with zipfile.ZipFile(altered, "w") as dest:
            for name, body in data.items():
                dest.writestr(name, body)
        with self.assertRaisesRegex(ValueError, "not reproducible"):
            verify(altered)

    def test_risk_ranking_and_cap_do_not_confuse_expired_kev(self):
        base = self.source.read_bytes()
        # The base fixture has mandatory KEV + one affected vendor. Increase
        # the EPSS for a non-selected published 50005 by rebuilding the DB.
        import sqlite3
        with sqlite3.connect(self.fixture.cve) as db:
            db.execute("INSERT INTO warehouse_epss VALUES (?,?,?)",
                       ("CVE-2026-50005", 0.8, 0.99))
        other = self.root / "second-source.zip"
        self.fixture._build(other)
        index = json.loads(compute(other.read_bytes(), self.policy.read_bytes(), target=3)
                           ["important_index.json"])
        self.assertEqual(index["important_review_candidate_count"], 3)
        self.assertEqual(index["discretionary_risk_count"], 1)
        self.assertEqual(index["top50_research_count"], 3)
        self.assertEqual(index["mandatory_new_kev_count"], 1)
        self.assertEqual(index["mandatory_126_vendor_count_excluding_new_kev_overlap"], 1)
        self.assertTrue(base)

if __name__ == "__main__":
    unittest.main()
