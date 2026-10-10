"""Offline registry and immutable advisory observation tests (no network)."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from eclipse_l0.vendor_registry import load_registry, validate
from eclipse_l0.vendor_store import connect, observe, facts_history

REGISTRY = Path(__file__).resolve().parents[1] / "config/vendor_source_registry.json"


class VendorSourceRegistryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.registry = load_registry(REGISTRY)

    def test_registry_valid_and_observed_counts(self):
        result = validate(self.registry)
        self.assertGreaterEqual(result["statuses"]["read_parse_verified"], 8)
        self.assertGreaterEqual(result["statuses"]["not_tested"], 1)
        self.assertEqual(result["production_enabled"], 0)

    def test_block_premature_production_promotion(self):
        data = copy.deepcopy(self.registry)
        data["sources"][0]["enabled_for_production"] = True
        with self.assertRaisesRegex(ValueError, "production"):
            validate(data)

    def test_block_http_source_url(self):
        data = copy.deepcopy(self.registry)
        data["sources"][0]["discovery_url"] = "http://filestore.fortinet.com/feed"
        with self.assertRaisesRegex(ValueError, "outside"):
            validate(data)

    def test_block_false_success_without_evidence(self):
        data = copy.deepcopy(self.registry)
        failed = next(s for s in data["sources"] if s["source_id"] == "cisco-openvuln")
        failed["verification_status"] = "read_parse_verified"
        with self.assertRaisesRegex(ValueError, "lacks evidence"):
            validate(data)

    def test_pilot_evidence_never_misreported_as_durable(self):
        data = copy.deepcopy(self.registry)
        good = next(s for s in data["sources"] if s["source_id"] == "fortinet-psirt")
        self.assertEqual(good["one_shot_evidence_pipeline"]["advisory_sample_count"], 1)
        good["one_shot_evidence_pipeline"]["persistence_state"] = "durable_production"
        with self.assertRaisesRegex(ValueError, "production-persistent"):
            validate(data)

    def test_unverified_source_cannot_claim_successful_ingest(self):
        data = copy.deepcopy(self.registry)
        cisco = next(s for s in data["sources"] if s["source_id"] == "cisco-openvuln")
        example = next(s for s in data["sources"] if s["source_id"] == "fortinet-psirt")
        cisco["one_shot_evidence_pipeline"] = copy.deepcopy(example["one_shot_evidence_pipeline"])
        with self.assertRaisesRegex(ValueError, "Only verified"):
            validate(data)

    def test_duplicate_source_rejected(self):
        data = copy.deepcopy(self.registry)
        data["sources"].append(copy.deepcopy(data["sources"][0]))
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            validate(data)


class ManufacturerVersionStoreTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = connect(Path(self.tmp.name) / "advisory.sqlite3")
        self.addCleanup(self.db.close)
        self.registry = load_registry(REGISTRY)
        self.kwargs = dict(
            registry=self.registry, source_id="fortinet-psirt",
            advisory_id="FG-IR-TEST-1",
            source_url="https://fortiguard.fortinet.com/psirt/FG-IR-TEST-1",
            source_sha256="a"*64, observed_utc="2026-10-10T11:45:00Z",
            facts={
                "title": "SYNTHETIC Fortinet advisory, not a genuine vulnerability",
                "cve_ids": ["CVE-2026-999999"],
                "affected": [{"product":"FAKE product", "versions":"1.0 through 1.1"}],
                "evidence_fields": ["synthetic HTML title", "synthetic HTML affected table"]
            }
        )

    def test_baseline_replay_source_change_and_fact_update(self):
        init=observe(self.db, **self.kwargs)
        self.assertEqual(init["event"],"baseline")
        self.assertTrue(init["version_created"])
        same=observe(self.db, **self.kwargs)
        self.assertEqual(same["event"],"unchanged")
        self.assertFalse(same["version_created"])
        meta={**self.kwargs, "source_sha256":"b"*64,
              "observed_utc":"2026-10-10T11:46:00Z"}
        meta_result=observe(self.db,**meta)
        self.assertEqual(meta_result["event"],"source_changed_only")
        changed=copy.deepcopy(meta)
        changed["observed_utc"]="2026-10-10T11:47:00Z"
        changed["facts"]["affected"][0]["versions"]="1.0 through 1.2"
        result=observe(self.db,**changed)
        self.assertEqual(result["event"],"extraction_revised")
        # A genuine upstream-byte change plus changed normalized claims
        # remains review-required; the event itself is not an exploit alarm.
        upstream=copy.deepcopy(changed)
        upstream["source_sha256"]="c"*64
        upstream["observed_utc"]="2026-10-10T11:48:00Z"
        upstream["facts"]["affected"][0]["versions"]="1.0 through 1.3"
        upstream_result=observe(self.db,**upstream)
        self.assertEqual(upstream_result["event"],"facts_updated")
        history=facts_history(self.db,"fortinet-psirt","FG-IR-TEST-1")
        self.assertEqual(len(history),4)
        self.assertEqual([x["version"] for x in history],[1,2,3,4])
        self.assertEqual(history[0]["facts"]["affected"][0]["versions"],"1.0 through 1.1")
        self.assertEqual(history[2]["facts"]["affected"][0]["versions"],"1.0 through 1.2")
        self.assertEqual(history[3]["facts"]["affected"][0]["versions"],"1.0 through 1.3")
        self.assertEqual([row[0] for row in self.db.execute(
            "SELECT event_kind FROM vendor_document_events ORDER BY event_id")],
            ["baseline","source_changed_only","extraction_revised","facts_updated"])

    def test_disallow_unverified_source_and_http_url(self):
        wrong={**self.kwargs,"source_id":"cisco-openvuln"}
        with self.assertRaisesRegex(ValueError,"not read/parse"):
            observe(self.db,**wrong)
        wrong={**self.kwargs,"source_url":"http://fortiguard.fortinet.com/psirt/test"}
        with self.assertRaisesRegex(ValueError,"not on official"):
            observe(self.db,**wrong)

    def test_refuse_missing_provenance_and_out_of_order(self):
        bad=copy.deepcopy(self.kwargs)
        bad["facts"]["evidence_fields"]=[]
        with self.assertRaisesRegex(ValueError,"provenance"):
            observe(self.db,**bad)
        observe(self.db,**self.kwargs)
        late={**self.kwargs,"observed_utc":"2026-10-09T11:45:00Z"}
        with self.assertRaisesRegex(ValueError,"Out-of-order"):
            observe(self.db,**late)

    def test_rollback_for_invalid_data_and_isolation_by_source(self):
        bad=copy.deepcopy(self.kwargs)
        bad["facts"]["cve_ids"]=["CVE-NOTREAL"]
        with self.assertRaisesRegex(ValueError,"Invalid CVE"):
            observe(self.db,**bad)
        self.assertEqual(self.db.execute("SELECT count(*) FROM vendor_documents").fetchone()[0],0)
        good=observe(self.db,**self.kwargs)
        self.assertEqual(good["version"],1)


if __name__ == "__main__":
    unittest.main()
