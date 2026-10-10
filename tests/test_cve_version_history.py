"""Synthetic CVE V5 source-history tests. No upstream/network in unit suite."""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
from pathlib import Path
import copy
import json
import tempfile
import unittest
import zipfile

from eclipse_l0.cve_version_history import collect, audit, _validate_record
from eclipse_l0.cve_history_export import build_pairs
from eclipse_l0.weekly_cve_material import analyze_pair_jsonl
from eclipse_l0.weekly_material import canonical

ID="CVE-2026-987654"
URL="https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/987xxx/"+ID+".json"


def record(*,version="1.0",stamp="2026-10-11T00:00:00Z",state="PUBLISHED"):
    return {"dataType":"CVE_RECORD","dataVersion":"5.1","cveMetadata":{
                "cveId":ID,"state":state,"datePublished":"2026-09-01T00:00:00Z",
                "dateUpdated":stamp},
            "containers":{"cna":{"affected":[{"vendor":"FICTIONAL","product":"DEMO",
                          "versions":[{"version":version,"status":"affected"}]}],
                          "descriptions":[{"lang":"en","value":"synthetic record"}]}}}


def delta(*,stamp="2026-10-11T00:00:00Z",baseline=False, count=1):
    events=[{"cve_id":ID,"kind":"cve_record_updated",
             "source_fetch_utc":stamp,"record_url":URL} for _ in range(count)]
    return {"baseline":baseline,"event_count":len(events),
            "watermark_utc":stamp,"events":events,
            "more_backlog":False}


def payload(data):
    return canonical(data).encode("utf-8")


def moment(time):
    return datetime.fromisoformat(time.replace("Z","+00:00"))


class CveHistoryTest(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)
        self.state=self.root/"data"
        self.outnum=0
    def capture(self, obj, *, result=None, stamp=None, download=None):
        self.outnum+=1
        if download is None:download=payload(result if result is not None else record())
        return collect(obj,self.state,self.root/f"report{self.outnum}.json",
                       observed_at=moment(stamp or obj["watermark_utc"]),
                       fetcher=lambda url:download,max_workers=2)

    def test_first_seen_baseline_then_affected_versions_real_diff(self):
        first=self.capture(delta(),result=record())
        self.assertEqual(first["snapshots_archived"],1)
        self.assertEqual(first["change_classes"]["FIRST_OBSERVED_BASELINE_NO_BEFORE"],1)
        self.assertEqual(first["prior_versions_compared"],0)
        second=self.capture(delta(stamp="2026-10-11T04:00:00Z"),
                            result=record(version="2.0",stamp="2026-10-11T04:00:00Z"))
        self.assertEqual(second["prior_versions_compared"],1)
        self.assertEqual(second["change_classes"]["MATERIAL_CNA_SECURITY_CONTENT_CHANGE_REVIEW"],1)
        proof=audit(self.state/"cve-version-history")
        self.assertEqual(proof["latest"],1)
        self.assertEqual(proof["shards"],2)
        report=json.loads((self.root/"report2.json").read_text())
        event=report["events"][0]
        self.assertEqual(event["changed_security_categories"],
                         ["AFFECTED_PRODUCTS_OR_VERSIONS_CHANGED"])
        self.assertFalse(event["publisher_release_date_confirmed"])

    def test_metadata_only_no_critical_promotion_and_raw_snapshot_preserved(self):
        self.capture(delta(),result=record())
        second=self.capture(delta(stamp="2026-10-11T04:00:00Z"),
                            result=record(stamp="2026-10-11T04:00:00Z"))
        self.assertEqual(second["change_classes"]["CVE_METADATA_ONLY_CHANGE"],1)
        proof=audit(self.state/"cve-version-history")
        self.assertEqual(proof["shards"],2)
        self.assertFalse(proof["complete_cve_history"])

    def test_duplicate_in_one_delta_is_coalesced_and_flagged_unrecoverable(self):
        res=self.capture(delta(count=3),result=record())
        self.assertEqual(res["distinct_fetched_cves"],1)
        self.assertEqual(res["collapsed_intermediate_events"],2)
        p=json.loads((self.root/"report1.json").read_text())
        self.assertFalse(p["events"][0]["intermediate_revisions_recoverable"])

    def test_injected_network_failure_no_checkpoint_or_archives_changed(self):
        self.capture(delta(),result=record())
        before=(self.state/"cve-version-history/manifest.json").read_bytes()
        failed=delta(stamp="2026-10-11T04:00:00Z")
        with self.assertRaisesRegex(ValueError,"ID mismatch"):
            self.capture(failed,result=record(),download=payload(
                {"cveMetadata":{"cveId":"CVE-2026-111111","state":"PUBLISHED"}}))
        self.assertEqual((self.state/"cve-version-history/manifest.json").read_bytes(),before)
        self.assertEqual(audit(self.state/"cve-version-history")["shards"],1)

    def test_corrupt_saved_archive_rejected_before_update(self):
        self.capture(delta(),result=record())
        arc=next((self.state/"cve-version-history/archives").glob("*.cvepack"))
        arc.write_bytes(b"tampered")
        with self.assertRaisesRegex(ValueError,"hash/length"):
            audit(self.state/"cve-version-history")
        with self.assertRaisesRegex(ValueError,"hash/length"):
            self.capture(delta(stamp="2026-10-11T04:00:00Z"),result=record(version="2.0"))

    def test_replay_or_watermark_rollback_blocked(self):
        self.capture(delta(),result=record())
        with self.assertRaisesRegex(ValueError,"Replayed"):
            self.capture(delta(),result=record())
        with self.assertRaisesRegex(ValueError,"regressed"):
            self.capture(delta(stamp="2026-10-10T20:00:00Z"),result=record())

    def test_weekly_pair_export_reconstructs_sha_checked_records(self):
        self.capture(delta(stamp="2026-10-11T00:00:00Z"), result=record())
        self.capture(delta(stamp="2026-10-11T04:00:00Z"),
                     result=record(version="2.0",stamp="2026-10-11T04:00:00Z"))
        pairs, summary=build_pairs(self.state, "2026-10-11", "2026-10-11")
        self.assertEqual(summary["published_v5_pairs_exported"],1)
        review=analyze_pair_jsonl(pairs,"2026-10-11","2026-10-11")
        self.assertEqual(review["counts_by_class"]["MATERIAL_CNA_SECURITY_CONTENT_CHANGE_REVIEW"],1)
        latest=audit(self.state/"cve-version-history")
        self.assertEqual(latest["transition_logs"],2)
        self.assertFalse(summary["publisher_revision_date_not_proven"] is False)

    def test_missing_previous_snapshot_fails_closed_for_export(self):
        self.capture(delta(),result=record())
        with self.assertRaisesRegex(ValueError,"No recorded"):
            build_pairs(self.state,"2026-10-10","2026-10-10")

    def test_initial_rollup_baseline_does_not_download_current_full_cve_archive(self):
        d={"baseline":True,"event_count":0,"watermark_utc":"2026-10-11T00:00:00Z",
           "events":[]}
        fetched=[]
        res=collect(d,self.state,self.root/"empty.json",
                    observed_at=moment("2026-10-11T00:00:00Z"),
                    fetcher=lambda x:fetched.append(x))
        self.assertEqual(res["distinct_fetched_cves"],0)
        self.assertEqual(res["snapshots_archived"],0)
        self.assertEqual(fetched,[])
        self.assertEqual(audit(self.state/"cve-version-history")["shards"],0)

    def test_old_version_state_is_review_only(self):
        self.capture(delta(),result=record(state="REJECTED"))
        res=self.capture(delta(stamp="2026-10-11T04:00:00Z"),
                         result=record(state="PUBLISHED",stamp="2026-10-11T04:00:00Z"))
        self.assertEqual(res["change_classes"]["NON_PUBLISHED_STATE_TRANSITION_REVIEW"],1)

    def test_delta_requires_real_pinned_github_host_and_record_url(self):
        bad=delta();bad["events"][0]["record_url"]="https://example.com/CVE-2026-987654.json"
        with self.assertRaisesRegex(ValueError,"Untrusted"):
            self.capture(bad)
        self.assertFalse((self.state/"cve-version-history").exists())


if __name__=="__main__":
    unittest.main()
