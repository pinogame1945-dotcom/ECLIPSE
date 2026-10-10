"""Offline test suite for strict, no-look-ahead EPSS->future CISA KEV backtest."""
import gzip
import hashlib
import json
import tempfile
import unittest
from datetime import date, timedelta
from pathlib import Path

from eclipse_l2.kev_backtest import (
    ANCHORED_FILES, TOP_K, combine, download_historic, evaluate_day,
    git_blob_sha, read_daily_csv, read_kev, verify_archive_bytes,
)

D = date(2025, 4, 1)


def mini_kev(*, release="2026-10-10", changed=None):
    vulnerable=[]
    for i in range(1000):
        cve=f"CVE-2025-{1000+i}"
        added=changed.get(cve,"2026-05-04") if changed else "2026-05-04"
        vulnerable.append({"cveID":cve,"dateAdded":added})
    return json.dumps({"count":1000,"dateReleased":release,
                       "catalogVersion":"TEST","vulnerabilities":vulnerable}).encode()


class HistoricalBacktestTests(unittest.TestCase):
    def score(self, rows):
        return [(float(p), cve) for p,cve in rows]

    def test_only_future_kevs_are_positives_and_preexisting_excluded(self):
        scored=self.score([(0.98,"CVE-2025-1001"),(0.75,"CVE-2025-1002"),
                           (0.60,"CVE-2025-1003"),(0.4,"CVE-2025-1004")])
        labels={"CVE-2025-1001":D-timedelta(days=1),
                "CVE-2025-1002":D+timedelta(days=1),
                "CVE-2025-1003":D+timedelta(days=8),
                "CVE-2025-1004":D+timedelta(days=31)}
        a=evaluate_day(D,scored,labels,top_k=(1,2,3))
        self.assertEqual(a["already_kev_as_of"],1)
        self.assertEqual(a["rankable_epss_scored_not_yet_kev"],3)
        self.assertEqual(a["evaluations"]["7"]["new_kev_rankable_in_historical_epss"],1)
        self.assertEqual(a["evaluations"]["30"]["new_kev_rankable_in_historical_epss"],2)
        self.assertEqual(a["evaluations"]["30"]["top_k"]["1"]["hits"],1)
        self.assertEqual(a["evaluations"]["30"]["top_k"]["1"]["lead_days"],[1])

    def test_missing_historical_epss_is_separate_denominator(self):
        r=evaluate_day(D,self.score([(0.9,"CVE-2025-1002")]),{
            "CVE-2025-1002":D+timedelta(days=15),
            "CVE-2025-1003":D+timedelta(days=15)})
        x=r["evaluations"]["30"]
        self.assertEqual(x["new_kev_all_catalog"],2)
        self.assertEqual(x["new_kev_rankable_in_historical_epss"],1)
        self.assertEqual(x["new_kev_not_in_historical_epss"],1)
        self.assertEqual(x["base_rate_scored"],1)

    def test_kevs_added_on_anchor_not_future(self):
        r=evaluate_day(D,self.score([(0.9,"CVE-2025-1002"),
                                     (0.7,"CVE-2025-1003")]),{
            "CVE-2025-1002":D,"CVE-2025-1003":D+timedelta(days=7)})
        self.assertEqual(r["already_kev_as_of"],1)
        self.assertEqual(r["evaluations"]["7"]["new_kev_all_catalog"],1)

    def test_no_leaked_current_cvss_or_current_kev_features(self):
        # Inputs are only historical EPSS pairs and label registration dates.
        r=evaluate_day(D,self.score([(0.1,"CVE-2025-1002"),
                                     (0.9,"CVE-2025-1003")]),{
            "CVE-2025-1002":D+timedelta(days=10)},top_k=(1,100))
        self.assertEqual(r["evaluations"]["30"]["top_k"]["1"]["hits"],0)
        self.assertEqual(r["evaluations"]["30"]["top_k"]["100"]["hits"],1)

    def test_random_baseline_lift_is_transparent(self):
        r=evaluate_day(D,self.score([(0.9,"CVE-2025-1001"),
                                     (0.2,"CVE-2025-1002"),
                                     (0.1,"CVE-2025-1003"),
                                     (0.0,"CVE-2025-1004")]),{
            "CVE-2025-1001":D+timedelta(days=2)},top_k=(1,))
        t=r["evaluations"]["30"]["top_k"]["1"]
        self.assertEqual(t["random_expected_hits"],0.25)
        self.assertEqual(t["lift_vs_random"],4)
        self.assertEqual(t["precision"],1)

    def test_no_future_kevs_has_null_recall_not_zero(self):
        r=evaluate_day(D,self.score([(0.6,"CVE-2025-1002")]),{})
        self.assertIsNone(r["evaluations"]["30"]["top_k"]["100"]["recall_among_scored_future_kev"])

    def test_era_split_is_based_on_original_score_day(self):
        self.assertEqual(evaluate_day(date(2026,6,1),[(.5,"CVE-2025-1001")],{})["model_era"],"EPSS_V4")
        self.assertEqual(evaluate_day(date(2026,7,1),[(.5,"CVE-2025-1001")],{})["model_era"],"EPSS_V5")

    def test_aggregate_micro_precision_and_no_label_overlap_in_monthly_example(self):
        r1=evaluate_day(D,[(.9,"CVE-2025-1001"),(.2,"CVE-2025-1002")],
                        {"CVE-2025-1001":D+timedelta(days=2)})
        next_day=date(2026,7,1)
        r2=evaluate_day(next_day,[(.9,"CVE-2025-1002"),(.2,"CVE-2025-1003")],
                        {"CVE-2025-1002":next_day+timedelta(days=2)})
        combined=combine([r1,r2],30,"ALL")
        self.assertEqual(combined["new_kev_all_catalog"],2)
        self.assertEqual(combined["top_k"]["100"]["hits"],2)
        self.assertEqual(combined["top_k"]["100"]["reviewed"],4)
        self.assertEqual(combine([r1,r2],30,"EPSS_V5")["new_kev_all_catalog"],1)

    def test_no_acceptance_of_mutated_git_blob_even_size_same(self):
        blob=b"hello historical EPSS"
        approved={"2025-04-01":(len(blob),git_blob_sha(blob))}
        verify_archive_bytes("2025-04-01",blob,approved)
        with self.assertRaisesRegex(ValueError,"mismatch"):
            verify_archive_bytes("2025-04-01",blob[:-1]+b"!",approved)
        with self.assertRaisesRegex(ValueError,"Unapproved"):
            verify_archive_bytes("2025-01-01",blob,approved)

    def test_gzip_date_mismatch_and_duplicate_cve_rejected(self):
        txt="#model_version:v2025.03.14,score_date:2025-04-02T00:00:00Z\ncve,epss,percentile\nCVE-2025-1001,0.1,0.9\n"
        with self.assertRaisesRegex(ValueError,"different score_date"):
            read_daily_csv(gzip.compress(txt.encode()),D,min_rows=1)
        txt="cve,epss,percentile\nCVE-2025-1001,0.1,0.9\nCVE-2025-1001,0.1,0.9\n"
        with self.assertRaisesRegex(ValueError,"duplicate"):
            read_daily_csv(gzip.compress(txt.encode()),D,min_rows=1)

    def test_nonnumeric_or_truncated_feed_cannot_be_used(self):
        txt="cve,epss,percentile\nCVE-2025-1001,0.9,0.9\n"
        with self.assertRaisesRegex(ValueError,"suspiciously small"):
            read_daily_csv(gzip.compress(txt.encode()),D,min_rows=10)
        with self.assertRaises((ValueError, OSError)):
            read_daily_csv(b"not gzip",D,min_rows=1)

    def test_cisa_catalog_release_and_duplicate_guard(self):
        base=mini_kev()
        labels, provenance=read_kev(base,last_observed_date=date(2026,9,1))
        self.assertEqual(len(labels),1000)
        self.assertEqual(provenance["catalog_rows"],1000)
        with self.assertRaisesRegex(ValueError,"predates"):
            read_kev(base,last_observed_date=date(2026,10,11))
        mutated=json.loads(base)
        mutated["vulnerabilities"][1]["cveID"]=mutated["vulnerabilities"][0]["cveID"]
        with self.assertRaisesRegex(ValueError,"Duplicate"):
            read_kev(json.dumps(mutated).encode(),last_observed_date=date(2026,9,1))

    def test_csv_historic_model_timestamp_valid(self):
        txt="#model_version:v2025.03.14,score_date:2025-04-01T12:00:00Z\ncve,epss,percentile\nCVE-2025-1001,0.1,0.9\n"
        rows,meta=read_daily_csv(gzip.compress(txt.encode()),D,min_rows=1)
        self.assertEqual(rows,[(.1,"CVE-2025-1001")])
        self.assertEqual(meta["score_date"],"2025-04-01")


if __name__ == "__main__":unittest.main()
