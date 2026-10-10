"""Offline, synthetic-only tests for L2 evidence prioritization; no live feeds."""
from __future__ import annotations
import csv
import json
import sqlite3
import tempfile
import unittest
from datetime import date
from pathlib import Path

from eclipse_l0.core import _upsert_cve, connect
from eclipse_l0.warehouse import _schema, _meta
from eclipse_l2.triage import Policy, analyze, evaluate

class TriageTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)
        self.db=self.root/"fictitious.sqlite3"
        c=connect(self.db)
        _schema(c)
        self.c=c
        for key,value in (
            ("source_archive_sha256","a"*64),("source_index_sha256","b"*64),
            ("cve_full_ingest_verified",True),("kev_source_sha256","c"*64),
            ("epss_source_sha256","d"*64),("epss_score_date","2026-10-10T00:00:00Z"),
        ):_meta(c,key,value)
        c.commit()
        self.addCleanup(c.close)

    def row(self,number:int,*,state="PUBLISHED",cvss=None,epss=None,kev=False,
            vendor="Fortinet",product="FortiOS",affected=True,versions=True):
        cve=f"CVE-2026-{number:04d}"
        body={"cveMetadata":{"cveId":cve,"state":state}}
        raw=json.dumps(body).encode()
        _upsert_cve(self.c,body,raw,"synthetic-fixture")
        self.c.execute("INSERT INTO warehouse_summary(cve_id,cvss_score,cvss_kind) VALUES (?,?,?)",
                       (cve,cvss,"cvssV3_1" if cvss is not None else None))
        if affected:
            self.c.execute("""INSERT INTO warehouse_affected
                (cve_id,container,ordinal,vendor,product,vendor_norm,product_norm,versions_json)
                VALUES (?,?,?,?,?,?,?,?)""", (cve,"cna",0,vendor,product,vendor.casefold(),
                    product.casefold(),"[{\"version\":\"1.0\",\"status\":\"affected\"}]" if versions else None))
        if kev:
            digest=self.c.execute("SELECT hash FROM cve_current WHERE cve_id=?",(cve,)).fetchone()[0]
            self.c.execute("""INSERT INTO kev_current
                (cve_id,hash,date_added,present,last_seen) VALUES (?,?,?,?,?)""",
                (cve,digest,"2026-10-09",1,"2026-10-10T00:00:00Z"))
        if epss is not None:
            self.c.execute("INSERT INTO warehouse_epss VALUES (?,?,?)",(cve,epss,0.90))
        self.c.commit()
        return cve

    def test_kev_wins_over_low_epss_even_with_missing_cvss(self):
        cve=self.row(1001,epss=0.0001,kev=True)
        r=analyze(self.db,as_of=date(2026,10,10))
        self.assertEqual(r["queue_counts"]["CONFIRMED_EXPLOITATION_REVIEW"],1)
        self.assertEqual(r["preview"][0]["cve_id"],cve)
        self.assertEqual(r["preview"][0]["rule_id"],"KEV_PRESENT_OVERRIDES_EPSS")
        self.assertEqual(r["preview"][0]["customer_exposure"],"NOT_ASSESSED")

    def test_non_kev_high_epss_and_critical_cvss(self):
        self.row(1001,epss=0.14,cvss=3.5)
        self.row(1002,epss=0.001,cvss=9.8)
        self.row(1003,epss=0.01,cvss=5.5)
        r=analyze(self.db,as_of=date(2026,10,10))
        self.assertEqual(r["queue_counts"]["ELEVATED_FORECAST_REVIEW"],1)
        self.assertEqual(r["queue_counts"]["HIGH_IMPACT_REVIEW"],1)
        self.assertEqual(r["queue_counts"]["ROUTINE_EVIDENCE_REVIEW"],1)
        self.assertEqual([x["queue"] for x in r["preview"]],
                         ["ELEVATED_FORECAST_REVIEW","HIGH_IMPACT_REVIEW","ROUTINE_EVIDENCE_REVIEW"])
        self.assertIn("not proof of no exploitation",r["sources"]["kev"]["not_listed_means"])

    def test_future_and_stale_feed_fail_closed(self):
        self.row(1001,epss=0.7)
        with self.assertRaisesRegex(ValueError,"future"):
            analyze(self.db,as_of=date(2026,10,9))
        stale=analyze(self.db,as_of=date(2026,10,19))
        self.assertFalse(stale["epss_fresh_for_policy"])
        self.assertEqual(stale["preview"][0]["queue"],"ROUTINE_EVIDENCE_REVIEW")
        self.assertEqual(stale["preview"][0]["epss_probability"],0.7)
        self.assertEqual(stale["evidence_gap_counts"]["epss_feed_stale"],1)

    def test_rejected_is_hold_even_kev(self):
        self.row(1001,state="REJECTED",kev=True,epss=0.95,cvss=10.0)
        report=analyze(self.db,as_of=date(2026,10,10))
        self.assertEqual(report["queue_counts"]["UNPUBLISHED_HOLD"],1)

    def test_missing_evidence_not_false_zero(self):
        self.row(1001,affected=False)
        r=analyze(self.db,as_of=date(2026,10,10))
        item=r["preview"][0]
        self.assertIsNone(item["epss_probability"])
        self.assertEqual(item["epss_status"],"MISSING_FOR_CVE")
        self.assertEqual(item["publisher_affected_version_data"],"UNKNOWN")
        self.assertIn("publisher_affected_rows_missing",item["missing_fields"])
        self.assertEqual(item["kev_status"],"NOT_LISTED_IN_KEV_SNAPSHOT")

    def test_exact_vendor_match_without_inferred_customer_assets(self):
        self.row(1001,vendor="Fortinet",product="FortiOS",epss=0.4)
        self.row(1002,vendor="Fortinet",product="FortiManager",epss=0.5)
        self.row(1003,vendor="NotFortinet",product="FortiOS",epss=0.9)
        matched=analyze(self.db,as_of=date(2026,10,10),vendor=" FORTINET ",product="fortios")
        self.assertEqual(matched["records_evaluated"],1)
        self.assertEqual(matched["preview"][0]["cve_id"],"CVE-2026-1001")
        self.assertEqual(matched["preview"][0]["customer_exposure"],"NOT_ASSESSED")
        self.assertEqual(matched["scope"],"EXACT_PUBLISHER_REPORTED_PRODUCT_NAMES")
        empty=analyze(self.db,as_of=date(2026,10,10),vendor="cisco")
        self.assertEqual(empty["records_evaluated"],0)

    def test_full_csv_has_all_rows_not_only_preview(self):
        for n in range(1001,1061):
            self.row(n,epss=(n-1000)/1000)
        path=self.root/"all.csv"
        r=analyze(self.db,as_of=date(2026,10,10),top=3,csv_path=path)
        self.assertEqual(r["records_evaluated"],60)
        self.assertEqual(len(r["preview"]),3)
        with path.open(encoding="utf-8",newline="") as f:
            rows=list(csv.DictReader(f))
        self.assertEqual(len(rows),60)
        self.assertTrue(all(x["customer_exposure"]=="NOT_ASSESSED" for x in rows))

    def test_zero_preview_still_counts_every_record(self):
        self.row(1001,epss=0.2)
        self.row(1002,epss=0.1)
        r=analyze(self.db,as_of=date(2026,10,10),top=0)
        self.assertEqual(r["records_evaluated"],2)
        self.assertEqual(r["preview"],[])

    def test_policy_validation_and_evidence_provenance(self):
        for val in (0,-0.2,2.1,float("nan"),float("inf")):
            with self.assertRaises(ValueError):
                Policy(epss_attention_probability=val)
        self.row(1001,epss=0.11,cvss=6)
        r=analyze(self.db,as_of=date(2026,10,10),
                  policy=Policy(epss_attention_probability=0.2))
        self.assertEqual(r["preview"][0]["queue"],"ROUTINE_EVIDENCE_REVIEW")
        self.assertEqual(r["sources"]["cve"]["sha256"],"a"*64)
        self.c.execute("DELETE FROM warehouse_metadata WHERE key='kev_source_sha256'")
        self.c.commit()
        with self.assertRaisesRegex(ValueError,"provenance"):
            analyze(self.db,as_of=date(2026,10,10))


if __name__=="__main__":unittest.main()
