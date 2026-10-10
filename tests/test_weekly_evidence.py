"""Phase 2: offline and tamper-resistant CVE/vendor weekly handoff contract.

Synthetic dates ensure historical baseline ingestion cannot masquerade as this
week's original publication. No email, real client data, network, or AI output.
"""
from __future__ import annotations
from datetime import date
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
import zipfile

from eclipse_l0.vendor_store import connect,observe
from eclipse_l0.vendor_registry import load_registry
from eclipse_l0.weekly_evidence import create,verify,build_payload


class WeeklyEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.registry_path=Path(__file__).resolve().parents[1]/"config/vendor_source_registry.json"
        self.registry=load_registry(self.registry_path)
        self.vendor=self.root/"vendor.sqlite3"
        self.cve=self.root/"cve.sqlite3"
        self.start=date(2026,10,4)
        self.end=date(2026,10,10)
        with sqlite3.connect(self.cve) as db:
            db.executescript("""
                CREATE TABLE cve_current (
                   cve_id TEXT PRIMARY KEY,record_state TEXT NOT NULL,hash TEXT NOT NULL,
                   date_published TEXT,date_updated TEXT,last_seen TEXT);
                CREATE TABLE warehouse_summary (
                   cve_id TEXT PRIMARY KEY,title TEXT,description_en TEXT,
                   cvss_score REAL,cvss_kind TEXT,cvss_severity TEXT);
                CREATE TABLE warehouse_affected (
                   cve_id TEXT,container TEXT,ordinal INTEGER,vendor TEXT,
                   product TEXT,default_status TEXT,versions_json TEXT);
                CREATE TABLE kev_current (
                   cve_id TEXT PRIMARY KEY,present INTEGER,date_added TEXT,
                   hash TEXT,last_seen TEXT);
                CREATE TABLE warehouse_epss (
                   cve_id TEXT PRIMARY KEY,probability REAL,percentile REAL);
                CREATE TABLE warehouse_metadata (
                   key TEXT PRIMARY KEY,value TEXT);
            """)
            db.executemany("INSERT INTO warehouse_metadata VALUES (?,?)",[
                 ("source_index_sha256",json.dumps("1"*64)),
                 ("source_archive_sha256",json.dumps("2"*64)),
            ])
            data=[
                ("CVE-2026-50001","PUBLISHED","2026-10-07T08:00:00Z","2026-10-07T08:00:00Z"),
                ("CVE-2026-50002","PUBLISHED","2026-09-17T08:00:00Z","2026-09-18T08:00:00Z"),
                ("CVE-2026-50003","PUBLISHED","2026-09-17T08:00:00Z","2026-09-18T08:00:00Z"),
                ("CVE-2026-50004","REJECTED","2026-09-17T08:00:00Z","2026-10-09T08:00:00Z"),
                ("CVE-2026-50005","PUBLISHED","2026-09-17T08:00:00Z","2026-10-09T08:00:00Z"),
            ]
            db.executemany("INSERT INTO cve_current VALUES (?,?,?,?,?,?)",
               [(ident,state,(str(i+1)*64)[:64],pub,upd,"2026-10-10T08:00:00Z")
                for i,(ident,state,pub,upd) in enumerate(data)])
            db.executemany("INSERT INTO warehouse_summary VALUES (?,?,?,?,?,?)",
                [(x[0],"Fixture synthetic CVE","FAKE supplier description no known exploitation",9.0,
                  "cvssV3_1","CRITICAL") for x in data])
            db.execute("INSERT INTO warehouse_affected VALUES (?,?,?,?,?,?,?)",
                ("CVE-2026-50001","cna",0,"Fortinet","FortiOS","unknown",
                 json.dumps([{"version":"7.0.0","lessThan":"7.0.11",
                              "versionType":"custom","status":"affected"}])))
            db.execute("INSERT INTO kev_current VALUES (?,?,?,?,?)",
                ("CVE-2026-50002",1,"2026-10-09","6"*64,"2026-10-10T08:00:00Z"))
            db.execute("INSERT INTO warehouse_epss VALUES (?,?,?)",
                ("CVE-2026-50001",0.793,0.997))
        sources={s["source_id"]:s for s in self.registry["sources"]}
        with connect(self.vendor) as db:
            sid="fortinet-psirt"
            src=sources[sid]["detail_sample_url"]
            for j,ident in enumerate(("SYNTH-WEEK-1","SYNTH-BASELINE-ONLY","SYNTH-OBSERVED-CHANGE")):
                cid=["CVE-2026-50001","CVE-2026-50003","CVE-2026-50003"][j]
                facts={"title":"Synthetic example, NOT real vendor advisory",
                       "cve_ids":[cid],"affected":[],
                       "evidence_fields":["synthetic detail body fixture"]}
                t="2026-10-09T12:00:00Z" if j<2 else "2026-10-01T12:00:00Z"
                observe(db,registry=self.registry,source_id=sid,
                        advisory_id=ident,source_url=src,
                        source_sha256=f"{j+1:064x}",
                        facts=facts,observed_utc=t)
                if j==2:
                    facts["title"]="Synthetic updated observation—not a publisher release date"
                    observe(db,registry=self.registry,source_id=sid,
                            advisory_id=ident,source_url=src,source_sha256=f"{j+10:064x}",
                            facts=facts,observed_utc="2026-10-09T12:00:00Z")
        db.close()

    def _build(self,path):
        return create(cve_db=self.cve,vendor_db=self.vendor,
            registry_path=self.registry_path,
            start=self.start,end=self.end,out=path)

    def test_research_handoff_deterministic_and_transparent_about_coverage(self):
        a=self.root/"weekly-one.zip"
        b=self.root/"weekly-two.zip"
        src_before=(self.cve.read_bytes(),self.vendor.read_bytes())
        res=self._build(a)
        self.assertEqual(res["cve_candidates"],4)
        self.assertEqual(res["vendor_evidence_documents"],2)
        self.assertFalse(res["weekly_coverage_certified"])
        self._build(b)
        self.assertEqual(a.read_bytes(),b.read_bytes())
        self.assertEqual((self.cve.read_bytes(),self.vendor.read_bytes()),src_before)
        audit=verify(a)
        self.assertEqual(audit["candidate_total"],4)
        self.assertEqual(audit["vendor_documents"],2)
        with zipfile.ZipFile(a) as z:
            rows=[json.loads(x) for x in z.read("vulnerabilities.jsonl").splitlines()]
            docs=[json.loads(x) for x in z.read("vendor_advisories.jsonl").splitlines()]
            changes=[json.loads(x) for x in z.read("weekly_changes.jsonl").splitlines()]
            missing=json.loads(z.read("quality_report.json"))
            index=json.loads(z.read("weekly_index.json"))
        self.assertEqual([x["cve_id"] for x in rows],
                         ["CVE-2026-50001","CVE-2026-50002","CVE-2026-50004","CVE-2026-50005"])
        self.assertEqual([x["advisory_id"] for x in docs],
                         ["SYNTH-OBSERVED-CHANGE","SYNTH-WEEK-1"])
        self.assertEqual(index["completeness"],"NOT_PROVEN_FIXED_SNAPSHOT_ONLY")
        self.assertFalse(missing["weekly_coverage_certified"])
        self.assertIn("mozilla-mfsa",missing["missing_publisher_data_in_vendor_snapshot"])
        self.assertEqual(next(x for x in rows if x["cve_id"]=="CVE-2026-50002")["week_reasons"],
                         ["CISA_KEV_DATE_ADDED_IN_WINDOW"])
        self.assertEqual(next(x for x in rows if x["cve_id"]=="CVE-2026-50004")["record_state"],
                         "REJECTED")
        self.assertIn("NOT_ASSESSED",next(x for x in rows if x["cve_id"]=="CVE-2026-50001")["remediation_verified"])
        self.assertEqual(next(x for x in rows if x["cve_id"]=="CVE-2026-50001")["epss"]["score_date"],
                         "NOT_PRESENT_IN_WAREHOUSE")
        self.assertTrue(any(x["event_type"]=="VENDOR_FACTS_UPDATED" for x in changes))
        self.assertFalse(next(x for x in changes
                            if x["event_type"]=="VENDOR_FACTS_UPDATED")["eligible_as_publisher_new_release"])

    def test_baseline_date_alone_never_publishes_old_cve_as_new(self):
        data,prov=build_payload(self.cve,self.vendor,self.registry,
                                start=self.start,end=self.end)
        docs=[json.loads(x) for x in data["vendor_advisories.jsonl"].splitlines()]
        self.assertFalse(any(x["advisory_id"]=="SYNTH-BASELINE-ONLY" for x in docs))
        changes=[json.loads(x) for x in data["weekly_changes.jsonl"].splitlines()]
        self.assertFalse(any(x.get("event_type")=="VENDOR_BASELINE" for x in changes))
        self.assertEqual(prov["vendor_document_count"],3)

    def test_corrupted_zip_manifest_fails(self):
        p=self.root/"weekly.zip"
        self._build(p)
        altered=self.root/"altered.zip"
        with zipfile.ZipFile(p) as source,zipfile.ZipFile(altered,"w") as dest:
            for name in source.namelist():
                body=source.read(name)
                if name=="quality_report.json":
                    obj=json.loads(body);obj["weekly_coverage_certified"]=True
                    body=json.dumps(obj).encode()
                dest.writestr(name,body)
        with self.assertRaisesRegex(ValueError,"hash or size"):
            verify(altered)

    def test_corrupt_zip_cannot_be_week_report_even_with_rehash(self):
        p=self.root/"weekly.zip"
        self._build(p)
        altered=self.root/"altered.zip"
        with zipfile.ZipFile(p) as src:
            d={n:src.read(n) for n in src.namelist()}
        quality=json.loads(d["quality_report.json"])
        quality["weekly_coverage_certified"]=True
        d["quality_report.json"]=json.dumps(quality).encode()
        manifest=json.loads(d["manifest.json"])
        manifest["members_sha256"]["quality_report.json"]=hashlib.sha256(d["quality_report.json"]).hexdigest()
        manifest["members_bytes"]["quality_report.json"]=len(d["quality_report.json"])
        d["manifest.json"]=json.dumps(manifest).encode()
        with zipfile.ZipFile(altered,"w") as z:
            for name,body in d.items():z.writestr(name,body)
        with self.assertRaisesRegex(ValueError,"Safety"):
            verify(altered)

    def test_refuses_overwrite_and_bad_week(self):
        p=self.root/"weekly.zip"
        self._build(p)
        with self.assertRaisesRegex(ValueError,"overwrite"):
            self._build(p)
        with self.assertRaisesRegex(ValueError,"ordered"):
            create(cve_db=self.cve,vendor_db=self.vendor,registry_path=self.registry_path,
                   start=date(2026,10,11),end=self.end,out=self.root/"bad.zip")

    def test_full_cve_required_fails_for_partial_synthetic_fixture(self):
        with self.assertRaisesRegex(ValueError,"403696"):
            create(cve_db=self.cve,vendor_db=self.vendor,registry_path=self.registry_path,
                   start=self.start,end=self.end,out=self.root/"x.zip",require_full_cve=True)


if __name__=="__main__":unittest.main()
