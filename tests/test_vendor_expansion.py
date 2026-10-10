"""Unseen-first bounded source expansion and historical recheck tests (offline)."""
from pathlib import Path
import tempfile
import unittest

from eclipse_l0.vendor_registry import load_registry
from eclipse_l0.vendor_pilot import discover, ingest_source, run
from eclipse_l0.vendor_store import connect

REGISTRY=load_registry(Path(__file__).resolve().parents[1]/"config/vendor_source_registry.json")
SOURCE=next(x for x in REGISTRY["sources"] if x["source_id"]=="fortinet-psirt")


class OfflineFetch:
    def __init__(self, data):
        self.data=data
        self.calls=[]
    def get(self,url,limit=None):
        self.calls.append(url)
        return self.data[url]


class ExpansionTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db=Path(self.temp.name)/"vendor.sqlite3"
        self.records=[
            ("FG-IR-26-175","CVE-2026-22111"),
            ("FG-IR-26-174","CVE-2026-22112"),
            ("FG-IR-26-173","CVE-2026-22113"),
            ("FG-IR-26-172","CVE-2026-22114"),
            ("FG-IR-26-171","CVE-2026-22115"),
            ("FG-IR-26-170","CVE-2026-22116"),
        ]
        feed="<rss version='2.0'><channel>"
        self.content={}
        for ident,cve in self.records:
            link=f"https://fortiguard.fortinet.com/psirt/{ident}"
            feed+=f"<item><title>{cve} disclosure</title><link>{link}</link><description>Security fix</description></item>"
            page=(f"<html><body><h1>{cve}</h1><p>This is a synthetic example and "
                  "not an actual Fortinet vulnerability report. This test "
                  "validates bounded archival readback and versioned storage "
                  "rather than vendor claims. No real customer action required.</p>"
                  "<table><tr><td>ExampleOS 1.0</td><td>1.0 through 1.3</td>"
                  "<td>Upgrade to 1.4 or above</td></tr></table></body></html>")
            self.content[link]=page.encode()
        feed+="</channel></rss>"
        self.content[SOURCE["discovery_url"]]=feed.encode()

    def test_unseen_first_plus_recent_recheck(self):
        get=OfflineFetch(self.content)
        new=discover(SOURCE,get,3,known_ids=set())
        self.assertEqual([x["id"] for x in new], [r[0] for r in self.records[:3]])
        known={r[0] for r in self.records[:3]}
        following=discover(SOURCE,get,3,known_ids=known)
        self.assertEqual([x["id"] for x in following],
                         [self.records[0][0],self.records[3][0],self.records[4][0]])
        all_known={r[0] for r in self.records}
        self.assertEqual(len(discover(SOURCE,get,6,known_ids=all_known)),1)

    def test_pilot_accumulates_without_recreating_baselines(self):
        first=ingest_source(REGISTRY,SOURCE,self.db,2,OfflineFetch(self.content))
        self.assertEqual(first["status"],"PASS")
        self.assertEqual(first["baseline"],2)
        second=ingest_source(REGISTRY,SOURCE,self.db,4,OfflineFetch(self.content))
        self.assertEqual(second["status"],"PASS")
        self.assertEqual(second["baseline"],3)
        self.assertEqual(second["replay_unchanged"],5)  # 4 selected + one historical recheck
        with connect(self.db) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM vendor_documents").fetchone()[0],5)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM vendor_document_events").fetchone()[0],5)

    def test_explicit_upper_budget_limit(self):
        with self.assertRaisesRegex(ValueError,"Limit is 1-8"):
            run(registry=REGISTRY,db_path=self.db,source_ids=["fortinet-psirt"],max_items=9)


if __name__=="__main__":
    unittest.main()
