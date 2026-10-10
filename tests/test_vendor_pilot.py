"""Offline source-discovery-to-SQLite integration checks; absolutely no network."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from eclipse_l0.vendor_pilot import (
    _host_allowed, discover, normalize, ingest_source, _csaf_facts,
)
from eclipse_l0.vendor_registry import load_registry
from eclipse_l0.vendor_store import connect, facts_history

REGISTRY = Path(__file__).resolve().parents[1] / "config/vendor_source_registry.json"


class StubGetter:
    def __init__(self, data):
        self.data=data
        self.calls=[]
    def get(self, url, limit=None):
        self.calls.append(url)
        if url not in self.data:
            raise AssertionError("Unexpected URL "+url)
        return self.data[url]


class SourcePilotOfflineTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.registry=load_registry(REGISTRY)
        cls.sources={x["source_id"]:x for x in cls.registry["sources"]}

    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db=Path(self.tmp.name)/"out.sqlite"

    def test_fortinet_rss_to_detail_to_versioned_local_database(self):
        s=self.sources["fortinet-psirt"]
        feed=b"""<?xml version="1.0"?><rss version="2.0"><channel><item>
          <title>Example vulnerability</title>
          <link>https://fortiguard.fortinet.com/psirt/FG-IR-26-123</link>
          <description>CVE-2026-12345</description>
          </item></channel></rss>"""
        page=b"""<html><body><h1>CVE-2026-12345</h1><h2>Affected Products</h2>
          <table><tr><th>Product</th><th>Affected</th><th>Solution</th></tr>
          <tr><td>FortiMail 7.6</td><td>7.6.0 through 7.6.2</td>
          <td>Upgrade to 7.6.3 or above</td></tr></table>
          <p>Security vulnerability advisory, example with adequate text.</p></body></html>"""
        getter=StubGetter({s["discovery_url"]:feed,
                           "https://fortiguard.fortinet.com/psirt/FG-IR-26-123":page})
        result=ingest_source(self.registry,s,self.db,1,getter)
        self.assertEqual(result["status"],"PASS")
        self.assertEqual(result["saved"],1)
        self.assertEqual(result["replay_unchanged"],1)
        with connect(self.db) as db:
            h=facts_history(db,"fortinet-psirt","FG-IR-26-123")
            self.assertEqual(len(h),1)
            self.assertEqual(h[0]["facts"]["cve_ids"],["CVE-2026-12345"])
            self.assertEqual(h[0]["facts"]["affected"][0]["affected_versions_raw"],"7.6.0 through 7.6.2")
            self.assertEqual(db.execute("SELECT count(*) FROM vendor_document_events").fetchone()[0],1)
        self.assertEqual(len(getter.calls),2)

    def test_csaf_product_ids_not_claimed_as_fixed_versions(self):
        result=_csaf_facts({"document":{"title":"A"},
                           "product_tree":{"branches":[]},
                           "vulnerabilities":[{"cve":"CVE-2026-12345",
                               "product_status":{"known_affected":["CSAF_PRODUCT-999"]},
                               "remediations":[{"category":"vendor_fix","details":"Update"}]}]},"A")
        self.assertEqual(result["affected"][0]["product_id_unresolved"],"CSAF_PRODUCT-999")
        self.assertNotIn("fixed_version",result["affected"][0])
        self.assertEqual(result["cve_ids"],["CVE-2026-12345"])

    def test_redhat_releases_csv_and_json(self):
        s=self.sources["redhat-csaf"]
        url="https://security.access.redhat.com/data/csaf/v2/advisories/2026/rhsa-2026_123.json"
        getter=StubGetter({s["discovery_url"]:b"2026/rhsa-2026_123.json,2026-10-10T11:45Z\n",
                           url:json.dumps({"document":{"title":"Red Hat advisory"},
                                            "vulnerabilities":[{"cve":"CVE-2026-12345",
                                                "product_status":{"known_affected":["RHSA:PACKAGE"]}}]}).encode()})
        result=ingest_source(self.registry,s,self.db,1,getter)
        self.assertEqual(result["status"],"PASS")
        self.assertEqual(result["details"][0]["provisional_cve_count"],1)
        with connect(self.db) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM vendor_document_versions").fetchone()[0],1)

    def test_reject_unsafe_domain_and_bad_data_without_fake_success(self):
        s=self.sources["siemens-csaf"]
        self.assertFalse(_host_allowed("http://cert-portal.siemens.com/x",s["allowed_hosts"]))
        self.assertFalse(_host_allowed("https://cert-portal.siemens.com.evil.com/x",s["allowed_hosts"]))
        bad={"feed":{"entry":[{"id":"SSA-1","link":[{"rel":"self","href":"https://evil.invalid/x"}]}]}}
        getter=StubGetter({s["discovery_url"]:json.dumps(bad).encode()})
        result=ingest_source(self.registry,s,self.db,1,getter)
        self.assertEqual(result["status"],"FAIL")
        self.assertEqual(result["saved"],0)
        self.assertIn("outside official allowlist",result["errors"][0])

    def test_article_candidates_exclude_nav_and_stay_unlinked(self):
        source=self.sources["gitlab-security-releases"]
        item={"id":"gitlab-notice-example","title":"SYNTHETIC security patch release",
              "url":"https://docs.gitlab.com/releases/patch-example/"}
        page=b"""<html><head><script>CVE-2026-99901</script></head>
          <nav>CVE-2026-99902</nav><main><article>
          <h1>Patch release</h1><p>Example CVE-2026-99903 was addressed.
          This content is entirely synthetic, serving only as a parser regression test.</p>
          <aside>CVE-2026-99904</aside>
          </article></main><footer>CVE-2026-99905</footer>
          <p>More background information to satisfy the content-length threshold.
          No claim of real vendor activity is made in this fixture and no real
          security advisory is represented by the sample data herein.</p></html>"""
        result=normalize(source,item,page)
        self.assertEqual(result["cve_ids"],[])
        self.assertEqual(result["unreviewed_article_cve_candidates"],["CVE-2026-99903"])
        self.assertIn("CVE-2026-99902",result["unreviewed_page_cve_candidates"])

    def test_atlassian_navigation_cves_not_promoted_to_facts(self):
        source=self.sources["atlassian-security"]
        item={"id":"CVE-2026-21589","title":"CVE-2026-21589 bulletin",
              "url":"https://confluence.atlassian.com/security/cve-2026-21589.html"}
        page=b"<html><body><h1>CVE-2026-21589 bulletin</h1><nav>CVE-2025-99999 irrelevant</nav><main>Official bulletin concerning the affected product and patched versions. Review needed. Publisher claims should be source-scoped and reviewed, and this fixture deliberately contains irrelevant navigation references that must not become asserted facts. Example contextual text for extraction safeguards and normalized processing.</main></body></html>"
        facts=normalize(source,item,page)
        self.assertEqual(facts["cve_ids"],["CVE-2026-21589"])
        self.assertIn("CVE-2025-99999",facts["unreviewed_page_cve_candidates"])
        self.assertEqual(facts["affected"],[])


if __name__=="__main__":
    unittest.main()
