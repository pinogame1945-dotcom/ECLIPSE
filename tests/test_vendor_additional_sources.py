"""Offline synthetic tests for publisher allowlists and scoped evidence extraction."""
import copy
from pathlib import Path
import unittest

from eclipse_l0.vendor_registry import load_registry
from eclipse_l0.vendor_pilot import discover,normalize,ingest_source

REGISTRY=load_registry(Path(__file__).resolve().parents[1]/"config/vendor_source_registry.json")
SRC={v["source_id"]:v for v in REGISTRY["sources"]}


class Stub:
    def __init__(self, data):self.data=data
    def get(self,url,limit=None):
        if url not in self.data:raise AssertionError("Unexpected external request "+url)
        return self.data[url]


class ExpansionSourceTests(unittest.TestCase):
    def test_mozilla_official_listing_detail_and_scoped_cve(self):
        x=SRC["mozilla-mfsa"]
        url=x["detail_sample_url"]
        feed=f"""<html><nav><a href='https://attacker.invalid/ignore'>MFSA 2026-999</a></nav>
        <main><a href='/en-US/security/advisories/mfsa2026-104/'>MFSA 2026-104 Security Vulnerabilities fixed in Firefox 157.0.1</a></main></html>""".encode()
        detail=b"""<html><header>CVE-2026-11111 global navigation</header><main>
        <h1>Mozilla Foundation Security Advisory 2026-104</h1>
        <h2>Security Vulnerabilities fixed in Firefox 157.0.1</h2>
        <p>Official synthetic advisory content should be enough for bounded parsing
        even though the actual page from the publisher may have different layout.
        It documents one synthetically numbered identifier but does not establish
        customer applicability or a complete affected version list.</p>
        <h3>CVE-2026-106016: Synthetic subheading</h3>
        </main></html>"""
        selected=discover(x,Stub({x["discovery_url"]:feed}),1)
        self.assertEqual(selected[0]["id"],"MFSA-2026-104")
        facts=normalize(x,selected[0],detail)
        self.assertEqual(facts["cve_ids"],["CVE-2026-106016"])
        self.assertFalse(facts["affected"])
        self.assertNotIn("CVE-2026-11111",facts["cve_ids"])
        self.assertNotIn("fixed_version",facts)
        self.assertEqual(x["verification_status"],"read_parse_verified")

    def test_debian_list_not_confused_with_tracker_and_no_fake_product_fix(self):
        x=SRC["debian-dsa"]
        url="https://lists.debian.org/debian-security-announce/2026/msg00888.html"
        index=f"""<html><main><a href="https://security-tracker.debian.org/tracker/DSA-6549-1">T</a>
        <a href="{url}">DSA-6549-1 xz-utils security update</a></main></html>""".encode()
        detail=b"""<html><main><pre>
        Debian Security Advisory DSA-6549-1
        Package       : xz-utils
        CVE ID        : CVE-2026-11111 CVE-2026-11112
        Several vulnerabilities have been discovered in an untrusted example.
        For the stable distribution (trixie), these problems have been fixed in
        version 5.8.1-1+deb13u2.
        </pre></main><footer>CVE-2026-99999 footer link</footer></html>"""
        selected=discover(x,Stub({x["discovery_url"]:index}),1)
        self.assertEqual(selected,[{"id":"DSA-6549-1","url":url,"title":"DSA-6549-1 xz-utils security update"}])
        facts=normalize(x,selected[0],detail)
        self.assertEqual(facts["cve_ids"],["CVE-2026-11111","CVE-2026-11112"])
        self.assertEqual(facts["package_release_fixes_review_state"],"not_extracted")
        self.assertFalse(facts["affected"])
        self.assertNotIn("CVE-2026-99999",facts["cve_ids"])

    def test_debian_wrong_dsa_detail_fails_closed(self):
        x=SRC["debian-dsa"]
        item={"id":"DSA-6549-1","url":x["detail_sample_url"],"title":"DSA-6549-1"}
        raw=("<main>Debian Security Advisory DSA-6548-1 "+("not matching publisher source "*10)+"</main>").encode()
        with self.assertRaisesRegex(ValueError,"did not contain"):
            normalize(x,item,raw)

    def test_mozilla_publisher_heading_mismatch_fails_closed(self):
        x=SRC["mozilla-mfsa"]
        item={"id":"MFSA-2026-104","url":x["detail_sample_url"],"title":"MFSA 2026-104"}
        raw=("<main><h1>Mozilla Foundation Security Advisory 2026-103</h1>"+
             "Publisher unrelated page text "*16+"</main>").encode()
        with self.assertRaisesRegex(ValueError,"does not match"):
            normalize(x,item,raw)

    def test_both_sources_promoted_only_with_real_live_proof_not_to_customer(self):
        self.assertTrue(all(SRC[s]["verification_status"]=="read_parse_verified"
                            for s in ("mozilla-mfsa","debian-dsa")))
        for sid in ("mozilla-mfsa","debian-dsa"):
            source=SRC[sid]
            proof=source["publisher_expansion_live_probe"]
            self.assertEqual(proof["sampled_advisories"],2)
            self.assertFalse(proof["production_enabled"])
            self.assertFalse(proof["sqlite_history_verified"])
            self.assertFalse(proof["accuracy_reviewed"])
            self.assertFalse(source["enabled_for_production"])
            self.assertEqual(source["live_polling"],"not_enabled")


if __name__=="__main__":unittest.main()
