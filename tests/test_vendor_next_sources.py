"""New vendor expansion synthetic offline tests; no HTTP dependencies."""
from pathlib import Path
import unittest

from eclipse_l0.vendor_registry import load_registry
from eclipse_l0.vendor_pilot import discover,normalize
from eclipse_l0.vendor_next_sources import _identity

registry=load_registry(Path(__file__).resolve().parents[1]/"config/vendor_source_registry.json")
sources={x["source_id"]:x for x in registry["sources"]}
samples={
  "apple-security-releases":(
    "APPLE-ARTICLE-149226","https://support.apple.com/en-us/149226",
    "iOS 26.7.1 and iPadOS 26.7.1",
    "About the security content of iOS 26.7.1 and iPadOS 26.7.1"),
  "adobe-security-bulletins":(
    "APSB26-141","https://helpx.adobe.com/security/products/acrobat/apsb26-141.html",
    "APSB26-141 Security update available for Adobe Acrobat and Reader",
    "Adobe Security Bulletin APSB26-141"),
  "google-chrome-releases":(
    "CHROME-2026-10-stable-channel-update-for-desktop",
    "https://chromereleases.googleblog.com/2026/10/stable-channel-update-for-desktop.html",
    "Stable Channel Update for Desktop","Stable Channel Update for Desktop"),
  "android-security-bulletins":(
    "ANDROID-2026-10-01",
    "https://source.android.com/docs/security/bulletin/2026/2026-10-01",
    "October 2026","Android Security Bulletin October 2026"),
  "postgresql-security":(
    "CVE-2026-19385","https://www.postgresql.org/support/security/CVE-2026-19385/",
    "CVE-2026-19385","PostgreSQL CVE-2026-19385"),
}

class Fetch:
    def __init__(self,x):self.x=x
    def get(self,url,limit=None):return self.x[url]

class ExpandedOfficialTests(unittest.TestCase):
    def test_all_five_no_premature_verified_claim(self):
        self.assertEqual(len(samples),5)
        for sid in samples:
            self.assertEqual(sources[sid]["verification_status"],"not_tested")
            self.assertFalse(sources[sid]["enabled_for_production"])
    def test_advisory_identity_and_navigation_scope(self):
        for sid,(ident,url,title,heading) in samples.items():
            with self.subTest(sid=sid):
                source=sources[sid]
                listing=("<html><nav><a href='https://evil.invalid/x'>"+title+
                         "</a></nav><main><a href='"+url+"'>"+title+
                         "</a></main></html>").encode()
                items=discover(source,Fetch({source["discovery_url"]:listing}),1)
                self.assertEqual(items[0]["id"],ident)
                article=("<html><nav>CVE-2026-99999</nav>"
                         "<header>CVE-2026-99998</header>"+
                         ("<div class='post-body'>" if sid=="google-chrome-releases" else "<main>")+
                         "<h1>"+heading+"</h1><p>Publisher describes a synthetic "+
                         "official security bulletin describing selected patches "+
                         "and security fixes. CVE-2026-123456 is inside the article. "+
                         "No customer impact assertion follows from this example.</p>"+
                         ("</div>" if sid=="google-chrome-releases" else "</main>")+
                         "<footer>CVE-2026-99997</footer></html>").encode()
                data=normalize(source,items[0],article)
                if sid=="postgresql-security":
                    self.assertEqual(data["cve_ids"],["CVE-2026-19385"])
                else:
                    self.assertEqual(data["cve_ids"],["CVE-2026-123456"])
                self.assertEqual(data["affected"],[])
                self.assertEqual(data["publisher_published_at"],"UNVERIFIED")
    def test_untrusted_offsite_and_listing_identity_rejected(self):
        x=sources["adobe-security-bulletins"]
        bad="<main><a href='https://evil.invalid/security/products/acrobat/apsb26-141.html'>APSB26-141</a></main>"
        with self.assertRaisesRegex(ValueError,"no verified-shape"):
            discover(x,Fetch({x["discovery_url"]:bad.encode()}),1)
        fake="<main><a href='https://helpx.adobe.com/security/products/acrobat/apsb26-140.html'>APSB26-141</a></main>"
        with self.assertRaisesRegex(ValueError,"no verified-shape"):
            discover(x,Fetch({x["discovery_url"]:fake.encode()}),1)
        item={"id":"APSB26-141","url":samples["adobe-security-bulletins"][1],
              "title":samples["adobe-security-bulletins"][2]}
        body=("<main>"+("irrelevant security text "*20)+"APSB26-142 CVE-2026-123456</main>").encode()
        with self.assertRaisesRegex(ValueError,"ID mismatch"):
            normalize(x,item,body)
    def test_no_cve_in_navigation_becomes_official_link(self):
        x=sources["apple-security-releases"]
        item={"id":samples["apple-security-releases"][0],
              "url":samples["apple-security-releases"][1],
              "title":samples["apple-security-releases"][2]}
        body=("<nav>CVE-2026-88888</nav><main>About the security content of iOS 26.7.1 and "+
              "iPadOS 26.7.1. This advisory has no CVE content in its main "+
              "publisher body but is a valid release note.</main>").encode()
        self.assertEqual(normalize(x,item,body)["cve_ids"],[])

if __name__=="__main__":unittest.main()
