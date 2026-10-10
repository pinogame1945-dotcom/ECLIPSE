"""Synthetic safe RSS adapter tests; no live feed is assumed before GitHub probe."""
import unittest
from pathlib import Path
from eclipse_l0.vendor_registry import load_registry
from eclipse_l0.vendor_next_rss import discover_security_rss,normalize_security_rss
from eclipse_l0.vendor_pilot import SUPPORTED
reg=load_registry(Path(__file__).resolve().parents[1]/"config/vendor_source_registry.json")
src={x["source_id"]:x for x in reg["sources"]}
cases=[
("juniper-mist-security-rss","https://www.mist.com/documentation/radius-protocol-vulnerability-blast-radius/","RADIUS Protocol Vulnerability (Blast-RADIUS)"),
("ivanti-security-advisory-rss","https://www.ivanti.com/blog/april-2026-security-update","April 2026 Security Update")
]
class OfficialRSSNextTest(unittest.TestCase):
 def test_registry_unverified_and_scope(self):
  for sid,_,_ in cases:
   self.assertIn(sid,SUPPORTED)
   self.assertFalse(src[sid]["enabled_for_production"])
   self.assertEqual(src[sid]["verification_status"],"not_tested")
  self.assertIn("NOT entire Juniper",src["juniper-mist-security-rss"]["product_scope"])
 def test_official_rss_selects_exact_item_and_scopes_detail(self):
  for sid,url,title in cases:
   with self.subTest(source=sid):
    rss=("<rss><channel><item><title>"+title+"</title><link>"+url+
         "</link></item><item><title>Evil</title><link>https://notvendor.invalid/documentation/evil/"+
         "</link></item></channel></rss>").encode()
    items=discover_security_rss(src[sid],rss)
    self.assertEqual(len(items),1)
    html=("<header>CVE-2026-55555</header><main><h1>"+title+"</h1><p>"+
          "Official advisory publisher describes a synthetic security issue CVE-2026-123456 "+
          "and security controls; precise customer product versions are never assumed. "+
          "Additional security configuration and release guidance is publisher-specific."+
          "</p></main><footer>CVE-2026-77777</footer>").encode()
    facts=normalize_security_rss(src[sid],items[0],html)
    self.assertEqual(facts["cve_ids"],["CVE-2026-123456"])
    self.assertEqual(facts["affected"],[])
 def test_fail_closed_missing_body_or_rss(self):
  s=src["juniper-mist-security-rss"]
  with self.assertRaisesRegex(ValueError,"RSS"):discover_security_rss(s,b"<html><a href='evil'>bad</a></html>")
  item={"id":"MIST-ARTICLE-test-security-news","url":"https://www.mist.com/documentation/test-security-news/",
        "title":"Test Security News"}
  with self.assertRaisesRegex(ValueError,"bounded"):
   normalize_security_rss(s,item,b"<html><nav>CVE-2026-123456</nav></html>")
if __name__=="__main__":unittest.main()
