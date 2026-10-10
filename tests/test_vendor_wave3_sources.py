"""Wave3 offline parser safety and source registry guards; no network."""
import unittest
from pathlib import Path
from eclipse_l0.vendor_registry import load_registry
from eclipse_l0.vendor_wave3_sources import identity,discover_wave3,normalize_wave3
from eclipse_l0.vendor_pilot import SUPPORTED
reg=load_registry(Path(__file__).resolve().parents[1]/"config/vendor_source_registry.json")
S={v["source_id"]:v for v in reg["sources"]}
cases=[
("jenkins-security","JENKINS-2026-09-16","https://www.jenkins.io/security/advisory/2026-09-16/","Jenkins Security Advisory 2026-09-16"),
("grafana-security","CVE-2026-17033","https://grafana.com/security/security-advisories/cve-2026-17033/","Advisory ID: CVE-2026-17033 Security"),
("netapp-psirt","NTAP-20260130-0010","https://security.netapp.com/advisory/ntap-20260130-0010","Advisory ID: NTAP-20260130-0010 Security"),
("hpe-psirt","HPE-HPESBNW05134EN_US","https://support.hpe.com/hpesc/public/docDisplay?docId=hpesbnw05134en_us&docLocale=en_US","Security Bulletin HPESBNW05134"),
("tomcat-security","TOMCAT-SECURITY-11","https://tomcat.apache.org/security-11.html","Apache Tomcat 11.x vulnerabilities"),
("wordpress-core-security","WORDPRESS-2026-10-wordpress-7-1-3-maintenance-and-security-release","https://wordpress.org/news/2026/10/wordpress-7-1-3-maintenance-and-security-release/","WordPress security release"),
]
class ThirdWaveTests(unittest.TestCase):
 def test_all_are_provisional_only(self):
  self.assertEqual(len(reg["sources"]),34)
  for sid in ["juniper-jsa","hpe-psirt","ibm-security-bulletins","netapp-psirt","jenkins-security","grafana-security","nginx-security","openssl-security","tomcat-security","wordpress-core-security"]:
   self.assertIn(sid,SUPPORTED)
   self.assertEqual(S[sid]["verification_status"],"not_tested")
   self.assertFalse(S[sid]["enabled_for_production"])
 def test_index_identification_and_scoped_article(self):
  for sid,ident,url,title in cases:
   with self.subTest(sid=sid):
    listing=("<header>CVE-2026-789456</header><main><a href='"+url+"'>"+title+"</a></main>").encode()
    item=discover_wave3(S[sid],listing)[0]
    self.assertEqual(item["id"],ident)
    article=("<nav>CVE-2026-785111</nav><main><h1>"+title+"</h1><p>"+
        "This is a synthetic security bulletin about a publisher response. CVE-2026-223344. "+
        "Any affected version statement must be verified with the publisher before release."+
        "</p></main><footer>CVE-2026-785222</footer>").encode()
    facts=normalize_wave3(S[sid],item,article)
    if sid=="grafana-security":self.assertEqual(facts["cve_ids"],["CVE-2026-17033"])
    else:self.assertEqual(facts["cve_ids"],["CVE-2026-223344"])
    self.assertEqual(facts["affected"],[])
 def test_prohibit_offsite_and_global_cve_without_article(self):
  source=S["jenkins-security"]
  with self.assertRaisesRegex(ValueError,"No verifiable"):
   discover_wave3(source,b"<a href='https://attacker.invalid/security/advisory/2026-09-16/'>Jenkins Security Advisory 2026-09-16</a>")
  item={"id":"JENKINS-2026-09-16","url":"https://www.jenkins.io/security/advisory/2026-09-16/","title":"Jenkins Security Advisory 2026-09-16"}
  with self.assertRaisesRegex(ValueError,"No bounded"):
   normalize_wave3(source,item,b"<header>CVE-2026-999999 security advisory</header><nav>malicious</nav>")
 def test_singletons_fail_closed_on_invalid_full_page(self):
  for sid in ("nginx-security","openssl-security"):
   with self.assertRaisesRegex(ValueError,"Unusable"):
    discover_wave3(S[sid],b"<html><script>CVE-2026-12345</script></html>")
 def test_netapp_official_rss_item_identity_not_third_party(self):
  s=S["netapp-psirt"]
  good="https://security.netapp.com/advisory/ntap-20260130-0010"
  xml=("<rss><channel><item><title>CVE-2026-21441 official NetApp</title>"+
       "<link>"+good+"</link></item><item><title>malicious</title>"+
       "<link>https://evil.invalid/advisory/ntap-20260130-0001</link></item></channel></rss>").encode()
  got=discover_wave3(s,xml)
  self.assertEqual(len(got),1)
  self.assertEqual(got[0]["id"],"NTAP-20260130-0010")
 def test_nginx_solo_page_after_verified_heading(self):
  s=S["nginx-security"]
  body=("<header>CVE-2026-777777</header><h1>nginx security advisories</h1>"+
        "<p>Official nginx product security catalog contains CVE-2026-123456 and "+
        "shows the relevant product impact statements and severity list as text.</p>"+
        "<footer>CVE-2026-888888</footer>").encode()
  item=discover_wave3(s,body)[0]
  facts=normalize_wave3(s,item,body)
  self.assertEqual(facts["cve_ids"],["CVE-2026-123456"])
 def test_grafana_index_requires_official_bounded_context(self):
  src=S["grafana-security"]
  good=("<main><h1>Security Advisories</h1><table><tr><td>CVE-2026-17033</td>"+
       "<td>Grafana Vulnerability</td></tr></table></main>").encode()
  discovered=discover_wave3(src,good)
  self.assertEqual(discovered[0]["id"],"CVE-2026-17033")
  with self.assertRaisesRegex(ValueError,"No verifiable"):
   discover_wave3(src,b"<header>Security Advisories CVE-2026-17033</header>")
if __name__=="__main__":unittest.main()
