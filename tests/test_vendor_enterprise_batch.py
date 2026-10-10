"""Enterprise batch2 bounded synthetic source validation, not an online success claim."""
import unittest
import json
from pathlib import Path
from eclipse_l0.vendor_registry import load_registry
from eclipse_l0.vendor_enterprise_batch import discover_enterprise,normalize_enterprise
from eclipse_l0.vendor_pilot import SUPPORTED
source={x["source_id"]:x for x in load_registry(Path(__file__).resolve().parents[1]/"config/vendor_source_registry.json")["sources"]}
examples=[
 ("oracle-security-patches","ORACLE-CPUJUL2026","https://www.oracle.com/security-alerts/cpujul2026.html","Oracle July 2026 Critical Patch Update"),
 ("sap-security-patch-days","SAP-PATCH-2026-SEPTEMBER","https://support.sap.com/en/my-support/knowledge-base/security-notes-news/september-2026.html","SAP September 2026 Security Patch Day"),
 ("vmware-broadcom-vmsa","VMSA-PAGE-38288","https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/38288","VMSA-2026-0007 VMware security notice"),
 ("drupal-core-security","SA-CORE-2026-012","https://www.drupal.org/sa-core-2026-012","Drupal Core SA-CORE-2026-012"),
 ("apache-httpd-security","APACHE-HTTPD-2.4-AGGREGATE","https://httpd.apache.org/security/vulnerabilities_24.html","Apache HTTP Server 2.4 vulnerabilities")
]
class EnterpriseBatch(unittest.TestCase):
 def test_six_unverified_and_no_production(self):
  for x in ("cisco-public-advisories",)+tuple(y[0] for y in examples):
   self.assertIn(x,SUPPORTED)
   self.assertEqual(source[x]["verification_status"],"not_tested")
   self.assertFalse(source[x]["enabled_for_production"])
 def test_publication_identity_and_navigation_false_positive(self):
  for sid,ident,url,title in examples:
   with self.subTest(sid=sid):
    index=f"<main><a href='{url}'>{title}</a></main>".encode()
    items=discover_enterprise(source[sid],index)
    self.assertEqual(items[0]["id"],ident)
    detail=("<nav>CVE-2026-333333</nav><main><h1>"+title+"</h1><p>"+
            "This is a publisher-style synthetic advisory used for deterministic "+
            "tests. CVE-2026-222222 is a test identifier not a live security claim."+
            "</p></main><footer>CVE-2026-444444</footer>").encode()
    f=normalize_enterprise(source[sid],items[0],detail)
    self.assertEqual(f["cve_ids"],["CVE-2026-222222"])
    self.assertEqual(f["affected"],[])
 def test_cisco_json_exact_ids_and_scoped_detail(self):
  sid="cisco-public-advisories"
  url="https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ssm-access-nttb2dhE"
  data=[{"identifier":"cisco-sa-ssm-access-nttb2dhE","url":url,"name":"Cisco Security Advisory","title":"Cisco SSM vulnerability"}]
  item=discover_enterprise(source[sid],json.dumps(data).encode())[0]
  detail=("<main><h1>Cisco security cisco-sa-ssm-access-nttb2dhE</h1><p>"+
          "This synthetic advisory references CVE-2026-222222 with no"+
          " validated product range or exploit status.</p></main>").encode()
  self.assertEqual(normalize_enterprise(source[sid],item,detail)["cve_ids"],["CVE-2026-222222"])
 def test_offsite_source_not_promoted(self):
  with self.assertRaisesRegex(ValueError,"no authoritative"):
   discover_enterprise(source["drupal-core-security"],b"<a href='https://evil.invalid/sa-core-2026-012'>Drupal SA-CORE-2026-012</a>")
if __name__=="__main__":unittest.main()
