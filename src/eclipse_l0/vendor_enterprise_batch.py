"""Official enterprise publisher candidates: identity-first, evidence-only, one-shot."""
import json
import re
from html.parser import HTMLParser
from urllib.parse import urljoin,urlsplit
CVE=re.compile(r"\bCVE-\d{4}-\d{4,}\b",re.I)
ORACLE=re.compile(r"^/security-alerts/(cpu(?:jan|apr|jul|oct)\d{4}|[a-z]+(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)\d{4})\.html$",re.I)
SAP=re.compile(r"^/en/my-support/knowledge-base/security-notes-news/([a-z]+)-(20\d{2})\.html$",re.I)
VMWARE=re.compile(r"/external/content/(?:SecurityAdvisories|security-advisories)/0/(\d{4,9})/?$",re.I)
DRUPAL=re.compile(r"^/sa-core-(20\d{2})-(\d{3})/?$",re.I)
CISCO=re.compile(r"^cisco-sa-[A-Za-z0-9-]{6,80}$")
APACHE=re.compile(r"^/security/vulnerabilities_24\.html$",re.I)
SOURCES={"cisco-public-advisories","oracle-security-patches","sap-security-patch-days",
         "vmware-broadcom-vmsa","drupal-core-security","apache-httpd-security"}
class PublisherArticle(HTMLParser):
    EXCLUDE={"nav","script","style","footer","header","aside","noscript","svg"}
    def __init__(self):
        super().__init__();self.tags=[];self.focus=0;self.ignored=0;self.after_h1=False;self.words=[]
    def handle_starttag(self,tag,attrs):
        cls=set(dict(attrs).get("class","").split())
        active=(tag in ("main","article") or (tag in ("div","section") and
                 bool(cls & {"main-content","content-main","page-content","article-content","node__content"})))
        if tag=="h1" and not self.ignored:self.after_h1=True
        self.tags.append((tag,active,tag in self.EXCLUDE))
        self.focus+=active;self.ignored+=tag in self.EXCLUDE
    def handle_endtag(self,tag):
        idx=next((i for i in range(len(self.tags)-1,-1,-1) if self.tags[i][0]==tag),None)
        if idx is None:return
        closing=self.tags[idx:]
        self.focus=max(0,self.focus-sum(x[1] for x in closing))
        self.ignored=max(0,self.ignored-sum(x[2] for x in closing))
        del self.tags[idx:]
        if tag=="footer":self.after_h1=False
    def handle_data(self,s):
        if not self.ignored and (self.focus or self.after_h1):
            t=" ".join(s.split())
            if t:self.words.append(t)
def publisher_id(sid,url):
    path=urlsplit(url).path
    if sid=="cisco-public-advisories":
        v=path.rsplit("/",1)[-1]
        return v if "/content/CiscoSecurityAdvisory/" in path and CISCO.fullmatch(v) else None
    if sid=="oracle-security-patches":
        m=ORACLE.fullmatch(path)
        return "ORACLE-"+m.group(1).upper() if m else None
    if sid=="sap-security-patch-days":
        m=SAP.fullmatch(path)
        return f"SAP-PATCH-{m.group(2)}-{m.group(1).upper()}" if m else None
    if sid=="vmware-broadcom-vmsa":
        m=VMWARE.search(path)
        return "VMSA-PAGE-"+m.group(1) if m else None
    if sid=="drupal-core-security":
        m=DRUPAL.fullmatch(path)
        return "SA-CORE-"+m.group(1)+"-"+m.group(2) if m else None
    if sid=="apache-httpd-security":
        return "APACHE-HTTPD-2.4-AGGREGATE" if APACHE.fullmatch(path) else None
    return None
def discover_enterprise(source,raw):
    from .vendor_pilot import _host_allowed,_page
    sid=source["source_id"];results=[]
    if sid=="cisco-public-advisories":
        data=json.loads(raw)
        if not isinstance(data,list):raise ValueError("Cisco official listing must be array")
        for row in data[:100]:
            if not isinstance(row,dict):continue
            url=row.get("url");identity=row.get("identifier")
            if not isinstance(url,str) or not _host_allowed(url,source["allowed_hosts"]):continue
            if identity!=publisher_id(sid,url) or row.get("name")!="Cisco Security Advisory":continue
            results.append({"id":identity,"url":url,"title":str(row.get("title") or identity)[:220]})
    else:
        for title,link in _page(raw).links:
            url=urljoin(source["discovery_url"],link)
            if not _host_allowed(url,source["allowed_hosts"]):continue
            identity=publisher_id(sid,url)
            if identity:results.append({"id":identity,"url":url,"title":title[:220] or identity})
            if len(results)>=800:break
    if not results:raise ValueError("Publisher index yielded no authoritative advisory URLs")
    return results
def normalize_enterprise(source,item,raw):
    from .vendor_pilot import _host_allowed
    sid=source["source_id"]
    if publisher_id(sid,item["url"])!=item["id"] or not _host_allowed(item["url"],source["allowed_hosts"]):
        raise ValueError("Official publisher URL identity mismatch")
    p=PublisherArticle();p.feed(raw.decode("utf-8","replace"))
    text=" ".join(p.words)
    if len(text)<90:raise ValueError("No usable publisher-scoped body text")
    if sid in ("cisco-public-advisories","drupal-core-security") and item["id"].lower() not in text.lower():
        raise ValueError("Advisory ID absent from official detail content")
    if sid=="oracle-security-patches":
        m=re.search(r"cpu(jan|apr|jul|oct)(\d{4})",item["id"],re.I)
        if m and (m.group(2) not in text or {"jan":"january","apr":"april","jul":"july","oct":"october"}[m.group(1).lower()] not in text.lower()):
            raise ValueError("Oracle CPU identity month/year missing")
    if sid=="sap-security-patch-days":
        x=item["id"].split("-")
        if len(x)!=4 or x[2] not in text or x[3].lower() not in text.lower():
            raise ValueError("SAP patch month/year missing")
    if sid=="vmware-broadcom-vmsa" and not re.search(r"\bVMSA-20\d{2}-\d{4}\b",text,re.I):
        raise ValueError("VMSA identifier missing")
    if sid=="apache-httpd-security" and not re.search(r"Apache HTTP Server.*vulnerabilit",text,re.I):
        raise ValueError("Apache HTTP Server identity missing")
    refs=sorted({v.upper() for v in CVE.findall(text)})
    if len(refs)>4500:raise ValueError("Unbounded CVE references")
    return {"title":item["title"][:500],"cve_ids":refs,"affected":[],
            "evidence_fields":["official index identity","publisher HTTPS detail document","article-scoped CVE references"],
            "unreviewed_dates":"NOT_PARSED","unreviewed_version_ranges":"NOT_PARSED",
            "extraction_notes":["Document-CVE references only, product impact not verified",
                                "Publisher dates and fixes require source-specific human audit"],
            "_extractor_revision":"enterprise_batch2_v1"}
