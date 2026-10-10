"""Official publisher wave3: ten independent public source candidates, one-shot only.

Discovery is confined to official HTTPS publisher hosts and exact publication URLs.
The main content is required; full-page or menu CVEs are NEVER trusted.
A matching bulletin is evidence for a *document*, not exact customer exposure.
"""
from __future__ import annotations
import re
from html.parser import HTMLParser
from urllib.parse import parse_qs, urljoin, urlsplit
CVE=re.compile(r"\bCVE-\d{4}-\d{4,}\b",re.I)
JENKINS=re.compile(r"^/security/advisory/(20\d{2}-\d{2}-\d{2})/?$",re.I)
GRAFANA=re.compile(r"^/security/security-advisories/(cve-\d{4}-\d{4,})/?$",re.I)
JUNIPER=re.compile(r"^/s/article/([A-Za-z0-9_-]{5,80})/?$",re.I)
HPE=re.compile(r"^/hpesc/public/docDisplay$",re.I)
IBM1=re.compile(r"^/support/pages/node/(\d{4,10})/?$",re.I)
IBM2=re.compile(r"^/support/pages/(security-bulletin-[a-z0-9-]{15,240})/?$",re.I)
NETAPP=re.compile(r"^/advisory/(ntap-\d{8}-\d{4})/?$",re.I)
NGINX=re.compile(r"^/en/security_advisories\.html$",re.I)
OPENSSL=re.compile(r"^/news/vulnerabilities/?$",re.I)
TOMCAT=re.compile(r"^/security-(9|10|11)\.html$",re.I)
WORDPRESS=re.compile(r"^/news/(20\d{2})/(\d{2})/([a-z0-9-]*(?:security|release)[a-z0-9-]*)/?$",re.I)
SINGLETON={"nginx-security","openssl-security"}
LIMIT=4500
def identity(source_id:str,url:str,link_title:str="")->str|None:
    parsed=urlsplit(url);path=parsed.path
    if source_id=="jenkins-security":
        m=JENKINS.fullmatch(path);return f"JENKINS-{m.group(1)}" if m else None
    if source_id=="grafana-security":
        m=GRAFANA.fullmatch(path);return m.group(1).upper() if m else None
    if source_id=="juniper-jsa":
        m=JUNIPER.fullmatch(path)
        return "JUNIPER-"+m.group(1) if m and ("JSA" in m.group(1).upper() or "security" in link_title.lower()) else None
    if source_id=="hpe-psirt":
        m=HPE.fullmatch(path)
        ids=parse_qs(parsed.query).get("docId",[])
        if m and len(ids)==1 and re.fullmatch(r"hpesb[a-z]{1,4}\d{4,6}en_us",ids[0],re.I):
            return "HPE-"+ids[0].upper()
        return None
    if source_id=="ibm-security-bulletins":
        m=IBM1.fullmatch(path)
        if m and "security" in link_title.lower():return "IBM-NODE-"+m.group(1)
        m=IBM2.fullmatch(path)
        return "IBM-"+m.group(1).upper() if m else None
    if source_id=="netapp-psirt":
        m=NETAPP.fullmatch(path);return m.group(1).upper() if m else None
    if source_id=="nginx-security":return "NGINX-SECURITY-AGGREGATE" if NGINX.fullmatch(path) else None
    if source_id=="openssl-security":return "OPENSSL-SECURITY-AGGREGATE" if OPENSSL.fullmatch(path) else None
    if source_id=="tomcat-security":
        m=TOMCAT.fullmatch(path);return "TOMCAT-SECURITY-"+m.group(1) if m else None
    if source_id=="wordpress-core-security":
        m=WORDPRESS.fullmatch(path)
        return "WORDPRESS-"+m.group(1)+"-"+m.group(2)+"-"+m.group(3)[:100] if m else None
    return None

class ScopedText(HTMLParser):
    IGNORE={"script","style","nav","header","footer","aside","noscript","svg"}
    # Do not let unrelated header/footer/menu CVEs become evidence in a bulletin.
    BODY_CLASSES={"main","entry-content","article-content","post-content","page-content",
                  "devsite-article-body","content","body","content-main","main-content",
                  "node__content","richtext","page-body","section-content"}
    def __init__(self):
        super().__init__();self.stack=[];self.focus=0;self.ignored=0;self.text=[];self.headings=[]
        self.hdepth=0
    def handle_starttag(self,tag,attrs):
        attr=dict(attrs);classes=set(attr.get("class","").split())
        active=(tag in ("main","article") or (tag in ("div","section") and bool(classes & self.BODY_CLASSES)))
        self.stack.append((tag,active,tag in self.IGNORE))
        self.focus+=int(active);self.ignored+=int(tag in self.IGNORE)
        if tag in ("h1","h2","h3"):self.hdepth+=1
    def handle_endtag(self,tag):
        idx=next((i for i in range(len(self.stack)-1,-1,-1) if self.stack[i][0]==tag),None)
        if idx is None:return
        closing=self.stack[idx:];self.focus=max(0,self.focus-sum(x[1] for x in closing))
        self.ignored=max(0,self.ignored-sum(x[2] for x in closing))
        self.hdepth=max(0,self.hdepth-sum(x[0] in ("h1","h2","h3") for x in closing))
        del self.stack[idx:]
    def handle_data(self,value):
        if self.focus>0 and self.ignored==0:
            value=" ".join(value.split())
            if value:self.text.append(value)
            if value and self.hdepth:self.headings.append(value)

def _strict_html(raw):
    if len(raw)>6*1024*1024:raise ValueError("oversize public publisher HTML")
    p=ScopedText();p.feed(raw.decode("utf-8","replace"))
    return p

def discover_wave3(source:dict,raw:bytes)->list[dict]:
    from .vendor_pilot import _host_allowed,_page
    sid=source["source_id"];base=source["discovery_url"]
    if sid in SINGLETON:
        if not _host_allowed(base,source["allowed_hosts"]):raise ValueError("Bad singleton official origin")
        txt=" ".join(_strict_html(raw).text)
        # No all-page CVE scan: page body must identify its publisher product and
        # be long enough that an access challenge page cannot become a baseline.
        label="nginx security advisories" if sid=="nginx-security" else "vulnerabilities"
        if label not in txt.lower() or len(txt)<150:raise ValueError("Unusable official aggregate page body")
        return [{"id":identity(sid,base),"url":base,"title":label.title()}]
    out=[]
    for title,href in _page(raw).links:
        url=urljoin(base,href)
        if not _host_allowed(url,source["allowed_hosts"]):continue
        ident=identity(sid,url,title)
        if not ident:continue
        out.append({"id":ident,"url":url,"title":title[:220] or ident})
        if len(out)>=800:break
    if not out:raise ValueError("No verifiable publisher index detail URLs; dynamic index or auth may be unsupported")
    return out

def normalize_wave3(source:dict,item:dict,raw:bytes)->dict:
    from .vendor_pilot import _host_allowed
    sid=source["source_id"];url=item["url"]
    if not _host_allowed(url,source["allowed_hosts"]) or identity(sid,url,item["title"])!=item["id"]:
        raise ValueError("Publisher identity and official HTTPS URL mismatch")
    parsed=_strict_html(raw)
    body=" ".join(parsed.text)
    if len(body)<100:raise ValueError("No bounded publication body; refusing pagewide fallback")
    needles={
      "jenkins-security":"Jenkins Security Advisory",
      "grafana-security":"Advisory ID",
      "juniper-jsa":"security",
      "hpe-psirt":"Security Bulletin",
      "ibm-security-bulletins":"Security Bulletin",
      "netapp-psirt":"Advisory ID",
      "nginx-security":"nginx security advisories",
      "openssl-security":"vulnerabilities",
      "tomcat-security":"Apache Tomcat",
      "wordpress-core-security":"security",
    }
    if needles[sid].lower() not in body.lower():
        raise ValueError("Expected publisher advisory heading absent")
    if sid=="jenkins-security" and item["id"].removeprefix("JENKINS-") not in body:
        raise ValueError("Jenkins advisory date mismatch")
    if sid in ("netapp-psirt","grafana-security") and item["id"].upper() not in body.upper():
        raise ValueError("Publisher advisory ID mismatch")
    if sid=="tomcat-security" and item["id"].split("-")[-1]+".x" not in body:
        raise ValueError("Tomcat major branch did not match detail page")
    ids=sorted({x.upper() for x in CVE.findall(body)})
    if len(ids)>LIMIT:raise ValueError("Too many scoped CVE references")
    if sid=="grafana-security":
        if item["id"] not in ids:raise ValueError("Grafana own CVE not found")
        ids=[item["id"]]  # one Grafana CVE page must not include related CVEs
    return {
      "title":item["title"][:500],"cve_ids":ids,"affected":[],
      "publisher_dates_review_state":"NOT_EXTRACTED",
      "fix_version_review_state":"NOT_EXTRACTED",
      "detail_scope":"official_main_article_only",
      "evidence_fields":["official HTTPS publisher index and verified advisory URL",
                         "official bounded main/article HTML body and publisher identity",
                         "document-level CVE strings only; no CVE-to-product claim"],
      "extraction_notes":["CVE references require human source review and exact product/firmware versions",
                          "Official source publication / last-modified dates not normalized",
                          "Aggregate vulnerability catalogs must not be counted as new individual advisories"
                            if sid in SINGLETON or sid=="tomcat-security"
                            else "One publisher advisory page; revision and coverage are unverified."]
    }
