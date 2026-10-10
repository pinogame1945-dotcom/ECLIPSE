"""Five additional official security publication adapters (research-only).

Exact publisher advisory identity + HTTPS publisher allowlist are mandatory.
No page-wide CVEs, arbitrary navigation text, or inferred product versions are
treated as security claims. Publisher versions, commercial rights and periodic
coverage require separate human audit before production use.
"""
from __future__ import annotations

from html.parser import HTMLParser
import re
from urllib.parse import urljoin, urlsplit

CVE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)
APSB = re.compile(r"\bAPSB\d{2}-\d{1,4}\b", re.I)
POST_PATH = re.compile(r"^/(20\d{2})/(0[1-9]|1[0-2])/([a-z0-9-]+)\.html$", re.I)
APPLE_PATH = re.compile(r"^/en-us/(\d{5,7})/?$")
ADOBE_PATH = re.compile(r"^/(?:[a-z]{2}(?:_[a-z]{2})?/)?security/products/[^?#]+/apsb(\d{2})-(\d{1,4})\.html$",re.I)
ANDROID_PATH = re.compile(r"^/docs/security/bulletin/(20\d{2})/(\d{4}-\d{2}-01)/?$")
POSTGRES_PATH = re.compile(r"^/support/security/(CVE-\d{4}-\d{4,})/?$", re.I)
MAX_CVE_REFERENCES = 500

class ContentOnly(HTMLParser):
    """Only main/article or Chrome's post-body; ignore site chrome and scripts."""
    IGNORED={"script","style","nav","header","footer","aside","noscript","svg"}
    def __init__(self, chrome=False):
        super().__init__()
        self.chrome=chrome
        self.stack=[]
        self.focus=0
        self.ignored=0
        self.text=[]
    def handle_starttag(self,tag,attrs):
        attrs=dict(attrs)
        active=(tag=="div" and "post-body" in attrs.get("class","").split()) if self.chrome else tag in ("main","article")
        self.stack.append((tag,active,tag in self.IGNORED))
        self.focus+=int(active)
        self.ignored+=int(tag in self.IGNORED)
    def handle_endtag(self,tag):
        pos=next((i for i in range(len(self.stack)-1,-1,-1) if self.stack[i][0]==tag),None)
        if pos is None:
            return
        closing=self.stack[pos:]
        self.focus-=sum(x[1] for x in closing)
        self.ignored-=sum(x[2] for x in closing)
        del self.stack[pos:]
    def handle_data(self,value):
        if self.focus>0 and self.ignored==0:
            value=" ".join(value.split())
            if value:self.text.append(value)


def _identity(sid, title, url):
    p=urlsplit(url)
    path=p.path
    if sid=="apple-security-releases":
        m=APPLE_PATH.fullmatch(path)
        if m and re.search(r"\b(iOS|iPadOS|macOS|watchOS|tvOS|visionOS|Safari|Xcode)\b",title,re.I):
            return "APPLE-ARTICLE-"+m.group(1)
    elif sid=="adobe-security-bulletins":
        m=ADOBE_PATH.fullmatch(path)
        title_id=APSB.search(title)
        if m and title_id and title_id.group(0).upper()==f"APSB{m.group(1)}-{int(m.group(2))}":
            return title_id.group(0).upper()
    elif sid=="google-chrome-releases":
        m=POST_PATH.fullmatch(path)
        if m and re.search(r"\b(Stable|Security)\b",title,re.I):
            return "CHROME-"+m.group(1)+"-"+m.group(2)+"-"+m.group(3)[:100]
    elif sid=="android-security-bulletins":
        m=ANDROID_PATH.fullmatch(path)
        if m and m.group(2).startswith(m.group(1)):
            return "ANDROID-"+m.group(2)
    elif sid=="postgresql-security":
        m=POSTGRES_PATH.fullmatch(path)
        if m: return m.group(1).upper()
    return None


def discover_official(source:dict,raw:bytes) -> list[dict]:
    from .vendor_pilot import _page, _host_allowed
    page=_page(raw)
    sid=source["source_id"]
    out=[]
    for title,link in page.links:
        absolute=urljoin(source["discovery_url"],link)
        if not _host_allowed(absolute,source["allowed_hosts"]):
            continue
        identity=_identity(sid,title,absolute)
        if identity:
            out.append({"id":identity,"url":absolute,"title":title[:220] or identity})
        if len(out)>=750:break
    if not out:
        raise ValueError("Publisher index yielded no verified-shape advisory links")
    return out


def normalize_official(source:dict,item:dict,raw:bytes) -> dict:
    sid=source["source_id"]
    from .vendor_pilot import _host_allowed
    ident=_identity(sid,item.get("title",""),item["url"])
    if ident!=item["id"] or not _host_allowed(item["url"],source["allowed_hosts"]):
        raise ValueError("Publisher advisory URL, listing title or ID mismatch")
    parser=ContentOnly(chrome=(sid=="google-chrome-releases"))
    parser.feed(raw.decode("utf-8","replace"))
    content=" ".join(parser.text)
    if len(content)<65:
        raise ValueError("No isolated main/article publisher content; fail closed")
    if sid=="adobe-security-bulletins":
        found={x.upper() for x in APSB.findall(content)}
        if ident not in found:
            raise ValueError("Adobe detail bulletin ID mismatch")
    elif sid=="postgresql-security":
        # PostgreSQL's unique CVE page identifies one issue, not a giant index.
        if not re.search(r"(?:^|\s)"+re.escape(ident)+r"(?:\s|$)",content,re.I):
            raise ValueError("PostgreSQL detail CVE ID mismatch")
    elif sid=="android-security-bulletins":
        month=int(ident.split("-")[2])
        names=["January","February","March","April","May","June","July","August",
               "September","October","November","December"]
        if names[month-1].lower() not in content.lower():
            raise ValueError("Android bulletin month missing from publisher content")
    elif sid=="apple-security-releases":
        if "security content" not in content.lower():
            raise ValueError("Apple detail lacks expected security content heading")
    elif sid=="google-chrome-releases":
        if not re.search(r"(stable|security)",content,re.I):
            raise ValueError("Chrome security/stable article body missing")
    ids=sorted({x.upper() for x in CVE.findall(content)})
    if len(ids)>MAX_CVE_REFERENCES:
        raise ValueError("Unbounded publisher CVE references")
    if sid=="postgresql-security":
        # The PostgreSQL individual CVE detail is an explicit publisher claim.
        ids=[ident]
    # On multi-issue HTML pages, references are advisory-level, NOT per-version
    # product impact. Never infer "affected" just because the CVE was mentioned.
    return {
        "title":item["title"][:500],
        "cve_ids":ids,
        "affected":[],
        "publisher_content_type":"publisher_main_article" if sid!="google-chrome-releases" else "publisher_post_body",
        "publisher_published_at":"UNVERIFIED",
        "remediation_version_extraction":"NOT_IMPLEMENTED",
        "evidence_fields":["official index identity and HTTPS document link",
                           "publisher article body isolated from navigation",
                           "publisher detail advisory identity" if sid in (
                               "adobe-security-bulletins","postgresql-security") else "publisher scoped content",
                           "publisher body CVE references, not product applicability"],
        "extraction_notes":[
            "Official publisher content only. Advisory CVE references do not prove applicability to any inventory item.",
            "Affected products, versions, severity and exploit evidence require separate source-specific validation.",
            "No automated customer exposure assessment and no republication authorization.",
        ]
    }
