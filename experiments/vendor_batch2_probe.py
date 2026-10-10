"""Read-only live vendor source discovery for expanding ECLIPSE source registry.

Public official sites only; best-effort, bounded, no persistence/customer data.
PASS proves one-shot listing and selected detail parse, not full monitoring.
"""
import argparse
import hashlib
from html.parser import HTMLParser
import json
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import re
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen
import xml.etree.ElementTree as ET

CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
MAX_BYTES = 5 * 1024 * 1024


def read(url, hosts):
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in hosts or parsed.username or parsed.password:
        raise ValueError("Host is not official allowlisted source")
    req = Request(url, headers={
        "User-Agent": "ECLIPSE-official-public-advisory-one-shot-probe/1.0",
        "Accept": "application/json,application/atom+xml,application/rss+xml,text/html;q=0.8,*/*;q=0.5"})
    with urlopen(req, timeout=22) as resp:
        final = resp.url
        p = urlparse(final)
        if p.scheme != "https" or p.hostname not in hosts:
            raise ValueError("Redirect outside source allowlist")
        raw = resp.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ValueError("Exceeded 5 MiB response cap")
        return raw, {"url":final,"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest(),
                     "content_type":resp.headers.get("Content-Type",""),
                     "observed_utc":datetime.now(timezone.utc).isoformat(timespec="seconds")}


class Page(HTMLParser):
    def __init__(self):
        super().__init__()
        self.text=[]
        self.links=[]
        self.cur=None
        self.title=[]
    def handle_starttag(self,t,a):
        if t=="a":
            self.cur=dict(a).get("href","")
            self.title=[]
    def handle_data(self,s):
        self.text.append(s)
        if self.cur is not None: self.title.append(s)
    def handle_endtag(self,t):
        if t=="a" and self.cur is not None:
            self.links.append((" ".join(self.title).strip(),self.cur))
            self.cur=None
            self.title=[]


def record(source,name,tests):
    passed=sum(t.get("status")=="PASS" for t in tests.values())
    return {"source_id":source,"vendor":name,"tests":tests,
            "verdict":"PASS" if passed==len(tests) else "PARTIAL" if passed else "FAIL",
            "limitations":["One-time retrieval, not durability/delta/coverage/licensing certification."]}


def test(fn):
    try:
        d=fn()
        return {"status":"PASS",**d}
    except Exception as e:
        return {"status":"FAIL","error":f"{type(e).__name__}: {str(e)[:220]}"}


def gitlab():
    hosts={"docs.gitlab.com"}
    fetched=[]
    def listing():
        raw,e=read("https://docs.gitlab.com/releases/patch-releases.xml",hosts)
        if b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper(): raise ValueError("XML DTD refused")
        root=ET.fromstring(raw)
        if root.tag.endswith("rss"):
            items=[{"title":x.findtext("title") or "","url":x.findtext("link") or ""}
                   for x in root.findall("./channel/item")]
        else:
            atom="{http://www.w3.org/2005/Atom}"
            items=[]
            for x in root.findall(atom+"entry"):
                links=[z.attrib.get("href","") for z in x.findall(atom+"link")
                       if z.attrib.get("rel","alternate") in ("alternate","")]
                items.append({"title":x.findtext(atom+"title") or "",
                              "url":links[0] if links else ""})
        if not items: raise ValueError("Empty/unknown GitLab security patch feed")
        fetched.extend(items)
        return {"evidence":e,"items":len(items),"first":items[0]}
    def detail():
        if not fetched: raise ValueError("Missing feed list")
        url=fetched[0]["url"]
        raw,e=read(url,hosts)
        page=Page();page.feed(raw.decode("utf-8","replace"))
        t=" ".join(page.text)
        if len(t)<300:raise ValueError("Body empty")
        return {"evidence":e,"cve_samples":list(dict.fromkeys(CVE.findall(t)))[:10],
                "body_chars":len(t),"has_patch_version_terms":"patch" in t.lower() or "release" in t.lower()}
    a=test(listing);b=test(detail)
    return record("gitlab-release-feed","GitLab",{"feed":a,"detail":b})


def ubuntu():
    hosts={"ubuntu.com"}
    picks=[]
    def listing():
        raw,e=read("https://ubuntu.com/security/notices.json?limit=5",hosts)
        obj=json.loads(raw)
        if not isinstance(obj,dict):raise ValueError("Unexpected Ubuntu notices type")
        entries=obj.get("notices",[])
        if not isinstance(entries,list) or not entries:raise ValueError("Missing Ubuntu notices list")
        for item in entries:
            if isinstance(item,dict):
                candidate=item.get("id") or item.get("notice_id")
                if isinstance(candidate,str) and re.fullmatch(r"USN-\d+-\d+",candidate):
                    picks.append(candidate)
        if not picks: raise ValueError("Ubuntu notices missing USN IDs")
        return {"evidence":e,"items":len(entries),"sample_ids":picks[:3],"keys":list(obj)[:12]}
    def detail():
        if not picks:raise ValueError("Missing USN")
        raw,e=read("https://ubuntu.com/security/notices/"+picks[0]+".json",hosts)
        doc=json.loads(raw)
        if not isinstance(doc,dict) or not doc:raise ValueError("Empty Ubuntu detail")
        return {"evidence":e,"notice_id":picks[0],
                "fields":list(doc)[:15],
                "mentions_cve":bool(CVE.search(json.dumps(doc)))}
    a=test(listing);b=test(detail)
    return record("ubuntu-security-api","Canonical Ubuntu",{"api_list":a,"api_detail":b})


def chrome():
    hosts={"chromereleases.googleblog.com"}
    picked=[]
    def listing():
        raw,e=read("https://chromereleases.googleblog.com/feeds/posts/default?alt=atom&max-results=10",hosts)
        if b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():raise ValueError("DTD refused")
        root=ET.fromstring(raw)
        atom="{http://www.w3.org/2005/Atom}"
        entries=root.findall(atom+"entry")
        if not entries:raise ValueError("No Chrome release Atom entries")
        rows=[]
        for x in entries:
            title=x.findtext(atom+"title") or ""
            links=[y.attrib.get("href","") for y in x.findall(atom+"link")
                   if y.attrib.get("rel")=="alternate"]
            if links:
                rows.append({"title":title,"url":links[0]})
        if not rows:raise ValueError("No valid release links")
        picked.extend(rows)
        return {"evidence":e,"entries":len(entries),"first":rows[0]}
    def detail():
        if not picked:raise ValueError("Missing Chrome entry")
        # Prefer a stable channel entry but never claim the selected article is a vulnerability advisory.
        x=next((x for x in picked if "stable" in x["title"].lower()),picked[0])
        raw,e=read(x["url"],hosts)
        page=Page();page.feed(raw.decode("utf-8","replace"))
        t=" ".join(page.text)
        if len(t)<200:raise ValueError("Short Chrome update page")
        return {"evidence":e,"title":x["title"],"cve_samples":list(dict.fromkeys(CVE.findall(t)))[:8],
                "body_chars":len(t)}
    return record("google-chrome-release","Google Chrome",{"feed":test(listing),"detail":test(detail)})


def atlassian():
    hosts={"www.atlassian.com"}
    links=[]
    def listing():
        raw,e=read("https://www.atlassian.com/trust/security/advisories",hosts)
        page=Page();page.feed(raw.decode("utf-8","replace"))
        t=" ".join(page.text)
        for title,link in page.links:
            url=urljoin(e["url"],link)
            if (urlparse(url).hostname in hosts and ("bulletin" in url.lower() or "CVE-" in title
                                                     or "security advisory" in title.lower())
                and url!=e["url"]):
                links.append((title,url))
        if not links:raise ValueError("No Atlassian bulletin links found")
        return {"evidence":e,"candidate_links":len(links),
                "first":[{"title":a[:100],"url":b} for a,b in links[:3]]}
    def detail():
        if not links:raise ValueError("No bulletin link")
        title,url=links[0]
        raw,e=read(url,hosts)
        page=Page();page.feed(raw.decode("utf-8","replace"))
        t=" ".join(page.text)
        if len(t)<300:raise ValueError("No readable bulletin content")
        return {"evidence":e,"title":title[:130],"cve_samples":list(dict.fromkeys(CVE.findall(t)))[:8],
                "body_chars":len(t)}
    return record("atlassian-security-advisories","Atlassian",{"listing":test(listing),"detail":test(detail)})


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--out",type=Path,required=True)
    args=parser.parse_args()
    with ThreadPoolExecutor(max_workers=3) as ex:
        results=list(ex.map(lambda f:f(),[gitlab,ubuntu,chrome,atlassian]))
    report={"schema_version":1,"run_scope":"one-shot public GET, no customer or production state",
            "observed_utc":datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "results":results,"summary":{v:sum(r["verdict"]==v for r in results)
                                          for v in ("PASS","PARTIAL","FAIL")}}
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(report,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    print(json.dumps(report,ensure_ascii=False,indent=2))
    return 1 if report["summary"]["FAIL"]==4 else 0

if __name__=="__main__":
    raise SystemExit(main())
