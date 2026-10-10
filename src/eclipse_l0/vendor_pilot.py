"""One-shot, low-volume official vendor advisory -> local versioned evidence pilot.

Not a production monitor. SOURCE REGISTRY gates access. Source-body SHA-256,
source URL, normalized (UNREVIEWED) facts and history go to local SQLite; raw
third-party bodies and customer-specific data are NOT archived. No customer mail.
"""
from __future__ import annotations

import argparse
import csv
from datetime import datetime, timezone
from contextlib import closing
from html.parser import HTMLParser
from io import StringIO
import json
import re
from pathlib import Path
from urllib.parse import urljoin, urlsplit
from urllib.request import Request, build_opener, HTTPRedirectHandler
from xml.etree import ElementTree as ET
import hashlib
import sqlite3

from .vendor_registry import load_registry
from .vendor_store import connect, observe
from .vendor_quality import inspect_facts, summarize_source_quality

CVE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)
ATOM = "{http://www.w3.org/2005/Atom}"
MAX_DOCUMENT = 64 * 1024 * 1024
MAX_FEED = 6 * 1024 * 1024
SUPPORTED = {
    "fortinet-psirt", "paloalto-advisories", "siemens-csaf", "redhat-csaf",
    "ubuntu-security-api", "gitlab-security-releases", "yamaha-network",
    "atlassian-security", "microsoft-msrc",
}


def _host_allowed(url: str, allowed: list[str]) -> bool:
    try:
        x = urlsplit(url)
        return (x.scheme == "https" and x.hostname in allowed
                and not x.username and not x.password and x.port in (None, 443)
                and not x.fragment)
    except ValueError:
        return False


class _StrictRedirect(HTTPRedirectHandler):
    def __init__(self, allowed):
        self.allowed = allowed

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not _host_allowed(newurl, self.allowed):
            raise ValueError("Source redirected outside official HTTPS allowlist")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class OfficialFetch:
    """Rejects unapproved redirects; bounded reads; injectable for offline testing."""
    def __init__(self, source: dict):
        self.allowed = source["allowed_hosts"]
        self.total = 0
        self.max_requests = 12

    def get(self, url: str, limit: int = MAX_FEED) -> bytes:
        if not _host_allowed(url, self.allowed):
            raise ValueError("Nonofficial HTTPS URL refused")
        if self.total >= self.max_requests:
            raise ValueError("Request budget exceeded")
        self.total += 1
        req = Request(url, headers={"User-Agent": "PROJECT-ECLIPSE-one-shot-vendor-evidence/1.0",
                     "Accept": "application/json,application/rss+xml,application/atom+xml,text/html,application/xml,*/*"})
        opener = build_opener(_StrictRedirect(self.allowed))
        with opener.open(req, timeout=25) as response:
            if not _host_allowed(response.url, self.allowed):
                raise ValueError("Final host outside official allowlist")
            raw = response.read(limit + 1)
        if len(raw) > limit:
            raise ValueError("Official response exceeded bounded limit")
        return raw


def _json(raw):
    doc = json.loads(raw)
    if not isinstance(doc, (dict, list)):
        raise ValueError("Unexpected JSON root")
    return doc


def _xml(raw):
    if b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
        raise ValueError("Unsafe DTD/entity in official XML")
    return ET.fromstring(raw)


class Page(HTMLParser):
    def __init__(self):
        super().__init__()
        self.text = []
        self.links = []
        self.cell = None
        self.row = []
        self.rows = []
        self.anchor = None
        self.anchor_text = []

    def handle_starttag(self, tag, attrs):
        if tag == "tr":
            self.row = []
        elif tag in ("td", "th"):
            self.cell = []
        elif tag == "a":
            self.anchor = dict(attrs).get("href")
            self.anchor_text = []

    def handle_data(self, data):
        self.text.append(data)
        if self.cell is not None:
            self.cell.append(data)
        if self.anchor is not None:
            self.anchor_text.append(data)

    def handle_endtag(self, tag):
        if tag in ("td", "th") and self.cell is not None:
            self.row.append(" ".join(" ".join(self.cell).split())[:400])
            self.cell = None
        elif tag == "tr":
            if self.row:
                self.rows.append(self.row)
        elif tag == "a" and self.anchor is not None:
            self.links.append((" ".join(" ".join(self.anchor_text).split())[:220], self.anchor))
            self.anchor = None
            self.anchor_text = []


class ArticleText(HTMLParser):
    """Conservative main/article text only; never promotes candidates to CVE links."""
    IGNORE={"script","style","nav","header","footer","aside","noscript","svg"}
    def __init__(self):
        super().__init__()
        self._stack=[]
        self._focus=0
        self._excluded=0
        self.text=[]
    def handle_starttag(self,tag,attrs):
        if tag in ("main","article"):
            self._focus+=1
        if tag in self.IGNORE:
            self._excluded+=1
        self._stack.append(tag)
    def handle_endtag(self,tag):
        # Ignore malformed HTML nesting by balancing nearest matching tag.
        if tag not in self._stack:
            return
        idx=len(self._stack)-1-self._stack[::-1].index(tag)
        closing=self._stack[idx:]
        self._focus=max(0,self._focus-sum(x in ("main","article") for x in closing))
        self._excluded=max(0,self._excluded-sum(x in self.IGNORE for x in closing))
        del self._stack[idx:]
    def handle_data(self,text):
        if self._focus and not self._excluded:
            self.text.append(text)


def _page(raw):
    p = Page()
    p.feed(raw.decode("utf-8", "replace"))
    return p


def _ids(text):
    return sorted(set(x.upper() for x in CVE.findall(text)))  # page-wide candidates are not impact assertions


def _safe_candidates(entries, source, count):
    unique, seen = [], set()
    for item in entries:
        url, identity = item.get("url"), item.get("id")
        if not isinstance(url, str) or not isinstance(identity, str):
            continue
        if not _host_allowed(url, source["allowed_hosts"]):
            raise ValueError("Publisher index contains URL outside official allowlist")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,159}", identity):
            raise ValueError("Bad publisher advisory ID")
        if identity not in seen:
            unique.append(item)
            seen.add(identity)
        if len(unique) >= count:
            break
    if not unique:
        raise ValueError("No valid official advisory candidates")
    return unique


def discover(source, getter, max_items):
    sid = source["source_id"]
    url = source["discovery_url"]
    raw = getter.get(url)
    entries = []
    if sid == "fortinet-psirt":
        from .advisory_feeds import parse_feed
        rows = parse_feed(raw, source_id="fortinet-psirt", vendor="Fortinet",
                          allowed_hosts=source["allowed_hosts"])
        for item in rows:
            match = re.search(r"/psirt/(FG-IR-[A-Za-z0-9-]+)$", urlsplit(item["link"]).path)
            if match:
                entries.append({"id": match.group(1), "url": item["link"], "title": item["title"]})
    elif sid == "paloalto-advisories":
        data = _json(raw)
        rows = data if isinstance(data, list) else data.get("data", data.get("advisories", []))
        if not isinstance(rows, list):
            raise ValueError("Palo Alto listing is not an array")
        for row in rows:
            ident = row.get("ID") if isinstance(row, dict) else None
            if ident and re.fullmatch(r"(CVE-\d{4}-\d{4,}|PAN-SA-\d{4}-\d+)", ident):
                entries.append({"id": ident, "url": "https://security.paloaltonetworks.com/json/"+ident,
                                "title": row.get("title") or ident})
    elif sid == "siemens-csaf":
        data = _json(raw)
        feed = data.get("feed") if isinstance(data, dict) else None
        for row in feed.get("entry", []) if isinstance(feed, dict) else []:
            if not isinstance(row, dict):
                continue
            ident = row.get("id")
            for link in row.get("link", []):
                if isinstance(link, dict) and link.get("rel") == "self":
                    entries.append({"id": ident, "url": link.get("href"), "title": ident})
                    break
    elif sid == "redhat-csaf":
        rows = csv.reader(StringIO(raw.decode("utf-8-sig", "replace")))
        for row in rows:
            if not row or not re.fullmatch(r"\d{4}/rhsa-\d{4}_\d+\.json", row[0]):
                continue
            file_id = row[0].rsplit("/", 1)[-1].removesuffix(".json")
            entries.append({"id": file_id, "url": "https://security.access.redhat.com/data/csaf/v2/advisories/"+row[0],
                            "title": file_id})
            if len(entries) >= max_items:
                break
    elif sid == "ubuntu-security-api":
        data = _json(raw)
        rows = data.get("notices", []) if isinstance(data, dict) else []
        for row in rows:
            ident = row.get("id") if isinstance(row, dict) else None
            if isinstance(ident, str) and re.fullmatch(r"USN-\d+-\d+", ident):
                entries.append({"id": ident, "url": "https://ubuntu.com/security/notices/"+ident+".json",
                                "title": row.get("title") or ident})
    elif sid == "gitlab-security-releases":
        root = _xml(raw)
        if root.tag not in (ATOM+"feed", "rss"):
            raise ValueError("Unknown GitLab release feed XML")
        if root.tag == ATOM+"feed":
            for item in root.findall(ATOM+"entry"):
                links = [x.attrib.get("href", "") for x in item.findall(ATOM+"link")
                         if x.attrib.get("rel", "alternate") in ("alternate", "")]
                if links:
                    url = links[0]
                    ident = re.sub(r"[^A-Za-z0-9._-]", "-", urlsplit(url).path.strip("/"))[-150:]
                    entries.append({"id": ident, "url": url, "title": item.findtext(ATOM+"title") or ident})
    elif sid in ("yamaha-network", "atlassian-security"):
        p = _page(raw)
        for title, link in p.links:
            absolute = urljoin(url, link)
            if not _host_allowed(absolute, source["allowed_hosts"]):
                continue
            if sid == "yamaha-network":
                if "脆弱性" not in title or "/CVE-" not in absolute:
                    continue
                match = CVE.search(absolute)
                ident = match.group(0) if match else ""
            else:
                match = CVE.search(title)
                if not match:
                    continue  # Do not use bulletin navigation/body-wide CVE strings.
                ident = match.group(0)
            entries.append({"id": ident, "url": absolute, "title": title})
    elif sid == "microsoft-msrc":
        data = _json(raw)
        rows = data.get("value", []) if isinstance(data, dict) else []
        year_month = re.compile(r"^\d{4}-(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)$")
        # use newest released CVRF document, not a future schedule
        now = datetime.now(timezone.utc).strftime("%Y-%m")
        ms = {"Jan":"01","Feb":"02","Mar":"03","Apr":"04","May":"05","Jun":"06",
              "Jul":"07","Aug":"08","Sep":"09","Oct":"10","Nov":"11","Dec":"12"}
        ids = [str(x.get("ID") or x.get("Id") or "") for x in rows if isinstance(x, dict)]
        ids = [x for x in ids if year_month.fullmatch(x) and x[:4]+"-"+ms[x[-3:]] <= now]
        for ident in sorted(ids, key=lambda x:x[:4]+ms[x[-3:]], reverse=True):
            entries.append({"id": ident, "url": "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/"+ident,
                            "title": ident})
    else:
        raise ValueError("Unsupported collector source type")
    return _safe_candidates(entries, source, max_items)


def _csaf_facts(doc, title):
    # Semantic extraction is centralized; legacy callers use this wrapper.
    from .vendor_csaf import normalize_csaf
    return normalize_csaf(doc, title)


def normalize(source, item, raw):
    sid = source["source_id"]
    if sid in ("redhat-csaf","siemens-csaf"):
        return _csaf_facts(_json(raw), item["title"])
    if sid == "paloalto-advisories":
        doc = _json(raw)
        if not isinstance(doc, dict):
            raise ValueError("Malformed Palo Alto detail")
        meta = doc.get("cveMetadata") or {}
        cna = (doc.get("containers") or {}).get("cna") or {}
        ident = meta.get("cveId")
        if ident and ident != item["id"]:
            raise ValueError("CVE identifier does not match publisher index")
        if not cna and not doc.get("title"):
            raise ValueError("Palo Alto detail has no recognized advisory body")
        versions = cna.get("affected", []) if cna else []
        if not isinstance(versions, list) or len(versions)>1000:
            raise ValueError("Invalid affected array")
        descs = cna.get("descriptions", []) if cna else []
        desc = next((x.get("value") for x in descs if isinstance(x,dict) and
                     str(x.get("lang","")).lower().startswith("en")),None)
        return {"title": (desc or doc.get("title") or item["title"])[:500],
                "cve_ids": [ident] if ident else ([] if not CVE.fullmatch(item["id"]) else [item["id"]]),
                "affected":[{"vendor":v.get("vendor"),"product":v.get("product"),
                             "versions_raw":v.get("versions",[]),"status":"unreviewed"}
                            for v in versions if isinstance(v,dict)],
                "evidence_fields":["cveMetadata.cveId" if ident else "advisory.title",
                                   "containers.cna.affected" if cna else "advisory"],
                "extraction_notes":["Affected/version records copied from publisher CNA; no customer matching performed."]}
    if sid == "ubuntu-security-api":
        doc = _json(raw)
        if not isinstance(doc,dict) or doc.get("id")!=item["id"]:
            raise ValueError("Ubuntu USN ID mismatch")
        ids = doc.get("cves_ids",[])
        if not isinstance(ids,list):raise ValueError("Unexpected cves_ids structure")
        cves = sorted(set(x for x in ids if isinstance(x,str) and CVE.fullmatch(x)))
        return {"title":str(doc.get("title") or item["title"])[:500],"cve_ids":cves,
                "affected":[],"releases_unreviewed":list((doc.get("release_packages") or {}).keys())
                if isinstance(doc.get("release_packages"),dict) else [],
                "instructions_present":bool(doc.get("instructions")),
                "evidence_fields":["id","cves_ids","release_packages","instructions"],
                "extraction_notes":["Exact fixed package versions not yet interpreted."]}
    if sid == "microsoft-msrc":
        doc = _xml(raw)
        cves=[]
        for el in doc.iter():
            if el.tag.rsplit("}",1)[-1] == "CVE" and el.text and CVE.fullmatch(el.text.strip()):
                cves.append(el.text.strip())
        cves = sorted(set(cves))
        if not cves:raise ValueError("MSRC CVRF has no CVE identifiers")
        if len(cves)>8000:raise ValueError("Unexpected CVE count")
        return {"title":"MSRC monthly CVRF "+item["id"],"cve_ids":cves,"affected":[],
                "evidence_fields":["vuln:Vulnerability/vuln:CVE","prod:ProductTree","cvrf:DocumentTracking"],
                "extraction_notes":["CVE-to-product mapping deferred; no impact determination."]}
    page = _page(raw)
    fulltext=" ".join(page.text)
    if len(fulltext)<200:
        raise ValueError("Official detail has no usable text")
    if sid == "fortinet-psirt":
        affected=[]
        for row in page.rows:
            if len(row)<3:continue
            solution=row[2]
            if "Upgrade to" in solution or "Migrate to" in solution or row[1]=="Not affected":
                affected.append({"product_release":row[0],"affected_versions_raw":row[1],
                                 "remediation_raw":solution,
                                 "status":"not_affected" if row[1]=="Not affected" else "unreviewed"})
        if not affected:
            raise ValueError("Fortinet impact/remediation table not extracted")
        return {"title":item["title"][:500],"cve_ids":_ids(fulltext),
                "affected":affected,"evidence_fields":["psirt HTML visible title","psirt HTML impact table rows"],
                "extraction_notes":["Version/status strings unreviewed; exploit label presence is NOT proof of exploitation."]}
    if sid in ("gitlab-security-releases","yamaha-network","atlassian-security"):
        # HTML pages can include unrelated CVE references in global navigation.
        # Only CVEs appearing in publisher-supplied feed title/individual URL
        # can be asserted. The page-wide CVEs remain separate candidates.
        scoped = _ids(item["title"]+" "+urlsplit(item["url"]).path)
        article = ArticleText()
        article.feed(raw.decode("utf-8", "replace"))
        inside = _ids(" ".join(article.text))
        return {"title":item["title"][:500],"cve_ids":scoped,"affected":[],
                "unreviewed_article_cve_candidates":inside[:150],
                "unreviewed_page_cve_candidates":_ids(fulltext)[:150],
                "evidence_fields":["publisher listing title","official detail URL",
                                   "main/article HTML text CVE candidates UNVERIFIED",
                                   "page-wide CVE candidates UNVERIFIED"],
                "extraction_notes":["Article-body CVE candidates remain UNLINKED until source-text audit.",
                                    "No affected version assertion; page navigation may contain unrelated CVEs."]}
    raise ValueError("Unsupported normalizer")


def ingest_source(registry, source, db_path: Path, max_items:int, getter=None):
    sid = source["source_id"]
    status = {"source_id":sid,"status":"FAIL","candidates":0,"saved":0,"replay_unchanged":0,
              "baseline":0,"updates":0,"source_only_changes":0,"extraction_revisions":0,
              "errors":[],"details":[]}
    if source.get("verification_status")!="read_parse_verified":
        status["errors"].append("Not verified; blocked by registry")
        return status
    get = getter or OfficialFetch(source)
    try:
        candidates=discover(source,get,max_items)
        status["candidates"]=len(candidates)
    except Exception as exc:
        status["errors"].append("discovery: "+type(exc).__name__+": "+str(exc)[:200])
        return status
    with closing(connect(db_path)) as db:
        # On later runs re-check one older tracked advisory as well as current
        # front-of-feed candidates. Do not equate rolling-feed disappearance
        # with withdrawal. The historical URL is a verified official host.
        existing = db.execute("""SELECT advisory_id,source_url FROM vendor_documents
                                 WHERE source_id=? ORDER BY last_observed_utc ASC,
                                 advisory_id ASC LIMIT 3""", (sid,)).fetchall()
        selected_ids = {x["id"] for x in candidates}
        for row in existing:
            if row["advisory_id"] in selected_ids:
                continue
            if not _host_allowed(row["source_url"],source["allowed_hosts"]):
                raise ValueError("Previously tracked source URL outside official allowlist")
            previous = db.execute("""SELECT facts_json FROM vendor_document_versions
                                      WHERE source_id=? AND advisory_id=?
                                      ORDER BY version DESC LIMIT 1""",
                                  (sid,row["advisory_id"])).fetchone()
            preserved_title = (json.loads(previous["facts_json"]).get("title")
                               if previous else row["advisory_id"])
            candidates.append({"id":row["advisory_id"],"url":row["source_url"],
                               "title":preserved_title or row["advisory_id"]})
            break
        status["candidates"] = len(candidates)
        for item in candidates:
            try:
                size = MAX_DOCUMENT if sid == "microsoft-msrc" else MAX_FEED
                raw = get.get(item["url"],size)
                facts = normalize(source,item,raw)
                # Metadata about interpretation, not a vendor-published claim.
                # The ledger will classify schema upgrades as extraction_revised.
                facts["_extractor_revision"] = "vendor_semantics_20261010_v2"
                quality = inspect_facts(facts,sid)
                key = hashlib.sha256(raw).hexdigest()
                stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
                args = dict(registry=registry,source_id=sid,advisory_id=item["id"],
                            source_url=item["url"],source_sha256=key,facts=facts,
                            observed_utc=stamp)
                first=observe(db,**args)
                second=observe(db,**args)
                if second["event"]!="unchanged":
                    raise ValueError("Idempotent replay check failed")
                status["saved"]+=1
                status["replay_unchanged"]+=1
                if first["event"]=="baseline":status["baseline"]+=1
                if first["event"]=="facts_updated":status["updates"]+=1
                if first["event"]=="source_changed_only":status["source_only_changes"]+=1
                if first["event"]=="extraction_revised":status["extraction_revisions"]+=1
                status["details"].append({"id":item["id"],"source_url":item["url"],
                    "first_event":first["event"],"source_sha256":key,
                    "provisional_cve_count":len(facts["cve_ids"]),
                    "affected_rows_unreviewed":len(facts["affected"]),
                    "extraction_review":"parsed_unreviewed",
                    "remediation_claims_unreviewed":len(facts.get("remediations_unreviewed",[])),
                    "product_status_claims_unreviewed":len(facts.get("product_status_claims_unreviewed",[])),
                    "unresolved_product_ids":len(facts.get("unresolved_product_ids",[])),
                    "field_quality":quality})
            except Exception as exc:
                status["errors"].append(item["id"]+": "+type(exc).__name__+": "+str(exc)[:190])
    status["status"]="PASS" if status["saved"]==status["candidates"] else "PARTIAL" if status["saved"] else "FAIL"
    status["quality_summary"]=summarize_source_quality(status["details"])
    return status


def run(*,registry:dict,db_path:Path,source_ids:list[str],max_items:int):
    if not 1 <= max_items <= 3:raise ValueError("Limit is 1-3 per source")
    sources = {x["source_id"]: x for x in registry["sources"]}
    if not source_ids or len(source_ids)!=len(set(source_ids)):
        raise ValueError("Duplicate/empty source selection")
    if any(x not in sources or x not in SUPPORTED for x in source_ids):
        raise ValueError("Unknown/unsupported source")
    results=[ingest_source(registry,sources[sid],db_path,max_items) for sid in source_ids]
    with closing(connect(db_path)) as db:
        counts={"advisories":db.execute("SELECT COUNT(*) FROM vendor_documents").fetchone()[0],
                "versions":db.execute("SELECT COUNT(*) FROM vendor_document_versions").fetchone()[0],
                "events":db.execute("SELECT COUNT(*) FROM vendor_document_events").fetchone()[0],
                "integrity":db.execute("PRAGMA quick_check").fetchone()[0]}
    return {"mode":"ONE_SHOT_OFFICIAL_UNREVIEWED_PILOT",
        "persistence":"local SQLite only; Actions artifact expires after 7 days",
        "production_polling":False,"source_results":results,"db_counts":counts,
        "sources_pass":sum(x["status"]=="PASS" for x in results),
        "sources_partial":sum(x["status"]=="PARTIAL" for x in results),
        "sources_failed":sum(x["status"]=="FAIL" for x in results),
        "caution":"Read/parse success does not certify completeness, affected versions, exploitation, rights or customer coverage."}


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--registry",type=Path,default=Path("config/vendor_source_registry.json"))
    p.add_argument("--db",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True)
    p.add_argument("--sources",default="fortinet-psirt,paloalto-advisories,siemens-csaf,redhat-csaf,ubuntu-security-api,gitlab-security-releases,yamaha-network,atlassian-security,microsoft-msrc")
    p.add_argument("--max-items",type=int,default=1)
    args=p.parse_args()
    registry=load_registry(args.registry)
    result=run(registry=registry,db_path=args.db,source_ids=args.sources.split(","),
               max_items=args.max_items)
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(result,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    print(json.dumps(result,ensure_ascii=False,indent=2))
    if (result["db_counts"]["integrity"]!="ok" or result["sources_failed"] or
            result["sources_partial"] or result["sources_pass"]!=len(result["source_results"])):
        raise SystemExit("Incomplete vendor pilot: refusing to promote partial state as successful")


if __name__=="__main__":
    main()
