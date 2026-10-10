"""Official security RSS publication sources for Juniper Mist and Ivanti.

These are distinct *narrow* scopes and must never be reported as all Juniper
JSA or all Ivanti support advisories. No raw article or customer information.
"""
from __future__ import annotations
import re
from urllib.parse import urlsplit
from .vendor_pilot import _xml,_host_allowed
from .vendor_wave3_sources import _strict_html
CVE=re.compile(r"\bCVE-\d{4}-\d{4,}\b",re.I)
MIST=re.compile(r"^/documentation/([a-z0-9-]{4,140})/?$",re.I)
IVANTI=re.compile(r"^/blog/([a-z0-9-]{4,140})/?$",re.I)
IDS={"juniper-mist-security-rss","ivanti-security-advisory-rss"}
def _identity(sid,url):
    path=urlsplit(url).path
    if sid=="juniper-mist-security-rss":
        match=MIST.fullmatch(path)
        if match and match.group(1)!="category":
            return "MIST-ARTICLE-"+match.group(1).lower()
    if sid=="ivanti-security-advisory-rss":
        match=IVANTI.fullmatch(path)
        if match:return "IVANTI-BLOG-"+match.group(1).lower()
    return None
def discover_security_rss(source,raw):
    sid=source["source_id"]
    if sid not in IDS:raise ValueError("Unknown official RSS source")
    root=_xml(raw)
    if root.tag.rsplit("}",1)[-1].lower()!="rss":
        raise ValueError("Not a standard official RSS root")
    channel=root.find("./channel")
    if channel is None:raise ValueError("No official RSS channel")
    entries=[]
    for entry in channel.findall("item")[:200]:
        url=(entry.findtext("link") or "").strip()
        title=(entry.findtext("title") or "").strip()[:220]
        if not title or not _host_allowed(url,source["allowed_hosts"]):continue
        ident=_identity(sid,url)
        if not ident:continue
        entries.append({"id":ident,"url":url,"title":title})
        if len(entries)>=150:break
    if not entries:raise ValueError("RSS has no valid security advisory article links")
    return entries
def normalize_security_rss(source,item,raw):
    sid=source["source_id"]
    if sid not in IDS:raise ValueError("Unknown security RSS type")
    if not _host_allowed(item["url"],source["allowed_hosts"]) or _identity(sid,item["url"])!=item["id"]:
        raise ValueError("Publisher RSS advisory identity mismatch")
    main=" ".join(_strict_html(raw).text)
    title=" ".join(item.get("title","").split())
    if len(main)<120:raise ValueError("Publisher article has no bounded body")
    # Visible publisher heading may differ in punctuation, require at least
    # nontrivial text overlap; mere index URL alone is not detail evidence.
    words=[w.lower() for w in re.findall(r"[A-Za-z0-9]{5,}",title)[:8]]
    if not words or sum(w in main.lower() for w in words)<min(2,len(words)):
        raise ValueError("RSS article title not recognizable in publisher detail")
    ids=sorted({v.upper() for v in CVE.findall(main)})
    if len(ids)>300:raise ValueError("Excessive advisory body CVE references")
    return {"title":title,"cve_ids":ids,"affected":[],
            "evidence_fields":["official publisher RSS item: title and HTTPS URL",
                               "source-host verified bounded article body",
                               "unreviewed advisory-level CVE references only"],
            "publisher_date_review_state":"RSS publish time not yet cross-validated",
            "fix_version_review_state":"NOT_EXTRACTED",
            "extraction_notes":["Category RSS scope limited to Mist or Ivanti blog.",
                "No confirmation of affected software or exploit activity.",
                "No auto attribution of a source update as a newly disclosed CVE."]}
