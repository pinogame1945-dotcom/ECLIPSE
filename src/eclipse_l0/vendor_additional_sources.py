"""Additional official publisher HTML endpoints, bounded and evidence-conservative.

Mozilla MFSA and Debian DSA are separate from the original nine vendor sources.
Discovery uses only the publisher's official index and exact advisory identifiers.
No uncertain page-wide navigation CVEs or unreviewed fixes become exposure claims.
"""
from __future__ import annotations

import re
from urllib.parse import urljoin, urlsplit

MFSA = re.compile(r"MFSA\s*(20\d{2})-(\d{1,4})\b", re.I)
MFSA_URL = re.compile(r"/security/advisories/mfsa(20\d{2})-(\d{1,4})/?$", re.I)
DSA = re.compile(r"\bDSA-(\d{3,5})-(\d{1,2})\b", re.I)
CVE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)
MAX_EXTRACTED = 200


def discover_html(source:dict, raw:bytes) -> list[dict]:
    from .vendor_pilot import _page, _host_allowed
    parsed=_page(raw)
    results=[]
    for title,link in parsed.links:
        url=urljoin(source["discovery_url"],link)
        if not _host_allowed(url,source["allowed_hosts"]):
            continue
        sid=source["source_id"]
        if sid=="mozilla-mfsa":
            match=MFSA_URL.search(urlsplit(url).path)
            title_id=MFSA.search(title)
            if not match or not title_id:
                continue
            if (match.group(1),int(match.group(2)))!=(title_id.group(1),int(title_id.group(2))):
                raise ValueError("Mozilla index title/URL MFSA identity mismatch")
            ident=f"MFSA-{match.group(1)}-{int(match.group(2))}"
        elif sid=="debian-dsa":
            title_id=DSA.search(title)
            if not title_id:
                continue
            # Debian index gives the exact official announcement mail URL,
            # not the neighboring security-tracker package link ("T").
            if not (urlsplit(url).hostname=="lists.debian.org" and
                    "/debian-security-announce/" in urlsplit(url).path and
                    urlsplit(url).path.endswith(".html")):
                continue
            ident=f"DSA-{int(title_id.group(1))}-{int(title_id.group(2))}"
        else:
            raise ValueError("Unsupported additional vendor endpoint")
        results.append({"id":ident,"url":url,"title":title[:220]})
        if len(results)>=800:
            break
    if not results:
        raise ValueError("No official publisher advisory identities in HTML listing")
    return results


def _safe_html_text(raw:bytes):
    from .vendor_pilot import _page, ArticleText
    page=_page(raw)
    article=ArticleText()
    article.feed(raw.decode("utf-8","replace"))
    page_text=" ".join(page.text)
    article_text=" ".join(article.text)
    if len(page_text)<120:
        raise ValueError("Detail HTML lacks publisher-readable content")
    return page_text,article_text


def normalize_html(source:dict,item:dict,raw:bytes) -> dict:
    page_text,article_text=_safe_html_text(raw)
    sid=source["source_id"]
    ident=item["id"]
    if sid=="mozilla-mfsa":
        check=re.fullmatch(r"MFSA-(20\d{2})-(\d{1,4})",ident)
        if not check:
            raise ValueError("Malformed Mozilla advisory ID")
        # Must match the advisory heading in the publisher's own detail.
        heading=re.search(
            r"Mozilla Foundation Security Advisory\s+(20\d{2})-(\d{1,4})\b",
            page_text,re.I)
        if not heading or (heading.group(1),int(heading.group(2)))!=(
                check.group(1),int(check.group(2))):
            raise ValueError("Mozilla advisory heading does not match official listing")
        if not article_text or len(article_text)<70:
            raise ValueError("Mozilla main/article HTML content not isolated")
        # Every CVE has its own heading on a publisher's MFSA page. Do not
        # elevate CVEs seen only in global header/footer/sidebar.
        ids=sorted({x.upper() for x in CVE.findall(article_text)})
        if len(ids)>MAX_EXTRACTED:
            raise ValueError("Unbounded MFSA CVE references")
        return {
            "title":item["title"][:500],
            "cve_ids":ids,
            "affected":[],
            "publisher_release_title_unreviewed":item["title"][:220],
            "evidence_fields":["official MFSA listing title and detail URL",
                               "detail publisher advisory heading",
                               "main/article advisory CVE references"],
            "extraction_notes":[
                "Scoped CVE references from a single official MFSA; individual product/version applicability not established.",
                "A title saying 'fixed in' is NOT a parsed per-CVE fixed-version range.",
                "Vendor page content and licensing are unreviewed."]}
    if sid=="debian-dsa":
        if not DSA.fullmatch(ident):
            raise ValueError("Malformed Debian advisory ID")
        # Official announcement mail is a whole message page and can have
        # unrelated links in the mailing-list sidebar.
        if not DSA.search(page_text) or not any(
                "DSA-"+m.group(1)+"-"+m.group(2)==ident
                for m in DSA.finditer(page_text)):
            raise ValueError("Debian announcement did not contain its DSA ID")
        match=re.search(
            r"\bCVE\s+ID\s*:\s*((?:CVE-\d{4}-\d{4,}(?:[\s,;]+|$)){1,200})",
            page_text,re.I)
        # DSA mail usually prints CVE ID on a line and may wrap. Candidate
        # IDs within this scoped section are trustworthy; otherwise hold them
        # for human review rather than attach arbitrary page links.
        ids=sorted({v.upper() for v in CVE.findall(match.group(1))}) if match else []
        if len(ids)>MAX_EXTRACTED:
            raise ValueError("Too many DSA CVE references in scoped mail header")
        return {
            "title":item["title"][:500],
            "cve_ids":ids,
            "affected":[],
            "unreviewed_page_cve_candidates":sorted({x.upper() for x in CVE.findall(page_text)})[:MAX_EXTRACTED],
            "package_release_fixes_review_state":"not_extracted",
            "evidence_fields":["Debian DSA number in official listing",
                               "Debian security-announce original DSA mail",
                               "CVE ID mail header (if parsed)"],
            "extraction_notes":[
                "Potential CVE IDs from mail header only, never from unscoped navigation.",
                "Fixed Debian release/package versions are NOT computed or asserted.",
                "Debian stable/testing/oldstable cannot be conflated."]}
    raise ValueError("Unsupported new vendor detail parser")
