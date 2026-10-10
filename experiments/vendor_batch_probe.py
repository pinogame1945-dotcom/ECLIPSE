"""Bounded read-only live verification of five official vendor advisory sources.

A one-shot connectivity/field extraction probe, not a monitoring service.
No customer data, no credentials, no storage other than a 7-day Actions artifact.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import hashlib
from html.parser import HTMLParser
import json
from pathlib import Path
import re
from urllib.parse import urljoin, urlsplit
from urllib.request import Request, build_opener, HTTPRedirectHandler

MAX_BYTES = 16 * 1024 * 1024
CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)


class StrictRedirect(HTTPRedirectHandler):
    def __init__(self, allowed_hosts):
        self.allowed_hosts = allowed_hosts
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not is_allowed(newurl, self.allowed_hosts):
            raise ValueError("Redirect outside verified vendor hostnames")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def is_allowed(url, allowed_hosts):
    p = urlsplit(url)
    return (p.scheme == "https" and not p.username and not p.password
            and p.port in (None, 443) and (p.hostname or "").lower() in allowed_hosts)


def fetch(url, hosts, max_bytes=MAX_BYTES):
    if not is_allowed(url, hosts):
        raise ValueError("Nonofficial host or URL")
    request = Request(url, headers={
        "User-Agent": "ECLIPSE-public-vendor-readonly-validation/1.0",
        "Accept": "application/json, text/html, application/xml;q=0.9, */*;q=0.7",
    })
    opener = build_opener(StrictRedirect(hosts))
    with opener.open(request, timeout=22) as response:
        raw = response.read(max_bytes + 1)
        final = response.geturl()
        if len(raw) > max_bytes:
            raise ValueError("Response larger than safety cap")
        if not is_allowed(final, hosts):
            raise ValueError("Final URL outside official domain")
        return raw, {
            "url": final,
            "bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "content_type": response.headers.get("Content-Type", "")[:100],
            "observed_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }


def json_source(url, hosts, max_bytes=MAX_BYTES):
    raw, evidence = fetch(url, hosts, max_bytes=max_bytes)
    obj = json.loads(raw)
    if not isinstance(obj, (dict, list)):
        raise ValueError("Unexpected nonobject JSON")
    return obj, evidence


class TextLinks(HTMLParser):
    def __init__(self):
        super().__init__()
        self.text = []
        self.links = []
        self.anchor_href = None
        self.anchor_text = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self.anchor_href = dict(attrs).get("href")
            self.anchor_text = []

    def handle_data(self, data):
        self.text.append(data)
        if self.anchor_href is not None:
            self.anchor_text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self.anchor_href is not None:
            self.links.append((" ".join(self.anchor_text).strip(), self.anchor_href))
            self.anchor_href = None
            self.anchor_text = []


def html_source(url, hosts):
    raw, evidence = fetch(url, hosts, max_bytes=5 * 1024 * 1024)
    parser = TextLinks()
    parser.feed(raw.decode("utf-8", "replace"))
    return parser, evidence


def call(result, label, fn):
    try:
        result["tests"][label] = {"status": "PASS", **fn()}
        return result["tests"][label]
    except Exception as exc:
        result["tests"][label] = {
            "status": "FAIL", "error": f"{type(exc).__name__}: {str(exc)[:250]}"}
        return None


def result_for(vendor, kind):
    return {"vendor": vendor, "source_type": kind, "tests": {}, "verdict": "FAIL",
            "limitations": ["One-time read-only test; no ongoing coverage or update-diff guarantee.",
                            "This does not establish commercial redistribution permission."]}


def probe_microsoft():
    hosts = {"api.msrc.microsoft.com"}
    r = result_for("Microsoft", "MSRC public CVRF JSON API")
    def listing():
        obj, ev = json_source("https://api.msrc.microsoft.com/cvrf/v3.0/updates", hosts)
        records = obj.get("value", obj) if isinstance(obj, dict) else obj
        if not isinstance(records, list) or not records:
            raise ValueError("Empty/unknown MSRC updates structure")
        return {"evidence": ev, "records_count": len(records),
                "sample": [str(x.get("ID", x.get("Id", x.get("id", ""))))[:80]
                           for x in records[:4] if isinstance(x, dict)]}
    def detail():
        import xml.etree.ElementTree as ET
        raw, ev = fetch("https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Sep",
                        hosts, max_bytes=64 * 1024 * 1024)
        if b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
            raise ValueError("Refusing unsafe XML")
        # Official CVRF endpoints may return application/xml regardless of Accept.
        if raw.lstrip().startswith(b"<"):
            root = ET.fromstring(raw)
            tags = [node.tag.rsplit("}", 1)[-1] for node in root.iter()]
            count = tags.count("Vulnerability")
            if count < 1:
                raise ValueError("XML CVRF has no vulnerability nodes")
            samples = []
            for node in root.iter():
                if node.tag.rsplit("}", 1)[-1] in ("CVE", "CVEID") and node.text:
                    samples.append(node.text.strip())
                    if len(samples) >= 4:
                        break
            return {"evidence": ev, "format": "XML/CVRF", "vulnerability_count": count,
                    "cve_samples": samples, "product_tree": "ProductTree" in tags,
                    "tracking_present": "DocumentTracking" in tags,
                    "root_element": root.tag.rsplit("}", 1)[-1]}
        obj = json.loads(raw)
        if not isinstance(obj, dict):
            raise ValueError("Unknown CVRF structure")
        issues = obj.get("Vulnerability", obj.get("vulnerabilities", []))
        if not isinstance(issues, list) or not issues:
            raise ValueError("JSON CVRF has no vulnerabilities")
        return {"evidence": ev, "format": "JSON/CVRF", "vulnerability_count": len(issues),
                "product_tree": "ProductTree" in obj, "tracking_present": "DocumentTracking" in obj}
    a = call(r, "updates_list", listing)
    b = call(r, "monthly_cvrf_details", detail)
    r["verdict"] = "PASS" if a and b else "PARTIAL" if a or b else "FAIL"
    return r


def probe_redhat():
    hosts = {"access.redhat.com"}
    r = result_for("Red Hat", "Security Data API")
    list_docs = []
    def listing():
        urls = [
            "https://access.redhat.com/hydra/rest/securitydata/cve.json?after=2026-09-20&per_page=5",
            "https://access.redhat.com/labs/securitydataapi/cve.json?per_page=5",
            "https://access.redhat.com/hydra/rest/securitydata/cve.json?per_page=5",
        ]
        errors = []
        for url in urls:
            try:
                obj, ev = json_source(url, hosts)
                if isinstance(obj, list) and obj:
                    break
                errors.append(url + " returned " + type(obj).__name__)
            except Exception as exc:
                errors.append(url + " " + type(exc).__name__ + ": " + str(exc)[:80])
        else:
            raise ValueError("; ".join(errors)[:250])
        for item in obj:
            if isinstance(item, dict) and CVE.fullmatch(str(item.get("CVE", ""))):
                list_docs.append(item["CVE"])
        if not list_docs:
            raise ValueError("Red Hat data missing CVE IDs")
        return {"evidence": ev, "records_count": len(obj), "cve_samples": list_docs[:4]}
    def detail():
        cve = list_docs[0] if list_docs else "CVE-2024-3094"
        obj, ev = json_source(f"https://access.redhat.com/hydra/rest/securitydata/cve/{cve}.json", hosts)
        if not isinstance(obj, dict) or obj.get("name", obj.get("CVE", "")) != cve:
            raise ValueError("Red Hat detail CVE identity mismatch")
        return {"evidence": ev, "cve_id": cve, "fields": list(obj.keys())[:20],
                "has_details": bool(obj.get("details") or obj.get("statement")),
                "has_affected_releases": bool(obj.get("affected_release") or obj.get("package_state")),
                "has_mitigation": bool(obj.get("mitigation"))}
    a = call(r, "cve_list", listing)
    b = call(r, "cve_detail", detail)
    r["verdict"] = "PASS" if a and b else "PARTIAL" if a or b else "FAIL"
    return r


def probe_paloalto():
    hosts = {"security.paloaltonetworks.com"}
    r = result_for("Palo Alto Networks", "official JSON advisories")
    def listing():
        obj, ev = json_source("https://security.paloaltonetworks.com/json?severity=CRITICAL&sort=-updated", hosts)
        records = obj if isinstance(obj, list) else (
            obj.get("advisories", obj.get("data", obj.get("results", obj.get("items", [])))))
        if not isinstance(records, list) or not records:
            raise ValueError(f"Unknown or empty JSON advisory listing; keys={list(obj)[:12] if isinstance(obj, dict) else 'list'}")
        return {"evidence": ev, "records_count": len(records),
                "sample_fields": list(records[0])[:16] if isinstance(records[0], dict) else [],
                "sample_ids": [str(x.get("ID", x.get("id", x.get("cve", x.get("CVE", "")))))[:80]
                               for x in records[:4] if isinstance(x, dict)]}
    def detail():
        obj, ev = json_source("https://security.paloaltonetworks.com/json/CVE-2024-3400", hosts)
        if not isinstance(obj, dict) or len(obj) < 3:
            raise ValueError("Missing JSON advisory object")
        body = json.dumps(obj, ensure_ascii=False)
        if "CVE-2024-3400" not in body:
            raise ValueError("Requested CVE absent in returned advisory")
        return {"evidence": ev, "cve_id": "CVE-2024-3400", "root_fields": list(obj)[:20],
                "contains_affected": "affected" in body.lower(),
                "contains_solution": "solution" in body.lower() or "fixed" in body.lower()}
    a = call(r, "advisory_list", listing)
    b = call(r, "advisory_detail", detail)
    r["verdict"] = "PASS" if a and b else "PARTIAL" if a or b else "FAIL"
    return r


def probe_siemens():
    hosts = {"cert-portal.siemens.com"}
    r = result_for("Siemens", "official CSAF JSON")
    def csaf_detail():
        obj, ev = json_source("https://cert-portal.siemens.com/productcert/csaf/ssa-827383.json", hosts)
        doc = obj.get("document") if isinstance(obj, dict) else None
        vulns = obj.get("vulnerabilities") if isinstance(obj, dict) else None
        if not isinstance(doc, dict) or not isinstance(vulns, list) or not vulns:
            raise ValueError("No CSAF document/vulnerabilities")
        return {"evidence": ev, "csaf_version": doc.get("csaf_version"),
                "title": str(doc.get("title", ""))[:160],
                "vulnerability_count": len(vulns),
                "cve_samples": [v.get("cve") for v in vulns[:6] if isinstance(v, dict)],
                "product_tree": isinstance(obj.get("product_tree"), dict),
                "has_remediations": any(bool(v.get("remediations")) for v in vulns if isinstance(v, dict))}
    def discovery():
        obj, ev = json_source("https://cert-portal.siemens.com/productcert/csaf/ssa-feed-tlp-white.json", hosts)
        feed = obj.get("feed") if isinstance(obj, dict) else None
        entries = feed.get("entry", []) if isinstance(feed, dict) else []
        if not entries or not isinstance(entries, list):
            raise ValueError("No ROLIE CSAF entries in Siemens feed")
        sample = entries[:4]
        return {"evidence": ev, "feed_id": feed.get("id"), "feed_updated": feed.get("updated"),
                "entry_count": len(entries),
                "sample_ids": [x.get("id") for x in sample if isinstance(x, dict)],
                "entry_links": [[v.get("href") for v in x.get("link", []) if v.get("rel") == "self"]
                                for x in sample if isinstance(x, dict)]}
    a = call(r, "csaf_detail", csaf_detail)
    call(r, "csaf_feed_discovery", discovery)
    r["verdict"] = "PASS" if a and r["tests"]["csaf_feed_discovery"]["status"] == "PASS" else "PARTIAL" if a else "FAIL"
    return r


def probe_yamaha():
    hosts = {"network.yamaha.com", "www.rtpro.yamaha.co.jp"}
    r = result_for("Yamaha", "Japanese notice HTML")
    discovered = []
    def listing():
        obj, ev = html_source("https://network.yamaha.com/support/notice", hosts)
        for title, link in obj.links:
            full = urljoin(ev["url"], link)
            if is_allowed(full, hosts) and ("脆弱性" in title or ("RTpro" in title and "セキュリティ" in title)):
                discovered.append((title, full))
        page = " ".join(obj.text)
        if "重要なお知らせ" not in page and "脆弱性" not in page:
            raise ValueError("Yamaha HTML lacked news contents")
        return {"evidence": ev, "vulnerability_links": len(discovered),
                "sample_links": [{"title": t[:160], "url": u} for t, u in discovered[:5]]}
    def detail():
        if not discovered:
            raise ValueError("No security link discovered in listing")
        # Do not confuse a vulnerability disclosure policy with a vulnerability advisory.
        selected = next(((t, u) for t, u in discovered if "VPN" in t or "UTX" in t), discovered[0])
        obj, ev = html_source(selected[1], hosts)
        text = " ".join(obj.text)
        if len(text.strip()) < 150:
            raise ValueError("Detail page missing human-readable text")
        return {"evidence": ev, "headline": selected[0][:150],
                "cve_samples": list(dict.fromkeys(CVE.findall(text)))[:8],
                "mentions_affected_product": any(x in text for x in ("UTX200", "UTX100", "RTX")),
                "contains_remediation_terms": any(x in text for x in ("対策", "更新", "アップデート", "回避"))}
    a = call(r, "notice_listing", listing)
    b = call(r, "vulnerability_notice_detail", detail)
    r["verdict"] = "PASS" if a and b else "PARTIAL" if a or b else "FAIL"
    return r


PROBES = [probe_microsoft, probe_redhat, probe_paloalto, probe_siemens, probe_yamaha]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    results = []
    with ThreadPoolExecutor(max_workers=3) as pool:
        tasks = [pool.submit(fn) for fn in PROBES]
        for future in as_completed(tasks):
            try:
                results.append(future.result())
            except Exception as exc:
                results.append({"vendor": "unhandled-probe-exception", "verdict": "FAIL",
                                "error": f"{type(exc).__name__}: {str(exc)[:300]}"})
    results.sort(key=lambda x: x["vendor"])
    summary = {k: sum(x["verdict"] == k for x in results) for k in ("PASS", "PARTIAL", "FAIL")}
    payload = {
        "purpose": "One-shot official source reachability, schema, detail test",
        "scope": "Read-only external GET; 5 vendors; 3 workers max; no credentials",
        "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "summary": summary,
        "results": results,
        "disclaimer": "A page containing a label such as 'Known Exploited' does not establish its boolean value. Field presence is not a truthful exploit-state claim. This batch does not prove longitudinal monitoring, product coverage, customer exposure, delta detection, licensing, or persistent storage."
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    # Evidence collected even if an upstream vendor fails. Fail only if every vendor fails.
    return 1 if summary["FAIL"] == len(results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
