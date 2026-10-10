"""Read-only Fortinet PSIRT live collection feasibility probe.

Never writes production state, never contacts customer systems, and never treats
RSS summaries as authoritative impact/patch evidence.
"""
import argparse
import hashlib
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import sys
import tempfile
from urllib.parse import urlparse
from urllib.request import Request, urlopen
import xml.etree.ElementTree as ET

FEEDS = (
    "https://filestore.fortinet.com/fortiguard/rss/ir.xml",
    "https://www.fortiguard.com/rss/ir.xml",
    "https://fortiguard.fortinet.com/rss/ir.xml",
)
MAX_BYTES = 5 * 1024 * 1024
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)


def official(url):
    p = urlparse(url)
    host = (p.hostname or "").lower()
    return p.scheme == "https" and not p.username and not p.password and (
        host == "fortinet.com" or host.endswith(".fortinet.com") or
        host == "fortiguard.com" or host.endswith(".fortiguard.com")
    )


def get(url):
    if not official(url):
        raise ValueError("Refusing nonofficial URL: " + url[:160])
    req = Request(url, headers={
        "User-Agent": "PROJECT-ECLIPSE-Fortinet-PSIRT-ReadOnly-Probe/1.0",
        "Accept": "application/rss+xml,application/atom+xml,application/xml,text/xml,text/html,*/*",
    })
    with urlopen(req, timeout=25) as response:
        final = response.url
        if not official(final):
            raise ValueError("Redirected to nonofficial host: " + final)
        raw = response.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ValueError("Exceeds max size 5 MiB")
        return raw, final, response.headers.get("Content-Type", "")


def rss_rows(raw):
    if b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
        raise ValueError("Unsafe XML")
    root = ET.fromstring(raw)
    result = []
    if root.tag == "rss":
        for i in root.findall("./channel/item"):
            result.append({
                "title": (i.findtext("title") or "").strip(),
                "url": (i.findtext("link") or "").strip(),
                "date": (i.findtext("pubDate") or "").strip(),
                "summary": (i.findtext("description") or "").strip(),
            })
    elif root.tag == "{http://www.w3.org/2005/Atom}feed":
        n = "{http://www.w3.org/2005/Atom}"
        for i in root.findall(n + "entry"):
            links = [x.attrib.get("href", "") for x in i.findall(n + "link")
                     if x.attrib.get("rel", "alternate") in ("alternate", "")]
            result.append({
                "title": (i.findtext(n + "title") or "").strip(),
                "url": links[0] if links else "",
                "date": (i.findtext(n + "updated") or "").strip(),
                "summary": (i.findtext(n + "summary") or "").strip(),
            })
    else:
        raise ValueError("Unexpected RSS/Atom root " + str(root.tag))
    if not result:
        raise ValueError("No advisory items")
    return result


class Tables(HTMLParser):
    def __init__(self):
        super().__init__()
        self.rows = []
        self.in_row = False
        self.depth = 0
        self.row = []
        self.cell = None
        self.text = []

    def handle_starttag(self, tag, attrs):
        if tag == "tr":
            self.in_row = True
            self.row = []
        if self.in_row and tag in ("td", "th"):
            self.cell = []

    def handle_data(self, data):
        self.text.append(data)
        if self.cell is not None:
            self.cell.append(data)

    def handle_endtag(self, tag):
        if tag in ("td", "th") and self.cell is not None:
            self.row.append(re.sub(r"\s+", " ", " ".join(self.cell)).strip())
            self.cell = None
        if tag == "tr" and self.in_row:
            if self.row:
                self.rows.append(self.row)
            self.in_row = False


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    result = {
        "scope": "one-shot-public-official-Fortinet-PSIRT-ONLY",
        "read_only": True,
        "feed_attempts": [],
        "rss": None,
        "existing_eclipse_adapter": None,
        "details": [],
        "verdict": "FAIL",
        "limitations": [
            "One-time fetch is not proof of future continuous reliability.",
            "RSS summary alone cannot confirm complete affected versions or patches.",
            "Manufacturer publication time and our observation time differ.",
            "Not a commercial reuse/license approval.",
        ],
    }
    try:
        feed_raw = None
        for source in FEEDS:
            try:
                raw, final, ct = get(source)
                rows = rss_rows(raw)
                feed_raw = raw
                result["feed_attempts"].append({
                    "url": source, "status": "PASS", "final_url": final,
                    "content_type": ct, "bytes": len(raw)
                })
                result["rss"] = {
                    "source": final, "sha256": hashlib.sha256(raw).hexdigest(),
                    "item_count": len(rows),
                    "official_link_count": sum(official(r["url"]) for r in rows),
                    "items_with_cve": sum(bool(CVE_RE.search(r["title"] + " " + r["summary"])) for r in rows),
                    "sample": [{"title": r["title"][:150], "url": r["url"], "date": r["date"]} for r in rows[:6]],
                }
                break
            except Exception as e:
                result["feed_attempts"].append({
                    "url": source, "status": "FAIL", "error": type(e).__name__ + ": " + str(e)[:280]
                })
        if feed_raw is not None:
            try:
                sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
                from eclipse_l0.advisory_feeds import observe_advisories
                with tempfile.TemporaryDirectory() as temp:
                    root = Path(temp)
                    (root / "feed.xml").write_bytes(feed_raw)
                    hosts = sorted({urlparse(x["url"]).hostname for x in rows if official(x["url"])})
                    a = observe_advisories(root / "feed.xml", root / "state", root / "first.json",
                                           source_id="fortinet-live-probe", vendor="Fortinet", allowed_hosts=hosts)
                    b = observe_advisories(root / "feed.xml", root / "state", root / "second.json",
                                           source_id="fortinet-live-probe", vendor="Fortinet", allowed_hosts=hosts)
                    result["existing_eclipse_adapter"] = {
                        "status": "PASS" if a["baseline"] and not b["baseline"] and b["event_count"] == 0 else "FAIL",
                        "first_baseline": a["baseline"], "replayed_event_count": b["event_count"]
                    }
            except Exception as e:
                result["existing_eclipse_adapter"] = {
                    "status": "FAIL", "error": type(e).__name__ + ": " + str(e)[:350]
                }

            chosen = [r["url"] for r in rows if official(r["url"]) and "/psirt/" in urlparse(r["url"]).path]
            chosen = chosen[:3]
            chosen.append("https://fortiguard.fortinet.com/psirt/FG-IR-26-124")
            for detail_url in list(dict.fromkeys(chosen))[:4]:
                try:
                    raw, final, ct = get(detail_url)
                    parsed = Tables()
                    parsed.feed(raw.decode("utf-8", errors="replace"))
                    text = re.sub(r"\s+", " ", " ".join(parsed.text))
                    affected_rows = [r for r in parsed.rows if len(r) >= 3 and (
                        "Upgrade to" in " ".join(r) or "Migrate to" in " ".join(r) or
                        "Not affected" in " ".join(r))]
                    result["details"].append({
                        "url": final, "status": "PASS", "content_type": ct,
                        "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw),
                        "has_cve_text": bool(CVE_RE.search(text)),
                        "has_affected": "Affected" in text,
                        "has_solution": "Solution" in text,
                        "has_severity": "Severity" in text,
                        "has_known_exploited": "Known Exploited" in text,
                        "impact_rows_count": len(affected_rows),
                        "impact_rows_sample": affected_rows[:6],
                    })
                except Exception as e:
                    result["details"].append({
                        "url": detail_url, "status": "FAIL",
                        "error": type(e).__name__ + ": " + str(e)[:300]
                    })
            if result["rss"]["item_count"] > 0:
                result["verdict"] = "PARTIAL"
            if result["existing_eclipse_adapter"] and result["existing_eclipse_adapter"]["status"] == "PASS" and any(
                x["status"] == "PASS" and x["has_affected"] and x["has_solution"] and x["impact_rows_count"] > 0
                for x in result["details"]
            ):
                result["verdict"] = "PASS_READ_AND_PARSE_ONLY"
        args.out.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(result, ensure_ascii=False, indent=2))
        if result["verdict"] == "FAIL":
            return 1
        return 0
    except Exception as e:
        result["fatal"] = type(e).__name__ + ": " + str(e)[:400]
        args.out.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
