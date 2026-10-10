"""ECLIPSE weekly *evidence handoff*, never an authored weekly report.

The immutable CVE warehouse and official vendor ledger are read-only. A single
frozen snapshot cannot prove complete weekly monitoring: the output explicitly
labels record publication/update dates vs observations and reports that gap.
No client inventory, LLM prose, inferred patch or attack claims in the ZIP.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from contextlib import closing
from datetime import date, datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import re
import sqlite3
import zipfile

from .vendor_registry import load_registry
from .vendor_replay import inspect_db

SCHEMA_VERSION=1
NAMES=("weekly_index.json","vulnerabilities.jsonl","vendor_advisories.jsonl",
       "weekly_changes.jsonl","evidence.jsonl","quality_report.json")
REQUIRED_META=("source_index_sha256","source_archive_sha256")
HEX=re.compile(r"^[0-9a-f]{64}$")
CVE=re.compile(r"^CVE-\d{4}-\d{4,}$")
MAX_WEEK_CVES=30000
MAX_WEEK_DOCS=2000
MAX_VENDOR_LINKS=100000
MAX_BYTES_PER_MEMBER=150*1024*1024


def canonical(obj):
    return json.dumps(obj,ensure_ascii=False,sort_keys=True,separators=(",",":"))


def sha(raw:bytes)->str:
    return hashlib.sha256(raw).hexdigest()


def _date(value):
    if value is None:return None
    if not isinstance(value,str):raise ValueError("Invalid source date type")
    try:
        return date.fromisoformat(value[:10]) if len(value)>=10 else None
    except ValueError:
        return None


def _open_ro(path):
    p=Path(path)
    if not p.is_file() or p.is_symlink():raise ValueError("Missing or symlinked evidence SQLite")
    db=sqlite3.connect(p.resolve().as_uri()+"?mode=ro",uri=True)
    db.row_factory=sqlite3.Row
    db.execute("PRAGMA query_only=ON")
    return db


def _jsonlines(rows):
    return "".join(canonical(row)+"\n" for row in rows).encode("utf-8")


def _meta(db):
    existing={r["key"]:json.loads(r["value"])
              for r in db.execute("SELECT key,value FROM warehouse_metadata")}
    if any(not isinstance(existing.get(k),str) or not HEX.fullmatch(existing[k])
           for k in REQUIRED_META):
        raise ValueError("Missing original CVE archive/source index SHA-256")
    return existing


def _weekly_source_events(cve,start,end):
    """CVE-publisher metadata dates, NOT verified time of first observation."""
    conditions="""(substr(date_published,1,10) BETWEEN ? AND ?
                  OR substr(date_updated,1,10) BETWEEN ? AND ?)"""
    selected={}
    for row in cve.execute("""SELECT cve_id,date_published,date_updated,record_state,hash
                              FROM cve_current WHERE """+conditions+" ORDER BY cve_id",
                           (start.isoformat(),end.isoformat(),start.isoformat(),end.isoformat())):
        pub=_date(row["date_published"]); upd=_date(row["date_updated"])
        reasons=[]
        if pub and start<=pub<=end:reasons.append("CVE_SOURCE_DATE_PUBLISHED_IN_WINDOW")
        if upd and start<=upd<=end and (not pub or not start<=pub<=end):
            reasons.append("CVE_SOURCE_DATE_UPDATED_IN_WINDOW")
        if reasons:
            selected[row["cve_id"]]={"record":row,"reasons":reasons}
    for row in cve.execute("""SELECT c.cve_id,c.date_published,c.date_updated,c.record_state,c.hash,
                                    k.date_added
                             FROM kev_current k JOIN cve_current c ON c.cve_id=k.cve_id
                             WHERE k.present=1 AND substr(k.date_added,1,10) BETWEEN ? AND ?
                             ORDER BY c.cve_id""",(start.isoformat(),end.isoformat())):
        if row["cve_id"] not in selected:
            selected[row["cve_id"]]={"record":row,"reasons":[]}
        selected[row["cve_id"]]["reasons"].append("CISA_KEV_DATE_ADDED_IN_WINDOW")
    if len(selected)>MAX_WEEK_CVES:
        raise ValueError("Week candidates exceed safety cap; no silent truncation")
    return selected


def _vendor_records(vendor,registry,start,end,selected):
    """"Baseline" never equals newly published; only observed revisions count."""
    known={x["source_id"]:x for x in registry["sources"]}
    docs=[]; links=defaultdict(list); changes=[]; candidates=Counter()
    source_docs=Counter()
    for d in vendor.execute("""SELECT d.source_id,d.advisory_id,d.source_url,
                    d.current_facts_sha,d.current_source_sha,d.first_observed_utc,
                    d.last_observed_utc,v.extract_status,v.facts_json
                FROM vendor_documents d JOIN vendor_document_versions v
                 ON v.source_id=d.source_id AND v.advisory_id=d.advisory_id
                 AND v.version=(SELECT MAX(x.version)
                        FROM vendor_document_versions x
                        WHERE x.source_id=d.source_id AND x.advisory_id=d.advisory_id)
                ORDER BY d.source_id,d.advisory_id"""):
        sid=d["source_id"];source_docs[sid]+=1
        entry=known.get(sid)
        if not entry or entry.get("verification_status")!="read_parse_verified":
            raise ValueError("Vendor document not present in reviewed registry")
        facts=json.loads(d["facts_json"])
        ids=facts.get("cve_ids",[])
        if (not isinstance(ids,list) or any(not isinstance(i,str) or
            not CVE.fullmatch(i) for i in ids) or len(set(ids))!=len(ids)):
            raise ValueError("Invalid extracted vendor CVE candidates")
        events=[]
        for event in vendor.execute("""SELECT e.event_kind,e.observed_utc,e.version
                   FROM vendor_document_events e
                   WHERE e.source_id=? AND e.advisory_id=?
                   ORDER BY e.event_id""",(sid,d["advisory_id"])):
            when=_date(event["observed_utc"])
            if when and start<=when<=end:
                events.append({"kind":event["event_kind"],"observed_utc":event["observed_utc"],
                               "version":event["version"]})
        modified=[e for e in events if e["kind"]!="baseline"]
        matched=[i for i in ids if i in selected]
        if not matched and not modified:
            # Not every baseline record is a weekly publication!
            continue
        if len(docs)>=MAX_WEEK_DOCS:raise ValueError("Too many vendor advisories; cannot silently cut")
        doc_key=f"{sid}/{d['advisory_id']}"
        links_count=sum(len(v) for v in links.values())+len(matched)
        if links_count>MAX_VENDOR_LINKS:raise ValueError("Unbounded vendor linking")
        item={"document_key":doc_key,"source_id":sid,"advisory_id":d["advisory_id"],
              "source_url":d["source_url"],"source_sha256":d["current_source_sha"],
              "normalized_facts_sha256":d["current_facts_sha"],
              "source_extract_status":d["extract_status"],
              "first_observed_utc":d["first_observed_utc"],
              "last_observed_utc":d["last_observed_utc"],
              "observations_in_window":events,
              "cve_candidates":ids,
              "cve_link_confidence":"EXTRACTED_UNREVIEWED",
              "publisher_publication_date":"UNKNOWN_NOT_STORED",
              "product_impact_review_state":"UNREVIEWED",
              "normalized_source_facts":facts}
        docs.append(item);candidates[sid]+=1
        for ident in matched:links[ident].append(doc_key)
        for event in modified:
            changes.append({"subject":doc_key,"event_type":"VENDOR_"+event["kind"].upper(),
                            "time_basis":"ECLIPSE_OBSERVED_UTC_NOT_PUBLISHER_DATE",
                            "observed_utc":event["observed_utc"],
                            "source_url":d["source_url"],"source_id":sid,
                            "quality":"UNREVIEWED","eligible_as_publisher_new_release":False})
    return docs,links,changes,source_docs


def build_payload(cve_db,vendor_db,registry,*,start:date,end:date,
                  require_full_cve=False):
    if end<start or (end-start).days>31:raise ValueError("Week window must be ordered and <=32 inclusive days")
    ver=inspect_db(vendor_db,registry)
    with closing(_open_ro(cve_db)) as cve,closing(_open_ro(vendor_db)) as vendor:
        md=_meta(cve)
        count=cve.execute("SELECT COUNT(*) FROM cve_current").fetchone()[0]
        if require_full_cve and count!=403696:
            raise ValueError("Pinned CVE 403696 source snapshot not present")
        selected=_weekly_source_events(cve,start,end)
        docs,links,vendor_changes,source_docs=_vendor_records(vendor,registry,start,end,selected)
        vulnerabilities=[]; changes=[]; evidence=[]
        for ident in sorted(selected):
            data=selected[ident]
            row=data["record"]
            state=row["record_state"]
            summary=cve.execute("""SELECT title,description_en,cvss_score,cvss_kind,cvss_severity
                                     FROM warehouse_summary WHERE cve_id=?""",(ident,)).fetchone()
            if not summary:raise ValueError("Missing original CVE metadata/summary: "+ident)
            affected=[{"container":a["container"],"ordinal":a["ordinal"],
                        "vendor":a["vendor"],"product":a["product"],
                        "default_status":a["default_status"],
                        "versions_raw":json.loads(a["versions_json"]) if a["versions_json"] else None}
                      for a in cve.execute("""SELECT container,ordinal,vendor,product,default_status,versions_json
                                   FROM warehouse_affected WHERE cve_id=?
                                   ORDER BY container,ordinal""",(ident,))]
            kev=cve.execute("""SELECT present,date_added
                               FROM kev_current WHERE cve_id=?""",(ident,)).fetchone()
            epss=cve.execute("""SELECT probability,percentile
                                FROM warehouse_epss WHERE cve_id=?""",(ident,)).fetchone()
            entry={"cve_id":ident,"record_state":state,"source_cve_record_sha256":row["hash"],
                   "cve_published_utc":row["date_published"],
                   "cve_updated_utc":row["date_updated"],
                   "week_reasons":sorted(set(data["reasons"])),
                   "cve_cna_title":summary["title"],
                   "cve_cna_description_en":summary["description_en"],
                   "cvss":{"base_score":summary["cvss_score"],"kind":summary["cvss_kind"],
                           "severity":summary["cvss_severity"],
                           "attribution":"CVE_CNA"},
                   "cve_affected_original_predicates":affected,
                   "kev":{"present":bool(kev["present"]) if kev else False,
                          "date_added":kev["date_added"] if kev else None,
                          "meaning":"CISA_KNOWN_EXPLOITED_VULNERABILITY_NOT_CUSTOMER_ATTACK"},
                   "epss":{"probability":epss["probability"],
                           "percentile":epss["percentile"],
                           "score_date":"NOT_PRESENT_IN_WAREHOUSE"}
                          if epss else None,
                   "linked_vendor_documents":sorted(set(links.get(ident,[]))),
                   "attack_prerequisites":"NOT_STRUCTURED_OR_VERIFIED",
                   "technical_root_cause":"NOT_STRUCTURED_OR_VERIFIED",
                   "remediation_verified":"NOT_ASSESSED",
                   "customer_exposure":"NOT_ASSESSED",
                   "editorial_priority":"NOT_SELECTED_BY_ECLIPSE",
                   "quality":"SOURCE_REPORTED_UNREVIEWED" if state=="PUBLISHED"
                             else "REJECTED_OR_OTHER_RECORD_STATE_NO_ACTIVE_CLAIM"}
            vulnerabilities.append(entry)
            evidence.append({"subject":ident,"source_kind":"CVE_V5_CNA",
                "source_url":f"https://www.cve.org/CVERecord?id={ident}",
                "record_sha256":row["hash"],
                "source_index_sha256":md["source_index_sha256"],
                "reference_scope":"CVE metadata / CNA description / affected predicate as recorded",
                "assertion_status":"SOURCE_REPORTED_NOT_INDEPENDENTLY_FACT_CHECKED"})
            if kev and kev["present"]:
                evidence.append({"subject":ident,"source_kind":"CISA_KEV",
                    "source_url":"https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                    "date_added":kev["date_added"],
                    "reference_scope":"CISA KEV catalog membership",
                    "assertion_status":"SOURCE_REPORTED"})
            if epss:
                evidence.append({"subject":ident,"source_kind":"FIRST_EPSS",
                    "source_url":"https://www.first.org/epss/",
                    "reference_scope":"Statistical estimate, snapshot score date not stored",
                    "assertion_status":"SOURCE_REPORTED_SCORE_DATE_UNKNOWN"})
            for reason in sorted(set(data["reasons"])):
                changes.append({"subject":ident,"event_type":reason,
                    "time_basis":"SOURCE_CVE_METADATA_DATE" if reason!="CISA_KEV_DATE_ADDED_IN_WINDOW"
                                 else "CISA_KEV_DATE_ADDED",
                    "observed_utc":None,"quality":"SOURCE_REPORTED",
                    "publisher_event_confirmed":reason!="CVE_SOURCE_DATE_UPDATED_IN_WINDOW"})
        for doc in docs:
            evidence.append({"subject":doc["document_key"],
                "source_kind":"OFFICIAL_VENDOR_ADVISORY",
                "source_url":doc["source_url"],
                "source_sha256":doc["source_sha256"],
                "normalized_facts_sha256":doc["normalized_facts_sha256"],
                "reference_scope":"Publisher document; only scoped facts from parser",
                "assertion_status":doc["source_extract_status"]})
        changes+=vendor_changes
        changes.sort(key=lambda r:(r["subject"],r["event_type"],r.get("observed_utc") or ""))
        evidence.sort(key=lambda r:(r["subject"],r["source_kind"]))
        archived=set(source_docs)
        active={r["source_id"] for r in registry["sources"]
                if r.get("verification_status")=="read_parse_verified"}
        missing=sorted(active-archived)
        counts=Counter(x["record_state"] for x in vulnerabilities)
        quality={
            "result":"PARTIAL_SNAPSHOT_EVIDENCE_NOT_COMPLETE_WEEKLY_MONITORING",
            "weekly_coverage_certified":False,
            "week_source_event_log_complete":False,
            "cve_snapshot_historical_not_live":True,
            "vendor_baseline_does_not_mean_weekly_new_publication":True,
            "missing_publisher_data_in_vendor_snapshot":missing,
            "vendor_documents_per_source":dict(sorted(source_docs.items())),
            "cve_records_by_state":dict(sorted(counts.items())),
            "unknown_fields":["EXPLOIT_PRECONDITIONS_UNLESS_IN_QUOTED_CNA_PROSE",
                "VENDOR_AFFECTED_VERSION_VERIFICATION","VENDOR_PUBLISHED_DATES",
                "FIRST_EPSS_SCORE_DATE","COMPLETE_WEEKLY_SOURCE_OBSERVATION_LOG"],
            "collection_failures_for_week":"UNKNOWN_NOT_OBSERVED",
            "critical_notes":[
                "This is a snapshot-filtered evidence pack, NOT verified monitoring of every publication in the week.",
                "No reliable week-by-week event continuity/negative observation is provided by fixed CVE and vendor pilot snapshots.",
                "Vendor pilot baseline is NOT evidence a vulnerability was published in this week.",
                "EPSS is a probabilistic estimate; the stored score snapshot lacks an exact score date.",
                "Vendor extraction and CVE linking are unreviewed and may contain cross-product/HTML candidate references.",
                "No model-generated exploitation, affected versions, workarounds or confirmed attacks appear here."
            ],
            "delivery_decision":"ALLOW_RESEARCH_HANDOFF_WITH_VISIBLE_INCOMPLETE_COVERAGE_NOT_PRODUCTION_WEEKLY_COMPLETE"
        }
        overview={"schema_version":SCHEMA_VERSION,
            "kind":"ECLIPSE_WEEKLY_EVIDENCE_INDEX_NOT_REPORT",
            "window_start_utc":start.isoformat(),"window_end_utc":end.isoformat(),
            "candidate_total":len(vulnerabilities),
            "vendor_advisory_documents_linked_or_observed_changed":len(docs),
            "change_events":len(changes),"evidence_entries":len(evidence),
            "selection_policy":"ALL_CVE_METADATA_DATES_OR_KEV_ADDITIONS_IN_WINDOW_PLUS_VENDOR_OBSERVED_REVISIONS",
            "ranking_policy":"NO_EDITORIAL_FILTERING",
            "completeness":"NOT_PROVEN_FIXED_SNAPSHOT_ONLY"}
        provenance={"cve_source_index_sha256":md["source_index_sha256"],
            "cve_source_archive_sha256":md["source_archive_sha256"],
            "cve_record_count":count,
            "vendor_sqlite_sha256":ver["sqlite_sha256"],
            "vendor_document_count":ver["advisories"],
            "vendor_version_count":ver["versions"],
            "vendor_event_count":ver["events"]}
        data={
          "weekly_index.json":canonical(overview).encode("utf-8")+b"\n",
          "vulnerabilities.jsonl":_jsonlines(vulnerabilities),
          "vendor_advisories.jsonl":_jsonlines(docs),
          "weekly_changes.jsonl":_jsonlines(changes),
          "evidence.jsonl":_jsonlines(evidence),
          "quality_report.json":canonical(quality).encode("utf-8")+b"\n"}
        return data,provenance


def create(*,cve_db,vendor_db,registry_path,start,end,out,require_full_cve=False):
    out=Path(out)
    if out.exists():raise ValueError("Refusing to overwrite handoff ZIP")
    if out.is_symlink():raise ValueError("Symlink output not allowed")
    registry=load_registry(Path(registry_path))
    data,provenance=build_payload(cve_db,vendor_db,registry,start=start,end=end,
                                   require_full_cve=require_full_cve)
    for name,raw in data.items():
        if len(raw)>MAX_BYTES_PER_MEMBER:raise ValueError("Oversized weekly handoff member "+name)
    manifest={"schema_version":SCHEMA_VERSION,
        "kind":"ECLIPSE_WEEKLY_EVIDENCE_HANDOFF_NOT_WEEKLY_REPORT",
        "window":{"start_utc":start.isoformat(),"end_utc":end.isoformat()},
        "input_provenance":provenance,
        "members_sha256":{name:sha(raw) for name,raw in sorted(data.items())},
        "members_bytes":{name:len(raw) for name,raw in sorted(data.items())},
        "time_semantics":"CVE_PUBLISH_UPDATE_KEV_ADDED_AND_OBSERVED_VENDOR_EVENT_DISTINCT",
        "freshness":"FIXED_HISTORICAL_SNAPSHOT_ONLY",
        "completeness":"UNVERIFIED_WEEK_NOT_A_PRODUCTION_WEEKLY_REPORT",
        "no_invented_impact_or_attack_details":True,
        "no_customer_identifiers":True}
    data["manifest.json"]=canonical(manifest).encode("utf-8")+b"\n"
    out.parent.mkdir(parents=True,exist_ok=True)
    try:
        with zipfile.ZipFile(out,"x",compression=zipfile.ZIP_DEFLATED,
                             compresslevel=6,strict_timestamps=True) as z:
            for name in sorted(data):
                info=zipfile.ZipInfo(name,date_time=(1980,1,1,0,0,0))
                info.compress_type=zipfile.ZIP_DEFLATED
                z.writestr(info,data[name],compress_type=zipfile.ZIP_DEFLATED,compresslevel=6)
        proof=verify(out)
        return {"result":"SOURCE_SNAPSHOT_RESEARCH_EVIDENCE_PACKAGE_VERIFIED",
                "zip_sha256":sha(out.read_bytes()),"zip_bytes":out.stat().st_size,
                "cve_candidates":proof["candidate_total"],
                "vendor_evidence_documents":proof["vendor_documents"],
                "weekly_coverage_certified":False}
    except BaseException:
        out.unlink(missing_ok=True)
        raise


def _lines(raw):
    return [json.loads(line) for line in raw.splitlines() if line]


def verify(path):
    path=Path(path)
    if not path.is_file() or path.is_symlink():raise ValueError("Invalid weekly handoff ZIP")
    with zipfile.ZipFile(path) as z:
        entries=z.namelist()
        if len(entries)!=len(NAMES)+1 or len(set(entries))!=len(entries) or set(entries)!=set(NAMES)|{"manifest.json"}:
            raise ValueError("Missing, duplicate or unexpected handoff members")
        if any(z.getinfo(name).file_size>MAX_BYTES_PER_MEMBER for name in entries):
            raise ValueError("Excessive zip uncompressed member")
        data={name:z.read(name) for name in entries}
    m=json.loads(data["manifest.json"])
    if (m.get("schema_version")!=1 or
        m.get("kind")!="ECLIPSE_WEEKLY_EVIDENCE_HANDOFF_NOT_WEEKLY_REPORT" or
        m.get("completeness")!="UNVERIFIED_WEEK_NOT_A_PRODUCTION_WEEKLY_REPORT" or
        m.get("freshness")!="FIXED_HISTORICAL_SNAPSHOT_ONLY" or
        m.get("no_invented_impact_or_attack_details") is not True or
        m.get("no_customer_identifiers") is not True or
        set(m.get("members_sha256",{}))!=set(NAMES)):
        raise ValueError("Unexpected handoff contract or missing safety caveat")
    for name in NAMES:
        if sha(data[name])!=m["members_sha256"][name] or len(data[name])!=m["members_bytes"][name]:
            raise ValueError("Handoff file hash or size mismatch: "+name)
    index=json.loads(data["weekly_index.json"])
    quality=json.loads(data["quality_report.json"])
    records=_lines(data["vulnerabilities.jsonl"])
    docs=_lines(data["vendor_advisories.jsonl"])
    changes=_lines(data["weekly_changes.jsonl"])
    evidence=_lines(data["evidence.jsonl"])
    if (quality.get("weekly_coverage_certified") is not False or
        index.get("completeness")!="NOT_PROVEN_FIXED_SNAPSHOT_ONLY" or
        index.get("candidate_total")!=len(records) or
        index.get("vendor_advisory_documents_linked_or_observed_changed")!=len(docs) or
        index.get("change_events")!=len(changes) or
        index.get("evidence_entries")!=len(evidence) or
        any(not CVE.fullmatch(x.get("cve_id","")) for x in records) or
        any(x.get("customer_exposure")!="NOT_ASSESSED" or
            x.get("remediation_verified")!="NOT_ASSESSED" for x in records) or
        any(x.get("product_impact_review_state")!="UNREVIEWED" for x in docs)):
        raise ValueError("Safety/completeness/cardinality contract violated")
    return {"result":"INDEPENDENT_WEEKLY_HANDOFF_CONTRACT_VERIFIED",
            "candidate_total":len(records),"vendor_documents":len(docs),
            "change_events":len(changes),"evidence_entries":len(evidence),
            "weekly_coverage_certified":False,
            "sha256":sha(path.read_bytes())}


def main():
    p=argparse.ArgumentParser()
    cmds=p.add_subparsers(dest="command",required=True)
    a=cmds.add_parser("build")
    for label in ("cve-db","vendor-db","registry","out"):
        a.add_argument("--"+label,required=True,type=Path)
    a.add_argument("--start",required=True,type=date.fromisoformat)
    a.add_argument("--end",required=True,type=date.fromisoformat)
    a.add_argument("--require-full-cve",action="store_true")
    b=cmds.add_parser("verify")
    b.add_argument("--zip",required=True,type=Path)
    opts=p.parse_args()
    proof=(create(cve_db=opts.cve_db,vendor_db=opts.vendor_db,registry_path=opts.registry,
                  start=opts.start,end=opts.end,out=opts.out,require_full_cve=opts.require_full_cve)
           if opts.command=="build" else verify(opts.zip))
    print(json.dumps(proof,ensure_ascii=False,sort_keys=True,indent=2))


if __name__=="__main__":main()
