"""Bounded official CVE record enrichment for automated briefing.

Only reads trusted CVEProject raw-content URLs and ignores all redirects.
No customer-provided external URLs or unbounded crawling.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

from eclipse_l0.core import CVE_ID
from eclipse_l0.kev_monitor import _atomic_text, _dump
from .timeline import official_record_url


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def default_url(cve: str) -> str:
    if not CVE_ID.fullmatch(cve):
        raise ValueError('Invalid CVE record ID')
    _, year, seq=cve.split('-')
    return official_record_url(cve,
        f'https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{year}/{seq[:-3]}xxx/{cve}.json')


def candidates(timeline: dict, max_records: int) -> list[tuple[str,str]]:
    if not 1<=max_records<=40:
        raise ValueError('max_records must be 1..40')
    grouped={}
    for event in timeline.get('events',[]):
        cve=event.get('cve_id')
        if not cve:
            continue
        if not CVE_ID.fullmatch(cve): raise ValueError('Invalid event CVE')
        url=event.get('source_url') if event.get('source_kind')=='cve' else default_url(cve)
        # Fail closed for poisoned log URLs; never blindly fetch.
        if event.get('source_kind')=='cve': official_record_url(cve,url)
        priority=0 if event.get('type')=='kev_added' else (1 if event.get('type')=='kev_updated' else 2)
        prev=grouped.get(cve)
        if prev is None or priority<prev[0]:
            grouped[cve]=(priority,url)
    return [(cve,grouped[cve][1]) for cve in sorted(grouped,key=lambda c:(grouped[c][0],c))[:max_records]]


def fetch_records(timeline_file: Path, dest: Path, *, max_records: int=12,
                  opener=None, backoff: bool = True) -> dict:
    timeline=json.loads(timeline_file.read_text(encoding='utf-8'))
    selected=candidates(timeline,max_records)
    dest.mkdir(parents=True,exist_ok=True)
    client=opener or build_opener(_NoRedirect)
    ok=[];failed=[]
    for cve,url in selected:
        try:
            data=None
            for attempt in range(2):
                try:
                    req=Request(url,headers={'User-Agent':'ECLIPSE-evidence-collector/0.6'})
                    with client.open(req,timeout=25) as response:
                        data=response.read(2*1024*1024+1)
                        if len(data)>2*1024*1024: raise ValueError('CVE record oversize')
                    break
                except (HTTPError,URLError,TimeoutError):
                    if attempt==0 and backoff: time.sleep(1.5)
                    else: raise
            doc=json.loads(data)
            if doc.get('cveMetadata',{}).get('cveId')!=cve:
                raise ValueError('Official CVE body identity mismatch')
            _atomic_text(dest/(cve+'.json'),data.decode('utf-8'))
            ok.append({'cve_id':cve,'source_url':url,'sha256':hashlib.sha256(data).hexdigest()})
        except (ValueError,HTTPError,URLError,TimeoutError,UnicodeError,KeyError) as exc:
            failed.append({'cve_id':cve,'error_type':type(exc).__name__})
    meta={'schema_version':1,'attempted':len(selected),'fetched':len(ok),'missing':len(failed),
          'success':ok,'failures':failed,
          'coverage_warning':'Only a bounded subset of current CVE record bodies was fetched. Failed IDs have no verified technical detail.'}
    _atomic_text(dest/'fetch-manifest.json',_dump(meta))
    return meta


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--timeline',type=Path,required=True)
    p.add_argument('--out-dir',type=Path,required=True)
    p.add_argument('--max-records',type=int,default=12)
    args=p.parse_args()
    result=fetch_records(args.timeline,args.out_dir,max_records=args.max_records)
    print(json.dumps({k:v for k,v in result.items() if k not in ('success','failures')},ensure_ascii=False))

if __name__=='__main__':main()
