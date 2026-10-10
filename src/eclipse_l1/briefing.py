"""Evidence-constrained Japanese briefing from multiple public-source events.

No LLM is invoked: Japanese sections are deterministic analysis scaffolding.
CVE CNA description and affected versions are explicitly unattributed-to-client
source text; manufacturer RSS items are pointers, not verified remediation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime
from pathlib import Path

from eclipse_l0.core import CVE_ID
from eclipse_l0.epss import SOURCE as EPSS_SOURCE
from eclipse_l0.kev_monitor import _atomic_text, _dump
from eclipse_l1.evidence import dossier


def _load_state(path: Path) -> dict:
    data=json.loads(path.read_text(encoding='utf-8'))
    if data.get('schema_version')!=1 or not isinstance(data.get('records'),dict):
        raise ValueError('Missing or invalid official KEV state')
    for cve, row in data['records'].items():
        if not CVE_ID.fullmatch(cve) or row.get('cveID')!=cve:
            raise ValueError('Corrupt KEV catalog in public state')
    return data


def _select(event: dict, profile: dict, details: dict | None, kev: dict | None) -> tuple[bool,bool]:
    """Return (matches, identity_unknown); no substring matching on random prose."""
    if profile.get('include_all') is True:
        return True,False
    vendors=[s.casefold().strip() for s in profile.get('vendors',[]) if isinstance(s,str) and s.strip()]
    products=[s.casefold().strip() for s in profile.get('products',[]) if isinstance(s,str) and s.strip()]
    cves=profile.get('cve_ids',[])
    if event.get('cve_id') in cves:
        return True,False
    if not (vendors or products):
        raise ValueError('Customer profile lacks explicit watch criteria')
    vendor_names=[];product_names=[]
    if kev:
        vendor_names.append(str(kev.get('vendorProject') or '').casefold())
        product_names.append(str(kev.get('product') or '').casefold())
    rec=event.get('record') or {}
    if event['source_kind']=='kev':
        vendor_names.append(str(rec.get('vendorProject') or '').casefold())
        product_names.append(str(rec.get('product') or '').casefold())
    elif event['source_kind']=='manufacturer':
        vendor_names.append(str(rec.get('vendor') or '').casefold())
    if details:
        for affected in details.get('affected_unverified',[]):
            vendor_names.append(str(affected.get('vendor') or '').casefold())
            product_names.append(str(affected.get('product') or '').casefold())
    vendor_names=[x for x in vendor_names if x and x not in ('unknown','n/a')]
    product_names=[x for x in product_names if x and x not in ('unknown','n/a')]
    unknown=(bool(vendors) and not vendor_names) or (bool(products) and not product_names)
    match_vendor=not vendors or any(v==name for v in vendors for name in vendor_names)
    match_product=not products or any(p==name for p in products for name in product_names)
    return match_vendor and match_product, unknown


def make_briefing(timeline_file: Path, kev_state_file: Path, profile_file: Path,
                  output_file: Path, *, epss_file: Path | None = None,
                  cve_dir: Path | None = None, max_items: int = 10000) -> dict:
    timeline=json.loads(timeline_file.read_text(encoding='utf-8'))
    if timeline.get('schema_version')!=1 or not isinstance(timeline.get('events'),list):
        raise ValueError('Invalid public-source timeline')
    kev_state=_load_state(kev_state_file)
    profile=json.loads(profile_file.read_text(encoding='utf-8'))
    if not isinstance(profile.get('customer_name'),str) or not profile['customer_name'].strip():
        raise ValueError('Profile display name required')
    if not profile.get('include_all') and not (profile.get('vendors') or profile.get('products') or profile.get('cve_ids')):
        raise ValueError('Profile must specify include_all or watch criteria')
    epss=None
    if epss_file and epss_file.exists():
        epss=json.loads(epss_file.read_text(encoding='utf-8'))
        if epss.get('source')!=EPSS_SOURCE or not isinstance(epss.get('scores'),dict):
            raise ValueError('EPSS source/shape invalid')
    by_key={}
    for event in timeline['events']:
        key=event.get('cve_id')
        if key is not None and not CVE_ID.fullmatch(key):
            raise ValueError('Malformed CVE identity in timeline')
        if not key:
            key='ADVISORY-'+hashlib.sha256(event['source_url'].encode()).hexdigest()[:14].upper()
        by_key.setdefault(key,[]).append(event)
    if len(by_key)>max_items:
        raise ValueError('Selected window contains too many topics; reduce report window')
    topics=[];uncategorized=0;source_coverage=dict(timeline.get('coverage',{}))
    for key,events in by_key.items():
        cve=key if key.startswith('CVE-') else None
        kev=kev_state['records'].get(cve) if cve else None
        detail=None;record_hash=None
        if cve and cve_dir and (cve_dir/(cve+'.json')).is_file():
            raw=(cve_dir/(cve+'.json')).read_bytes()
            if len(raw)>2*1024*1024:
                raise ValueError('Unreasonably large CVE record')
            doc=json.loads(raw)
            if doc.get('cveMetadata',{}).get('cveId')!=cve:
                raise ValueError('CVE record file ID mismatch')
            record_hash=hashlib.sha256(raw).hexdigest()
            detail=dossier(doc,kev=kev,epss=epss,source_hash=record_hash)
        matches=[];unknown=False
        for event in events:
            included,is_unknown=_select(event,profile,detail,kev)
            matches.append(included)
            unknown=unknown or is_unknown
        if not any(matches):
            if unknown: uncategorized+=1
            continue
        events=sorted(events,key=lambda e:(e['observed_utc'],e['event_id']))
        changed_types=sorted(set(e['type'] for e in events))
        kev_added='kev_added' in changed_types
        kev_removed='kev_removed' in changed_types
        listed=bool(kev)
        priority=('KEV新規登録・要確認' if kev_added else
                  'KEV掲載中・要確認' if listed else '公式情報の変更・確認')
        source_record=next((e.get('record') for e in reversed(events) if e['source_kind']=='kev' and e.get('record')),None)
        advisory_record=next((e.get('record') for e in reversed(events) if e['source_kind']=='manufacturer'),None)
        vendor=(kev or source_record or {}).get('vendorProject') or (advisory_record or {}).get('vendor')
        product=(kev or source_record or {}).get('product')
        if not vendor and detail and detail.get('affected_unverified'):
            vendor=detail['affected_unverified'][0].get('vendor')
        if not product and detail and detail.get('affected_unverified'):
            product=detail['affected_unverified'][0].get('product')
        original_description=(detail.get('descriptions_en') or [None])[0] if detail else None
        if original_description:
            description='CVE公式の技術説明（原文／未翻訳）: '+original_description[:900]
        elif (kev or source_record or {}).get('shortDescription'):
            description='CISAの説明（英語原文）: '+str((kev or source_record)['shortDescription'])[:900]
        elif advisory_record:
            description='メーカー公告の見出し（影響確定ではない）: '+str(advisory_record.get('title') or '')[:250]
        else:
            description='変更を検知。技術的内容の裏付けとなる原文レコードは未取得。'
        reasons=[]
        if kev_added:
            reasons.append('CISA KEVへの新規登録を観測。悪用確認の公的な判断材料。登録日は攻撃開始日ではない。')
        elif listed:
            reasons.append('現時点のCISA KEVカタログに掲載。今回初めて悪用が始まった意味ではない。')
        if kev_removed:
            reasons.append('KEVカタログ上の削除を観測。悪用リスクの消滅と解釈しない。')
        if 'cve_record_updated' in changed_types or 'cve_record_added' in changed_types:
            reasons.append('CVE公式レコードの変更を観測。新規公開・新規攻撃を直接意味しない。')
        if any(e['source_kind']=='manufacturer' for e in events):
            reasons.append('メーカーRSS等の公告更新を観測。影響製品・修正済み版は公告本文との照合が必要。')
        if not reasons: reasons.append('公開情報の変更を観測。重要度の最終判定には追加の根拠が必要。')
        actions=[]
        if kev and kev.get('requiredAction'):
            actions.append('CISA掲載の対応文（原文）: '+str(kev['requiredAction'])[:360])
        actions.append('当該製品の利用有無、影響条件と修正方法をメーカー一次情報で照合する。')
        if detail and detail.get('record_state')=='REJECTED':
            reasons.append('CVE公式レコードはREJECTED。通常の有効な脆弱性として扱わない。')
        evidence=[]
        seen_urls=set()
        for ev in events:
            url=ev.get('source_url')
            if url and url not in seen_urls:
                evidence.append({'source_kind':ev['source_kind'],'url':url,
                                 'sha256':ev.get('source_sha256'),'observed_utc':ev['observed_utc'],
                                 'time_meaning':ev.get('source_time_meaning')})
                seen_urls.add(url)
        if detail:
            cve_url=detail['source_provenance']['cve_record_url']
            if cve_url not in seen_urls:
                evidence.append({'source_kind':'cve_record','url':cve_url,'sha256':record_hash,
                                 'observed_utc':None,'time_meaning':'Fetched source file is a CURRENT CVE record; may postdate the event'})
                seen_urls.add(cve_url)
        if listed and 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog' not in seen_urls:
            evidence.append({'source_kind':'kev_current_state',
                             'url':'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
                             'sha256':kev_state.get('source_sha256'),'observed_utc':None,
                             'time_meaning':'Current saved KEV membership, NOT exploitation start'})
        score=epss['scores'].get(cve) if epss and cve else None
        if score is not None:
            if not 0<=score['epss']<=1 or not 0<=score['percentile']<=1:
                raise ValueError('Invalid EPSS score value')
        if score is not None:
            evidence.append({'source_kind':'epss_daily','url':EPSS_SOURCE,
                             'sha256':epss.get('source_sha256'),'observed_utc':None,
                             'time_meaning':'EPSS score_date, not source event timestamp'})
        # Facts for downstream LLMs: all verifiable claims link to one or more
        # actual source evidence records. Future text generation must use this
        # ledger, not free-form prior model knowledge.
        claims=[]
        for number,ev in enumerate(events,1):
            source_id=next((idx for idx,e in enumerate(evidence) if e['url']==ev.get('source_url')),None)
            if source_id is None:
                raise ValueError('Event missing source in evidence ledger')
            claims.append({'claim_id':f'{key}:event:{number}',
                           'statement':f"Observed source update {ev['type']} on {ev['observed_utc']}",
                           'basis':'observed-event log', 'evidence_indices':[source_id],
                           'assessment':'direct observation, not exploitation time'})
        if detail:
            idx=next(i for i,e in enumerate(evidence) if e['source_kind']=='cve_record') if any(e['source_kind']=='cve_record' for e in evidence) else None
            if idx is None:
                # CVE delta URL can serve as the CURRENT record attribution.
                idx=next((i for i,e in enumerate(evidence) if e['url']==detail['source_provenance']['cve_record_url']),None)
            if idx is None: raise ValueError('CVE record has no source attribution')
            claims.append({'claim_id':f'{key}:cve:description','statement':description,
                           'basis':'official CVE JSON 5 CNA description',
                           'evidence_indices':[idx],'assessment':'CNA source text, not client impact'})
        if score is not None:
            claims.append({'claim_id':f'{key}:epss','statement':f"EPSS {score['epss']:.4f} dated {epss.get('score_date')}",
                           'basis':'FIRST EPSS daily CSV','evidence_indices':[len(evidence)-1],
                           'assessment':'population-level probability, NOT client-specific'})
        topics.append({
            'topic_id':key,'cve_id':cve,'vendor':vendor or '未特定','product':product or '未特定',
            'priority_label':priority,'kev_listed_now':listed,'kev_added_in_window':kev_added,
            'event_types':changed_types, 'event_count':len(events),
            'last_observed_utc':events[-1]['observed_utc'],
            'timeline':[{'event_id':e['event_id'],'type':e['type'],
                         'observed_utc':e['observed_utc'],'source_time':e.get('source_time'),
                         'source_time_meaning':e.get('source_time_meaning')} for e in events],
            'description_source_text':description,'why_now_ja':' '.join(reasons),
            'next_checks_ja':' '.join(actions),
            'affected_from_cna_unverified':detail.get('affected_unverified',[])[:10] if detail else [],
            'epss': {'score':score['epss'],'percentile':score['percentile'],'score_date':epss.get('score_date')}
                    if score is not None else None,
            'technical_detail_status':'official_CVE_record_fetched' if detail else 'missing_official_CVE_record',
            'evidence':evidence, 'claims':claims,
        })
    topics.sort(key=lambda x:(not x['kev_added_in_window'],not x['kev_listed_now'], -datetime.fromisoformat(x['last_observed_utc'].replace('Z','+00:00')).timestamp(), x['topic_id']))
    result={'schema_version':1,'report_scope':'PUBLIC-source topics, not an assessment of client asset exposure',
            'customer_name':profile['customer_name'],'window':timeline['window'],
            'input_event_count':len(timeline['events']),'topics_count':len(topics),
            'unclassified_excluded_count':uncategorized,
            'source_coverage':source_coverage,'source_warnings':timeline.get('warnings',[]),
            'topics':topics,
            'caveats':['Not an asset-specific impact/patch verdict.',
                       'CVE change-index time, KEV catalog registration and system observation time are distinct.',
                       'Manufacturer RSS entries are pointers, not validation of affected versions.',
                       'EPSS is the estimated population-level 30-day exploitation probability.',
                       'Automatic prose is deterministic and source-constrained, not generative-AI validation.']}
    _atomic_text(output_file,_dump(result))
    return result


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--timeline',type=Path,required=True)
    p.add_argument('--kev-state',type=Path,required=True)
    p.add_argument('--profile',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True)
    p.add_argument('--epss-json',type=Path)
    p.add_argument('--cve-dir',type=Path)
    args=p.parse_args()
    result=make_briefing(args.timeline,args.kev_state,args.profile,args.out,
                         epss_file=args.epss_json,cve_dir=args.cve_dir)
    print(json.dumps({'topics':result['topics_count'],'unclassified':result['unclassified_excluded_count']},ensure_ascii=False))

if __name__=='__main__':main()
