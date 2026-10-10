"""Evidence-first per-CVE briefing: CVE record + optional KEV and EPSS.

This does not infer exploitability, impacted customer assets, or patch status.
Every claim has source attribution. Do not call this AI analysis.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from eclipse_l0.core import CVE_ID, stable_json_hash
from eclipse_l0.epss import SOURCE as EPSS_SOURCE
from eclipse_l0.kev_monitor import _atomic_text, _dump


def _english_descriptions(cna: dict) -> list[str]:
    return [str(d.get('value', '')).strip() for d in cna.get('descriptions', [])
            if isinstance(d, dict) and str(d.get('lang', '')).lower().startswith('en')
            and d.get('value')]


def _affected(cna: dict) -> list[dict]:
    results = []
    for item in cna.get('affected', []) or []:
        if not isinstance(item, dict):
            continue
        results.append({'vendor': str(item.get('vendor', 'unknown'))[:100],
                        'product': str(item.get('product', 'unknown'))[:200],
                        'versions_raw': item.get('versions', [])})
    return results


def dossier(cve_doc: dict, *, kev: dict | None = None, epss: dict | None = None,
            source_hash: str | None = None) -> dict:
    meta = cve_doc.get('cveMetadata') or {}
    cve = meta.get('cveId')
    if not isinstance(cve, str) or not CVE_ID.fullmatch(cve):
        raise ValueError('Expected an official CVE 5 record')
    container = (cve_doc.get('containers') or {}).get('cna') or {}
    affected = _affected(container)
    descriptions = _english_descriptions(container)
    refs = []
    for link in container.get('references', []) or []:
        if isinstance(link, dict) and isinstance(link.get('url'), str) and link['url'].startswith('https://'):
            refs.append(link['url'])
    # Since the 2024 CVE Program Container migration, references may reside
    # in the official CVE Program ADP container rather than solely in CNA.
    program_refs = []
    for adp in (cve_doc.get('containers') or {}).get('adp', []) or []:
        if not isinstance(adp, dict) or (adp.get('providerMetadata') or {}).get('shortName') != 'CVE':
            continue
        for ref in adp.get('references', []) or []:
            if isinstance(ref, dict) and isinstance(ref.get('url'), str) and ref['url'].startswith('https://'):
                program_refs.append(ref['url'])
    entries = []

    def add_claim(text: str, evidence: str):
        entries.append({'statement': text, 'evidence': evidence})

    add_claim('Official CVE record state: ' + str(meta.get('state') or 'unknown'), 'CVE record: cveMetadata.state')
    if descriptions:
        add_claim(descriptions[0][:2000], 'CVE record: containers.cna.descriptions[en]')
    else:
        add_claim('English technical description not supplied in CNA container.', 'CVE record: containers.cna.descriptions')
    if kev is not None:
        if kev.get('cveID') != cve:
            raise ValueError('CISA KEV CVE does not match CVE source record')
        add_claim('Listed in CISA KEV (confirmed exploitation catalog). Date added: '+str(kev.get('dateAdded', 'unknown')),
                  'CISA KEV: dateAdded, cveID')
        if kev.get('requiredAction'):
            add_claim(str(kev['requiredAction'])[:1500], 'CISA KEV: requiredAction')
    else:
        add_claim('KEV status not provided to this run (NOT evidence of absence).', 'Input coverage: KEV not supplied')
    score = None
    percentile = None
    if epss:
        if epss.get('source') != EPSS_SOURCE:
            raise ValueError('Untrusted EPSS source in dossier')
        score = epss.get('scores', {}).get(cve)
        if score is not None:
            if not 0 <= score.get('epss', -1) <= 1 or not 0 <= score.get('percentile', -1) <= 1:
                raise ValueError('Malformed selected EPSS scores')
            percentile = score['percentile']
            add_claim(f"EPSS: {score['epss']:.4f}; percentile: {percentile:.4f}; date: {epss.get('score_date') or 'unknown'}",
                      'FIRST EPSS: selected daily file')
    risk_note = ('EPSS is a model of population-level exploitation probability over the next 30 days. '
                 'It is not an asset-specific breach probability. CVE existence and KEV listing alone '
                 'do not establish impact on a particular customer.')
    result = {
        'schema_version': 1, 'cve_id': cve, 'record_state': meta.get('state'),
        'published_utc': meta.get('datePublished'), 'updated_utc': meta.get('dateUpdated'),
        'descriptions_en': descriptions[:3], 'affected_unverified': affected[:50],
        'references_cna': list(dict.fromkeys(refs))[:30],
        'references_cve_program': list(dict.fromkeys(program_refs))[:30],
        'kev_listed_in_supplied_feed': bool(kev),
        'kev_date_added': kev.get('dateAdded') if kev else None,
        'epss_score': score.get('epss') if score else None,
        'epss_percentile': percentile,
        'epss_score_date': epss.get('score_date') if epss else None,
        'claims': entries, 'interpretation_caveat': risk_note,
        'source_provenance': {
            'cve_record_url': 'https://www.cve.org/CVERecord?id='+cve,
            'cve_record_sha256': source_hash or stable_json_hash(cve_doc),
            'kev_source': 'https://github.com/cisagov/kev-data' if kev else None,
            'epss_source': EPSS_SOURCE if epss else None,
            'epss_source_sha256': epss.get('source_sha256') if epss else None,
        },
    }
    return result


def from_files(cve_path: Path, out: Path, *, kev_file: Path | None = None,
               epss_file: Path | None = None) -> dict:
    raw = cve_path.read_bytes()
    record = json.loads(raw)
    id_ = (record.get('cveMetadata') or {}).get('cveId')
    kev = None
    if kev_file:
        doc = json.loads(kev_file.read_bytes())
        items = doc.get('vulnerabilities') or []
        if not isinstance(items, list):
            raise ValueError('Malformed KEV data')
        kev = next((x for x in items if x.get('cveID') == id_), None)
    epss = json.loads(epss_file.read_text('utf-8')) if epss_file else None
    result = dossier(record, kev=kev, epss=epss, source_hash=hashlib.sha256(raw).hexdigest())
    _atomic_text(out, _dump(result))
    return result


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--cve-json', type=Path, required=True)
    p.add_argument('--kev-json', type=Path)
    p.add_argument('--epss-json', type=Path)
    p.add_argument('--out', type=Path, required=True)
    args=p.parse_args()
    data=from_files(args.cve_json,args.out,kev_file=args.kev_json,epss_file=args.epss_json)
    print(json.dumps({'cve_id':data['cve_id'],'claims':len(data['claims']),'output':str(args.out)},indent=2))


if __name__=='__main__':
    main()
