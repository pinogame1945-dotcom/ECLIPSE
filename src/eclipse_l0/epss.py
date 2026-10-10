"""FIRST EPSS daily CSV enrichment for a public set of watched CVEs.

Do not mistake an EPSS probability for probability that one specific customer
will be compromised. Only a watched subset is written to the public state repo.
"""
from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import json
from itertools import chain
from datetime import date
from pathlib import Path

from .core import CVE_ID
from .kev_monitor import _atomic_text, _dump

SOURCE = 'https://epss.empiricalsecurity.com/epss_scores-current.csv.gz'


def targets_from_kev_state(path: Path) -> set[str]:
    obj = json.loads(path.read_text(encoding='utf-8'))
    rows = obj.get('records')
    if not isinstance(rows, dict) or not rows or not all(CVE_ID.fullmatch(x) for x in rows):
        raise ValueError('Official KEV state missing/invalid; EPSS watch set unavailable')
    return set(rows)


def select_scores(archive: Path, watched: set[str], output: Path, *, min_scored: int = 100000,
                  observed_day: date | None = None) -> dict:
    if not watched or any(not isinstance(c, str) or not CVE_ID.fullmatch(c) for c in watched):
        raise ValueError('A nonempty, valid watchlist is required')
    if min_scored < 1:
        raise ValueError('Invalid EPSS row threshold')
    if archive.stat().st_size > 100 * 1024 * 1024:
        raise ValueError('EPSS compressed download exceeds 100 MB limit')
    digest = hashlib.sha256()
    with archive.open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(chunk)
    sha = digest.hexdigest()
    comments = []
    found = {}
    seen = set()
    count = 0
    with gzip.open(archive, 'rt', encoding='utf-8-sig', newline='') as handle:
        while True:
            line = handle.readline()
            if not line.startswith('#'):
                break
            comments.append(line.strip())
        if not line:
            raise ValueError('EPSS gzip missing CSV header')
        reader = csv.DictReader(chain([line], handle))
        if not {'cve', 'epss', 'percentile'} <= set(reader.fieldnames or []):
            raise ValueError('Unexpected EPSS CSV schema')
        for row in reader:
            cve = row.get('cve', '')
            if not CVE_ID.fullmatch(cve):
                raise ValueError('Invalid CVE in EPSS feed')
            count += 1
            if cve in watched:
                if cve in seen:
                    raise ValueError('Duplicate watched EPSS CVE record')
                seen.add(cve)
                try:
                    score = float(row['epss'])
                    percentile = float(row['percentile'])
                except (TypeError, ValueError) as exc:
                    raise ValueError('Non-numeric EPSS score') from exc
                if not (0 <= score <= 1 and 0 <= percentile <= 1):
                    raise ValueError('EPSS score or percentile out of range')
                found[cve] = {'epss': score, 'percentile': percentile}
    if count < min_scored:
        raise ValueError(f'EPSS file too small ({count} < {min_scored})')
    score_date = None
    for line in comments:
        if line.lower().startswith('#score_date:'):
            score_date = line.split(':', 1)[1].strip()
    if score_date:
        date.fromisoformat(score_date)
    if observed_day and score_date and date.fromisoformat(score_date) > observed_day:
        raise ValueError('Future EPSS score date')
    result = {
        'schema_version': 1, 'source': SOURCE, 'source_sha256': sha,
        'score_date': score_date, 'total_feed_rows': count,
        'watched_count': len(watched), 'matched_count': len(found),
        'missing_ids': sorted(watched - found.keys()),
        'scores': dict(sorted(found.items())),
        'interpretation': 'EPSS estimates exploitation probability in the next 30 days at population level; not customer-specific.',
    }
    _atomic_text(output, _dump(result))
    return result


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--file', type=Path, required=True)
    p.add_argument('--kev-state', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    args = p.parse_args()
    result = select_scores(args.file, targets_from_kev_state(args.kev_state), args.out)
    print(json.dumps({k: v for k, v in result.items() if k != 'scores' and k != 'missing_ids'}, indent=2))


if __name__ == '__main__':
    main()
