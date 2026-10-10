"""HTTPS adapters for official public data releases. No credentials by default."""
from __future__ import annotations

import json
import os
import shutil
import urllib.error
import urllib.request
from pathlib import Path

GITHUB_RELEASES = 'https://api.github.com/repos/CVEProject/cvelistV5/releases?per_page=100'
KEV_JSON = 'https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json'


def _request(url: str) -> urllib.request.Request:
    headers = {'User-Agent': 'PROJECT-ECLIPSE-L0/0.1 (+public-data-collector)',
               'Accept': 'application/vnd.github+json' if 'api.github.com/' in url else '*/*'}
    token = os.environ.get('GITHUB_TOKEN')
    if token and ('github.com/' in url):
        headers['Authorization'] = 'Bearer ' + token
    return urllib.request.Request(url, headers=headers)


def fetch_latest_cve_full_asset() -> tuple[str, str]:
    """Find freshest *_all_CVEs_at_midnight.zip among newest GitHub releases."""
    with urllib.request.urlopen(_request(GITHUB_RELEASES), timeout=35) as response:
        releases = json.load(response)
    candidates = []
    for release in releases:
        for asset in release.get('assets', []):
            name = asset.get('name', '')
            if name.endswith('_all_CVEs_at_midnight.zip') and asset.get('browser_download_url'):
                candidates.append((name, asset['browser_download_url']))
    if not candidates:
        raise RuntimeError('No official CVE full baseline in latest 100 releases; verify upstream manually')
    # YYYY-MM-DD is lexicographically sortable. Latest full snapshot, NOT latest hourly delta.
    return max(candidates, key=lambda pair: pair[0])


def download(url: str, path: Path, max_bytes: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + '.incomplete')
    try:
        with urllib.request.urlopen(_request(url), timeout=120) as response, temp.open('wb') as output:
            total = 0
            while chunk := response.read(1024 * 1024):
                total += len(chunk)
                if total > max_bytes:
                    raise ValueError('Remote archive exceeds explicit size limit')
                output.write(chunk)
        temp.replace(path)
    finally:
        temp.unlink(missing_ok=True)


def fetch_sources(workdir: Path, max_zip_mb: int = 1100) -> tuple[Path, Path, str]:
    name, url = fetch_latest_cve_full_asset()
    zip_path = workdir / name
    if not zip_path.exists():
        download(url, zip_path, max_bytes=max_zip_mb * 1024 * 1024)
    kev_path = workdir / 'known_exploited_vulnerabilities.json'
    download(KEV_JSON, kev_path, max_bytes=25 * 1024 * 1024)
    return zip_path, kev_path, name
