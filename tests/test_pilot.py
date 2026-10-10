import csv
import json
import tempfile
import unittest
from pathlib import Path
from urllib.error import HTTPError

from eclipse_l0.pilot import cve_url, run_pilot

ROOT = Path(__file__).resolve().parents[1]

class BoundedPilotTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.kev = self.base / 'kev.json'
        self.source = json.loads((ROOT/'examples/SYNTHETIC-kev-sample.json').read_text())
        self.source['count'] = len(self.source['vulnerabilities'])
        self.kev.write_text(json.dumps(self.source), encoding='utf-8')
        self.sample = [x['cveID'] for x in sorted(self.source['vulnerabilities'],
                     key=lambda x:(x['dateAdded'],x['cveID']), reverse=True)]

    def fetch_ok(self, url):
        cve = url.rsplit('/', 1)[-1].removesuffix('.json')
        return json.dumps({'cveMetadata': {'cveId': cve, 'state': 'PUBLISHED'},
                           'containers': {'cna': {'descriptions': [{'lang': 'en', 'value': 'synthetic only'}]}}}).encode()

    def test_official_url_partition_and_fixed_host(self):
        self.assertEqual(cve_url('CVE-2026-76504'),
                         'https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/76xxx/CVE-2026-76504.json')
        with self.assertRaises(ValueError):
            cve_url('https://example.org/123')

    def test_import_subset_and_full_catalog_validation(self):
        result = run_pilot(self.kev, self.base/'out', limit=2, min_records=1, fetcher=self.fetch_ok)
        self.assertEqual(result['selected_kev_identifiers'], 2)
        self.assertEqual(result['cve_records_imported'], 2)
        self.assertEqual(result['sqlite_audit']['sqlite_quick_check'], 'ok')
        self.assertEqual(result['sqlite_counts']['kev_present'], len(self.source['vulnerabilities']))
        self.assertEqual(result['sqlite_counts']['cve_total'], 2)
        self.assertEqual(result['mode'], 'READ_ONLY_BOUNDED_SMOKE_TEST')
        self.assertTrue((self.base/'out/pilot-cve-observations.csv').exists())

    def test_missing_record_reported_not_fabricated(self):
        def missing(url):
            raise HTTPError(url, 404, 'not found', None, None)
        result = run_pilot(self.kev, self.base/'out', limit=1, min_records=1, fetcher=missing)
        self.assertEqual(result['cve_records_imported'], 0)
        self.assertEqual(result['sqlite_counts']['cve_total'], 0)
        with (self.base/'out/pilot-cve-observations.csv').open(encoding='utf-8-sig') as f:
            row = next(csv.DictReader(f))
        self.assertEqual(row['status'], 'failed')
        self.assertIn('HTTPError', row['error'])

    def test_identifier_mismatch_rejected(self):
        data = self.fetch_ok(cve_url(self.sample[0]))
        result = run_pilot(self.kev, self.base/'out', limit=1, min_records=1,
                           fetcher=lambda _: data.replace(self.sample[0].encode(), b'CVE-2026-9999999'))
        self.assertEqual(result['cve_records_imported'], 0)

    def test_suspiciously_small_kev_feed_refused(self):
        with self.assertRaisesRegex(ValueError, 'too small'):
            run_pilot(self.kev, self.base/'out', limit=1, min_records=1000, fetcher=self.fetch_ok)

    def test_kev_count_mismatch_refused(self):
        self.source['count'] = len(self.source['vulnerabilities'])+1
        self.kev.write_text(json.dumps(self.source))
        with self.assertRaisesRegex(ValueError, 'count'):
            run_pilot(self.kev, self.base/'out', limit=1, min_records=1, fetcher=self.fetch_ok)

    def test_record_oversize_guard(self):
        result = run_pilot(self.kev, self.base/'out', limit=1, min_records=1,
                           fetcher=lambda _: b' '*(2*1024*1024 + 1))
        self.assertEqual(result['cve_records_imported'], 0)
        self.assertEqual(result['cve_records_missing_or_invalid'], 1)

    def test_explicit_sample_cap(self):
        with self.assertRaisesRegex(ValueError, 'sample size'):
            run_pilot(self.kev, self.base/'out', limit=500, min_records=1, fetcher=self.fetch_ok)

if __name__ == '__main__':
    unittest.main()
