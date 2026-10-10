import json
import sys
import tempfile
import unittest
from pathlib import Path
from zipfile import ZipFile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from eclipse_l0.core import (audit, connect, export_current, get_original, ingest_cve_zip,
                             ingest_kev_json, report)


def cve(cve_id, description='First description', state='PUBLISHED'):
    return {'dataType': 'CVE_RECORD', 'dataVersion': '5.2',
            'cveMetadata': {'cveId': cve_id, 'state': state,
                            'datePublished': '2026-01-01T00:00:00Z'},
            'containers': {'cna': {'descriptions': [{'lang': 'en', 'value': description}]}}}


def make_zip(path, records):
    with ZipFile(path, 'w') as z:
        for rec in records:
            cid = rec['cveMetadata']['cveId']
            z.writestr(f'cves/2026/12xxx/{cid}.json', json.dumps(rec))


def make_kev(path, rows):
    path.write_text(json.dumps({'title': 'CISA Known Exploited Vulnerabilities Catalog',
                                'vulnerabilities': rows}), encoding='utf8')


def kev_entry(cid, date='2026-10-10'):
    return {'cveID': cid, 'dateAdded': date, 'vendorProject': 'TestVendor',
            'product': 'TestProduct', 'vulnerabilityName': 'Example',
            'requiredAction': 'Follow official guidance', 'dueDate': date}


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.p = Path(self.dir.name)
        self.db = connect(self.p / 'state' / 'eclipse.sqlite3')
        self.addCleanup(self.db.close)
        self.cid = 'CVE-2026-12345'
        self.cid2 = 'CVE-2026-12346'

    def test_ingest_change_history_and_replay(self):
        a = self.p / 'baseline1.zip'
        make_zip(a, [cve(self.cid), cve(self.cid2, state='REJECTED')])
        self.assertEqual(ingest_cve_zip(self.db, a, 'base-1', min_records=2)['changes'], 2)
        self.assertEqual(report(self.db)['cve_rejected'], 1)
        # Same source label = exact no-op
        self.assertEqual(ingest_cve_zip(self.db, a, 'base-1', min_records=2)['changes'], 0)
        b = self.p / 'baseline2.zip'
        make_zip(b, [cve(self.cid, 'Changed description'), cve(self.cid2, state='REJECTED')])
        self.assertEqual(ingest_cve_zip(self.db, b, 'base-2', min_records=2)['changes'], 1)
        self.assertEqual(report(self.db)['cve_versions'], 3)
        old_hash = self.db.execute('SELECT old_hash FROM cve_events WHERE cve_id=? ORDER BY id DESC',
                                   (self.cid,)).fetchone()[0]
        self.assertIn(b'First description', get_original(self.db, old_hash))
        csv_path = self.p / 'export.csv'
        self.assertEqual(export_current(self.db, csv_path), 2)
        self.assertIn('kev_present', csv_path.read_text(encoding='utf-8-sig'))

    def test_kev_change_removal_restoration(self):
        k = self.p / 'kev.json'
        make_kev(k, [kev_entry(self.cid), kev_entry(self.cid2)])
        self.assertEqual(ingest_kev_json(self.db, k, 'kev1', min_records=2)['changes'], 2)
        self.assertEqual(ingest_kev_json(self.db, k, 'kev1', min_records=2)['changes'], 0)
        make_kev(k, [kev_entry(self.cid)])
        # Deliberate TEST override: small fixtures allow >5% shrink.
        self.assertEqual(ingest_kev_json(self.db, k, 'kev2', min_records=1, max_removed_fraction=.6)['changes'], 1)
        self.assertEqual(report(self.db)['kev_present'], 1)
        make_kev(k, [kev_entry(self.cid), kev_entry(self.cid2)])
        self.assertEqual(ingest_kev_json(self.db, k, 'kev3', min_records=2)['changes'], 1)
        kinds = [r[0] for r in self.db.execute('SELECT kind FROM kev_events ORDER BY id')]
        self.assertEqual(kinds, ['added', 'added', 'removed', 'restored'])

    def test_reject_incomplete_feed_before_removals(self):
        k = self.p / 'kev.json'
        ids = [f'CVE-2026-{12000+i}' for i in range(10)]
        make_kev(k, [kev_entry(cid) for cid in ids])
        ingest_kev_json(self.db, k, 'kev1', min_records=10)
        make_kev(k, [kev_entry(cid) for cid in ids[:5]])
        with self.assertRaisesRegex(ValueError, 'shrank'):
            ingest_kev_json(self.db, k, 'kev2', min_records=1)
        self.assertEqual(report(self.db)['kev_present'], 10)

    def test_corrupt_or_partial_baseline_does_not_complete(self):
        bad = self.p / 'bad.zip'
        with ZipFile(bad, 'w') as z:
            z.writestr('cves/2026/12xxx/CVE-2026-12345.json', json.dumps(cve(self.cid)))
            z.writestr('cves/2026/12xxx/CVE-2026-12346.json', b'{not-json')
        with self.assertRaises(json.JSONDecodeError):
            ingest_cve_zip(self.db, bad, 'corrupt1', min_records=2, batch_size=1)
        self.assertEqual(report(self.db)['source_runs_incomplete'], 1)
        # The already-committed first record is retained, safely replayable.
        self.assertEqual(report(self.db)['cve_total'], 1)

    def test_prevent_older_baseline_rollback(self):
        fresh = self.p / 'fresh.zip'
        make_zip(fresh, [cve(self.cid)])
        ingest_cve_zip(self.db, fresh, '2026-10-10_all_CVEs_at_midnight.zip', min_records=1)
        old = self.p / 'old.zip'
        make_zip(old, [cve(self.cid, 'older record')])
        with self.assertRaisesRegex(ValueError, 'older CVE'):
            ingest_cve_zip(self.db, old, '2026-10-09_all_CVEs_at_midnight.zip', min_records=1)
        self.assertEqual(report(self.db)['cve_versions'], 1)
        self.assertEqual(audit(self.db)['sqlite_quick_check'], 'ok')

    def test_reject_archive_name_mismatch(self):
        bad = self.p / 'wrong.zip'
        with ZipFile(bad, 'w') as z:
            z.writestr('cves/2026/12xxx/CVE-2026-12345.json', json.dumps(cve(self.cid2)))
        with self.assertRaisesRegex(ValueError, 'disagrees'):
            ingest_cve_zip(self.db, bad, 'wrong', min_records=1)


if __name__ == '__main__':
    unittest.main()
