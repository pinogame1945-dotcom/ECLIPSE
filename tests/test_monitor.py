import copy
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from pptx import Presentation

from eclipse_l0.kev_monitor import observe
from eclipse_reports.event_report import render_events

ROOT = Path(__file__).resolve().parents[1]
OBS = datetime(2026, 10, 10, 9, 25, tzinfo=timezone.utc)


class KEVMonitorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.feed = self.root / 'kev.json'
        self.state = self.root / 'state'
        self.events = self.root / 'outputs' / 'events.json'
        self.data = json.loads((ROOT / 'examples/SYNTHETIC-kev-sample.json').read_text(encoding='utf-8'))
        # use observed artificial records only for tests: never describe as live
        self.write()

    def write(self):
        self.data['count'] = len(self.data['vulnerabilities'])
        self.feed.write_text(json.dumps(self.data), encoding='utf-8')

    def observe(self):
        return observe(self.feed, self.state, self.events, min_records=1, observed_at=OBS)

    def test_first_run_is_baseline_and_no_alarm(self):
        out = self.observe()
        self.assertTrue(out['baseline'])
        self.assertEqual(out['event_count'], 0)
        self.assertEqual(out['catalog_count'], len(self.data['vulnerabilities']))
        self.assertTrue((self.state / 'kev-current.json').exists())
        self.assertFalse((self.state / 'events' / '2026-10.jsonl').exists())

    def test_noop_same_source_does_not_modify_durable_files(self):
        self.observe()
        original = (self.state / 'kev-current.json').read_bytes()
        second = self.observe()
        self.assertFalse(second['baseline'])
        self.assertFalse(second['state_changed'])
        self.assertEqual(second['event_count'], 0)
        self.assertEqual((self.state / 'kev-current.json').read_bytes(), original)

    def test_added_updated_removed_change_event_and_idempotence(self):
        self.observe()
        original = copy.deepcopy(self.data['vulnerabilities'][0])
        next_cve = copy.deepcopy(original)
        next_cve['cveID'] = 'CVE-2026-900111'
        next_cve['dateAdded'] = '2026-10-09'
        self.data['vulnerabilities'].append(next_cve)
        self.data['vulnerabilities'][0]['requiredAction'] = 'Apply update.'
        out = self.data['vulnerabilities'].pop(1)
        self.write()
        result = self.observe()
        self.assertEqual((result['added_count'], result['updated_count'], result['removed_count']), (1, 1, 1))
        self.assertEqual(result['material_event_count'], 3)
        self.assertTrue(all(e['event_id'] for e in result['events']))
        self.assertIn('requiredAction', next(e['changed_fields'] for e in result['events'] if e['kind'] == 'updated'))
        log = self.state / 'events/2026-10.jsonl'
        self.assertEqual(len(log.read_text().splitlines()), 3)
        twice = self.observe()
        self.assertEqual(twice['event_count'], 0)
        self.assertEqual(len(log.read_text().splitlines()), 3)
        # Re-adding a previously removed record is observed as new membership.
        self.data['vulnerabilities'].append(out)
        self.write()
        third = self.observe()
        self.assertEqual(third['added_count'], 1)

    def test_metadata_only_change_has_no_vulnerability_event(self):
        self.observe()
        self.data['catalogVersion'] = '2099.9'
        self.write()
        changed = self.observe()
        self.assertTrue(changed['state_changed'])
        self.assertEqual(changed['event_count'], 0)

    def test_corrupt_count_fails_without_writing_state(self):
        self.data['count'] = 100000
        self.feed.write_text(json.dumps(self.data), encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'count mismatch'):
            self.observe()
        self.assertFalse((self.state/'kev-current.json').exists())

    def test_duplicate_cve_fails_and_preserves_state(self):
        self.observe()
        baseline = (self.state/'kev-current.json').read_bytes()
        self.data['vulnerabilities'].append(copy.deepcopy(self.data['vulnerabilities'][0]))
        self.write()
        with self.assertRaisesRegex(ValueError, 'Duplicate'):
            self.observe()
        self.assertEqual((self.state/'kev-current.json').read_bytes(), baseline)

    def test_invalid_date_and_invalid_state_fail_closed(self):
        self.data['vulnerabilities'][0]['dateAdded'] = '2026/01/01'
        self.write()
        with self.assertRaisesRegex(ValueError, 'dateAdded'):
            self.observe()
        self.data['vulnerabilities'][0]['dateAdded'] = '2026-10-09'
        self.write()
        self.observe()
        statefile = self.state / 'kev-current.json'
        state = json.loads(statefile.read_text())
        state['records']['CVE-2026-900987'] = dict(self.data['vulnerabilities'][0])
        statefile.write_text(json.dumps(state))
        with self.assertRaisesRegex(ValueError, 'persisted KEV'):
            self.observe()

    def test_mass_removal_guard(self):
        # 200 fake-but-valid rows, so 2 missing is allowed and 3 is rejected
        base = self.data['vulnerabilities'][0]
        self.data['vulnerabilities'] = [dict(base, cveID=f'CVE-2026-{10000+i}') for i in range(200)]
        self.write()
        self.observe()
        baseline = (self.state/'kev-current.json').read_bytes()
        self.data['vulnerabilities'] = self.data['vulnerabilities'][:-4]
        self.write()
        with self.assertRaisesRegex(ValueError, 'Mass removal'):
            self.observe()
        self.assertEqual((self.state/'kev-current.json').read_bytes(), baseline)

    def test_older_release_rejected(self):
        self.data['dateReleased'] = '2026-10-10T00:00:00Z'
        self.write()
        self.observe()
        self.data['dateReleased'] = '2026-10-09T00:00:00Z'
        self.write()
        with self.assertRaisesRegex(ValueError, 'older KEV release'):
            self.observe()

    def test_event_pptx_uses_observed_difference_not_date_added(self):
        self.observe()
        row = copy.deepcopy(self.data['vulnerabilities'][0])
        row['cveID'] = 'CVE-2026-998877'
        row['dateAdded'] = '2022-01-01'  # older KEV date deliberately
        row['vendorProject'] = 'Cisco'
        self.data['vulnerabilities'].append(row)
        self.write()
        self.observe()
        output = self.root/'reports'/'diff.pptx'
        report = render_events(self.events, ROOT/'config/customer-network-example.json', output)
        self.assertTrue(output.exists())
        self.assertGreaterEqual(len(Presentation(output).slides), 4)
        self.assertEqual(report['counts']['added'], 1)
        self.assertEqual(report['selected_count'], 1)
        # Replaying a no-op MUST NOT generate a false 'fresh' PowerPoint.
        self.observe()
        with self.assertRaisesRegex(ValueError, 'baseline/no-change'):
            render_events(self.events, ROOT/'config/customer-network-example.json', output)

    def test_non_matching_profile_zero_selected_but_durable_state_advances(self):
        self.observe()
        newrow = dict(self.data['vulnerabilities'][0], cveID='CVE-2026-990088', vendorProject='Random Vendor')
        self.data['vulnerabilities'].append(newrow)
        self.write()
        self.observe()
        report = render_events(self.events, ROOT/'config/customer-network-example.json', self.root/'diff.pptx')
        self.assertEqual(report['selected_count'], 0)


if __name__ == '__main__':
    unittest.main()
