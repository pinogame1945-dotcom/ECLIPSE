"""Offline-only tests; all CVEs, timestamps and advisories are synthetic."""
import copy
import gzip
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone, date
from pathlib import Path
from pptx import Presentation

from eclipse_l0.cve_delta import observe as observe_delta
from eclipse_l0.epss import select_scores, targets_from_kev_state
from eclipse_l0.advisory_feeds import parse_feed, observe_advisories
from eclipse_reports.event_report import render_events
from eclipse_l0.kev_monitor import observe as observe_kev

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 10, 10, 8, 0, tzinfo=timezone.utc)


def entry(stamp, ids, updates=()):
    def row(c):
        y=c.split('-')[1]
        return {'cveId': c, 'dateUpdated': stamp, 'githubLink':
                f'https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{y}/{c.split("-")[2][:2]}xxx/{c}.json'}
    return {'fetchTime': stamp, 'new': [row(c) for c in ids],
            'updated': [row(c) for c in updates], 'numberOfChanges': len(ids)+len(updates)}


class CVEDeltaTests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.base=Path(t.name)
        self.raw=self.base/'delta.json'
        self.state=self.base/'state'
        self.report=self.base/'run.json'
        self.rows=[entry('2026-10-10T05:00:00Z',['CVE-2026-12345'])]
        self.write()

    def write(self):
        self.raw.write_text(json.dumps(self.rows),encoding='utf-8')

    def run_observe(self,max_events=5000):
        return observe_delta(self.raw,self.state,self.report,max_events=max_events,observed_at=NOW)

    def test_baseline_suppresses_existing_deltas(self):
        baseline=self.run_observe()
        self.assertTrue(baseline['baseline'])
        self.assertEqual(baseline['event_count'],0)
        self.assertEqual(baseline['watermark_utc'],'2026-10-10T05:00:00.000+00:00')
        self.assertFalse(list(self.state.glob('cve-observations/*.jsonl')))

    def test_delta_incremental_and_noop(self):
        self.run_observe()
        self.rows += [entry('2026-10-10T06:00:00Z',['CVE-2026-23456']),
                      entry('2026-10-10T07:00:00Z',[],updates=['CVE-2026-12345'])]
        self.write()
        out=self.run_observe()
        self.assertEqual(out['event_count'],2)
        self.assertFalse(out['baseline'])
        again=self.run_observe()
        self.assertEqual(again['event_count'],0)
        lines=(self.state/'cve-observations/2026-10.jsonl').read_text().splitlines()
        self.assertEqual(len(lines),2)

    def test_bounded_batches_do_not_lose_simultaneous_groups(self):
        self.run_observe()
        self.rows += [entry('2026-10-10T06:00:00Z',['CVE-2026-23456','CVE-2026-23457']),
                      entry('2026-10-10T07:00:00Z',['CVE-2026-34567'])]
        self.write()
        first=self.run_observe(max_events=2)
        self.assertEqual(first['event_count'],2)
        self.assertTrue(first['more_backlog'])
        second=self.run_observe(max_events=2)
        self.assertEqual(second['event_count'],1)
        self.assertFalse(second['more_backlog'])
        self.assertEqual(self.run_observe(max_events=2)['event_count'],0)

    def test_gap_rejected_with_old_cursor_unchanged(self):
        self.run_observe()
        before=(self.state/'cve-delta-checkpoint.json').read_bytes()
        self.rows=[entry('2026-10-12T07:00:00Z',['CVE-2026-44444'])]
        self.write()
        with self.assertRaisesRegex(ValueError,'retention gap'):
            observe_delta(self.raw,self.state,self.report,observed_at=NOW+timedelta(days=3))
        self.assertEqual((self.state/'cve-delta-checkpoint.json').read_bytes(),before)

    def test_invalid_official_url_rejected(self):
        self.rows[0]['new'][0]['githubLink']='https://bad.example/CVE-2026-12345.json'
        self.write()
        with self.assertRaisesRegex(ValueError,'Untrusted'):
            self.run_observe()

    def test_batch_too_small_for_one_source_group_is_error(self):
        self.run_observe()
        self.rows.append(entry('2026-10-10T06:00:00Z',['CVE-2026-56789','CVE-2026-56790']))
        self.write()
        with self.assertRaisesRegex(ValueError,'exceeds bounded'):
            self.run_observe(max_events=1)


class EPSSParserTests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.base=Path(t.name)
        self.csv=self.base/'epss.csv.gz'
        self.out=self.base/'epss-result.json'

    def write(self, rows):
        with gzip.open(self.csv, 'wt') as f:
            f.write('#model_version:v4\n#score_date:2026-10-10\ncve,epss,percentile\n')
            for row in rows:
                f.write(row+'\n')

    def test_selected_scores_only_and_reproducibility(self):
        self.write(['CVE-2026-11111,0.8,0.98','CVE-2026-22222,0.2,0.55',
                    'CVE-2026-33333,0.001,0.08'])
        s=select_scores(self.csv,{'CVE-2026-11111','CVE-2026-99999'},self.out,min_scored=2)
        self.assertEqual(s['watched_count'],2)
        self.assertEqual(s['matched_count'],1)
        self.assertEqual(s['missing_ids'],['CVE-2026-99999'])
        self.assertEqual(s['scores']['CVE-2026-11111']['epss'],0.8)
        self.assertEqual(s['score_date'],'2026-10-10')
        self.assertEqual(json.loads(self.out.read_text()),s)

    def test_official_combined_metadata_version_and_timestamp(self):
        # Real FIRST daily feed places model_version and score_date on one line.
        with gzip.open(self.csv, 'wt') as f:
            f.write('#model_version:v2026.06.15,score_date:2026-10-10T12:03:43Z\\n'.replace('\\n', '\n'))
            f.write('cve,epss,percentile\\n'.replace('\\n', '\n'))
            f.write('CVE-2026-11111,0.8,0.98\\n'.replace('\\n', '\n'))
        result = select_scores(self.csv, {'CVE-2026-11111'}, self.out, min_scored=1)
        self.assertEqual(result['score_date'], '2026-10-10')
        self.assertEqual(result['score_timestamp'], '2026-10-10T12:03:43Z')
        self.assertEqual(result['model_version'], 'v2026.06.15')

    def test_fail_closed_before_creating_output(self):
        self.write(['CVE-2026-11111,1.8,0.98'])
        with self.assertRaisesRegex(ValueError,'out of range'):
            select_scores(self.csv,{'CVE-2026-11111'},self.out,min_scored=1)
        self.assertFalse(self.out.exists())

    def test_kev_state_targets(self):
        state=self.base/'state.json'
        state.write_text(json.dumps({'records': {'CVE-2026-11111': {'dateAdded': '2026-10-10'}}}))
        self.assertEqual(targets_from_kev_state(state),{'CVE-2026-11111'})


class VendorFeedsTests(unittest.TestCase):
    RSS='''<?xml version="1.0"?><rss version="2.0"><channel><title>Example vendor advisories</title>
    <item><title>Example security update CVE-2026-11111</title>
    <link>https://security.vendor.example/advisories/x</link>
    <description>Patch advisory under investigation</description><pubDate>Sat, 10 Oct 2026 10:00:00 GMT</pubDate></item></channel></rss>'''

    def setUp(self):
        t=tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.base=Path(t.name)
        self.xml=self.base/'advisory.xml'
        self.xml.write_text(self.RSS)
        self.state=self.base/'state'
        self.out=self.base/'advisory.json'

    def test_rss_baseline_and_update_are_vendor_agnostic(self):
        kw=dict(source_id='example-vendor',vendor='EXAMPLE',allowed_hosts=['security.vendor.example'])
        baseline=observe_advisories(self.xml,self.state,self.out,**kw,observed_at=NOW)
        self.assertTrue(baseline['baseline'])
        self.assertFalse(baseline['events'])
        new_xml=self.RSS.replace('Patch advisory under investigation','Official correction added')
        self.xml.write_text(new_xml)
        nextout=observe_advisories(self.xml,self.state,self.out,**kw,observed_at=NOW)
        self.assertEqual(nextout['event_count'],1)
        self.assertEqual(nextout['events'][0]['cve_ids'],['CVE-2026-11111'])
        self.assertEqual(observe_advisories(self.xml,self.state,self.out,**kw,observed_at=NOW)['event_count'],0)

    def test_unsafe_link_rejected(self):
        raw=self.RSS.replace('security.vendor.example','evil.example')
        with self.assertRaisesRegex(ValueError,'allowlist'):
            parse_feed(raw.encode(),source_id='example-vendor',vendor='EXAMPLE',allowed_hosts=['security.vendor.example'])

    def test_atom_and_doctype(self):
        atom=b'''<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom"><entry>
            <title>Vendor update</title><link rel="alternate" href="https://security.vendor.example/a"/>
            <updated>2026-10-10T00:00:00Z</updated><summary>Just metadata</summary>
            </entry></feed>'''
        rows=parse_feed(atom,source_id='example-vendor',vendor='EXAMPLE',allowed_hosts=['security.vendor.example'])
        self.assertEqual(len(rows),1)
        with self.assertRaisesRegex(ValueError,'Unsafe'):
            parse_feed(b'<!DOCTYPE rss><rss/>',source_id='example-vendor',vendor='EXAMPLE',allowed_hosts=['security.vendor.example'])


if __name__ == '__main__':
    unittest.main()
