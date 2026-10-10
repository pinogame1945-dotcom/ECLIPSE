"""Offline-only, fake data. No real CVE/KEV or network used in CI."""
import json
import tempfile
import unittest
from pathlib import Path

from eclipse_l0.cve_seed import (run_batch, audit_seed, ABSOLUTE_CVE_CAP)


class SeedTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root=Path(temp.name)
        self.state=self.root/'data'
        self.state.mkdir()
        self.calls=[]
        records={}
        for i in range(1005):
            cve=f'CVE-2026-{10000+i}'
            records[cve]={'cveID':cve,'dateAdded':'2026-10-10',
                          'vendorProject':'FAKE','product':'NONEXISTENT'}
        self.kev={'schema_version':1,'source_sha256':'0'*64,'records':records}
        (self.state/'kev-current.json').write_text(json.dumps(self.kev))

    def fetch(self,url):
        cve=url.rsplit('/',1)[-1].removesuffix('.json')
        self.calls.append(cve)
        return json.dumps({'cveMetadata': {'cveId':cve,'state':'PUBLISHED'},
                           'containers':{'cna':{'descriptions':[{'lang':'en','value':'SYNTHETIC'}]}}}).encode()

    def test_resume_at_25_to_50_then_noop(self):
        first=run_batch(self.state,batch_size=25,max_total=50,fetcher=self.fetch)
        self.assertEqual(first['archived_cve_count'],25)
        self.assertEqual(first['new_cve_records'],25)
        self.assertEqual(len(self.calls),25)
        second=run_batch(self.state,batch_size=25,max_total=50,fetcher=self.fetch)
        self.assertEqual(second['archived_cve_count'],50)
        self.assertEqual(second['completed_shards'],2)
        self.assertEqual(len(self.calls),50)
        final=run_batch(self.state,batch_size=25,max_total=50,fetcher=self.fetch)
        self.assertTrue(final['no_op'])
        self.assertEqual(len(self.calls),50)
        self.assertEqual(audit_seed(self.state)['archived_cve_count'],50)

    def test_rebuild_sqlite_from_verbatim_bodies(self):
        run_batch(self.state,batch_size=10,max_total=10,fetcher=self.fetch)
        output=self.root/'recovered.sqlite3'
        result=audit_seed(self.state,export_sqlite=output)
        self.assertEqual(result['sqlite_quick_check'],'ok')
        self.assertEqual(result['sqlite_cve_count'],10)
        self.assertTrue(output.stat().st_size>0)

    def test_fail_atomic_if_any_one_official_record_missing(self):
        def fails_on_third(url):
            if len(self.calls)==2:
                raise ConnectionError('Injected source outage')
            return self.fetch(url)
        with self.assertRaises(ConnectionError):
            run_batch(self.state,batch_size=5,max_total=20,fetcher=fails_on_third)
        self.assertFalse((self.state/'cve-seed/manifest.json').exists())
        self.assertFalse((self.state/'cve-seed/cohort.json').exists())
        self.assertEqual(run_batch(self.state,batch_size=5,max_total=20,fetcher=self.fetch)['archived_cve_count'],5)
        self.calls.clear()
        def fails_second(url):
            if self.calls:
                raise ConnectionError('Injected outage')
            return self.fetch(url)
        original=(self.state/'cve-seed/manifest.json').read_bytes()
        with self.assertRaises(ConnectionError):
            run_batch(self.state,batch_size=5,max_total=20,fetcher=fails_second)
        self.assertEqual((self.state/'cve-seed/manifest.json').read_bytes(),original)
        self.assertEqual(audit_seed(self.state)['archived_cve_count'],5)

    def test_immutable_frozen_cohort_keeps_position(self):
        run_batch(self.state,batch_size=4,max_total=10,fetcher=self.fetch)
        first=self.calls[:4]
        cve='CVE-2026-9999999'
        self.kev['records'][cve]={'cveID':cve,'dateAdded':'2026-10-11','vendorProject':'FAKE','product':'FAKE'}
        (self.state/'kev-current.json').write_text(json.dumps(self.kev))
        run_batch(self.state,batch_size=4,max_total=10,fetcher=self.fetch)
        self.assertEqual(len(self.calls),8)
        self.assertNotIn(cve,self.calls)
        self.assertEqual(self.calls[:4],first)

    def test_corrupt_shard_and_cursor_rejected(self):
        run_batch(self.state,batch_size=2,max_total=10,fetcher=self.fetch)
        shard=next((self.state/'cve-seed/shards').glob('*.jsonl'))
        shard.write_text(shard.read_text().replace('SYNTHETIC','MUTATED'))
        with self.assertRaisesRegex(ValueError,'checksum'):
            audit_seed(self.state)
        with self.assertRaisesRegex(ValueError,'checksum'):
            run_batch(self.state,batch_size=2,max_total=10,fetcher=self.fetch)

    def test_record_cve_mismatch_fails_before_persistence(self):
        def wrong(_url):
            return b'{"cveMetadata":{"cveId":"CVE-2026-999999"}}'
        with self.assertRaisesRegex(ValueError,'body ID mismatch'):
            run_batch(self.state,batch_size=1,max_total=10,fetcher=wrong)
        self.assertFalse((self.state/'cve-seed').exists())

    def test_limits_enforced_before_any_fetch(self):
        for inputs in ({'batch_size':26,'max_total':50},
                       {'batch_size':25,'max_total':ABSOLUTE_CVE_CAP+1}):
            with self.assertRaisesRegex(ValueError,'bounded'):
                run_batch(self.state,fetcher=self.fetch,**inputs)
        self.assertFalse(self.calls)

    def test_shard_budget_fails_atomically(self):
        def oversized(_url):
            # Existing 2 MiB per-record cap catches this before writing.
            return b'x'*(2*1024*1024+1)
        with self.assertRaisesRegex(ValueError,'oversized'):
            run_batch(self.state,batch_size=1,max_total=10,fetcher=oversized)
        self.assertFalse((self.state/'cve-seed').exists())

    def test_reject_untracked_shard(self):
        run_batch(self.state,batch_size=2,max_total=10,fetcher=self.fetch)
        extra=self.state/'cve-seed/shards/9999-9999.jsonl'
        extra.write_text('garbage')
        with self.assertRaisesRegex(ValueError,'Untracked'):
            audit_seed(self.state)


if __name__=='__main__':
    unittest.main()
