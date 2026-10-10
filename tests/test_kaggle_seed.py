"""Purely synthetic, offline Kaggle data transport tests."""
import json
import tempfile
import unittest
from pathlib import Path

from eclipse_l0.cve_seed import run_batch
from eclipse_l0.kaggle_seed import BUNDLE_NAME, INDEX_NAME, prepare, verify

class KaggleSeedTransportTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root=Path(temp.name)
        self.state=self.root/'state'
        self.state.mkdir()
        rows={}
        for i in range(1005):
            cve=f'CVE-2026-{10000+i}'
            rows[cve]={'cveID':cve, 'dateAdded':'2026-10-10'}
        (self.state/'kev-current.json').write_text(json.dumps({'schema_version':1,'source_sha256':'a'*64,'records':rows}))
        def fake(url):
            cve=url.rsplit('/',1)[-1].replace('.json','')
            return json.dumps({'cveMetadata':{'cveId':cve,'state':'PUBLISHED'}}).encode()
        run_batch(self.state,batch_size=2,max_total=2,fetcher=fake)

    def test_prepared_bundle_round_trip_and_rebuild(self):
        src=self.root/'staged'
        index=prepare(self.state,src,expected_records=2)
        self.assertEqual(index['record_count'],2)
        self.assertTrue((src/BUNDLE_NAME).is_file())
        restored=verify(src,self.root/'restore',expected_records=2)
        self.assertEqual(restored['sqlite_cve_count'],2)
        self.assertEqual(restored['sqlite_quick_check'],'ok')

    def test_wrong_expected_count_and_reused_staging_refused(self):
        src=self.root/'staged'
        with self.assertRaisesRegex(ValueError,'approved record count'):
            prepare(self.state,src,expected_records=100)
        prepare(self.state,src,expected_records=2)
        with self.assertRaisesRegex(ValueError,'reuse'):
            prepare(self.state,src,expected_records=2)

    def test_tampered_archive_rejected(self):
        src=self.root/'staged'
        prepare(self.state,src,expected_records=2)
        target=src/BUNDLE_NAME
        target.write_bytes(target.read_bytes()+b'BAD')
        with self.assertRaisesRegex(ValueError,'altered'):
            verify(src,self.root/'restore',expected_records=2)

    def test_manifest_index_binding_and_recovery_dir_reuse(self):
        src=self.root/'staged'
        prepare(self.state,src,expected_records=2)
        with self.assertRaisesRegex(ValueError,'index'):
            verify(src,self.root/'restore',expected_records=2,expected_index_sha256='f'*64)
        verify(src,self.root/'restore',expected_records=2)
        with self.assertRaisesRegex(ValueError,'empty'):
            verify(src,self.root/'restore',expected_records=2)

    def test_corrupt_member_manifest_rejected(self):
        src=self.root/'staged'
        prepare(self.state,src,expected_records=2)
        idx=json.loads((src/INDEX_NAME).read_text())
        idx['members']['../escape.txt']={'bytes':1,'sha256':'f'*64}
        (src/INDEX_NAME).write_text(json.dumps(idx))
        with self.assertRaisesRegex(ValueError,'Unsafe'):
            verify(src,self.root/'restore',expected_records=2)
