"""Offline Kaggle full source integrity and recovery tests."""
import json
import tempfile
import unittest
from pathlib import Path
from test_full_baseline import BaselineTests
from eclipse_l0.full_baseline import process, sha
from eclipse_l0.kaggle_full import prepare, verify


class KaggleFullTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)

    def make_zip(self):
        maker = BaselineTests()
        maker.root = self.root
        return maker.archive(count=1000)

    def test_complete_roundtrip_and_resume(self):
        source=self.make_zip()
        stage=self.root/'dataset'
        m=process(source,stage,None,shard_size=200)
        self.assertEqual(m['cve_member_count'],1000)
        self.assertEqual(m['records_staged'],1000)
        self.assertEqual(len(m['shards']),5)
        self.assertTrue(all(s['file'].endswith('.cvepack') for s in m['shards']))
        index=prepare(stage)
        self.assertEqual(index['record_count'],1000)
        expected=sha(stage/'archive-index.json')
        report=verify(stage,self.root/'rebuild',expected)
        self.assertEqual(report['records_checked'],1000)
        self.assertEqual(report['sqlite_sample_count'],5)
        process(source,stage,None,shard_size=200)
        self.assertEqual(prepare(stage),index)
        self.assertEqual(sha(stage/'archive-index.json'),expected)

    def test_corrupt_shard_or_index_rejected(self):
        source=self.make_zip()
        stage=self.root/'dataset'
        process(source,stage,None,shard_size=250)
        prepare(stage)
        expected=sha(stage/'archive-index.json')
        target=sorted(stage.glob('*.cvepack'))[0]
        target.write_bytes(b'CORRUPTED')
        with self.assertRaisesRegex(ValueError,'modified'):
            verify(stage,self.root/'rebuild',expected)
        with self.assertRaisesRegex(ValueError,'hash'):
            prepare(stage)
        with self.assertRaisesRegex(ValueError,'index'):
            verify(stage,self.root/'other','f'*64)

    def test_sample_cannot_be_labeled_full(self):
        source=self.make_zip()
        stage=self.root/'sample'
        process(source,stage,1000)
        with self.assertRaisesRegex(ValueError,'complete source'):
            prepare(stage)

if __name__=='__main__':unittest.main()
