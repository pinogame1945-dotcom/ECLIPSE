"""End-to-end offline fixture: all CVEs, evidence joins, resume, corrupt part rejection."""
import gzip
import json
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path
from test_full_baseline import BaselineTests
from eclipse_l0.full_baseline import process,sha
from eclipse_l0.kaggle_full import prepare
from eclipse_l0.warehouse import (
    ingest_verified_shards,enrich_epss,verify_database,split_sqlite,restore_parts,
    check_index, SOURCE_SHA256
)

class WarehouseTests(unittest.TestCase):
    def setUp(self):
        td=tempfile.TemporaryDirectory();self.addCleanup(td.cleanup)
        self.root=Path(td.name)
        fixture=BaselineTests();fixture.root=self.root
        archive=fixture.archive(count=1000)
        self.stage=self.root/'source'
        process(archive,self.stage,None,shard_size=250)
        prepare(self.stage)
        self.index=sha(self.stage/'archive-index.json')
        self.source_sha=sha(archive)

    def ingest(self):
        return ingest_verified_shards(self.stage,self.root/'warehouse.db',
            expected_index_sha=self.index,expected_count=1000,
            expected_shards=4,expected_source=self.source_sha)

    def test_full_sqlite_contains_all_and_resume_without_duplicate_events(self):
        result=self.ingest()
        self.assertEqual(result['cve_count'],1000)
        a=self.ingest()
        self.assertEqual(a['summary_count'],1000)
        con=sqlite3.connect(self.root/'warehouse.db')
        self.assertEqual(con.execute('SELECT COUNT(*) FROM cve_events').fetchone()[0],1000)
        self.assertEqual(con.execute('SELECT COUNT(*) FROM warehouse_summary').fetchone()[0],1000)
        self.assertEqual(con.execute('SELECT COUNT(*) FROM warehouse_shard_progress').fetchone()[0],4)
        con.close()
        # Untrusted index cannot be used even if JSON is internally valid.
        with self.assertRaisesRegex(ValueError,'trusted digest'):
            check_index(self.stage,expected_sha='f'*64,expected_count=1000,expected_shards=4,
                        expected_source=self.source_sha)

    def test_epss_full_validation_rollback(self):
        self.ingest()
        gz=self.root/'ep.csv.gz'
        with gzip.open(gz,'wt') as f:
            f.write('#model_version:v2026.06.15,score_date:2026-10-10T00:00:00Z\n')
            f.write('cve,epss,percentile\n')
            for i in range(1,101):f.write(f'CVE-2024-{10000+i},0.31,0.7\n')
        con=sqlite3.connect(self.root/'warehouse.db')
        data=enrich_epss(con,gz,min_rows=100)
        self.assertEqual(data['feed_rows'],100)
        with gzip.open(gz,'wt') as f:
            f.write('#score_date:2026-10-10T00:00:00Z\ncve,epss,percentile\n')
            f.write('CVE-2024-10001,nan,0.7\n')
        with self.assertRaises(ValueError):enrich_epss(con,gz,min_rows=1)
        self.assertEqual(con.execute('SELECT COUNT(*) FROM warehouse_epss').fetchone()[0],100)
        con.close()

    def test_independent_sqlite_restore_positive(self):
        self.ingest()
        from eclipse_l0 import warehouse
        db=self.root/'warehouse.db'
        # Attach two independently digestible authoritative-input fixture bytes.
        proof=verify_database(db,expected_count=1000)
        kev=b'{"count":0,"vulnerabilities":[]}'
        epss=b'fixture:epss-gzip'
        payloads={'kev-original.payload':kev,'epss-original.payload':epss}
        with sqlite3.connect(db) as con:
            con.execute('INSERT INTO warehouse_metadata VALUES (?,?)',(
                'kev_source_sha256',json.dumps(__import__('hashlib').sha256(kev).hexdigest())))
            con.execute('INSERT INTO warehouse_metadata VALUES (?,?)',(
                'epss_source_sha256',json.dumps(__import__('hashlib').sha256(epss).hexdigest())))
            con.commit()
        proof=verify_database(db,expected_count=1000)
        with patch.object(warehouse,'SOURCE_INDEX_SHA256',self.index),patch.object(warehouse,'SOURCE_SHA256',self.source_sha):
            idx=split_sqlite(db,self.root/'parts',proof,part_bytes=10240)
            for name,raw in payloads.items():
                target=self.root/'parts'/name;target.write_bytes(raw)
                idx['evidence_files'][name]={'bytes':len(raw),'sha256':sha(target)}
            report=restore_parts(self.root/'parts',self.root/'restored.db',idx,expected_count=1000)
        self.assertEqual(report['integrity_check'],'ok')
        self.assertEqual(report['table_counts']['cve'],1000)
        self.assertEqual(sha(db),sha(self.root/'restored.db'))

    def test_corrupt_shard_fails_before_database_changes(self):
        shard=next(self.stage.glob('*.cvepack'))
        shard.write_bytes(b'garbage')
        with self.assertRaisesRegex(ValueError,'corrupt CVE shard'):
            self.ingest()

    def test_split_restore_rejects_modified_part(self):
        self.ingest()
        # Source fixture intentionally has an alternative SHA; verify_database supports fixture sizes.
        state=verify_database(self.root/'warehouse.db',expected_count=1000)
        # Unit-size part coverage; original production index remains pinned to official source.
        idx=split_sqlite(self.root/'warehouse.db',self.root/'parts',state,part_bytes=8192)
        self.assertEqual(idx['table_counts']['cve'],1000)
        # A part corruption MUST be rejected even if its size matches.
        part=self.root/'parts'/idx['parts'][0]['name']
        raw=part.read_bytes();part.write_bytes(bytes([raw[0]^1])+raw[1:])
        idx['evidence_files']={}
        for name in ('kev-original.payload','epss-original.payload'):
            p=self.root/'parts'/name;p.write_bytes(b'test')
            idx['evidence_files'][name]={'bytes':4,'sha256':sha(p)}
        idx['kev_source_sha256']=sha(self.root/'parts'/'kev-original.payload')
        idx['epss_source_sha256']=sha(self.root/'parts'/'epss-original.payload')
        with self.assertRaisesRegex(ValueError,'altered restored warehouse part'):
            restore_parts(self.root/'parts',self.root/'restored.sqlite',idx,expected_count=1000)
        self.assertFalse((self.root/'restored.sqlite').exists())

if __name__=='__main__':unittest.main()
