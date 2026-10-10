import json
import tempfile
import unittest
from datetime import date
from pathlib import Path

from pptx import Presentation

from eclipse_l0.core import connect, export_kev_catalog, ingest_kev_json
from eclipse_reports.pipeline import build


ROOT = Path(__file__).resolve().parents[1]


class FullPipelineTests(unittest.TestCase):
    def test_validated_l0_to_editable_pptx(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            out = root / 'out/report.pptx'
            source = ROOT / 'examples/SYNTHETIC-kev-sample.json'
            db = root / 'eclipse.db'
            result = build(source, db, ROOT / 'config/customer-network-example.json',
                           out, date(2026, 10, 9), date(2026, 10, 9),
                           demo=True, min_records=1)
            self.assertEqual(result['selected_count'], 2)
            self.assertEqual(result['l0_ingestion']['status'], 'completed')
            self.assertEqual(result['l0_sqlite_audit'], 'ok')
            self.assertTrue(out.is_file())
            self.assertEqual(len(Presentation(out).slides), 6)
            # Re-run with the identical source, but no duplicate source-run events.
            result2 = build(source, db, ROOT / 'config/customer-network-example.json',
                            out, date(2026, 10, 9), date(2026, 10, 9),
                            demo=True, min_records=1)
            self.assertEqual(result2['l0_ingestion']['status'], 'already_completed')

    def test_catalog_count_guard_blocks_bad_source(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'kev.json'
            original = json.loads((ROOT / 'examples/SYNTHETIC-kev-sample.json').read_text())
            original['count'] = 1000000
            path.write_text(json.dumps(original))
            with connect(Path(d) / 'test.db') as con:
                with self.assertRaisesRegex(ValueError, 'count disagrees'):
                    ingest_kev_json(con, path, 'bad', min_records=1)
                with self.assertRaisesRegex(ValueError, 'No completed KEV'):
                    export_kev_catalog(con, Path(d) / 'export.json')

    def test_no_report_from_insufficient_real_feed(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            with self.assertRaisesRegex(ValueError, 'suspiciously small'):
                build(ROOT / 'examples/SYNTHETIC-kev-sample.json', root / 'db.sqlite3',
                      ROOT / 'config/customer-all-example.json', root / 'output.pptx',
                      date(2026, 10, 9), date(2026, 10, 9))
            self.assertFalse((root / 'output.pptx').exists())
