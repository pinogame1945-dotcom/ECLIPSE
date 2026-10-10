import json
import tempfile
import unittest
from pathlib import Path

from eclipse_l1.evidence import dossier, from_files
from eclipse_l0.epss import SOURCE


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.record={'cveMetadata':{'cveId':'CVE-2026-123456','state':'PUBLISHED',
                                    'datePublished':'2026-10-08T10:00:00Z'},
                     'containers':{'cna':{'descriptions':[{'lang':'en','value':'Test advisory says condition requires local access.'}],
                                           'affected':[{'vendor':'Example Vendor','product':'Widget',
                                                        'versions':[{'version':'1.0','status':'affected'}]}],
                                           'references':[{'url':'https://vendor.example/advisories/test'}]}}}
        self.kev={'cveID':'CVE-2026-123456','dateAdded':'2026-10-10',
                  'requiredAction':'Follow official vendor guidance.'}
        self.epss={'source': SOURCE,'score_date':'2026-10-10',
                   'source_sha256':'fake_fixture_hash',
                   'scores':{'CVE-2026-123456':{'epss':0.2,'percentile':0.8}}}

    def test_evidence_keeps_raw_text_and_citations(self):
        result=dossier(self.record,kev=self.kev,epss=self.epss)
        self.assertEqual(result['epss_score'],0.2)
        self.assertTrue(result['kev_listed_in_supplied_feed'])
        self.assertEqual(result['affected_unverified'][0]['product'],'Widget')
        self.assertTrue(all(x['evidence'] for x in result['claims']))
        self.assertIn('not an asset-specific',result['interpretation_caveat'])

    def test_mismatched_kev_does_not_associate(self):
        with self.assertRaisesRegex(ValueError,'does not match'):
            dossier(self.record,kev=dict(self.kev,cveID='CVE-2026-888888'))

    def test_missing_sources_is_not_no_risk(self):
        result=dossier(self.record)
        self.assertIsNone(result['epss_score'])
        self.assertIsNone(result['kev_date_added'])
        self.assertTrue(any('NOT evidence of absence' in x['statement'] for x in result['claims']))

    def test_cli_input_output_evidence_json(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            source=root/'input.json';out=root/'evidence.json'
            source.write_text(json.dumps(self.record))
            result=from_files(source,out)
            self.assertEqual(json.loads(out.read_text())['cve_id'],result['cve_id'])


if __name__=='__main__':
    unittest.main()
