"""Synthetic offline CVE baseline sampling and source-selection safety tests."""
import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from eclipse_l0.full_baseline import acquire, members, process, select_asset


class BaselineTests(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.root = Path(t.name)

    def archive(self, nested=False, count=1000, mutate=None):
        data = io.BytesIO()
        with zipfile.ZipFile(data, 'w', zipfile.ZIP_DEFLATED) as z:
            for i in range(count):
                ident = f'CVE-2026-{10000 + i}'
                body = {'cveMetadata': {'cveId': ident, 'state': 'PUBLISHED'}, 'containers': {'cna': {}}}
                if mutate and i == 0:
                    body['cveMetadata']['cveId'] = mutate
                z.writestr(f'cves/2026/{ident}.json', json.dumps(body))
        target = self.root / 'official.zip.zip'
        if nested:
            with zipfile.ZipFile(target, 'w', zipfile.ZIP_DEFLATED) as z:
                z.writestr('inner.zip', data.getvalue())
        else:
            target.write_bytes(data.getvalue())
        return target

    def test_doubled_zip_and_release_selection(self):
        def release(date, suffix):
            name = date + '_all_CVEs_at_midnight.zip' + suffix
            return {'tag_name': 'cve_' + date + '_1000Z', 'assets': [
                {'name': name, 'size': 623918711, 'id': 12,
                 'browser_download_url': 'https://github.com/CVEProject/cvelistV5/releases/download/foo/' + name}]}
        doc = [release('2026-10-09', ''), release('2026-10-10', '.zip')]
        self.assertEqual(select_asset(doc)['name'], '2026-10-10_all_CVEs_at_midnight.zip.zip')
        doc[1]['assets'][0]['size'] = 99999999999
        with self.assertRaisesRegex(ValueError, 'oversize'):
            select_asset(doc)

    def test_direct_and_nested_layout_and_resume(self):
        for nested in (False, True):
            with self.subTest(nested=nested):
                a = self.archive(nested=nested)
                stage = self.root / ('stage-nested' if nested else 'stage-direct')
                result = process(a, stage, 1000, shard_size=250)
                self.assertEqual(result['cve_member_count'], 1000)
                self.assertEqual(len(result['shards']), 4)
                before = (stage/'shards/000000-000249.zip').read_bytes()
                process(a, stage, 1000, shard_size=250)
                self.assertEqual(before, (stage/'shards/000000-000249.zip').read_bytes())
                with zipfile.ZipFile(stage/'shards/000000-000249.zip') as z:
                    first_name = z.namelist()[0]
                    body = z.read(first_name)
                    self.assertEqual(json.loads(body)['cveMetadata']['cveId'], first_name[:-5])

    def test_mutation_detected_before_publish(self):
        a = self.archive(mutate='CVE-2026-888888')
        with self.assertRaisesRegex(ValueError, 'mismatch'):
            process(a, self.root/'stage', 1000)
        self.assertFalse((self.root/'stage/manifest.json').exists())

    def test_resume_rejects_corrupt_existing_shard(self):
        a = self.archive()
        stage = self.root/'stage'
        process(a, stage, 1000)
        p = stage/'shards/000000-000499.zip'
        p.write_bytes(b'garbage')
        with self.assertRaises(zipfile.BadZipFile):
            process(a, stage, 1000)

    def test_zip_slip_and_duplicate_ids(self):
        p = self.root/'bad.zip'
        with zipfile.ZipFile(p, 'w') as z:
            z.writestr('../CVE-2026-10000.json', '{}')
        with zipfile.ZipFile(p) as z, self.assertRaisesRegex(ValueError, 'Unsafe'):
            members(z)
        with zipfile.ZipFile(p, 'w') as z:
            z.writestr('one/CVE-2026-10000.json', '{}')
            z.writestr('two/CVE-2026-10000.json', '{}')
        with zipfile.ZipFile(p) as z, self.assertRaisesRegex(ValueError, 'Duplicate CVE'):
            members(z)

    def test_partial_download_refuses_ignored_range(self):
        raw = self.archive().read_bytes()
        asset = {'name':'official.zip.zip', 'url':'https://github.com/CVEProject/cvelistV5/releases/download/tag/official.zip.zip',
                 'bytes':len(raw), 'asset_id':123, 'tag':'tag'}
        from eclipse_l0.full_baseline import write_json
        directory = self.root/'download'
        directory.mkdir()
        write_json(directory/(asset['name']+'.source.json'), {k: asset[k] for k in ('name','url','bytes','asset_id','tag')})
        (directory/(asset['name']+'.part')).write_bytes(raw[:100])
        class FakeResponse(io.BytesIO):
            status = 200
            headers = {}
            def getcode(self): return self.status
        class Manager:
            def __enter__(self):return FakeResponse(raw)
            def __exit__(self, *_):pass
        with self.assertRaisesRegex(ValueError, 'byte-range'):
            acquire(asset, directory, opener=lambda req, timeout: Manager())
        self.assertEqual((directory/(asset['name']+'.part')).stat().st_size,100)


if __name__ == '__main__':
    unittest.main()
