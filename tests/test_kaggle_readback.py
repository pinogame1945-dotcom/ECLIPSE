"""Offline exact-file private Kaggle readback tests (no network and no credentials)."""
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from test_full_baseline import BaselineTests
from eclipse_l0.full_baseline import process
from eclipse_l0.kaggle_full import prepare
from eclipse_l0.kaggle_readback import check_ref, files_to_fetch, fetch_one

class TargetedReadbackTests(unittest.TestCase):
    def setUp(self):
        td=tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.root=Path(td.name)
        fixture=BaselineTests()
        fixture.root=self.root
        self.archive=fixture.archive(count=1000)

    def test_reject_unexpected_dataset(self):
        with self.assertRaises(ValueError):
            check_ref("someone/other-dataset")

    def test_targeted_download_hash_verification(self):
        stage=self.root/"stage"
        process(self.archive,stage,None,shard_size=250)
        prepare(stage)
        index=stage/"archive-index.json"
        from eclipse_l0.full_baseline import sha
        dest=self.root/"download"
        calls=[]
        def simulated(cmd, **kwargs):
            calls.append(cmd)
            shutil.copyfile(stage/cmd[cmd.index("--file")+1],dest/cmd[cmd.index("--file")+1])
            return subprocess.CompletedProcess(cmd, 0, "", "")
        fetch_one("someone/eclipse-cve-full-20261010-v1", "archive-index.json",
                  sha(index), index.stat().st_size, dest, runner=simulated, sleeper=lambda _:None)
        self.assertEqual(len(calls),1)
        self.assertIn("--file",calls[0])
        self.assertIn("--unzip",calls[0])
        fetch_one("someone/eclipse-cve-full-20261010-v1","archive-index.json",
                  sha(index),index.stat().st_size,dest,runner=simulated,sleeper=lambda _:None)
        self.assertEqual(len(calls),1)

    def test_changed_provider_bytes_fail_closed(self):
        stage=self.root/"stage"
        process(self.archive,stage,None,shard_size=250)
        prepare(stage)
        from eclipse_l0.full_baseline import sha
        dest=self.root/"returned"
        def corrupted(cmd,**kwargs):
            (dest/"archive-index.json").write_bytes(b"X"* (stage/"archive-index.json").stat().st_size)
            return subprocess.CompletedProcess(cmd, 0, "", "")
        with self.assertRaisesRegex(ValueError,"hash differs"):
            fetch_one("someone/eclipse-cve-full-20261010-v1","archive-index.json",
                sha(stage/"archive-index.json"),(stage/"archive-index.json").stat().st_size,
                dest,runner=corrupted,sleeper=lambda _:None)

if __name__=="__main__":
    unittest.main()
