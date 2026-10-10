"""Audit the real, user-approved 126 source rows independently of synthetic risk tests."""
from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
import unittest

from eclipse_l0.weekly_important import validate_policy, vendor_key

POLICY=Path(__file__).resolve().parents[1]/"config/important_vendor_126.json"

class ApprovedVendorRegistryTest(unittest.TestCase):
    def test_126_presets_104_distinct_vendor_labels_and_14_categories(self):
        policy=json.loads(POLICY.read_text(encoding="utf-8"))
        aliases, unique=validate_policy(policy)
        self.assertEqual(unique,104)
        self.assertEqual(policy["source_sheet"],"監視プリセット候補")
        self.assertEqual(policy["expected_unique_vendors"],104)
        entries=policy["entries"]
        self.assertEqual(len(entries),126)
        self.assertEqual(len({row["source_row_id"] for row in entries}),126)
        self.assertEqual({row["source_row_id"].split("-")[0] for row in entries},
                         {f"{i:02d}" for i in range(1,15)})
        for i, row in enumerate(entries,1):
            self.assertTrue(row["source_row_id"].endswith(f"-{i:03d}"))
            self.assertEqual(row["aliases"],[])
            self.assertTrue(row["product_scope"])
            self.assertIn(row["preset_priority"],["P0","P1","P2"])
        self.assertEqual(Counter(row["preset_priority"] for row in entries),
                         {"P0":65,"P1":60,"P2":1})
        for name in ("Cisco","Microsoft","Fortinet","Palo Alto Networks","Siemens",
                     "Apple","Broadcom / VMware","Debian Project"):
            self.assertIn(vendor_key(name),aliases)
        self.assertEqual(len(aliases),104)
        self.assertEqual(policy["source_raw_xlsx_sha256"],
                         "NOT_AVAILABLE_FROM_AUTHORIZED_RAW_BYTES")

if __name__=="__main__":
    unittest.main()
