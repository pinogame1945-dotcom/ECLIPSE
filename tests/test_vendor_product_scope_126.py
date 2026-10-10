"""Offline user 126-candidate row-id to official source reconciliation; no workbook in git."""
import json,re,unittest
from pathlib import Path
from collections import defaultdict,Counter
from eclipse_l0.vendor_registry import load_registry

ROOT=Path(__file__).resolve().parents[1]
class Product126Audit(unittest.TestCase):
 def setUp(self):
  self.matrix=json.loads((ROOT/"config/vendor_product_scope_126.json").read_text("utf-8"))
  self.registry=load_registry(ROOT/"config/vendor_source_registry.json")
 def test_attested_source_only_not_misleading_product_coverage(self):
  x=self.matrix
  self.assertEqual(x["verified_input_rows"],126)
  self.assertEqual(x["priority_counts"],{"P0":65,"P1":60,"P2":1})
  self.assertEqual(x["inspection_kind"],"SOURCE_LEVEL_SINGLE_SAMPLE_ONLY_NOT_PRODUCT_CVE_MAPPING")
  self.assertFalse(x["licensed_redistribution_approved"])
  self.assertTrue(x["manual_review_required"])
  self.assertFalse(x["whole_workbook_published"])
 def test_every_manual_relation_has_actual_source_and_no_double_count(self):
  x=self.matrix; known={v["source_id"]:v for v in self.registry["sources"]}
  self.assertEqual(len(known),36)
  self.assertEqual(sum(v["verification_status"]=="read_parse_verified" for v in known.values()),27)
  labels={"aligned":4,"partial":3,"publisher":2,"failed":1}
  records=defaultdict(list);keys=set()
  for row in x["relations"]:
   self.assertIn(row["source_id"],known)
   self.assertIn(row["relation"],labels)
   self.assertGreater(len(row["rationale"]),8)
   if row["relation"]=="failed":
    self.assertEqual(known[row["source_id"]]["verification_status"],"probe_failed")
   else:
    self.assertEqual(known[row["source_id"]]["verification_status"],"read_parse_verified")
   for rid in row["row_ids"]:
    self.assertRegex(rid,r"^(?:0[1-9]|1[0-4])-\d{3}$")
    self.assertTrue(1<=int(rid.split("-")[1])<=126)
    self.assertNotIn((rid,row["source_id"]),keys)
    keys.add((rid,row["source_id"]))
    records[rid].append(labels[row["relation"]])
  counts=Counter()
  for rownum in range(1,127):
   matches=[values for rid,values in records.items() if int(rid.split("-")[1])==rownum]
   self.assertLessEqual(len(matches),1)
   rank=max(matches[0]) if matches else 0
   counts[{0:"E",1:"D",2:"C",3:"B",4:"A"}[rank]]+=1
  self.assertEqual(dict(counts),x["summary_grades"])
 def test_high_priority_important_false_equivalence_guards(self):
  x=self.matrix
  entries={k for item in x["relations"] for k in item["row_ids"]}
  for rid in ("01-002","06-042","07-053","10-086","12-098","13-109","14-120"):
   self.assertNotIn(rid,entries,"These P0 source candidates have not yet been implemented")
  for id in ("03-023","12-104"):
   r=[x for x in self.matrix["relations"] if id in x["row_ids"]]
   self.assertEqual(r[0]["relation"],"publisher")
  chrome=[x for x in self.matrix["relations"] if x["source_id"]=="google-chrome-releases"]
  self.assertEqual(chrome[0]["relation"],"failed")
if __name__=="__main__":unittest.main()
