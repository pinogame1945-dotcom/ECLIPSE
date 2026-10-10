"""Fail-closed golden template tests without distributing private source PPTX."""
from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

from eclipse_reports.weekly_template_gate import (
    GOLDEN_NAME, MissingApprovedTemplate, extract_source, verify_source,
)


def _pptx():
    out=io.BytesIO()
    with zipfile.ZipFile(out,"w",compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml","<types/>")
        z.writestr("ppt/presentation.xml","<presentation/>")
        z.writestr("ppt/theme/theme1.xml","<theme/>")
        for i in range(1,20):
            z.writestr(f"ppt/slides/slide{i}.xml",f"<slide>{i}</slide>")
    return out.getvalue()


def _package(payload,name=GOLDEN_NAME):
    out=io.BytesIO()
    with zipfile.ZipFile(out,"w",compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr(name,payload)
    return out.getvalue()


class WeeklyGoldenPreflightTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root=Path(temp.name)
        self.original=_pptx()
        self.spec=self.root/"lock.json"
        self.spec.write_text(json.dumps({
            "golden_name":GOLDEN_NAME,
            "approved_sample_sha256":hashlib.sha256(self.original).hexdigest(),
            "content_status":"UNVERIFIED_SAMPLE_NOT_FOR_CUSTOMERS",
            "sample_pages":19,
            "protected_base":{
                "ppt/theme/theme1.xml":hashlib.sha256(b"<theme/>").hexdigest()
            },
        }))

    def test_exact_original_source_is_accepted_without_changes(self):
        golden=self.root/GOLDEN_NAME
        golden.write_bytes(self.original)
        proof=verify_source(golden,spec_path=self.spec)
        self.assertTrue(proof["can_use_as_source"])
        self.assertTrue(proof["no_generated_layout_fallback"])
        self.assertFalse(proof["source_is_content_verified_for_customer_release"])

    def test_original_inside_delivery_zip_is_accepted_and_extracted_bit_identical(self):
        packaged=self.root/"ECLIPSE_WEEKLY_TEMPLATE_V1.0.1.zip"
        packaged.write_bytes(_package(self.original,"package/"+GOLDEN_NAME))
        target=self.root/"verified.pptx"
        extract_source(packaged,target,spec_path=self.spec)
        self.assertEqual(target.read_bytes(),self.original)
        with self.assertRaisesRegex(MissingApprovedTemplate,"Refusing overwrite"):
            extract_source(packaged,target,spec_path=self.spec)

    def test_missing_library_only_source_must_fail_without_fallback(self):
        ghost=self.root/"ECLIPSE_WEEKLY_TEMPLATE_V1.0.1.zip"
        with self.assertRaisesRegex(MissingApprovedTemplate,"not byte-accessible"):
            verify_source(ghost,spec_path=self.spec)

    def test_wrong_template_hash_cannot_be_replaced_with_custom_design(self):
        unapproved=self.root/GOLDEN_NAME
        unapproved.write_bytes(self.original+b"extra bytes")
        with self.assertRaisesRegex(MissingApprovedTemplate,"MISMATCH"):
            verify_source(unapproved,spec_path=self.spec)

    def test_untrusted_zip_member_name_is_rejected(self):
        z=self.root/"delivery.zip"
        z.write_bytes(_package(self.original,"../../"+GOLDEN_NAME))
        with self.assertRaisesRegex(MissingApprovedTemplate,"exactly one"):
            verify_source(z,spec_path=self.spec)

    def test_ambiguous_archive_multiple_golden_files_is_rejected(self):
        z=self.root/"delivery.zip"
        output=io.BytesIO()
        with zipfile.ZipFile(output,"w") as f:
            f.writestr(GOLDEN_NAME,self.original)
            f.writestr("also/"+GOLDEN_NAME,self.original)
        z.write_bytes(output.getvalue())
        with self.assertRaisesRegex(MissingApprovedTemplate,"exactly one"):
            verify_source(z,spec_path=self.spec)

    def test_wrong_filename_not_substituted_even_if_slide_bytes_match(self):
        fake=self.root/"placeholder.pptx"
        fake.write_bytes(self.original)
        with self.assertRaisesRegex(MissingApprovedTemplate,"Expected"):
            verify_source(fake,spec_path=self.spec)

    def test_corrupted_protected_design_part_rejected_even_if_hash_in_lock_matches(self):
        wrong_lock=json.loads(self.spec.read_text())
        wrong_lock["protected_base"]["ppt/theme/theme1.xml"]="0"*64
        self.spec.write_text(json.dumps(wrong_lock))
        golden=self.root/GOLDEN_NAME
        golden.write_bytes(self.original)
        with self.assertRaisesRegex(MissingApprovedTemplate,"protected slide part altered"):
            verify_source(golden,spec_path=self.spec)


if __name__=="__main__":
    unittest.main()
