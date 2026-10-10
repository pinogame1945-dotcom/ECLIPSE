"""Mandatory pinned weekly V1.0 PowerPoint source gate (fail closed).

The approved golden PPTX is intentionally not stored in the PUBLIC GitHub
repository. A listed Project/Library file is NOT a byte-accessible source.
No generic template and no prior synthetic slide is a valid fallback.

Usage:
    python -m eclipse_reports.weekly_template_gate verify --source PRIVATE_ZIP_OR_PPTX
    python -m eclipse_reports.weekly_template_gate extract --source PRIVATE_ZIP_OR_PPTX --out verified-golden.pptx
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import zipfile

MAX_SOURCE_BYTES=24*1024*1024
MAX_PPTX_BYTES=10*1024*1024
GOLDEN_NAME="WEEKLY_GOLDEN_V1.0.pptx"
EXPECTED_SPEC=Path(__file__).resolve().parents[2]/"templates/weekly_v1/design_lock.json"
PPTX_REQUIRED={"[Content_Types].xml","ppt/presentation.xml","ppt/theme/theme1.xml"}


class MissingApprovedTemplate(ValueError):
    """Cannot create a standards-compliant report without golden source bytes."""


def digest(data:bytes)->str:
    return hashlib.sha256(data).hexdigest()


def source_bytes(path:Path)->bytes:
    path=Path(path)
    if not path.is_file() or path.is_symlink():
        raise MissingApprovedTemplate(
            "Approved source PPTX/ZIP not byte-accessible: no fallback template is permitted. "
            "Attach ECLIPSE_WEEKLY_TEMPLATE_V1.0.1.zip or WEEKLY_GOLDEN_V1.0.pptx to this work.")
    if path.stat().st_size>MAX_SOURCE_BYTES:
        raise MissingApprovedTemplate("Approved source exceeds bounded size")
    return path.read_bytes()


def _get_golden(source:Path)->bytes:
    original=source_bytes(source)
    if source.name==GOLDEN_NAME:
        return original
    if source.suffix.lower()!=".zip":
        raise MissingApprovedTemplate("Expected the approved golden PPTX or V1.0.1 delivery ZIP, not an arbitrary slide deck")
    with zipfile.ZipFile(io.BytesIO(original)) as z:
        names=z.namelist()
        candidates=[n for n in names if n.split("/")[-1]==GOLDEN_NAME
                    and not n.startswith("/") and ".." not in n.split("/")
                    and "\\" not in n]
        if len(candidates)!=1:
            raise MissingApprovedTemplate("Template package must contain exactly one WEEKLY_GOLDEN_V1.0.pptx")
        member=z.getinfo(candidates[0])
        if member.file_size>MAX_PPTX_BYTES:
            raise MissingApprovedTemplate("Golden PPTX inside template ZIP exceeds maximum size")
        return z.read(member)


def verify_source(source:Path, *,spec_path:Path=EXPECTED_SPEC)->dict:
    spec=json.loads(Path(spec_path).read_text(encoding="utf-8"))
    if (spec.get("golden_name")!=GOLDEN_NAME or
        spec.get("content_status")!="UNVERIFIED_SAMPLE_NOT_FOR_CUSTOMERS" or
        not re.fullmatch("[a-f0-9]{64}",spec.get("approved_sample_sha256",""))):
        raise MissingApprovedTemplate("Missing or modified approved design lock")
    data=_get_golden(source)
    actual=digest(data)
    if actual!=spec["approved_sample_sha256"]:
        raise MissingApprovedTemplate(
            "Golden template SHA-256 MISMATCH; unapproved replacement or corrupted PPTX. "
            "Never approximate the original design.")
    if not 0<len(data)<=MAX_PPTX_BYTES:
        raise MissingApprovedTemplate("Invalid golden PPTX size")
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        missing=PPTX_REQUIRED-set(z.namelist())
        if missing or z.testzip():
            raise MissingApprovedTemplate("Pinned golden PPTX ZIP container corrupted")
        slide_count=sum(bool(re.fullmatch(r"ppt/slides/slide\d+\.xml",n)) for n in z.namelist())
        if slide_count!=spec["sample_pages"]:
            raise MissingApprovedTemplate("Approved golden PPTX page count changed")
        for name,sha256 in spec["protected_base"].items():
            if name not in z.namelist() or digest(z.read(name))!=sha256:
                raise MissingApprovedTemplate("Approved protected slide part altered: "+name)
    return {
      "status":"APPROVED_WEEKLY_GOLDEN_V1_0_BYTES_VERIFIED",
      "golden_name":GOLDEN_NAME,
      "golden_sha256":actual,
      "base_slides":slide_count,
      "can_use_as_source":True,
      "source_is_content_verified_for_customer_release":False,
      "no_generated_layout_fallback":True,
    }


def extract_source(source:Path,destination:Path,*,spec_path:Path=EXPECTED_SPEC)->dict:
    # Verify FIRST. Do not overwrite an existing report/template.
    receipt=verify_source(source,spec_path=spec_path)
    destination=Path(destination)
    if destination.exists() or destination.is_symlink():
        raise MissingApprovedTemplate("Refusing overwrite of template target")
    destination.parent.mkdir(parents=True,exist_ok=True)
    with destination.open("xb") as f:
        f.write(_get_golden(source))
    if digest(destination.read_bytes())!=receipt["golden_sha256"]:
        destination.unlink(missing_ok=True)
        raise MissingApprovedTemplate("Golden template changed during extraction")
    return receipt


def main():
    p=argparse.ArgumentParser(description="Required weekly design source byte gate; no generic fallback")
    sub=p.add_subparsers(dest="cmd",required=True)
    for name in ("verify","extract"):
        q=sub.add_parser(name)
        q.add_argument("--source",required=True,type=Path)
        if name=="extract":q.add_argument("--out",required=True,type=Path)
    args=p.parse_args()
    result=(verify_source(args.source) if args.cmd=="verify"
            else extract_source(args.source,args.out))
    print(json.dumps(result,ensure_ascii=False,sort_keys=True,indent=2))


if __name__=="__main__":
    main()
