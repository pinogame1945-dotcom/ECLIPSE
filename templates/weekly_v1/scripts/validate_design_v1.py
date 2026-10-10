#!/usr/bin/env python3
"""V1.0 fail-closed DESIGN checker. For the complete golden reference / all
45 protected XML parts, use the downloadable template pack validator."""
import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from zipfile import ZipFile
from lxml import etree

A = "{http://schemas.openxmlformats.org/drawingml/2006/main}t"
P = "http://schemas.openxmlformats.org/presentationml/2006/main"

def digest(data):
    return hashlib.sha256(data).hexdigest()

def shape_hash(xml):
    root = etree.fromstring(xml)
    for n in root.iter(A):
        n.text = ""
    return digest(etree.tostring(root, method="c14n", with_comments=False))

def verify(path, spec):
    errors = []
    with ZipFile(path) as z:
        files = set(z.namelist())
        if z.testzip():
            errors.append("invalid zip member")
        ps = etree.fromstring(z.read("ppt/presentation.xml"))
        size = ps.find("{%s}sldSz" % P)
        if size is None or [int(size.get("cx")), int(size.get("cy"))] != spec["size_emu"]:
            errors.append("page size changed")
        expected = spec["slide_style_signatures"]
        actual = sorted([f for f in files if re.fullmatch(r"ppt/slides/slide[0-9]+\.xml",f)], key=lambda f:int(re.search(r"slide([0-9]+)",f).group(1)))
        if len(actual) != len(expected):
            errors.append("unapproved number of slides")
        for i,name in enumerate(actual):
            if i >= len(expected):
                break
            raw=z.read(name)
            if shape_hash(raw)!=expected[i]:
                errors.append(f"slide {i+1}: design/typography/layout modified")
            root=etree.fromstring(raw)
            text=" ".join((el.text or "") for el in root.iter(A))
            for phrase in ("自社で使用している製品と稼働バージョンの照合から始めてください","該当する製品を探してください","読み順","このレポートでは"):
                if phrase in text:errors.append(f"slide {i+1}: banned phrase: {phrase}")
        for name, sha in spec["protected_base"].items():
            if name not in files or digest(z.read(name)) != sha:
                errors.append("protected theme/master/layout changed: "+name)
    return errors

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("pptx",type=Path)
    parser.add_argument("--spec",type=Path,default=Path(__file__).resolve().parents[1]/"design_lock.json")
    args=parser.parse_args()
    spec=json.loads(args.spec.read_text(encoding="utf-8"))
    violations=verify(args.pptx,spec)
    if violations:
        for error in violations:print("REJECT:",error)
        sys.exit(1)
    print("PASS: ECLIPSE weekly design V1.0, 19 reference layouts and core theme locked.")
    print("NOT A FACT-CHECK: vendor/CVE/fix evidence and visual overflow still require separate review.")

if __name__=="__main__":
    main()
