#!/usr/bin/env python3
"""Public-repo V1.0 design fingerprint verifier (operating rules v1.0.1).

The complete private golden source, all 45 protected parts and renderer live
in the downloadable V1.0.1 package; this is a public-safe lightweight gate.
Extra slides may repeat approved designs; unapproved layouts always fail.
"""
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
R = "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}id"
SLIDE_REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/slide"

def digest(data):
    return hashlib.sha256(data).hexdigest()

def shape_hash(xml):
    root = etree.fromstring(xml)
    for node in root.iter(A):
        node.text = ""
    return digest(etree.tostring(root, method="c14n", with_comments=False))

def ordered_parts(z):
    p=etree.fromstring(z.read("ppt/presentation.xml"))
    rels=etree.fromstring(z.read("ppt/_rels/presentation.xml.rels"))
    rmap={r.get("Id"):r for r in rels}
    nodes=p.findall(".//{%s}sldId"%"http://schemas.openxmlformats.org/presentationml/2006/main")
    result=[]
    for node in nodes:
        relation=rmap.get(node.get(R))
        if relation is None or relation.get("Type")!=SLIDE_REL:
            raise ValueError("missing slide relationship")
        target=relation.get("Target")
        if not re.fullmatch(r"slides/slide[0-9]+\.xml",target or ""):
            raise ValueError("unexpected slide target")
        result.append("ppt/"+target)
    if len(set(result))!=len(result):
        raise ValueError("duplicate slide")
    return result

def verify(path, spec):
    errors=[]
    try:
        with ZipFile(path) as z:
            files=set(z.namelist())
            if z.testzip():errors.append("invalid zip member")
            ps=etree.fromstring(z.read("ppt/presentation.xml"))
            size=ps.find("{%s}sldSz"%P)
            if size is None or [int(size.get("cx")),int(size.get("cy"))]!=spec["size_emu"]:
                errors.append("page size changed")
            expected=spec["slide_style_signatures"]
            parts=ordered_parts(z)
            if len(parts)<len(expected):errors.append("some approved baseline slides removed")
            if len(parts)>spec.get("pagination",{}).get("max_pages",250):
                errors.append("page count exceeds limit")
            if set(parts)!={f for f in files if re.fullmatch(r"ppt/slides/slide[0-9]+\.xml",f)}:
                errors.append("orphan slide parts")
            next_base=1
            for i,name in enumerate(parts,1):
                if name not in files:
                    errors.append(f"slide {i}: missing source");continue
                actual=shape_hash(z.read(name))
                m=re.fullmatch(r"ppt/slides/slide([0-9]+)\.xml",name)
                number=int(m.group(1)) if m else -1
                if number<=len(expected):
                    if number!=next_base:errors.append(f"slide {i}: baseline ordering changed")
                    next_base+=1
                    if actual!=expected[number-1]:errors.append(f"slide {i}: original design altered")
                elif actual not in expected:
                    errors.append(f"slide {i}: non-approved design detected")
                raw=etree.fromstring(z.read(name))
                content=" ".join((n.text or "") for n in raw.iter(A))
                for phrase in ("自社で使用している製品と稼働バージョンの照合から始めてください",
                               "該当する製品を探してください","読み順","このレポートでは"):
                    if phrase in content:errors.append(f"slide {i}: banned phrase")
            if next_base!=len(expected)+1:errors.append("not all original pages preserved")
            for name,sha in spec["protected_base"].items():
                if name not in files or digest(z.read(name))!=sha:
                    errors.append("protected theme/master/layout changed: "+name)
    except Exception as e:
        errors.append("cannot inspect PPTX: "+str(e))
    return errors

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("pptx",type=Path)
    parser.add_argument("--spec",type=Path,default=Path(__file__).resolve().parents[1]/"design_lock.json")
    args=parser.parse_args()
    spec=json.loads(args.spec.read_text(encoding="utf-8"))
    issues=verify(args.pptx,spec)
    if issues:
        for error in issues:print("REJECT:",error)
        sys.exit(1)
    print("PASS: ECLIPSE weekly V1.0 approved design; extra approved pages allowed.")
    print("NOT A FACT-CHECK: confirm CVEs, versions, text overflow and actual font rendering.")

if __name__=="__main__":
    main()
