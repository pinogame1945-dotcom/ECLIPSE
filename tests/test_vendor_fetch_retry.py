"""Fail-closed network retry and missing-table extraction tests; offline only."""
import io
import json
from pathlib import Path
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError

from eclipse_l0.vendor_pilot import OfficialFetch,normalize
from eclipse_l0.vendor_registry import load_registry

REGISTRY=load_registry(Path(__file__).resolve().parents[1]/"config/vendor_source_registry.json")
SOURCES={x["source_id"]:x for x in REGISTRY["sources"]}


class BytesResponse(io.BytesIO):
    def __init__(self,url,raw):
        super().__init__(raw)
        self.url=url


class RetryOpener:
    def __init__(self,url,raw):
        self.url=url
        self.raw=raw
        self.count=0
    def open(self,request,timeout):
        self.count+=1
        if self.count==1:
            raise HTTPError(self.url,503,"temporary publisher outage",{},None)
        return BytesResponse(self.url,self.raw)


class RetryAndIncompleteEvidenceTest(unittest.TestCase):
    def test_retries_transient_official_503_once(self):
        s=SOURCES["fortinet-psirt"]
        url=s["discovery_url"]
        getter=OfficialFetch(s)
        opener=RetryOpener(url,b"<rss>test</rss>")
        with patch("eclipse_l0.vendor_pilot.build_opener",return_value=opener), \
             patch("eclipse_l0.vendor_pilot.time.sleep"):
            result=getter.get(url)
        self.assertEqual(result,b"<rss>test</rss>")
        self.assertEqual(getter.total,2)

    def test_does_not_retry_permanent_not_found(self):
        s=SOURCES["fortinet-psirt"]
        getter=OfficialFetch(s)
        url=s["discovery_url"]
        class Always404:
            def __init__(self):self.count=0
            def open(self,request,timeout):
                self.count+=1
                raise HTTPError(url,404,"not found",{},None)
        opener=Always404()
        with patch("eclipse_l0.vendor_pilot.build_opener",return_value=opener), \
             patch("eclipse_l0.vendor_pilot.time.sleep"):
            with self.assertRaises(HTTPError):
                getter.get(url)
        self.assertEqual(opener.count,1)

    def test_missing_fortinet_impact_table_is_explicitly_unknown(self):
        source=SOURCES["fortinet-psirt"]
        item={"id":"FG-IR-22-059","title":"SYNTHETIC older security advisory",
              "url":"https://fortiguard.fortinet.com/psirt/FG-IR-22-059"}
        body=("""<html><body><h1>FG-IR-22-059 CVE-2022-88888</h1>"""
              """<p>This synthetic older advisory has no automatically-parsable
              impacted product table. Absence of a parsed field must not imply
              the affected products are empty, fixed, patched, or exempt.
              Manual validation is required before customer distribution.
              The page itself is official in shape but the test fixture is fake.</p>
              </body></html>""").encode()
        facts=normalize(source,item,body)
        self.assertEqual(facts["impact_table_extraction"],"not_extracted")
        self.assertEqual(facts["affected"],[])
        self.assertIn("CVE-2022-88888",facts["cve_ids"])
        self.assertIn("Missing affected rows"," ".join(facts["extraction_notes"]))

    def test_bad_fortinet_page_without_advisory_identity_fails(self):
        source=SOURCES["fortinet-psirt"]
        item={"id":"FG-IR-22-059","title":"Fake advisory",
              "url":"https://fortiguard.fortinet.com/psirt/FG-IR-22-059"}
        body=b"<html><body>Login screen with no vulnerability detail; "+b"no evidence "*25+b"</body></html>"
        with self.assertRaisesRegex(ValueError,"No impact table"):
            normalize(source,item,body)
