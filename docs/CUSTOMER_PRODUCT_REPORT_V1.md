# ECLIPSE — Customer product vulnerability report v1

**Goal:** Given a customer-maintained list of products, make a *readable and actionable
review candidate report*, rather than a generic 403,696-CVE dump. The user wants
this ahead of experimental EPSS forecasting. Separate vendor-advisory ingestion
is being independently verified; this report neither edits nor depends on it.

## Output and limitations

In a **private authorized environment only**, generate together:
- `customer-product-report.pptx`: editable Japanese executive summary, product
  by product counts, up to 40 leading CVE candidates and up to 8 evidence detail
  slides. Slides visibly say that installed-version impact is **not assessed**.
- `customer-product-report.json`: candidate evidence, every product's counts,
  SHA-256 provenance for CVE/KEV/EPSS, data date, clear unverified-impact labels,
  and a bounded preview with explicit truncation counts.
- `candidate-vulnerabilities.csv`: **all selected product-CVE candidate rows**,
  untruncated, including publisher version predicates as original JSON, CVE links,
  installed-version label, KEV, EPSS and CVSS. CSV cell formula injection is escaped.
- `customer-product-report.manifest.json`: slide and source-JSON digest receipt.

**No unverified impact or remediation:** The CVE v5 `affected[]` array may
contain `unaffected` versions. Matching its *exact publisher-supplied*
vendor+product label only establishes **potential relevance for human review**,
not that the installed product version is exploitable. Even a KEV entry does
not show customer compromise. This v1 intentionally does not parse arbitrary
version ranges, infer aliases, import inventory, or invent a vendor patch level.

## Input schema

Inventory MUST be kept outside a public repository:

```json
{
  "schema_version": 1,
  "customer_name": "PRIVATE_CLIENT_IDENTIFIER",
  "products": [
    {
      "id": "client-firewall-type-a",
      "vendor": "Fortinet",
      "product": "FortiOS",
      "installed_version": "customer-verified-version-or-null",
      "aliases": [
        {"vendor": "Fortinet", "product": "FortiOS Operating System"}
      ]
    }
  ]
}
```

`id` is unique within a profile. `installed_version` can be omitted or null;
it is **only displayed**, not interpreted as a match to a version interval.
`aliases` are an **explicit user-approved list** of official alternative
publisher strings. There is NO heuristic substring matching or cross-vendor
joining. Zero matched CVEs means **unknown**, not safe.

The public `config/SYNTHETIC-product-inventory-example.json` is entirely
fictional. Its product strings are illustrative and are not customer devices.

## Private/local usage

First reconstruct the already-verified pinned 2026-10-10 warehouse **in an
access-controlled local environment**. The 1.54 GB SQLite file includes
403,696 CVE records and separately captured CISA KEV / FIRST EPSS data.
Actual customer inventory MUST NOT go to public GitHub, GitHub Actions
artifacts, the public repo, or public Kaggle. The production CLI does not
perform any network calls.

```bash
python -m pip install -r requirements.txt
export PYTHONPATH=src
python -m eclipse_reports.customer_products \
  --db /private/ecl-warehouse.sqlite3 \
  --inventory /private/customer-products.json \
  --out-dir /private/customer-report \
  --as-of 2026-10-10 --days 90 --mode recent
python -m eclipse_reports.customer_product_slides \
  --report-json /private/customer-report/customer-product-report.json \
  --out /private/customer-report/customer-product-report.pptx
```

`recent` (default) reports CVE records published/updated in the
last 90 days **or listed in KEV**, regardless of age. In `all` mode it reports
all historical published CVE product references for the listed products.
Both modes count every matching published CVE over the entire retained
history per product. A CSV exports every in-scope match; JSON/PPTX are
summaries, not full dumps. For newer reports, `--as-of` is a user-selected
report-date; **the underlying source remains fixed to October 10, 2026**.
Stale EPSS is labelled and not used to rank candidates. Freshness must be
assessed before sending to a customer.

## Public proof, with synthetic inventory ONLY

The one-shot `one-shot-demo-customer-product-report.yml` restores the existing
SHA-verified warehouse into a fresh runner, runs unit tests, and generates
the same 3 formats for an explicitly fictional demo inventory. It uploads
the demo report as a short-lived artifact **only** because the inventory is
fictional; there is no automation for real customer uploads or delivery.

## Intended next work

1. Establish private product inventory intake with authorized storage, version
   provenance, customer-specific scoping and update timestamp.
2. Independently verify/complete the separate official vendor-advisory source
   pipeline, then add **evidence-locked vendor patch/exposure statements**.
3. Validate affected version ranges per vendor semantics; introduce
   `AFFECTED / NOT_AFFECTED / NEEDS_REVIEW` only when supporting evidence
   is sufficient, and ensure false-positive/false-negative audit tests.
4. Add private report approval, distribution controls, generation cadence and
   source freshness monitoring. Avoid inventing false certainty from CVSS/EPSS.

Existing early-warning research is **not** part of the customer report path.
