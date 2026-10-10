# PROJECT ECLIPSE — pinned CVE full SQLite warehouse (2026-10-10)

## Scope, provenance, boundaries

- **CVE original:** 403,696 CVE Project CVE V5 JSON records in 162 private-Kaggle `.cvepack` ZIP shards, independently hash-verified before SQLite import. The hard-pinned `archive-index.json` SHA-256 is stored in Git source code; do not trust a checksum provided by Kaggle alone.
- **Original JSON preserved verbatim:** SQLite `objects` holds zlib-compressed original JSON payloads; `cve_current` is indexed by the canonical CVE ID. Source events reflect a **historical baseline**, not fresh vulnerability sightings.
- **Queryable structure:** `warehouse_summary` holds the CNA English summary/title and CNA CVSS if explicitly supplied. `warehouse_affected` stores publisher-supplied vendor/product strings and raw version predicates, with exact casefolded lookup indexes. Missing affected data means **unknown**, not unaffected. ADP-affected rows retain their container origin. Additional published/update date indexes live on `cve_current`.
- **Enrichment:** Entire official CISA KEV catalog using pre-existing L0 historical ingestion; complete current FIRST EPSS gzip feed with score dates and original source digests. KEV membership is not a customer exploitation event. EPSS is a population-model estimate for the next 30 days, never a company-specific attack probability.
- **As-of caveat:** historical CVE snapshot is fixed to October 10, 2026. KEV and EPSS are collected at build time, thus are **not** historically as-of the pinned CVE snapshot. Source timestamps are kept separate; analyses must identify all three dates.

## Operational workflow

`one-shot-cve-warehouse.yml` is manually executable and runs once upon being added to `main`. Runs solely on ordinary GitHub-hosted CPU runner (no GPU, paid runner, or paid external services). Its first job creates a brand-new private Kaggle dataset `eclipse-cve-warehouse-20261010-v1`; it never edits an existing dataset. No customer assets, tokens, or source raw objects are committed to public GitHub. If an incomplete Kaggle dataset already exists, the job **fails closed**, rather than issuing a destructive `datasets version` overwrite.

The first job downloads source objects one-by-one via Kaggle's targeted `--file` API (bulk Kaggle export failed for the 162-shard source dataset), validates source digest, imports every JSON, joins KEV/EPSS, verifies counts/constraints, and chunks its SQLite file into opaque `.dbpart` files no larger than 64 MiB. It also archives the verbatim KEV JSON and FIRST EPSS gzip as opaque `.payload` files. Source-index and SQLite evidence manifests have SHA-256 for every independent piece. All the raw materials stay private in Kaggle.

A separate **new CPU runner** downloads every SQLite part and both source input payloads, compares trusted SHA-256s, reconstructs SQLite, performs `PRAGMA integrity_check`/`foreign_key_check` and checks source/key counts. Receipt metadata (not the DB) is exposed as a seven-day Actions artifact.

## Query examples for an authorized restored SQLite

```sql
-- CVE with authoritative publisher severity and joined enrichment
SELECT c.cve_id, c.record_state, c.date_published, s.description_en,
       s.cvss_score, s.cvss_kind, k.date_added AS kev_added,
       e.probability AS epss, e.percentile
FROM cve_current c
LEFT JOIN warehouse_summary s ON s.cve_id=c.cve_id
LEFT JOIN kev_current k ON k.cve_id=c.cve_id AND k.present=1
LEFT JOIN warehouse_epss e ON e.cve_id=c.cve_id
WHERE c.cve_id='CVE-2025-0001';

-- Exact normalized vendor/product attribution (not inferred product exposure)
SELECT a.cve_id, a.container, a.vendor, a.product, a.default_status,
       a.versions_json FROM warehouse_affected a
WHERE a.vendor_norm='fortinet' AND a.product_norm='fortios' LIMIT 20;
```

Never equate missing CVE record, affected product, KEV, or EPSS with security. This data is source evidence, not a vulnerability scanner.
