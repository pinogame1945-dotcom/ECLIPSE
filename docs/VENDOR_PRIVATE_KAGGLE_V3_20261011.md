# PRIVATE Vendor V3 / source expansion integration (2026-10-11)

Branch: `feature/vendor-source-registry-20261010` only; **never changes main**.

## What the successor does
- Reuse the previously independently verified PRIVATE Kaggle vendor V2 **160 official documents / 241 versions**, never overwrite it or V1.
- Verify PRE-UPLOAD V1 and V2 SHA256 proofs from immutable old GitHub Actions artifacts; retrieve V2 from PRIVATE Kaggle and prove SHA/SQLite.
- Copy V2 to a new child DB. Run 15 bounded **new, previously one-shot read/parse-verified publisher sources**, one newest documentary candidate per source: Mozilla, Debian, Apple, Adobe, Android, PostgreSQL, Cisco public, SAP public, Drupal Core, Apache httpd, Jenkins, nginx, OpenSSL, Tomcat, WordPress.
- Refuse any PARTIAL or degraded source; at least 12 of 15 must pass. Any 1–3 failed publisher sources must be explicitly listed as missing sample evidence; this is *never* complete source coverage. No source results are manufactured from old snapshots.
- Verify immutable prior events and full previous version rows, preserve first-observed for all V2 documents; reject rollback, no new official docs, offsite redirects or missing parser provenance.
- Stage a new Kaggle V3 index with parent index SHA, DB SHA, full source counts and errors, not raw publisher bodies, customer assets, or operational claims. **Only creates a NEW PRIVATE v3 slug**, never versions or overwrites V1/V2.
- A completely separate GitHub Actions runner retrieves V3 from Kaggle and compares its bytes with a trusted pre-upload index from the creating job, plus parent V1/V2 indices and SQLite integrity/counts.
- No changes to the CVE / KEV / EPSS databases. No long-running production schedule or downstream client advice activated.

Code `src/eclipse_l0/vendor_kaggle_v3.py`, tests `tests/test_vendor_kaggle_v3.py`, branch-only workflow `.github/workflows/vendor-kaggle-v3.yml`.

## Deployment and quality gates
The 25 sample-proven *publisher source IDs* are **not** 25 reliable production sources. Grafana succeeded once but its index was intermittent in subsequent SQLite rechecks; it is intentionally excluded from this Kaggle cohort. Other failed candidates (Chrome, Oracle, VMware, Juniper, HPE, IBM, NetApp) must not be marked as active. The private Kaggle snapshot remains parsed-unreviewed. Weekly source completeness, affected/fixed version semantics and commercial reuse rights remain NO-GO.

The 126 important product groups are a distinct candidate scope and MUST NOT be equated with the number of implemented source IDs. Any row-by-row matching requires the original spreadsheet's exact rows and product aliases.

An automatically created V3 or saved Actions artifact without **independent readback SUCCESS** is not a verified permanent snapshot. Review GitHub Actions proof before writing confirmed counts here.
