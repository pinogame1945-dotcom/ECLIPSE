# Enterprise vendor expansion batch 2 — 2026-10-10

Only `feature/vendor-source-registry-20261010`; **do not touch main**.
Google Chrome remains on hold.

Six separately tracked official publication candidates: Cisco public PSIRT JSON; Oracle Critical Patch Updates; SAP public Security Patch Day monthly bulletin; VMware/Broadcom VMSA; Drupal Core advisory; Apache httpd 2.4 aggregated vulnerability bulletin.

All start as `not_tested`. Synthetic tests are not live proof. Source-index discovery, individual detail, identity, allowlisted HTTPS and scope-limited CVE references are verified per source in the branch-only `.github/workflows/vendor-enterprise-batch2-probe.yml`. No one-source or six-source coverage inferred from success on one sample.

No product/firmware fixed-version or exploitation assertion; no source terms of use cleared; no permanent storage added; prior vendor Kaggle V1/V2 and fixed CVE corpus remain unmodified. New sources are only promoted upon live trace evidence and separate SQLite idempotence checks.
