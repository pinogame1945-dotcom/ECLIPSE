# Vendor expansion: wave 3 / 2026-10-10

Work exclusively on `feature/vendor-source-registry-20261010`. Main, CVE warehouse, KEV/EPSS pipelines and PRIVATE Kaggle V1/V2 are unchanged.

Ten new **unverified** public source candidates: Juniper JSA, HPE PSIRT, IBM security bulletins, NetApp PSIRT, Jenkins, Grafana, NGINX OSS, OpenSSL, Apache Tomcat and WordPress Core. Chrome is deliberately skipped. Initial status of **all ten** is `not_tested`: a page found online or a synthetic test does not establish live data ingestion. Some vendors require JavaScript or authorization and may fail the official static HTML probe.

No customer data, no hidden authenticated endpoints, no raw publisher HTML checked into git. The independent source registry must retain explicit failures and publisher URL/hash proofs before marking any source `read_parse_verified`. No original CVE replaced, no CVE-free advisories thrown out, no customer affected-version inference.

Technical details: Jenkins/Grafana per-advisory URLs; Juniper/HPE/IBM/NetApp official publisher-specific index patterns; Tomcat by-major-branch and NGINX/OpenSSL aggregate catalogs (aggregate does NOT mean new individual CVEs); WordPress security announcement article URLs.

GitHub Actions: `.github/workflows/vendor-wave3-probe.yml`. A source that passes a single article can next proceed to short-lived SQLite/idempotent replay; only then should a later PRIVATE Kaggle V3/V4 immutable generation be planned and verified. Weekly report coverage remains unverified. License review remains pending.


## Evidence update (2026-10-10, wave3)
Official read/parse from [Actions 38062701918](https://github.com/pinogame1945-dotcom/ECLIPSE/actions/runs/38062701918): **6/10 PASS**: Jenkins (20 CVE references), Grafana (1), nginx public aggregate (62), OpenSSL vulnerability aggregate (300), Tomcat 11 aggregate (86), WordPress security release (0 CVEs, announcement retained). These reference counts are not newly published distinct CVEs. Four source-specific probes failed and remain quarantined: Juniper, HPE, IBM (no validated index/detail links with current static HTML), NetApp (very large official RSS with no validated title/link pairs in bounded prefix). A failed parser or missing CVE count is never 'not affected'.

The 6 successful sources are single sampled documents with no human review, no weekly completeness guarantee, no product/firmware version determination, and no legal republication approval. A separate branch-only SQLite proof is `.github/workflows/vendor-wave3-six-sqlite.yml`. The existing private Kaggle V1/V2 remain unchanged; do not count this proof as permanent storage.
