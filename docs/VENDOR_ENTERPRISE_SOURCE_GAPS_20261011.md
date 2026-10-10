# Enterprise vendor remaining official-source gaps (research 2026-10-11)

Branch only. No source should be marked `read_parse_verified` without a successful bounded Actions detail read and parsed identity. Published index URLs and live article links are distinct evidence.

## Juniper Networks
- The current Juniper Support Portal Knowledge Base landing page `https://supportportal.juniper.net/s/knowledge` lists **Security Advisories (JSA)** with RSS subscription, but page content also requires sign-in to display some knowledge base results. Existing static HTML index parser failed: `https://github.com/pinogame1945-dotcom/ECLIPSE/actions/runs/38062701918`.
- Juniper official Mist documentation separately identifies an official **Mist security alert RSS feed**: `https://www.mist.com/documentation/category/security-alerts/feed/`. This is **Mist-only**, not complete Junos/EX/SRX JSA coverage. It is an independently bounded candidate for a follow-up live proof; do not silently attribute Mist coverage to Juniper's entire network portfolio.
- Next: establish publisher-owned RSS source, canonical article publisher IDs, no account boundary crossing. If publisher redirect is off allowlist, quarantine.

## HPE / Aruba
- Official HPE PSIRT Library `https://support.hpe.com/connect/s/securitybulletinlibrary?language=en_US` did not yield verified static advisory detail URLs in its index when probed on the feature branch.
- Official HPE bulletin `https://support.hpe.com/hpesc/public/docDisplay?docId=hpesbnw05059en_us&docLocale=en_US` explicitly advertises separately available **signed text and CSAF JSON** versions, and states affected products/versions. Individual bulletin retrieval plus publisher ID validation and CSAF field paths may therefore be safer than a general HTML table scraper.
- Next: identify publisher-provided CSAF manifest/catalog of public HPE advisories without crawling inferred sequential document IDs. Distinguish HPE Aruba from consumer HP security bulletins; do not conflate vendors. Keep failed static index state.

## IBM
- Official `https://www.ibm.com/support/pages/bulletin/` displays Product Security Central bulletin rows by product/CVE/severity/publication date, but the current machine parser on `https://www.ibm.com/support/pages/bulletin/` yielded no validated detail links; likely dynamic or API-backed.
- IBM's `https://www.ibm.com/support/pages/node/718119` documents its My Notifications delivery option, including **RSS by selected product** (selection and sign-in may be required). Do not invent an unauthenticated all-product feed.
- Next: verify a publisher-owned uncredentialed canonical detail feed only if officially offered; otherwise mark public index automation infeasible and rely on CVE/CSAF with explicit gaps. Do not bypass authentication or scrape dynamic undocumented private endpoints.

## NetApp
- Official `https://security.netapp.com/advisory/index.xml` is a valid candidate RSS mentioned by RSS readers, but ECLIPSE's first bounded prefix did not expose a validated complete advisory item+link pair. Do not claim verified NetApp source coverage.
- Next: evaluate publisher-provided summarized feed/index rather than broadening fetch limits indefinitely. Account for large inline full-text entries and publication-history ordering.

## 126 candidate product groups
The spreadsheet `ECLIPSE_標準監視ソース調査_126候補_20261010.xlsx` is the separate authoritative candidate-product list. Source ID count is **34 registrations, 25 one-shot read/parse verified**, not 34 or 25 covered product groups. Actual row-wise match must use the workbook and explicit product/firmware aliases, edition and service scopes; absent workbook bytes cannot justify a fabricated 126-row coverage matrix.

## Operational sequencing
1. V3 immutable historical preservation successful, 175 documents / 256 versions.
2. Juniper Mist, HPE CSAF catalog and IBM per-product RSS require distinct official-live source evidence. Keep their original failing source IDs in place.
3. A scheduled successor-generation process needs race-free coordination, no overwrites, independent readback, explicit per-source failure coverage metrics and preservation of private historical events. This document does not authorize production operation or client release.
