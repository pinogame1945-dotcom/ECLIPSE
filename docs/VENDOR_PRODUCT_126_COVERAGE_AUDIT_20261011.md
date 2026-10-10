# User Excel 126 source candidates × feature branch 36 official source registry

User input workbook SHA-256: `2ef5de9c39e076a6f1756794e68a39fdaad634b86ba2c0857a868736ace27e00`.
Source file is **not** committed to public GitHub. Mapping is row ID→official source ID only, with relation scope and caveat. Workbook-derived individual market-share or confidential customer inventory is not published.

## Confirmed row-level source *potential* matching (not production monitoring)
| Grade | Meaning | Rows | P0 |
|---|---|---:|---:|
| A | Representative official source within candidate product family | 10 | 9 |
| B | Representative official source only covering subset of candidate product family | 18 | 17 |
| C | Publisher-related information only, without exact candidate product evidence | 7 | 3 |
| D | Registered official connector but failed live read/parse | 6 | 4 |
| E | No matching official source connector registered | 85 | 32 |
| **Total** | **126 source-candidate rows** | **126** | **65** |

A+B (**28/126**, with **26/65 P0**) is a weak indicator of *source-connection opportunity*, not the fraction of truly monitored CVEs, product vulnerabilities, patched releases, or customer assets. Individual rows may reuse the same source ID and must never be summed as independent connectors. Registry 36 / single-sample read-parse 27 / PRIVATE Kaggle V3 source IDs 24 remain separate counts.

## Product scope and failure semantics
- Google Android public bulletin ≠ Google Chrome/ChromeOS. Chrome intentionally deferred.
- Juniper Mist security blog ≠ broad Juniper JSA or HPE Aruba product portfolio.
- Ivanti blog RSS ≠ Connect Secure/EPMM full advisories.
- NGINX OSS aggregate ≠ NGINX Plus / F5 BIG-IP PSIRT.
- Apache httpd 2.4 + Tomcat 11 ≠ Struts or Kafka security source coverage.
- SAP public monthly patch announcement ≠ product-level authenticated SAP Security Notes.
- Microsoft MSRC CVRF ≠ full Azure/Entra/Microsoft 365 SaaS update coverage.
- Vendor source one-shot parse ≠ verified installed-version applicability or exploitability.

## P0 work backlog
**39 P0 rows** remain in categories C/D/E; among them **32 P0 rows** have no corresponding registered official adapter at all. The most useful broad coverage work after the current branch merge freeze is official and identity-safe publisher connectors for AWS, Dell, Arista, Check Point, CrowdStrike, Trend Micro, Synology and OT sources (Rockwell/Schneider/Mitsubishi). These are *recommendations based on P0 row priority and product category breadth*, not current implementation claims.

Original Excel also lists vendor URLs for potential feed discovery; the repo's mapping source is `config/vendor_product_scope_126.json`. Tests `tests/test_vendor_product_scope_126.py` reconcile all 126 row IDs, source verification status and grade counts without importing or publishing the original workbook. Do not mark a source verified on the basis of a spreadsheet URL alone.

## Delivery to report generation
The weekly report ingestion remains a separate project step. This 126-row inventory is a **source-priority control**. It does not override newly added CISA KEV prioritization, report ~50 findings policy, 403,696 CVE warehouse integrity, or immutable PRIVATE Kaggle V1/V2/V3. main remains untouched.
