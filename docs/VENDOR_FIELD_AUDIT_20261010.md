# ECLIPSE Vendor Evidence — field-level quality audit (2026-10-10)

**Status: experimental extraction, not customer-release approved.** This file documents an actual bounded public-source read and SQLite replay, separated from the ongoing 403,696-record CVE/Kaggle project.

## Latest independently observed proof

Run [38050337430](https://github.com/pinogame1945-dotcom/ECLIPSE/actions/runs/38050337430): **9 publisher connectors PASS**, 17 official advisory documents retained across runs, 27 content-addressed versions, 27 events, SQLite `quick_check=ok`. All nine sources read their listing and limited detail(s) without credentials. The proof covered up to 2 new articles/source, plus a checked older sample where applicable.

| Official source | Docs observed in run | Structured affected evidence rows | Explicit remediation evidence rows | Caveat |
|---|---:|---:|---:|---|
| Fortinet PSIRT | 2 | 7 HTML table rows | 7 table cells | Parsed version strings, **not** tested client exposure |
| Palo Alto Networks | 2 | 6 CNA affected entries | 0 in sampled normalizer | Missing remediation normalization |
| Siemens CSAF | 2 | 9 `known_affected` rows | 6 remediations | Product IDs and names retained; no inferred patch ranges |
| Red Hat CSAF | 2 | 0 `known_affected` rows | 6 remediations | Other status entries present; zero affected rows ≠ unaffected |
| Canonical Ubuntu | 2 | 0 standardized affected rows | 0 | USN package/release mapping unimplemented |
| GitLab | 2 | 0 | 0 | Page-wide CVE hits are not trusted as advisory links |
| Yamaha | 1 | 0 | 0 | HTML firmware-version extraction unimplemented |
| Atlassian | 2 | 0 | 0 | Global navigation contaminates naive page-wide CVE matching |
| Microsoft MSRC | 2 monthly CVRF | 0 | 0 | Up to thousands of CVE IDs, but no per-CVE ProductTree join |

**Interpretation:** A successful document fetch does **not** mean the product impact and fix details are complete. All rows remain `parsed_unreviewed` and **none** are eligible for unreviewed customer-facing product-vulnerability assertions. A row count of zero means **we did not extract that field**, not that the product has no relevant vulnerabilities.

## Interpretation changes made in this branch

- **Structured CSAF:** `vendor_csaf.py` recursively resolves published `product_tree` branches, `full_product_names` and relationship product labels. It retains `vulnerabilities[*].product_status` per CVE with `known_affected`, `known_not_affected`, `fixed`, `first_fixed`, `under_investigation`. Remediation category/text, explicit product/group refs and JSON field paths are retained. CSAF product ID not resolvable => explicit null and unresolved list; never guess a version interval. Contradictory affected/not-affected statuses for the same CVE/product fail closed.
- **HTML scope:** `ArticleText` reads `<main>`/`<article>` while excluding `nav`, `footer`, `header`, `aside`, `script` and `style`. It keeps body CVEs under `unreviewed_article_cve_candidates` **separately from confirmed links**, without misidentifying unrelated sidebar references. This is still not a substitute for article-level verification.
- **Per-source quality:** `vendor_quality.py` exposes counts of publisher evidence fields, structured product statuses, remediations, unresolved product IDs and unlinked article CVE candidates. It always reports `quality_assured=false`, `safe_for_customer_facing_auto_claims=false`, `verified_product_exposure_assessments=0`.
- **Change classification:** `vendor_store.py` distinguishes a parser reinterpretation (`extraction_revised`) from a publisher source change (`source_changed_only`) and a simultaneous source-and-parsed-fact change (`facts_updated`, still unreviewed). The legacy 3-event SQLite CHECK is upgraded transactionally, preserving event IDs and history. New source facts include an explicit extractor revision marker to prevent upgrades plus dynamic HTML from creating false publisher-update alerts.
- **Persistence:** Only GitHub Actions' short-lived artifact state is available; the existing Kaggle CVE corpus is **not** modified. Permanent private storage, exact affected-version matching and commercial reuse approval remain separate production gates.

## Reproducibility

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
PYTHONPATH=src python -m eclipse_l0.vendor_registry --registry config/vendor_source_registry.json
```

Live one-shot limited run is in `.github/workflows/vendor-evidence-pilot.yml`, with an isolated workflow_dispatch and branch push triggers. It currently requests a maximum of 2 current official records per source and a bounded check on a tracked older advisory. The contents and hash audit of a previously successful artifact are required before replay; no silent reset to baseline is allowed. The downloaded SQLite and manifest artifact expire after 7 days.

## Production go/no-go (still **NO-GO**)

1. Field-by-field manual validation against representative advisories, including negatively scoped `not affected` and multiple CVEs in one advisory.
2. Resolve version/firmware/patch semantics for CSAF, Ubuntu, MSRC and HTML, avoiding string-version comparison mistakes.
3. Add secure independent durable storage with backup, recovery and expiry protection; customer data must remain segregated.
4. Verify time-series changes on real publisher-edited security content (not dynamic HTML chrome or parser upgrades).
5. Check permissions, commercial reuse constraints and source availability monitoring before scheduled customer service.

Success is **measured evidence coverage**, not an assumed 100% hit rate across all products.

## Additional bounded validation: publisher field meanings and extractor revisions

[Run 38050684230](https://github.com/pinogame1945-dotcom/ECLIPSE/actions/runs/38050684230) revalidated all nine official connectors (17 tracked advisory documents), SQLite `quick_check=ok`. The run made a safe **extractor version revision**, NOT a publisher security disclosure claim: all 17 sampled documents were classified `extraction_revised`, no `facts_updated` events. This is deliberately safer than attributing a parser deployment to a vulnerability change.

- **Palo Alto Networks CNA:** sampled documents exposed **4 remedy/workaround text entries**, now retained with exact `containers.cna.solutions[*].value` or `containers.cna.workarounds[*].value` evidence path, plus the previously collected 6 affected entries. These strings **have not** been interpreted as automatically verified fixed versions.
- **Ubuntu USN:** sampled notices' `release_packages` containers are retained as per-release package counts and types with source paths. Their actual package-level fixed versions are **not** asserted.
- **Siemens/Red Hat CSAF:** structured CVE, publisher product labels, `product_status` (including `fixed` and `first_fixed` only where explicitly published) and remediation targets are preserved separately. No regex conversion of these statuses into guessed affected-version intervals.
- **GitLab/Atlassian HTML:** `<main>`/`<article>` CVE candidates are collected separately from unrelated header/footer/sidebar/navigation text; even this body-scoped set is **unreviewed** and is never silently added to `cve_ids`.

The higher SQLite version count in this run includes extraction changes and dynamic HTML bytes. It is **not** a count of newly discovered vulnerabilities. The original CVE/Kaggle corpus has not been altered.
