# ECLIPSE L2 — historical FIRST EPSS vs future CISA KEV listing

## Question, outcome, and leakage boundary

**Research question:** If an analyst had used the EPSS daily score **on that date**, how many CVEs later newly included in CISA KEV **within 7 or 30 days** could they have put in a restricted review queue first?

This is a **CISA-catalog first-listing proxy**, not evidence of *when exploitation started*. Exploitation may have occurred long before CISA recognition. Historical KEV `dateAdded` from the exact 2026-10-10 catalog is an imperfect, retrospective label; catalog edits and removals could bias results. Labels from entries added after 2026-10-10 are by definition unknown. The scope ends at 2026-08-31 for all windows. Nothing here demonstrates an organization's compromise, affected version, or a safe response deadline.

To prevent obvious **look-ahead leakage**, the predictor is *only* the `epss` score in the official historical `empiricalsec/epss_scores` daily CSV for the forecast date. It does **not** load current `warehouse_summary.cvss_score`, current CVE descriptions, `warehouse_affected`, today's EPSS, current KEV membership, or vendor advisories as prediction features. CVEs whose KEV `dateAdded` was already on/before the forecast date are excluded from the candidate ranking (they were already known). Newly KEV-listed CVEs missing from that day's EPSS population are counted separately, not silently dropped from the aggregate catalog denominator.

## Predeclared experiment (before seeing outcomes)

- **17 date-locked monthly anchors**: first of every month April–December 2025 and January–August 2026. Evaluation windows are `(as_of, as_of + 7 days]` and `(as_of, as_of + 30 days]`.
- **Input**: official FIRST-maintainer repo [`empiricalsec/epss_scores`](https://github.com/empiricalsec/epss_scores) pinned to `df0307edc6e83b63538825ca70d8f46aab0b3df1`, with size **and exact Git blob SHA-1** independently pinned for each of the 17 archive files. Store resulting compressed SHA-256 for each day in output. Reject unexpected dates, sizes, hashes, missing/duplicate CVE IDs, invalid probabilities and incompatible `score_date` metadata.
- **Positive label**: authoritative CISA `dateAdded` in that future 7/30-day interval, derived exclusively from the preserved source `kev-original.payload` in the immutable private SQLite warehouse dataset. The historical KEV observation is separately SHA-256 verified against the *trusted GitHub build receipt*, not a checksum returned by Kaggle.
- **Candidate population**: CVEs present in the *historical* EPSS daily CSV and not already in CISA KEV on that date. This population is necessarily **EPSS-scored** and cannot measure all CVEs or the completeness of the CVE Program at that time. Every new KEV entry not in the candidate universe is reported as unrankable.
- **Workload-constrained metrics**: precision, recall among EPSS-scored future additions, expected random hits and ranking lift for fixed top 100, 500, 1,000; also alert counts, precision and recall at fixed EPSS probability thresholds 0.05, 0.10, 0.20. The fixed thresholds are NOT fitted to this evaluation. Report `null` when recall cannot be calculated because there are no positives. Preserve lead days to CISA registration for the selected positives. Precision denominator is all candidates selected for review, not only successful predictions.
- **Era segmentation**: EPSS v4 (2025-04-01 to 2026-06-01 anchors) vs EPSS v5 (2026-07-01, 2026-08-01), independently of an aggregate. EPSS model methodology changed 2026-06-15; score distributions are not assumed comparable across that boundary. Also retain per-anchor results to avoid hiding changing baseline prevalence.
- **Comparators**: chance expectation at identical analyst-review workload. Do **not** compare with a ``current CVSS baseline''—such a baseline would use after-the-fact revised severity and leak information. Not a supervised model training experiment.

## Operations

One-shot read-only workflow `.github/workflows/one-shot-historical-kev-backtest.yml` downloads the **original warehouse build receipt** (pinned Git SHA-256), retrieves **only** the preserved CISA KEV JSON from the private Kaggle warehouse, checks original source SHA-256, then fetches 17 bounded, Git-blob-pinned historical FIRST EPSS compressed CSVs. It does **not** repeat the 403,696-row SQLite build, upload a new Kaggle dataset, overwrite prior data or modify the vendor verification branch. Only an aggregated source-attributed JSON evaluation (public vulnerability information; no customers) is kept as a 7-day CI artifact. Runs on standard free CPU runner with a fixed bounded deadline and no recurring schedule.

Unit tests are synthetic and offline; historical retrospective accuracy, false-alarm burden and any customer deployment claim require **actual workflow completion and examination of its result**. Do not extrapolate results to future prospective attack warnings. A follow-on *prospective* precommitted alert-vs-KEV observation using changing real-time daily data would be needed to demonstrate an operational early-warning service.

Primary source on historical availability, API-vs-CSV, and model changes: https://www.first.org/epss/data.html. KEV inclusion criterion and its meaning: https://www.cisa.gov/known-exploited-vulnerabilities-catalog.
