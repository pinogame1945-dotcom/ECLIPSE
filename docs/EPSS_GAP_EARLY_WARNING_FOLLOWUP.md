# PROJECT ECLIPSE — historical EPSS coverage gaps + fixed-momentum competitor (2026-10-10)

## Why

The earlier **17-date** retrospective (2025-04-01 through 2026-08-01) found **374** CISA KEV first-listing **anchor events** within 30 days; **203** were in that month's historical FIRST EPSS candidate population and **171** were absent. These are sums of anchor-level occurrences, *not* necessarily unique CVE IDs. Here we test two **separate, predeclared** ideas on unchanged public evidence. This effort does not touch the vendor-advisory verification branch or private customer data.

**Aim A: use the existing EPSS-scored candidate universe more efficiently.** At equal fixed review budgets **100 / 500 / 1,000** candidates per monthly anchor, compare original absolute EPSS ranking against a candidate list with **80%** slots from highest EPSS and the remainder from **positive change since the immediately preceding month of the *same EPSS model era***. If fewer positive-momentum CVEs remain, fill slots using absolute EPSS ranks. New/unscored CVEs never acquire a fabricated previous score of zero. The first month in each EPSS era has no valid comparable previous score and is **excluded from paired comparisons**. This policy is not trained, tuned or calibrated against the future KEV labels. Compute **gained cases**, **lost cases**, net change, alert burden, conditional recall and precision *on the same months and at exactly the same budget*. We report results separately for EPSS v4 and v5. Even a positive net gain would be exploratory, not validation of a deployable forecasting model.

**Aim B: investigate the 171 unscored cases without information leakage.** For every historically EPSS-unscored CVE later registered in KEV within 30 days, classify it using the **historical first-of-month snapshots only**: was it scored in an **earlier** monthly anchor, does it **first appear in a subsequent** monthly anchor, or was it **never seen in any of these 17 snapshots**? Retain the label date, current month, remaining number of snapshots (right censoring), and CVE identifier year. **CVE identifier year is NOT CVE publication date**. A first appearance in a later monthly file is hindsight-only diagnostic material; it **must not be used as an as-of predictive feature**. An absence from monthly EPSS cannot identify whether the CVE was unpublished, rejected, delayed by scoring, or missing for other reasons. An as-of CVE publication history from timestamped trusted releases would be required to adjudicate those hypotheses.

### Temporal safeguards

- Every candidate score or trend is derived only from **historical FIRST EPSS compressed CSV** bytes as they existed on the as-of/earlier date. Scores are from the immutable Git SHA `df0307edc6e83b63538825ca70d8f46aab0b3df1` and 17 independently pinned Git blob hashes.
- Outcome is **later CISA KEV `dateAdded`** in `(forecast anchor, anchor+7/30 days]`, from the original CISA catalog bytes recovered from the previously verified immutable private warehouse. KEV is the retrospective label only; already-listed CVEs are not candidates.
- No future CVE V5 record, modern CVSS score, modern vendor affected-product claim, future EPSS appearance, current KEV flag, or retrospective publication date is used by the algorithm that selects candidate alerts.
- The June 2026 EPSS version break is a **hard boundary**: no cross-era monthly momentum. The April 2025 and July 2026 anchors are excluded from equal-basis paired comparisons.
- The original 17-anchor fixed-EPSS experiment is independently recomputed to verify **374 total**, **203 scored**, **171 unscored** anchor outcomes. Individual per-anchor/budget/horizon absolute-score results must also match. Any mismatch fails the entire job.
- Thresholds/allocations are fixed *before inspecting the current comparative outcomes*. No CVE scoring model is trained here and 30-day KEV registration is **not exploitation onset**.

### Operations

Run `Actions > ECLIPSE historical EPSS momentum and missing-KEV cohort audit`. This one-shot workflow uses a regular GitHub CPU runner, fetches only previously pinned public historical FIRST CSV files and the original immutable CISA KEV catalog from existing private Kaggle, verifies original trusted source hashes and executes both analyses in a single pass. Its artifact is a JSON receipt with aggregate counts and 171 retrospective **public CVE** diagnostic records; no Kaggle dataset is created/updated and no customer inventory is processed. No recurring workflow or paid runner is introduced.

CLI:

```bash
PYTHONPATH=src python -m eclipse_l2.epss_gap_research \
  --kev /secure/kev-original.payload \
  --epss-dir /work/pinned-historical-epss \
  --out /work/epss-gap-research.json --cutoff-date 2026-10-10
```

Important limitation: a candidate absent from EPSS at the anchor **cannot be rescued by rearranging EPSS scores**. The missing cohort analysis only tells us which additional *timestamped*, independent information should be investigated next; it is not a risk alert. A stronger next study would obtain as-of CVE publication/status feeds, explicit exploit proof dated before the anchor, and audited historical advisory dates (once the separate vendor work finishes).
