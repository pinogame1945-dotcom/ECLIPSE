# ECLIPSE L2 — evidence-first triage v1 (parallel to vendor verification)

This layer is a **deterministic review queue**, not a predictive model, calibrated
probability of compromise, customer risk score, remediation directive, or CVE event feed.
It deliberately does **not** modify `src/eclipse_l0/advisory_feeds.py` or the
separately verified vendor-source PR.

## Why not CVSS + EPSS + KEV in a single number?

These are different measurements. CISA KEV reflects a CISA catalog of vulnerabilities
with evidence of exploitation in the wild, not a detection inside a customer.
FIRST EPSS is a *population-level estimate* of observed exploitation activity for
the next 30 days. A CNA CVSS Base value measures technical severity, not exploitation
probability. None establishes whether a specific customer has an affected version,
internet exposure, relevant controls, or working patch. EPSS explicitly warns
against multiplying it by an ordinal CVSS score:
<https://www.first.org/epss/faq>.
See also <https://www.first.org/epss/> and <https://www.cisa.gov/known-exploited-vulnerabilities-catalog>.

The default *illustrative* sorting policy on **PUBLISHED** CVEs is:

1. `CONFIRMED_EXPLOITATION_REVIEW` — listed in the verified KEV snapshot.
   This takes precedence even when EPSS is low, high, missing or stale.
2. `ELEVATED_FORECAST_REVIEW` — not in KEV, but has a **fresh** EPSS
   probability `>= 0.10` under the configured local **attention threshold**.
3. `HIGH_IMPACT_REVIEW` — CNA CVSS Base `>= 9.0` under an independent
   local impact-screen threshold; may apply even if EPSS is missing/stale.
4. `ROUTINE_EVIDENCE_REVIEW` — no above-threshold signal currently observed;
   **this is not a finding of low risk or no exploitation**.
5. `UNPUBLISHED_HOLD` — reserved/rejected/non-PUBLISHED; reported separately,
   never passed off as a confirmed published exploitable vulnerability.

These thresholds are **unvalidated policy defaults**, configurable by the operator.
They are not learned decision boundaries, service-level agreements, or empirical
claims of precision/recall. Missing EPSS is `null`, not zero; lack of KEV listing
does **not** mean there is no exploitation. An EPSS feed more than seven days old
(default) is marked **stale** and never used to promote or order candidates.

Separate dimensions are retained explicitly:
- **Observed exploitation:** KEV membership and KEV registration date.
- **Predicted exploitation:** EPSS probability/percentile + exact model-score date
  and staleness. EPSS remains distinct from technical impact.
- **Impact evidence:** publisher's CNA CVSS Base and score version; absent
  numbers are unknown, never zero. CVSS Base is not environment-adjusted risk.
- **Evidence gaps/attribution:** CNA publisher affected-product rows and raw
  version predicates existence; absence or unspecified versions means unknown.
- **Exposure/remediation:** `NOT_ASSESSED` until *authorized private* asset
  inventory, verified vendor advisories, deployed versions and controls are
  available. No manufacturer claims are invented.

## Full-corpus implementation

Default run streams **every one** of the pinned 403,696 CVE keys from the immutable
SQLite baseline, with O(K) preview storage; optional CSV exports **every** evaluated
row, not only a shortlisted subset. The full count is reconciled to
`cve_current`; each row keeps rule ID and references to source DB fields.
The casefolded vendor/product filter is an *exact publisher label* match,
not substring search or proof that an organization's asset is affected.

The report includes source SHA-256s (CVE/KEV/EPSS), distinct source timeframes,
EPSS freshness, counts for every queue, missing-evidence counts and a ranked
preview, with no probability or fake composite "risk score".

For an authorized local or private warehouse SQLite:

```bash
PYTHONPATH=src python -m eclipse_l2.triage \
  --db /private/cve-warehouse.sqlite3 \
  --out /private/results/triage-summary.json \
  --csv /private/results/triage-all.csv \
  --as-of 2026-10-10 --top 100

# Exact upstream vendor/product labels only; NOT an exposure check:
PYTHONPATH=src python -m eclipse_l2.triage \
  --db /private/cve-warehouse.sqlite3 \
  --vendor Fortinet --product FortiOS \
  --out /private/results/fortios-triage.json
```

CI: `one-shot-cve-triage-audit.yml` uses a **new read-only CPU runner** to
recover the **already-existing private** immutable 1.54 GB warehouse (23 Kaggle
parts) and its KEV/EPSS raw evidence. It checks the frozen original index SHA and
the restored database SHA/SQLite integrity *before* analyzing all CVEs. Its
artifact is a small public-source-derived summary JSON only; it does not contain
customer inventories, source files, API tokens or newly uploaded datasets.

**Not yet implemented:** empirical validation of thresholds against forward
exploitation outcomes, vendor advisory reconciliation, customer version
matching and remediation SLA assignment, authenticated customer profiles,
production scheduling, analyst sign-off and notifications. Audit all policy
decisions before customer use.
