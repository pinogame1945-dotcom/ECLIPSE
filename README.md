# PROJECT ECLIPSE — Threat Intelligence L0/L1 v0.5

Cybersecurity intelligence prototype using authoritative public CISA KEV and CVE List V5 releases. This repository is **PUBLIC** and intentionally contains **no real customer details or private asset inventories**.

## Implemented (this release)

- **L0**: CVE full-snapshot ZIP importer, complete CISA KEV catalog importer, deduplication, version event history, restartable imports and SQLite integrity audit.
- **Integration**: Official KEV catalog → L0 SQLite evidence store → byte-identical validated source snapshot → editable PowerPoint and provenance manifest.
- **Customer profiles**: Local JSON vendor/product filters; example profiles only. Vendor labels are heuristic substring matches, **not** an exhaustive vendor/product mapping.
- **PowerPoint**: KEV `dateAdded` day/period selection, executive summary, matching entries, plain-language contextual notes, caveats and source hashes.
- **CI**: Offline unit + cross-module integration tests; **manually triggered** official KEV briefing workflow, downloadable as a short-lived Actions artifact.

Not implemented: production persistent cloud storage, scheduled collection, CVE incremental delta ingestion, manufacturer advisories, EPSS/NVD correlation, generative AI technical commentary, live incident detection, customer deployment, and automatic distribution. **No claimed exploit details or remediation version are fabricated.**

## Run tests

```bash
python -m pip install -r requirements.txt
PYTHONPATH=src python -m unittest discover -s tests -v
```

## Full CVE BACKFILL (local workstation with adequate disk)

```bash
PYTHONPATH=src python -m eclipse_l0.cli --db state/eclipse.sqlite3 sync-official
PYTHONPATH=src python -m eclipse_l0.cli --db state/eclipse.sqlite3 audit
```

This downloads an official CVE baseline ZIP (potentially large) plus KEV and imports them locally. Only perform with disk/bandwidth quotas; **do not schedule the full CVE baseline in default GitHub Actions**. The method currently uses full daily snapshots; hourly incremental CVE ingestion is a future step.

## Make a customer-filtered KEV briefing

1. Retrieve official CISA KEV JSON from the upstream project.
2. Use an example monitoring profile; clone it for an **approved private environment** if you need real customer filtering.
3. Execute:

```bash
PYTHONPATH=src python -m eclipse_reports.pipeline \
  --kev-json downloads/kev.json \
  --db state/eclipse.sqlite3 \
  --customer config/customer-all-example.json \
  --output output/kev-briefing.pptx \
  --days 7
```

Output: editable `.pptx` and `.manifest.json`. Use `--end-date YYYY-MM-DD` to produce a historic window. For synthetic demo data, add `--demo`, which marks all slides as fictional. Production mode refuses undersized feeds.

Or go to **Actions → KEV briefing (manual / official source) → Run workflow**. Artifacts are retained for 7 days. This workflow does **not** maintain cross-run history and does **not** automatically send reports.

### Interpretation and evidence

- `dateAdded` = the date an issue entered the KEV catalog, **not** publication date, exploit start, or first system detection.
- Reports include CISA-provided short descriptions and required actions; **technical AI analysis is not yet implemented**.
- No matching KEV events does not prove no relevant new vulnerabilities.
- On the first complete catalog ingestion, historical `added` entries are **baseline import events**, not fresh alerts. True new-to-us detection requires a durable store and diff across subsequent polling cycles.
- KEV data is not a full vulnerability intelligence corpus. Vendor monitoring beyond KEV requires upstream manufacturer feeds.

### Next milestones

1. Choose durable, access-controlled blob/object store for original snapshots + SQLite backup, within no-paid-service constraints.
2. Add explicit **baseline vs observed update** semantics and alert idempotency, then scheduled KEV polling.
3. Merge manufacturer advisories, CVE/EPSS evidence and validated commentary into customer-specific PPTX reports.
4. Review distribution rights and authorization before any commercial customer delivery.

Data: [CISA KEV official repo](https://github.com/cisagov/kev-data); [CVE List V5](https://github.com/CVEProject/cvelistV5). OpenCVE is **not** used as a reusable commercial source.

## v0.4 — Persistent CISA KEV monitoring (public data only)

**New workflow:** `Actions → ECLIPSE durable KEV monitor (public-data only)`.
Scheduled hourly at minute 23 UTC (GitHub scheduled execution may be delayed or skipped).
This is **not** a realtime monitoring SLA. A manual `workflow_dispatch` is also available.

State is persisted in the separate **`eclipse-state` Git branch**, not an Actions
artifact or an ephemeral runner SQLite file. The first successful run establishes a
baseline from the complete CISA KEV catalog without spamming historical entries.
Later runs compare per-CVE JSON content and capture **newly observed additions,
modifications, and removals** in `data/events/YYYY-MM.jsonl`, with timestamps and
source SHA-256. A repeated source run produces no duplicate events/commit. Suspicious
feed truncation, duplicate CVE IDs, invalid dates and stale release timestamps fail closed.

If meaningful changes are detected, the workflow produces two **editable PPTX**
examples using **public, fictional monitoring profiles only** (all/network). The
reports are attached to the run for 7 days; no mail/customer distribution is enabled.
KEV `dateAdded` is a CISA catalog-registration date, not the poll detection instant
or exploitation start. A metadata-only feed update creates no vulnerability alarm.
The output uses only official KEV fields; **no AI technical commentary** or
unverified patches/impact claims have been added.

### Security and cost constraints

- PUBLIC repo/state: never add private customer settings, names, secrets, CMDBs,
  inventories, unpublished vulnerabilities or employer data.
- Uses ordinary GitHub-hosted runners and built-in GITHUB_TOKEN; no paid storage.
- The data branch holds only a public CISA KEV snapshot + append-only change logs;
  it is **not** a permanent CVE raw-data archive. Full CVE BACKFILL remains local.
- No destructive rewrites of state branch; a failed non-fast-forward push fails the job.
- `contents: write` is required for state branch commits; branch protection/repo
  Actions permissions might require configuration by repository owner.
- Never equate KEV absence with no exploitation or catalog deletion with safety.

### Manual local deterministic run

```bash
PYTHONPATH=src python -m eclipse_l0.kev_monitor \
  --feed downloads/kev.json --state-dir /path/to/public-state-checkout/data \
  --out output/observed-changes.json
# On first execution: event_count=0 and baseline=true.
# After a genuine feed change: an event JSON and event PPTX can be generated.
PYTHONPATH=src python -m eclipse_reports.event_report \
  --events output/observed-changes.json \
  --customer config/customer-all-example.json \
  --out output/eclipse-kev-observed-changes.pptx
```

The last command intentionally refuses baseline and no-change input. Long-term
roadmap: source license audit, genuine advisories (including pre-CVE information),
severity triage validated by human review, and approved private client delivery.


## v0.5 — CVE change index + FIRST EPSS + source-adapter + evidence dossier

**Validated locally:** offline unit/integration tests for previous L0/KEV/PPTX and new components.
**Deployed as source:** new scheduled workflows below; runner success/network access is **not** yet verified.

### What runs automatically (GitHub Actions)

| Workflow | Interval | What it does | Persistence |
| --- | --- | --- | --- |
| `ECLIPSE durable KEV monitor` | Best-effort hourly | Existing full CISA KEV diff / incident PPTX | `eclipse-state` branch |
| `ECLIPSE CVE change-index observer` | Best-effort every 4 hours | Observes new/updated identifiers from official rolling `cves/deltaLog.json` | `eclipse-state` branch; recent public event window |
| `ECLIPSE EPSS daily selected-CVE enrichment` | Best-effort daily | Downloads FIRST's entire latest daily CSV, keeps **only KEV-listed** CVE scores/percentiles | `eclipse-state` branch (`data/epss-selected.json`) |

Cross-workflow public-state Git pushes share one concurrency group. First CVE poll is a baseline, **never a list of new incidents**. A rolling CVE log is not a full historical database. If the checkpoint is older than the official rolling retention, the program **fails** rather than pretending the missing days were covered. Recovery requires a controlled full-snapshot reconciliation. The CVE index deliberately does **not** download all new/updated source JSON documents; vendor filtering and definitive affected versions need the corresponding CVE records and vendor security notices. The periodic runner's database is temporary, and only **public** summaries may be committed. Recent raw change-index entries are kept for roughly two months, not forever.

EPSS: the selected scores are a **daily model estimate** for the next 30 days and are not a client's attack probability. This project does not interpret EPSS as confirmed exploitation. Daily rows are joined by exact CVE ID; if the KEV watchlist baseline has not yet been created the EPSS job explicitly skips. The entire EPSS CSV is **not** committed.

### Vendor feed adapter (manual only)

`eclipse_l0.advisory_feeds` supports official RSS 2.0 / Atom items with explicit allowed official hostnames, content size limit, safe XML parsing, source-by-source state, first-poll baseline, and subsequent item edits. **It is not automatically connected to any actual vendor feed.** Vendor-specific endpoints/credentials, permissible reuse, rate limits, and patch/impact extraction must be reviewed before enabling live monitoring or commercial redistribution. Cisco's openVuln API needs authorized credentials and Fortinet's public PSIRT-blog RSS is not a substitute for authoritative product PSIRT advisories. Entries are pointers to vendor notices; they are not vulnerability assertions.

```bash
PYTHONPATH=src python -m eclipse_l0.advisory_feeds \
  --xml downloaded-verified-feed.xml \
  --state-dir local-public-state/data \
  --out output/advisory-events.json \
  --source-id verified-vendor \
  --vendor 'Verified Vendor' \
  --allowed-host security.vendor.example
```

`security.vendor.example` is a **synthetic placeholder**; never poll it in production.

### Local standalone L1 evidence dossier (manual only)

The `eclipse_l1.evidence` module accepts a CVE v5 record JSON, the official KEV catalog, and (optionally) the **selected** official FIRST EPSS extract, then emits a structured JSON dossier with each fact tied to its original source field. It preserves vendor-reported affected version structures **without declaring local asset exposure**. Missing KEV input is reported as "not supplied" rather than "no exploitation". It is deterministic, **not yet AI analysis**.

```bash
PYTHONPATH=src python -m eclipse_l1.evidence \
  --cve-json downloaded-CVE-record.json \
  --kev-json downloaded-official-KEV.json \
  --epss-json public-state/data/epss-selected.json \
  --out output/evidence-dossier.json
```

The KEV change-briefing PowerPoint now **optionally** enriches detail slides with EPSS evidence if a verified `data/epss-selected.json` is already present; it falls back to `EPSS: 未取得` when not. Historical score date and SHA-256 appear in the report manifest. No autonomous technical deep-dive or client delivery is claimed.

Official feeds: [CVE Project](https://github.com/CVEProject/cvelistV5), [FIRST EPSS](https://www.first.org/epss/data.html), [CISA KEV](https://github.com/cisagov/kev-data). Enabling commercial redistribution or a specific vendor feed requires a separate rights assessment.

## v0.6 — Multi-source L1 event fusion & editable daily PPTX (public data)

**Implemented:** L1 joins durable CISA KEV observed events and CVE delta-index events
by **exact CVE ID**; when explicitly provided, it also joins observed RSS/Atom
publisher-advisory events by explicit CVE ID. An advisory without a CVE is
preserved as a **separate advisory event** instead of getting a guessed identifier.
An entry shared across three sources produces one topic with a source-by-source
timeline, not three unrelated news cards.

**Evidence preservation:** Event observation time, CVE index fetch time and KEV
`dateAdded` are distinct. Current CVE record bodies (when fetched) and the CVE
Program Container references supplement the KEV/EPSS evidence ledger. Each
technical/observational claim in the JSON has a reference to evidence entries.
Missing manufacturer feed, EPSS data, product identity or CVE body is explicitly
flagged instead of interpreted as clean/low risk. Profile matching is exact by
normalized manufacturer/product label (OR inside each group, AND across groups),
not an unrestricted fuzzy or substring match; unknown names are counted separately.

**Report:** Read-only GitHub Actions workflow `ECLIPSE daily multifeed briefing`
can run automatically once per day or manually with a 24/48/168-hour observation
window. Two **fictional public demonstration profiles** receive editable PPTX,
JSON analysis and a provenance manifest as a 7-day GitHub Actions artifact.
A limited number (12 maximum) of current CVE JSON files may be fetched from
CVEProject's official raw host; malformed URLs and redirects are rejected.
Unretrieved records remain labelled as unverified, never replaced by guesses.

**Honest boundaries:** This is **deterministic, source-bounded explanation**, not
yet LLM-powered expert technical interpretation. It does not claim exploitation
of a specific customer, exact patch versions, confirmed affected asset versions,
or coverage beyond the connected feeds. The upstream manufacturer RSS/Atom
adapter is available for permitted, independently configured sources, but **no
manufacturer feed is auto-enabled** in the public daily workflow. There is no
email or customer delivery and no real customer configuration in this PUBLIC repo.
The daily workflow depends on prior successful KEV/CVE observer runs; first
baseline state itself is not a newly detected event. GitHub scheduled jobs can
run late, fail or be skipped, so this is *best-effort*, not a 24-hour alert SLA.

**Concurrency correction:** KEV/CVE/EPSS public state writes all share the
`eclipse-public-state-writer` concurrency group to avoid cross-workflow races;
non-fast-forward pushes still fail rather than silently overwriting evidence.

Run v0.6 locally after the KEV and CVE monitors have produced saved public
observations (no network required for the first command):

```bash
PYTHONPATH=src python -m eclipse_l1.timeline \
  --state-dir /path/to/eclipse-state/data \
  --out output/observed-timeline.json --hours 24
PYTHONPATH=src python -m eclipse_l1.fetch_records \
  --timeline output/observed-timeline.json \
  --out-dir downloads/cve-records --max-records 12
PYTHONPATH=src python -m eclipse_l1.briefing \
  --timeline output/observed-timeline.json \
  --kev-state /path/to/eclipse-state/data/kev-current.json \
  --epss-json /path/to/eclipse-state/data/epss-selected.json \
  --cve-dir downloads/cve-records \
  --profile config/customer-all-example.json \
  --out output/briefing.json
PYTHONPATH=src python -m eclipse_reports.intelligence \
  --briefing-json output/briefing.json --out output/daily.pptx
```

The EPSS parameter is optional if the official selected-scores snapshot is
unavailable. Use `--advisory-events` on the timeline command to supply a file
produced from a manually authorized/verified publisher RSS/Atom feed; no feed
is discovered or crawled automatically.

Current limitations: EPSS selection is KEV-targeted only; many CVE-only event
records will lack EPSS scores. The report enriches a bounded subset of the
current official CVE records and is **not** a retrospective snapshot of every
record exactly as it existed when the source change was first observed.

## v0.7 — Controlled initial ingestion (NO full CVE download)

**Safety first:** Before a full CVE BACKFILL, use **Actions → ECLIPSE bounded KEV + CVE pilot (read-only) → Run workflow**, choosing 10 first, then 25, then 50 records. This is a **manual-only workflow**, with `contents: read`, no schedule, and no writes to the `eclipse-state` branch. It never downloads the massive CVE baseline ZIP.

Pilot actions:

1. Download the **full but relatively small CISA KEV JSON** (hard cap 25 MiB) and verify count/schema; ingest in a **throwaway SQLite DB**.
2. Choose the 10/25/50 *most recently KEV-listed* CVE IDs, fetch **only those individual official CVE JSON records**, with 2 MiB per-record cap, HTTPS/host restrictions, redirects refused, and bounded timeouts.
3. Validate each record's CVE ID matches the requested ID; log any 404, timeout, mismatched document or excess size **without inventing the missing data**.
4. Run a local SQLite structural audit and produce an evidence CSV and JSON manifest as a 7-day GitHub Actions artifact. These selected samples are **not representative of all global CVEs**, and the pilot is not a monitoring service.

The pilot does not generate or send customer reports, does not download EPSS, and does not alter durable monitoring state. The automatic KEV/CVE-delta/EPSS workflows already exist separately but **have not been verified as successfully running**. Repository owner may need to enable Actions and grant configured workflow token permissions before those can persist their public state.

**Stage gates for controlled rollout** (suggested, not automated success guarantees):

| Gate | Check | Next step |
| --- | --- | --- |
| P0: dry-run | 61+ offline tests pass; GitHub workflow can start | Manual 10-record pilot |
| P1: 10 | Complete KEV catalog parses; SQLite `quick_check=ok`; individual per-CVE fetch results reviewed; at least 8/10 accessible or root-caused | Manual 25-record pilot |
| P2: 25/50 | No malformed silent imports; all failures have evidence; response size and runtime acceptable | Manually run existing durable KEV baseline and inspect `eclipse-state` |
| P3: incremental | Re-run KEV with identical feed without duplicate events; validate bounded CVE delta and EPSS selected scores | Enable source expansion on approved schedule |
| P4: historical archive | Decide an independent durable database location and acceptable storage quotas first | Only then consider full CVE ZIP BACKFILL locally (never as default Actions step) |

**CVE vs KEV**: Full KEV catalog validation is safe as a small baseline; do **not** confuse that with downloading every CVE in history. Source observations are not proof of exploitation at a customer. Do not put customer profiles or private work data in public GitHub Actions artifacts.

## v0.9 — Kaggle private CVE source-seed transport acceptance

Workflow: `ECLIPSE Kaggle private CVE-100 durable roundtrip`, source:
`.github/workflows/kaggle-cve-seed-roundtrip.yml`. This is one-shot on creation
and manually replayable. Uses the **ECLIPSE repository** `KAGGLE_API_TOKEN`
GitHub secret; all dataset creation is PRIVATE (does not use `--public`).

The workflow first runs the existing full CVE seed audit on the 100 verified
KEV-linked records. It builds a deterministic lossless ZIP containing the
original UTF-8 official CVE record bodies, their checksums, frozen cohort and
manifest; publishes this as a private Kaggle dataset with the fixed account-local
slug `eclipse-cve-seed-100-v1`. It then downloads all uploaded files to a
clean directory, verifies archive/member SHA-256 and CVE record identities, and
rebuilds SQLite from the restored source bodies. A matching existing Kaggle
dataset is read-only verified on rerun, never overwritten.

Scope: **exactly 100 public KEV-selected CVEs**, not the complete historical CVE
corpus. The Kaggle dataset is intentionally retained after success as a seed
storage proof. Private Kaggle handles, credentials and customer information are
not put into the public Git repository or published GitHub Actions receipt.
This is NOT automatic full-history backfill. Before expanding to full CVE
snapshots, use a capacity/version/retention plan and a separate independent
full-snapshot ingestion + restoration audit; no endless Git history or Kaggle
uploads on schedule. The zip source records are lossless; Parquet may be added
only as a derived searchable view.

## 2026-10-10 v0.9 VERIFIED: private Kaggle storage and independent restore

**Actual GitHub Actions + Kaggle results**, not a synthetic upload:

| Acceptance gate | Measured result |
| --- | --- |
| Original source | 100 KEV-selected official CVE v5 raw record bodies, previously frozen on eclipse-state |
| Kaggle | Created a dataset using existing KAGGLE_API_TOKEN, with PRIVATE default; stable account-local slug `eclipse-cve-seed-100-v1` |
| Readback | Downloaded the actual Kaggle dataset and verified SHA-256 of every record/shard and source cohort/manifest |
| Transport detail | Kaggle AUTO-EXTRACTED the nested ZIP. ECLIPSE re-packed the original member bytes deterministically and proved the ZIP SHA-256 matched |
| SQLite recovery | 100 CVEs rebuilt from downloaded originals; `PRAGMA quick_check=ok` |
| Idempotency | Subsequent acceptance run detected an existing dataset and verified it without overwriting |
| Separate CPU runner | Independently downloaded the private Kaggle dataset; all checks and SQLite reconstruction passed |
| Offline GitHub CI | 85 unit/integration tests passed |

Evidence: [successful Kaggle upload/readback run](https://github.com/pinogame1945-dotcom/ECLIPSE/actions/runs/38045830690) and [independent restore run](https://github.com/pinogame1945-dotcom/ECLIPSE/actions/runs/38045881683). JSON audit receipts are short-lived GitHub Actions artifacts; the PRIVATE Kaggle dataset is retained. The account handle/API token is not in this public repository's commit or artifact receipts.

**Scope:** This is still only 100 KEV-linked CVEs. Complete CVE baseline from the official release, capacity bounds, throughput benchmarks, crash recovery, source licensing and independent count reconciliation must be established before turning on mass BACKFILL. No paid runners, GPU, public Kaggle data publication, or customer data were used.

## Vendor/source verification registry — design gate (2026-10-10)

- Canonical review ledger: [config/vendor_source_registry.json](config/vendor_source_registry.json)
- Architecture, limits and production acceptance: [docs/VENDOR_SOURCE_DESIGN.md](docs/VENDOR_SOURCE_DESIGN.md)
- Real-world structured extraction coverage and remaining correctness gates: [docs/VENDOR_FIELD_AUDIT_20261010.md](docs/VENDOR_FIELD_AUDIT_20261010.md)
- Bounded publisher scale-up: **125 advisory/monthly documents across 9 sources**, with provenance, statuses and limitations: [docs/VENDOR_SCALE_AUDIT_20261010.md](docs/VENDOR_SCALE_AUDIT_20261010.md)
- **PRIVATE vendor Kaggle v1 (125/202) and v2 (160/241) both independently restored; full real 403,696 CVE read-only joins verified for both**: [docs/VENDOR_PRIVATE_KAGGLE_AND_CVE_JOIN_20261010.md](docs/VENDOR_PRIVATE_KAGGLE_AND_CVE_JOIN_20261010.md)
- Two immutable vendor generations, +35 published documents, isolated redirects and acceptance gates: [docs/VENDOR_KAGGLE_INCREMENTAL_V2_AUDIT.md](docs/VENDOR_KAGGLE_INCREMENTAL_V2_AUDIT.md)
- Real vendor product/version content audit: **14,147 claims checked against full 403,696-CVE source, 127 strict product matches, 3 *review-only* raw-predicate differences on a single CVE**: [docs/VENDOR_PRODUCT_CONTENT_AUDIT_DESIGN.md](docs/VENDOR_PRODUCT_CONTENT_AUDIT_DESIGN.md)
- **Private customer-used product monitor V1:** Strict Red Hat / Siemens CSAF product ID/name, scoped CVE-status evidence + product-targeted remediation text; successful **real PRIVATE Kaggle data with two entirely SYNTHETIC monitored products, 436 review-only status candidates**: [docs/CUSTOMER_VENDOR_CSAF_PRODUCT_V1.md](docs/CUSTOMER_VENDOR_CSAF_PRODUCT_V1.md)
- Verified one-shot source read/parse only: Fortinet, Microsoft, Palo Alto Networks,
  Red Hat CSAF, Siemens, Yamaha, GitLab, Canonical Ubuntu and Atlassian.
- Not verified: Google Chrome release Atom (insecure FeedBurner redirect) and Cisco (OAuth required).
- **No manufacturer feed is enabled for production polling or customer delivery.**
  Data-storage prototype (`src/eclipse_l0/vendor_store.py`) is local/offline, not connected to live feeds.
- Offline check: `PYTHONPATH=src python -m eclipse_l0.vendor_registry`
- Live experimental one-shot evidence:
  [Fortinet](https://github.com/pinogame1945-dotcom/ECLIPSE/actions/runs/38047330191),
  [five-vendor batch](https://github.com/pinogame1945-dotcom/ECLIPSE/actions/runs/38047802167),
  [four-vendor batch](https://github.com/pinogame1945-dotcom/ECLIPSE/actions/runs/38048161575).
