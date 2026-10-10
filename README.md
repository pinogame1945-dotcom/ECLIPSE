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
