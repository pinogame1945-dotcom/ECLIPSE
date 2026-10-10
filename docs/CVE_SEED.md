# ECLIPSE — quota-bounded official CVE record seeding

## Purpose and scope

ECLIPSE already holds 1,739 public CISA KEV entries and a rolling CVE change **index**. We now preserve genuine CVE List V5 **record bodies**, but only in a reviewed, hard-capped cohort. This is a test of durable per-record archiving, **not** a claim to have every historical CVE.

An explicitly frozen list of the KEV catalog's CVE IDs (`dateAdded` descending; CVE ID tie-break) prevents moving targets when the upstream KEV catalog changes. Its SHA-256 and provenance are saved at `eclipse-state:data/cve-seed/cohort.json` and indexed in `manifest.json`.

Each bounded shard (`shards/0000-0024.jsonl`) holds exactly the original official UTF-8 CVE record text, a source SHA-256 and its deterministic official CVEProject raw URL. Each stage downloads **up to 25** original CVE records with **2 MiB** per-record, **3 MiB** per-shard, **12 MiB** total archive limits and an **absolute 100-CVE cap** in the engine. The workflow is further limited to **50** records and runs once or on manual replay; there is **no new recurring CVE backfill workflow**.

### Crash safety & recovery

- All source records for one shard must pass URL, byte-limit, JSON and exact CVE ID checks **before** any state files are written.
- A shard plus cursor/manifest is saved in a **single Git commit** on `eclipse-state`. A failed push is not silently retried with force. The write workflow shares the cross-workflow concurrency lock with KEV/CVE/EPSS.
- The next run validates **all existing** shard checksums, ordering and identities, then starts at the next unarchived CVE. A completed 50-item run is a no-op on replay.
- To recover a half-finished two-stage job, rerun the workflow. A first committed shard remains on the branch. No undetected cursor jumps are allowed.
- A GitHub state branch is a **small public-source prototype store**, not a long-term massive data lake. Git history grows with file revisions; a separate approved durable storage architecture is required before general all-CVE BACKFILL.

### Integrity audit & SQLite reconstruction

From a checkout that also contains the public `eclipse-state/data` directory:

```sh
PYTHONPATH=src python -m eclipse_l0.cve_seed \
  --state-dir /path/to/eclipse-state/data \
  --audit-only --export-sqlite output/rebuilt-cve-seed.sqlite3 \
  --out output/seed-audit.json
```

Audit enforces contiguous shard indexes, checksums over original bytes, CVE IDs and URLs, non-overlapping frozen cohort entries and the explicit storage quota. SQLite reconstruction replays each verified CVE body through the standard L0 `_upsert_cve` and asserts `PRAGMA quick_check = ok` and expected record counts.

### Full historical CVE requirements (NOT YET IMPLEMENTED)

1. Verify this small bounded source cohort against the upstream and failure/replay scenarios.
2. Choose and test a **durable capacity-controlled** object store (not unlimited Git commits) for full upstream CVE ZIP and incremental raw updates; verify licensing and quotas.
3. Implement a frozen-date full release baseline with archive checksum, extraction limits, chunk checkpoints, atomic commits, version history, reconciliation with the rolling delta cursor, resume semantics, and an end-to-end independent source count audit.
4. Only then consider scaling beyond the explicit 50-CVE pilot. Do not equate 50 KEV-linked records with arbitrary CVE coverage.

All paths here contain **PUBLIC upstream CVE source records** only. Customer profiles, asset inventories, private incident details, credentials, and client deliverables must never enter this public repo.
