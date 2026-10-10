# PROJECT ECLIPSE

Independent, evidence-first cyber threat intelligence pipeline.

## Goal
Collect authoritative public advisories and updates, preserve changes, detect meaningful events (especially CISA KEV additions), and generate **customer-configurable, editable PowerPoint briefings**. Future phases: evidence-based technical commentary and approved asset exposure matching.

## Architecture
- **L0 / BACKFILL**: CVE List V5 and CISA KEV, immutable observations, SQLite source audit.
- **Events**: KEV additions, advisories, evidence changes; do not confuse KEV `dateAdded` with exploitation start.
- **Reports**: filter by customer/vendor/product and generate daily/periodic PPTX with provenance.
- **Future**: EPSS, NVD, JVN, manufacturer PSIRT, validated analysis and optional customer inventory.

## Safety and operating rules
- **This repository is PUBLIC. Never commit real customer names, inventories, reports, API keys or employer work products.**
- Official/rights-cleared source feeds only; OpenCVE is not a commercial data-reuse source.
- KEV absence does not mean no exploitation; no automatic per-customer impact determination without authorized asset data.
- GitHub Actions runners and short-lived artifacts are not durable databases.
- No paid runners or services. CI is offline; automatic distribution is not enabled.

## Current bootstrap
Repository created; first code delivery in progress. Source prototypes have already been prepared separately:
- L0 evidence collector v0.1 (CVE + KEV).
- KEV PPTX report generator v0.2 (synthetic demo; independent of L0 DB).
Both need unification and a persistent data store before production scheduling.

## Roadmap
1. Import both prototypes, run unit tests on GitHub Actions.
2. Unify L0 KEV feed and report generator with provenance, manual execution first.
3. Add source-diff event detection and manufacturer-agnostic customer profiles.
4. Add validated technical explanation and user-controlled alert/report delivery.
