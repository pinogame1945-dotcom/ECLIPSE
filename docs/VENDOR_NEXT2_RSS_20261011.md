# Two extra official publisher RSS candidates — 2026-10-11

Following PRIVATE Kaggle V3 SUCCESS, two NEW independent RSS **candidate-only** source IDs were added on the isolated vendor feature branch.

- `juniper-mist-security-rss`: official Juniper Mist security alerts RSS `https://www.mist.com/documentation/category/security-alerts/feed/`. This covers **Mist category alerts**, not all Juniper SRX/EX/Junos JSA. The original `juniper-jsa` remains failed until its own source discovery is proven.
- `ivanti-security-advisory-rss`: official Ivanti security advisory blog RSS `https://www.ivanti.com/blog/topics/security-advisory/rss`. This covers RSS-published blog announcements, not every private Ivanti KB notice.

Both are initially `not_tested` and `enabled_for_production=false`. A dedicated separate GitHub Actions live probe must show official RSS → official HTTPS detail → bounded content → advisory ID + CVE links before any status changes. No source bodies or credentials are committed; no customer impact inferred.

Existing immutable PRIVATE V1/V2/V3 datasets and CVE/KEV/EPSS are untouched. Success in the dedicated RSS probe is not proof of full vendor coverage, version applicability or legal redistribution rights.
