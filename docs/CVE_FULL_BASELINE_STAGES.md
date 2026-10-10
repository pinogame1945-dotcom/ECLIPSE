# CVE full baseline: staged before Kaggle publication

This bounded staging pipeline does **not** claim a complete historical CVE mirror. The official CVEProject release asset may be named `...zip.zip`; the archive contents, rather than the filename suffix, are inspected (direct CVE JSON members or exactly one nested ZIP). Asset identity, byte size, release tag and resulting source SHA-256 are recorded. Acquisition supports a strict HTTP byte-range resume and rejects a changed source or ignored Range.

On push to `main`, the workflow executes the smallest **1,000-record** staging gate; manual dispatch can request **10,000 or 50,000 records**. One run downloads just one 800 MiB-capped official baseline ZIP. For consistency the sampler orders all available CVE IDs by SHA-256 digest and takes the first N, rather than selecting one historic year. This is a *repeatable sampling gate*, not a statistically validated representative study. Raw JSON bytes are preserved in deterministic shards and byte-compared with the pinned original source even on resumptions.

Execution: `PYTHONPATH=src python -m eclipse_l0.full_baseline --workdir /private/work --limit 1000`

ZIP entries are checked for path traversal, duplicates, symlinks, oversized CVE members and total uncompressed budget. Any invalid CVE JSON or ID mismatch fails closed. Staging manifests and observed source counts are uploaded as 7-day CI artifacts. **Verbatim raw sample files remain on ephemeral runner disk.** No existing Kaggle dataset is overwritten. Only after validated storage capacity, private dataset upload, independent download, per-shard SHA and SQLite reconstruction can historical backfill be declared durable.

The project keeps separate semantics for full baseline time, index fetch time and observation time. A full sample or historic snapshot does not retroactively close a missing CVE delta window.
