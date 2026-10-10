# CVE full baseline: staged before Kaggle publication

This bounded staging pipeline does **not** claim a complete historical CVE mirror. The official CVEProject release asset may be named `...zip.zip`; the archive contents, rather than the filename suffix, are inspected (direct CVE JSON members or exactly one nested ZIP). Asset identity, byte size, release tag and resulting source SHA-256 are recorded. Acquisition supports a strict HTTP byte-range resume and rejects a changed source or ignored Range.

On push to `main`, the workflow executes the smallest **1,000-record** staging gate; manual dispatch can request **10,000 or 50,000 records**. One run downloads just one 800 MiB-capped official baseline ZIP. For consistency the sampler orders all available CVE IDs by SHA-256 digest and takes the first N, rather than selecting one historic year. This is a *repeatable sampling gate*, not a statistically validated representative study. Raw JSON bytes are preserved in deterministic shards and byte-compared with the pinned original source even on resumptions.

Execution: `PYTHONPATH=src python -m eclipse_l0.full_baseline --workdir /private/work --limit 1000`

ZIP entries are checked for path traversal, duplicates, symlinks, oversized CVE members and total uncompressed budget. Any invalid CVE JSON or ID mismatch fails closed. Staging manifests and observed source counts are uploaded as 7-day CI artifacts. **Verbatim raw sample files remain on ephemeral runner disk.** No existing Kaggle dataset is overwritten. Only after validated storage capacity, private dataset upload, independent download, per-shard SHA and SQLite reconstruction can historical backfill be declared durable.

The project keeps separate semantics for full baseline time, index fetch time and observation time. A full sample or historic snapshot does not retroactively close a missing CVE delta window.

## Independent capacity verification and opt-in full private mirror

2026-10-10 official asset `627669472` was read in CI. SHA256
`727c63047df02ffb00c63812c82dcae20512c42c786be4b36c7630be30cb79c1`;
403,696 CVE JSON members; source asset 623,918,711 bytes; ZIP uncompressed
claimed bytes 3,378,548,983. The 10k and 50k gates both completed and matched
the source SHA, without a Kaggle upload.

`one-shot-kaggle-cve-full.yml` pins this **specific immutable archive** and
requires *exactly* 403,696 validated raw CVE records before a new Kaggle dataset
can be created. All historical source JSON bytes are kept as shards with opaque
`.cvepack` extension to avoid Kaggle automatically expanding every ZIP into
hundreds of thousands of individual files. Private dataset create only: no
`--public`, no `datasets version`, no update of an existing dataset; if existing,
readback and checksum verification only. A new clean runner may verify returned
manifest, every shard digest, every ZIP CRC and the entire ID coverage, plus
reconstruct a sampled SQLite database (one original record per shard). Claims
about durable full storage require that GitHub Actions run to **success**.

The full Kaggle dataset is **not** the running L0 SQLite database: future work
can import its verified shards into durable SQLite and join CISA KEV/EPSS. The
Actions artifact contains **receipt metadata only**, not dataset credentials,
raw CVEs or dataset owner. This is a historical baseline, not live alerts.
