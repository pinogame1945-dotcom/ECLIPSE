# ECLIPSE durable public-source state

This separate branch is written by the hourly CISA KEV monitoring workflow on `main`.
Only public CISA KEV record snapshots and change-event logs are allowed here.
No customer names, asset inventories, access tokens, unpublished findings, or employer data.

`data/kev-current.json` is initialized automatically by the first successful poll.
The first poll is a historical baseline, **not** a new-alert stream.
Events after the baseline go into `data/events/YYYY-MM.jsonl`.

Read application source and tests on `main`. Do not merge this branch into `main`.
