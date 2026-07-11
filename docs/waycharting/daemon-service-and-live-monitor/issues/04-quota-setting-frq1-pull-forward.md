# 04 — Quota setting surface + FR-Q1 pull-forward deltas

- Type: grilling
- Status: open
- Blocked by: 01

## Question

FR-Q1 (global store quota + tail pruning) is pulled forward from
post-v0.1.0 into this effort (owner decision at charting). The spec
(docs/FR-Q1.md) is largely ready; what needs deciding:

1. **Setting the quota** — FR-Q1 assumes `store_quota_bytes` in the daemon
   config file. The owner asked for "quota setting" as a monitor/control
   operation: does `set-quota` ride the admin channel (ticket 01) and
   persist into the config, is it config-file-edit + reload/restart only,
   or both? What about `min_snapshots` (the safety floor)?
2. **Spec deltas** — re-read FR-Q1 against today's tree: trigger points
   reference FR-M1 machinery that has since landed; does anything in
   Q1.1–Q1.7 need amending (e.g. enforcement status in the *live* status
   payload rather than the offline command)?
3. **Scheduling** — FR-Q1's "post-v0.1.0" line and ROADMAP R7 need
   updating; confirm it ships inside this effort's slice DAG and in what
   order relative to the monitor (Q1.6 observability wants the monitor
   fields to exist).

Resolution updates docs/FR-Q1.md status + docs/ROADMAP.md and hands the
enforcement-visible-in-monitor fields to ticket 03's data model if not
already settled there.
