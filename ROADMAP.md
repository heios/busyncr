# BusyNCR — Roadmap (post-v1 planned features)

Features planned beyond the v1 acceptance scope (PRD.md §4–§5). Not part of
the autonomous v1 build; specs here are directional, to be grilled before
implementation.

## R1 — WebDAV secondary backup target (daemon-side replication)

The daemon replicates its store to a WebDAV remote as an off-site copy.

- **Modes**:
  - *Full mirror*: entire chunk store + manifests replicated.
  - *Quota-bounded recent history*: given a space quota, keep the most recent
    snapshots that fit — pack newest-first: include snapshots one by one
    (newest → oldest), accounting each snapshot's *incremental* unique-chunk
    cost, stop before exceeding quota. Re-evaluated after each backup/prune.
- **Trust model**: WebDAV host is untrusted. Blobs are already client-side
  encrypted (PRD §3.4) and content-addressed, so replication uploads
  ciphertext + encrypted manifests only; nothing new leaks.
- **Mechanics**: resumable sync (compare remote listing vs local index; upload
  missing, delete evicted), periodic integrity spot-checks (ranged GET +
  hash), sync state journal so interrupted syncs converge.
- **Restore path**: daemon can re-hydrate its local store from WebDAV; client
  restore-from-WebDAV-directly is a stretch goal (needs manifest listing
  without daemon index).

## R2 — Real-time fs-notification triggers

`ReadDirectoryChangesW` (Windows) / inotify (Linux) watch + debounce as an
*additional* trigger in front of the schedule, with the scheduled backup
remaining as reconcile safety net. Deferred from v1 by decision (schedule
chosen as the primary model).

## R3 — Multi-daemon replication

Daemon↔daemon sync (same manifest/chunk protocol) for redundant backup
servers. WebDAV (R1) covers the simpler off-site case first.

## R4 — Bandwidth shaping & tunable compression

Upload throttling, per-schedule-window limits; zstd level tuning and
dictionary experiments per data profile (bench-chunking could grow a
compression-benchmark mode).

## R5 — Web UI / status dashboard

Read-only first: snapshot browser, retention grid visualization, storage
stats, per-client health. CLI remains the control plane.

## R7 — Store disk quota + tail pruning (FR-Q1)

Cap the daemon store's disk footprint (`store_quota_bytes`); when exceeded,
shed history strictly oldest-first (beyond what the retention grid already
thinned), with a never-drop safety floor of the newest `min_snapshots`.
Full spec: FR-Q1.md. Explicitly post-v0.1.0 by owner decision (2026-07-10).

## R6 — Restore ergonomics

Single-file / subtree restore without full-snapshot download (manifest
already supports per-file chunk lists); point-in-time browsing.
