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
Full spec: FR-Q1.md. Originally post-v0.1.0 by owner decision (2026-07-10);
**pulled forward 2026-07-11** into the daemon-service + live-monitor effort
(wayfinder map `docs/waycharting/daemon-service-and-live-monitor/`, ticket 04 owns
the spec deltas and the quota-setting surface).

## R6 — Restore ergonomics

Single-file / subtree restore without full-snapshot download (manifest
already supports per-file chunk lists); point-in-time browsing.

## R8 — Packed store layout + bookkeeping compaction

Directions agreed with the owner 2026-07-11 (sub-256K chunking discussion);
to be chartered as its own wayfinder map once the extended bench data
exists (issues 00001–00006). Seed notes + the owner's real-workload bench
data: `docs/waycharting/packed-store-layout/`.

- **Daemon-side pack files**: chunks remain the unit of identity, dedup,
  and encryption; the daemon concatenates individually-encrypted chunks
  into ~32–64 MiB pack files (index: chunk ID → pack, offset, len,
  refcount), collapsing the objects/ file count by 2–3 orders of magnitude
  and unlocking sub-256K chunk sizes. Because chunks are individually
  encrypted, the daemon can **compact packs by byte-range copy without any
  keys** — this is why packing is daemon-side; client-side packing was
  rejected (daemon couldn't compact ⇒ GC and quota enforcement would need
  client cooperation). Zero-knowledge unchanged: the daemon already knows
  chunk IDs and lengths; offsets add nothing (FR-K1 threat model intact).
- **GC changes meaning**: prune no longer deletes files, it strands dead
  bytes inside sealed packs; a repack policy (dead-fraction threshold,
  write-amplification budget) replaces file deletion. FR-Q1 interplay:
  footprint = pack bytes ≥ live bytes, so over-quota may trigger
  compaction, not just tail-pruning; the live monitor should surface pack
  utilization.
- **u64 seqno refs** (approved): the daemon assigns each unique chunk a
  u64 sequence number; `snapshot_refs` stores 8-byte seqnos instead of
  32-byte chunk IDs — 4× off the dominant bookkeeping term, daemon-local,
  migratable, and naturally bundled with the pack-layer index rewrite.
- **16-byte chunk-ID truncation** (parked): cryptographically defensible
  *only because* IDs are keyed (FR-K1 — no adversarial collision surface
  without the key; accidental 128-bit birthday risk negligible at any
  realistic chunk count). Halves manifest/wire ID bytes, but changes every
  chunk ID ⇒ resets dedup continuity like a chunk-size change, so it must
  be decided **before the first production backup**, and would amend
  ADR-0001. Revisit only if sub-256K is chosen.
- **Sequencing (production-run gate)**: chunk size is frozen at first
  backup; the pack layer is retrofittable later *without* a dedup reset
  (chunk identity untouched). Therefore: settle the chunk size before the
  first production backup; if the extended bench favors sub-256K, land
  packs first rather than operating a multi-million-file objects/ tree.
