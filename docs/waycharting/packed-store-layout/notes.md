# Packed store layout — pre-charter seed notes (2026-07-11)

Not yet a wayfinder map. Charter one when the extended bench data lands
(issues 00001–00006 give the rerun everything it needs). The agreed
directions live in docs/ROADMAP.md **R8** — that entry is normative-ish;
this file holds the surrounding reasoning a future design session (opus)
should not have to re-derive.

## Why packs and not "bigger chunks via secondary mapping"

Two interpretations of "map small chunks into uniform bigger blocks" were
weighed; only one survives:

- **Pack = storage container** (chosen): chunk keeps identity/dedup/
  encryption; the pack is only how bytes land on disk. Restic "pack
  files" / borg "segments" lineage.
- **Superchunk = second-level dedup unit** (rejected): if the bigger unit
  gets its own identity and becomes the transfer/comparison unit, any
  member change changes the container — dedup regresses toward the big
  size while small-chunk bookkeeping costs stay. Worst of both.

## Load-bearing facts (verified in code 2026-07-11)

- Store layout: `objects/<first2hex>/<hex>`, one file per chunk, 32-byte
  BLAKE3-of-blob header (`crates/busyncr-daemon/src/store.rs` module doc).
- Chunks are *individually* XChaCha20-Poly1305-encrypted ⇒ a pack is pure
  concatenation ⇒ the daemon can repack/compact via byte-range copies
  with no keys. This single fact drove: packing must be daemon-side.
- `snapshot_refs` (redb) stores 32 B per chunk reference per snapshot,
  unencrypted, so prune/GC never decrypts manifests — it is the dominant
  bookkeeping term and the seqno-refs target.
- FastCDC v2020 floor is a 256-*byte* average (`fastcdc` 4.0.1);
  `ChunkerConfig::with_target` (min = target/4) is legal far below 256K —
  sub-256K was never an engine limitation, only a bench-defaults one.
- redb store is exclusive-lock: any live pack-utilization / monitor
  surface must ride the daemon-service effort's admin channel
  (`docs/waycharting/daemon-service-and-live-monitor/`, ticket 01).

## Open questions for the future map (fog, pre-charter)

- Pack size target (~32–64 MiB assumed) vs restore-latency granularity:
  restore of one chunk = ranged read, fine; but does download streaming
  want pack-aligned batching?
- Repack policy: dead-fraction threshold? write-amplification budget?
  interaction with the GC grace period (S9 machinery) and with FR-Q1
  enforcement ordering (grid prune → tail-shed → compact?).
- Migration slice: existing ~1M-object store → packs, in place, crash-safe,
  with the store possibly serving during migration (or a documented
  offline migration as v1).
- Index schema rewrite: chunk ID → (pack, offset, len, refcount) + u64
  seqno; do refcounts move to per-pack live-byte counters?
- Does `bench-chunking` grow a pack-utilization projection (garbage rate
  from dead-chunk accrual, issue 00002, × repack threshold ⇒ steady-state
  overhead %)?
- 16-byte ID truncation: decide only if sub-256K wins; needs ADR-0001
  amendment and pre-first-backup timing (see R8).

## Owner decisions already made (do not re-litigate)

- Daemon-side packing: **approved**.
- u64 seqno refs in `snapshot_refs`: **approved**, bundle with pack index
  rewrite.
- Sub-256K sizes will be offered to users regardless (issue 00003).
- Production-run gate: chunk size settles before the first real backup;
  packs land first if sub-256K is chosen.
