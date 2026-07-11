# 03 — Monitor data model: what the daemon can honestly report per client

- Type: grilling
- Status: open
- Blocked by: none

## Question

Fix the "reasonable depth" of the monitor: the exact data set, per client
and store-wide, that v1 of the live monitor ships — and what new tracking
the daemon must start persisting to provide it. Grill through, against the
zero-knowledge constraint (daemon sees chunk IDs/sizes/refcounts and
snapshot→client attribution; never plaintext or file names):

1. **Client inventory** — enrolled clients with name, cert fingerprint,
   enrolled-at, revoked flag (identity store already has this); do we add
   daemon-side **last-seen** (any authenticated RPC) and is that persisted
   or in-memory-since-start?
2. **Last client work + outcome** ("status of that work if we can have this
   data"): the daemon observes upload sessions and manifest commits. Track
   per client: last completed snapshot (id, time, bytes received, chunk
   count), and an **in-progress/aborted** upload indicator? What survives a
   daemon restart?
3. **Per-client disk attribution** under dedup: bytes are shared between
   snapshots and (within a backup set) between clients. Pick semantics —
   e.g. borg-style `unique_bytes` (chunks referenced *only* by this
   client's snapshots) + `total_referenced_bytes`, and make the
   non-additivity explicit in output. Is computing this on demand
   affordable (index scan) or does it need maintained counters? Scale
   datum from the owner's real workload (2026-07-11 bench, see
   `docs/waycharting/packed-store-layout/2026-07-11-documents-bench.md`): ~940K
   unique chunks at the 256K front-runner size — an on-demand scan over
   ~1M index entries is likely affordable, weakening the case for
   maintained counters.
4. **Store-wide**: footprint (already in FR-M1 status), quota + headroom +
   over-quota flag (FR-Q1 Q1.6), zero-ref chunks awaiting GC, last
   prune/gc time+mode+amount reclaimed — anything else the first
   production run needs to *see*?
5. What of this is **v1-of-the-monitor** vs deferred? Depth is the
   deliverable: a field list with per-field source (existing index / new
   persisted record / computed on demand).

Output feeds the interface mock (ticket 06) and the spec assembly
(ticket 07).
