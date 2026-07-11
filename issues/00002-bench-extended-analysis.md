# 00002 — bench-chunking: file-size histogram, churn locality, dead-chunk accrual

- Type: AFK
- Priority: 3
- Tier: opus

## Why

The chunk-size decision (and the coming packed-store effort) needs three
figures the current report cannot answer (owner request, 2026-07-11, from
the sub-256K discussion):

1. **Where the bytes live** — small files chunk 1:1 at any target, so the
   benefit of finer chunking is capped by how much of the corpus sits in
   large files. A bytes-weighted file-size histogram makes that ceiling
   visible.
2. **Where the churn lives** — whether the baseline→current differences
   concentrate in a few large mutable files (finer chunks pay) or in
   wholesale-replaced files (they don't). Overlap% per file-size bucket.
3. **Garbage-generation rate** — the fraction of baseline unique chunks
   absent from the current tree (count + bytes, per candidate size). This
   drives pack-utilization/repack policy for the packed store layout.

All three are computable from data the single-pass walk already produces
(per-file sizes + per-file chunk lists in core `bench`); no second dataset
read.

## Behavior

- **File-size histogram** (always, no baseline needed): buckets `<64K`,
  `64–256K`, `256K–1M`, `1–4M`, `4–16M`, `16–64M`, `>64M` — file count,
  total bytes, % of corpus bytes per bucket.
- **Churn by bucket** (only with `--baseline`): per bucket and per
  candidate size, overlap% restricted to that bucket's files, plus
  changed/added/removed file counts and bytes (a file "changed" = same
  relative path, different chunk-ID set).
- **Dead-chunk accrual** (only with `--baseline`): per candidate size,
  baseline unique chunks (and bytes) with no occurrence in the current
  tree — reported as count, bytes, and % of baseline unique bytes.
- All of it lands in the JSON payload (hence in the 00001 history files)
  and as a compact section of the human table; baseline-dependent sections
  print `n/a (run with --baseline)` otherwise, matching the existing
  incremental-row convention.

## Scope (exact)

- Touch: `crates/busyncr-core/src/bench.rs` (analysis over the collected
  `FileChunking` data; pure, deterministic)
- Touch: `crates/busyncr-client/src/bench_cmd.rs` (table + JSON rendering)
- Touch: `crates/busyncr-client/tests/fr10_bench_chunking_cli.rs`
- Out of scope: any new dataset pass (single-read invariant FR10a stays),
  changes to existing measured figures or the recommendation heuristic,
  packing itself.

## Test-first spec

```rust
// crates/busyncr-client/tests/fr10_bench_chunking_cli.rs
#[test]
fn fr10h_histogram_buckets_match_generated_corpus() {
    // arrange: corpus with known file sizes straddling bucket edges
    // assert: per-bucket counts/bytes exact; % sums to 100 within rounding
}

#[test]
fn fr10i_churn_by_bucket_isolates_the_mutated_file() {
    // arrange: baseline + copy with exactly one large file mutated at a
    //   known rate; assert changed-file count == 1, its bucket's overlap%
    //   drops, other buckets stay 100%
}

#[test]
fn fr10j_dead_chunk_accrual_matches_known_deletion() {
    // arrange: baseline containing a file deleted from the current tree
    // assert: dead-chunk bytes ≈ that file's unique bytes, per size
}
```

Core-level unit tests for the pure analysis live next to `bench.rs`
(`#![deny(missing_docs)]` applies).

## Steps

1. Write the failing tests; see red.
2. Implement pure analysis in `busyncr-core::bench`, rendering in
   `bench_cmd.rs`.
3. `cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`.

## Done when

- [ ] Histogram, per-bucket churn, and dead-chunk figures asserted exact
      on generated corpora (the fr10h–j tests)
- [ ] Single-read invariant still holds (existing FR10a I/O accounting
      test unmodified and green)
- [ ] JSON payload carries all new sections; human table stays one screen
- [ ] Hard gates green from repo root, no new suppressions

## Blocked by

- 00001 (JSON payload shape should settle once — history + new fields land
  in one format change)
