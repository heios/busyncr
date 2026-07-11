# 00003 — bench-chunking: first-class sub-256K candidate sizes

- Type: AFK
- Priority: 3
- Tier: sonnet

## Why

The default candidate list starts at 256K, so a default run can recommend
256K only as the *boundary* candidate — the operator cannot see whether
64K/128K would win (owner request 2026-07-11: sub-256K sizes will be
offered so people can pick per situation, especially once the packed store
layout absorbs the object-count cost). The FastCDC engine already permits
this: `AVERAGE_MIN` is 256 bytes and `ChunkerConfig::with_target`'s
`min = target/4` stays within `MINIMUM_MIN` (64 B) far below 256K — the gap
is defaults, docs, and verification, not capability.

## Behavior

- Default `--sizes` becomes `64K,128K,256K,512K,1M,2M,4M`.
- Explicit sub-256K values (down to a sane documented floor, e.g. `16K`)
  are accepted and produce correct per-candidate rows; absurd values below
  the floor keep failing with the existing clear config error.
- The recommendation heuristic and all projections (index, manifest,
  bookkeeping) are re-checked for small-size arithmetic (they are
  per-entry linear, so this should be verification, not change).
- docs/PRD.md §3.7's example size list and the `--help`/long-about text
  gain the new defaults; note that sub-256K multiplies daemon object count
  until the packed layout lands (forward reference, one sentence).

## Scope (exact)

- Touch: `crates/busyncr-client/src/bench_cmd.rs` (default list, help text)
- Touch: `crates/busyncr-core/src/chunking.rs` (only if a doc comment or a
  named floor const is needed — no engine behavior change)
- Touch: `crates/busyncr-client/tests/fr10_bench_chunking_cli.rs`
- Touch: `docs/PRD.md` §3.7 (example sizes), docs/CHANGELOG.md
- Out of scope: committing sub-256K on the real backup path is already
  allowed by config validation — no client backup changes; the packed
  store layout; recommendation heuristic redesign.

## Test-first spec

```rust
// crates/busyncr-client/tests/fr10_bench_chunking_cli.rs
#[test]
fn fr10k_sub_256k_candidates_chunk_and_report() {
    // arrange: generated corpus; act: --sizes 64K,128K,256K
    // assert: three rows; 64K row's chunk count within CDC tolerance of
    //   bytes/64K; per-candidate counts match single-candidate reference
    //   runs (FR10b invariant extended downward)
}

#[test]
fn fr10l_default_sizes_include_small_candidates() {
    // act: run with no --sizes; assert rows for 64K and 128K exist
}
```

## Steps

1. Failing tests above; red.
2. Change defaults + docs; verify projections.
3. `cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`.

## Done when

- [ ] Default run reports 64K–4M; sub-256K figures match single-candidate
      reference runs (fr10k evidence inline)
- [ ] PRD §3.7 + help text updated; CHANGELOG entry
- [ ] Hard gates green from repo root, no new suppressions

## Blocked by

- none (independent of 00001/00002; merge-order with 00002 is whoever
  lands second rebases the report rows)
