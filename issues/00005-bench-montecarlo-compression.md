# 00005 — bench-chunking: sampled compression estimates + multi-size --compression

- Type: AFK
- Priority: 3
- Tier: opus

## Why

Compression materially changes the story-table figures (ships, growth
milestones), but the precise `--compression` simulation costs a full
policy pass and is locked to exactly one candidate size. Owner request
(2026-07-11): a Monte-Carlo-style sampled estimate baked into every run
for a rough picture, plus `--compression` accepting a *couple of promising
sizes* (not strictly one) for the precise picture — with a clear warning
that each listed size adds a full single-size pass of work. This also
resolves 00004's open "compression labeling" item: story figures are
sampled estimates by default, measured when a precise pass covers that
size.

## Behavior

1. **Sampled estimate, always on**: during the single-pass walk, each
   candidate size selects a deterministic pseudo-random subset of its
   unique chunks — selection by chunk-ID prefix threshold (e.g. first two
   ID bytes < ceiling), which is uniform, reproducible run-to-run, and
   needs no RNG injection (AGENTS.md determinism rule). Default sample:
   1 % of unique bytes, capped at 2 GiB per candidate;
   `--compression-sample <pct>` overrides, `0` disables. Sampled chunks
   run through the real `busyncr_core::policy_bench::simulate_policy`
   (default policy), yielding an estimated compression ratio and a rough
   ± margin from the per-chunk ratio variance. Story-table byte/time
   figures gain compressed variants labeled `est.`; the label notes the
   sample %.
2. **`--compression` becomes multi-valued**: `--compression 128K,256K`
   runs the full FR-C1 §4.1 five-policy simulation once per listed size
   (each must be among the resolved `--sizes` candidates). Bare
   `--compression` keeps today's semantics (requires exactly one
   candidate). Before starting, print: "N sizes requested — each adds a
   full single-size compression pass; this can run long."
   Sizes covered by a precise pass replace their `est.` story figures
   with measured ones (labeled `measured`).
3. **JSON**: sampled estimates land under a `compression_estimates` key
   (per candidate: sample bytes/chunks, ratio, margin); the existing
   `compression_policies` key becomes per-size. Both flow into the 00001
   history files.

## Scope (exact)

- Touch: `crates/busyncr-core/src/policy_bench.rs` (sampling selection +
  estimate/margin; pure and deterministic)
- Touch: `crates/busyncr-client/src/bench_cmd.rs` (flag change, warning,
  table labels, JSON keys)
- Touch: `crates/busyncr-client/tests/frc5_bench_compression.rs`
- Touch: `docs/CHANGELOG.md`
- Out of scope: changing the policy engine or FR-C1 policies themselves;
  compression on the real backup path; report layout beyond the labeled
  figures (00004 owns layout).

## Test-first spec

```rust
// crates/busyncr-client/tests/frc5_bench_compression.rs
#[test]
fn frc5e_sampled_estimate_tracks_full_run_within_margin() {
    // arrange: generated mixed-compressibility corpus
    // act: default run (sampling on) + full --compression run, same size
    // assert: |estimated ratio − measured ratio| ≤ reported margin × k
}

#[test]
fn frc5f_sampling_is_deterministic_across_runs() {
    // two identical runs -> byte-identical compression_estimates JSON
}

#[test]
fn frc5g_multi_size_compression_matches_single_size_runs() {
    // --compression A,B equals the union of two single-size runs;
    // warning line printed once with N=2
}
```

## Steps

1. Failing tests; red.
2. Sampling + estimate in core; CLI flag/labels/JSON in bench_cmd.
3. `cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`.

## Done when

- [ ] Default run reports per-candidate estimated compression ratio ±
      margin; estimate validated against a full run (frc5e evidence)
- [ ] `--compression <sizes>` multi-size works, warns about cost, and
      upgrades those sizes' story figures to `measured`
- [ ] Determinism: identical reruns produce identical estimates
- [ ] Hard gates green from repo root, no new suppressions

## Blocked by

- 00001 (JSON payload shape settles once)
