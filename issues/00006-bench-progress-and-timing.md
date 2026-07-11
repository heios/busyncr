# 00006 — bench-chunking: live progress + run timing stats

- Type: AFK
- Priority: 3
- Tier: sonnet

## Why

A real-workload run reads hundreds of GiB and can take hours, currently in
silence — the operator cannot tell a working run from a hung one, and the
report doesn't say what the run cost (owner request 2026-07-11). FR-M1
M2.1 already established the client progress conventions for
backup/restore; bench adopts the same ones.

## Behavior

1. **Live progress on stderr**, updated a couple of times a second
   (throttle ~3 Hz, never per-file): files processed (running / total once
   the enumeration pass knows it), bytes processed with running MB/s,
   current file path (middle-truncated to terminal width), and a phase
   label — `walk`, `chunk+hash`, `baseline`, `compression <size>`.
   M2.1 conventions apply: carriage-return updating line on a TTY, plain
   one-line-per-interval when not; `--quiet` suppresses everything but
   errors; `--json-progress` emits NDJSON events instead.
2. **Timing stats in the final report**: total wall clock plus per-phase
   breakdown (current tree, baseline tree, each precise compression
   pass), printed with the human table and included in the JSON payload
   (`timings` key) — so 00001's history records what every run cost.
   Clock is read at the CLI edge only (M2.2-style rule: timing must not
   perturb the measured figures, and core stays deterministic).
3. Progress accounting reuses the walk's own byte counters — the FR10a
   single-read invariant is untouched.

## Scope (exact)

- Touch: `crates/busyncr-client/src/bench_cmd.rs`
- Touch: `crates/busyncr-client/src/progress.rs` (a bench tick alongside
  `backup_tick`/`restore_tick`, or a small generalization — do not fork a
  second progress implementation)
- Touch: `crates/busyncr-client/tests/fr10_bench_chunking_cli.rs`
- Out of scope: progress for other subcommands; ETA modeling beyond the
  running rate; report layout (00004).

## Test-first spec

```rust
// crates/busyncr-client/tests/fr10_bench_chunking_cli.rs
#[test]
fn fr10m_json_progress_events_parse_and_are_monotone() {
    // act: run with --json-progress over a generated corpus
    // assert: every stderr line parses as a progress event; files/bytes
    //   counters are monotone; final event totals == report totals
}

#[test]
fn fr10n_quiet_emits_nothing_but_report() {
    // act: --quiet; assert stderr empty, stdout table present
}

#[test]
fn fr10o_timings_present_in_json_report() {
    // assert: timings.total_ms > 0, phases cover current tree (+ baseline
    //   when given), sum of phases ≤ total
}
```

## Steps

1. Failing tests; red.
2. Bench tick in progress.rs; wire counters + phase labels + timings.
3. `cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`.

## Done when

- [ ] TTY and non-TTY progress behave per M2.1 conventions; ~3 Hz throttle
      asserted (no per-file spam in the NDJSON stream)
- [ ] `--quiet` / `--json-progress` parity with backup/restore flags
- [ ] Timings printed and persisted in JSON (fr10o evidence)
- [ ] Hard gates green from repo root, no new suppressions

## Blocked by

- none (coordinate the `timings` JSON key with 00001 — whoever lands
  second rebases)
