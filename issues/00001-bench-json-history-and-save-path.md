# 00001 — bench-chunking: always persist JSON analysis, keep last 10 unique

- Type: AFK
- Priority: 3
- Tier: sonnet

## Why

A full `bench-chunking` run over a real workload costs a complete dataset
read (~494 GiB, hours). Today the machine-readable analysis exists only if
the operator thought to pass `--json` — otherwise the expensive run leaves
nothing behind for later, more elaborate analysis (owner request,
2026-07-11: an expensive benchmark without `--json` must not gate deeper
analysis after the fact). Persist every run's JSON automatically, ring-
buffered to the last 10 unique results.

Owner phrasing was "drop json analysis into daemon working directory";
bench-chunking is offline/keyless and typically runs on the *client* host
pre-enrollment (PRD §3.7), where no daemon or state dir exists — so the
history lives in busyncr's per-user data directory instead:

- Windows: `%LOCALAPPDATA%\busyncr\bench-history\`
- macOS: `~/Library/Application Support/busyncr/bench-history/`
- Linux: `$XDG_DATA_HOME/busyncr/bench-history/` (fallback
  `~/.local/share/busyncr/bench-history/`)

Resolved via std `env::var` only — no new dependency (AGENTS.md palette).

## Behavior

1. **Always-on history**: every completed run serializes the full JSON
   report to `bench-history/bench-<UTC yyyymmdd-HHMMSS>-<hash8>.json`,
   regardless of flags. Print one line telling the operator it was saved
   and where.
2. **Unique**: `<hash8>` = first 8 hex of BLAKE3 over the canonical JSON
   payload *excluding* the run timestamp field. If a file with the same
   hash suffix already exists in the history dir, skip the write (identical
   rerun), but still print its path.
3. **Ring of 10**: after a successful write, delete oldest-first (by
   filename timestamp, which sorts lexicographically) until ≤ 10 files
   remain.
4. **`--json` becomes an optional-value save flag**: `--json <path>` writes
   the JSON to that exact path; bare `--json` writes to the user's
   Documents folder (`%USERPROFILE%\Documents`, `~/Documents`) as
   `busyncr-bench-<timestamp>.json`. Either way the saved path is printed.
   JSON is **no longer emitted on stdout** (breaking change vs FR-M1-era
   behavior — record in docs/CHANGELOG.md; scripts read the file whose
   path is printed). The human-readable table prints to stdout in all
   modes, as today.
5. History write failure (read-only home, etc.) is a stderr warning, never
   a benchmark failure — the report still prints.

## Scope (exact)

- Touch: `crates/busyncr-client/src/bench_cmd.rs`
- Touch: `crates/busyncr-client/tests/fr10_bench_chunking_cli.rs` (existing
  `--json` stdout assertions must migrate to file-based)
- Touch: `docs/CHANGELOG.md`
- Out of scope: any change to the measured figures or report content
  (that is 00002); config-file knobs for history size; the daemon binary.

## Test-first spec

```rust
// crates/busyncr-client/tests/fr10_bench_chunking_cli.rs
#[test]
fn fr10e_history_json_written_without_json_flag() {
    // arrange: tiny corpus, HOME/XDG_DATA_HOME (unix) or LOCALAPPDATA
    //   (windows) pointed at a tempdir
    // act: run bench-chunking with NO --json
    // assert: exactly one bench-*.json in bench-history/, parses, and its
    //   figures match the stdout table's chunk counts
}

#[test]
fn fr10f_history_dedupes_identical_runs_and_caps_at_ten() {
    // arrange: same corpus; run twice (identical) -> 1 file;
    //   then 11 distinct runs (vary --sizes) -> 10 files, oldest gone
}

#[test]
fn fr10g_json_flag_writes_to_given_path_not_stdout() {
    // act: --json <tempfile>; assert file exists + parses, stdout contains
    //   the human table and the printed save path, but no JSON payload
}
```

## Steps

1. Write the failing tests above; run scoped tests to see red.
2. Implement history dir resolution + hash/dedupe/ring + `--json` value in
   `bench_cmd.rs` (clap `Option<Option<PathBuf>>` via
   `num_args(0..=1)`).
3. `cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`.

## Done when

- [ ] Run without `--json` leaves a parseable history JSON; 10-file ring
      and identical-run dedupe asserted by tests
- [ ] `--json [path]` semantics as specified; stdout carries no JSON
- [ ] CHANGELOG notes the `--json` stdout → file breaking change
- [ ] Hard gates green from repo root, no new suppressions

## Blocked by

- none
