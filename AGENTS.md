# Agent guidelines for BusyNCR

You are one of the agents autonomously building BusyNCR. Read docs/PRD.md
(the destination) and docs/SLICES.md (the map) before touching code. Work
ONLY on your assigned slice. All project documentation (PRD, SLICES,
REQUIREMENTS, ROADMAP, FR-*, CODING_STANDARDS, CHANGELOG, ADRs) lives under
`docs/`; the issue backlog lives under `issues/` (see issues/README.md).

## Hard gates — a slice is not done until ALL pass from repo root

```
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Code rules

- Rust 2021, stable. No nightly features.
- No `unwrap()`/`expect()`/`panic!` in library code paths (`busyncr-core`,
  `busyncr-proto`, non-main daemon/client modules). Tests and `main.rs`
  argument-handling edges may use them.
- Errors: `thiserror` enums in core/library crates; `anyhow` only at binary
  edges.
- Every public item gets a doc comment. `#![deny(missing_docs)]` stays on in
  busyncr-core.
- Approved dependency palette (ask-free): fastcdc, blake3, chacha20poly1305,
  argon2, rand, serde, postcard/bincode, redb, ulid, clap, tokio, tonic,
  prost, tonic-build, protoc-bin-vendored, rustls, tokio-rustls, rcgen,
  tempfile (dev), proptest (dev), zstd, tracing, tracing-subscriber, toml,
  windows-service (cfg windows), filetime. Anything else: prefer std or the
  above; add only with a comment in Cargo.toml justifying it.
- Tests must assert FR-level behavior, not existence. A test that cannot fail
  when the feature is broken is a defect. Name acceptance-relevant tests
  `fr<N>_<description>`.
- Cross-platform: core logic must build and pass tests on Linux; Windows-only
  code behind `#[cfg(windows)]` with Linux-compilable fallbacks.
- Determinism: no wall-clock/random in core logic paths without injection
  (clock and RNG passed in) — retention and tests depend on this.

## Process rules

- One slice per agent. Do not refactor other slices' code beyond what your
  slice requires; note wants in docs/SLICES.md "Notes" column instead.
- Commit granularity: 1–3 commits per slice, message `S<n>: <what>`.
- Update docs/SLICES.md: tick your checkbox and append a row to the Status log
  table (slice, "done", short-hash, one-line note) in your final commit.
- Never commit with a red gate. Push only at the owner's request
  (remote: github.com/heios/busyncr; pushing triggers CI).
- Never modify docs/PRD.md. docs/SLICES.md: status/notes only, specs are
  frozen.
- If the slice spec conflicts with reality, implement the closest faithful
  version, and record the deviation in the Status log note — do not silently
  reinterpret.
