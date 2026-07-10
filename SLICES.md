# BusyNCR — Vertical Slice DAG

Source of truth for the autonomous build. Each slice is a thin vertical cut that
MUST leave the tree green: `cargo fmt --check && cargo clippy --workspace
--all-targets -- -D warnings && cargo test --workspace`. Status is updated here
by the implementing agent (`[ ]` → `[x]`), one commit (or few) per slice,
message prefixed `S<n>:`.

FR references point at PRD.md §4.

---

- [x] **S0 — Workspace skeleton + CI scaffolding.** Cargo workspace with
  busyncr-core / busyncr-proto / busyncr-client / busyncr-daemon; GitHub
  Actions CI (linux + windows jobs); AGENTS.md gates. *(done at bootstrap)*

- [x] **S1 — CDC chunking engine.** In `busyncr-core`: `chunking` module
  wrapping FastCDC (crate `fastcdc`) with configurable min/target/max
  (defaults min=target/4, max=target*4), streaming over any `Read` without
  loading whole files; chunk ID = BLAKE3 of chunk plaintext (crate `blake3`),
  newtype `ChunkId([u8; 32])` with hex Display/FromStr. Tests: determinism
  (same input → same chunks/ids); boundary-shift resistance (insert 1 byte at
  file start of a 10 MiB random file → >90 % of chunk IDs unchanged); size
  bounds honored; empty file → 0 chunks; file < min → 1 chunk; streaming
  equals in-memory result. Deps: S0.

- [x] **S2 — `bench-chunking` offline sizing tool (PRD §3.7, FR10).** Client
  subcommand `bench-chunking <path> [--sizes 256K,512K,1M,2M,4M] [--baseline
  <path>] [--snapshots N] [--json]` (CLI via `clap`). Single read pass per
  file: bytes fanned to one chunker per candidate size; per-candidate report:
  total/unique chunks, dedup ratio, mean/median/p95 chunk size, daemon index
  bytes (exact per-entry layout from S3 once it exists; until then a
  documented `IndexEntry::WIRE_SIZE` constant in core that S3 must reuse),
  manifest bytes/snapshot, projected bookkeeping for N snapshots (default:
  steady-state occupancy of the PRD §3.5 grid). `--baseline` mode: chunk both
  trees, report chunk-ID overlap %. Tests (FR10): instrumented `Read` wrapper
  proves each file read exactly once; per-candidate counts match
  single-candidate reference runs; projection arithmetic exact; baseline
  overlap correct on corpus with known mutation rate. Human table + `--json`
  output; recommendation heuristic documented in `--help`. Deps: S1.

- [ ] **S3 — Manifest + content-addressed chunk store.** In core: `Manifest`
  (serde + bincode or postcard): snapshot id (ULID), created_at, files
  (relative path, size, mtime, unix mode/windows attrs, ordered chunk IDs).
  In daemon: `ChunkStore`: CAS layout `objects/<first2hex>/<hex>`, atomic
  writes (tmp + rename), `redb` index (chunk → len, refcount; snapshot →
  manifest blob). On-read hash verification → typed `IntegrityError` (FR9
  groundwork). Store/load/delete + refcount unit tests incl. crash-safety
  (tmp file left behind is ignored/cleaned). Deps: S1.

- [ ] **S4 — Client-side crypto + keyfile.** In core: `DataKey` (32-byte
  random); chunk encryption XChaCha20-Poly1305 (`chacha20poly1305` crate),
  nonce random per blob, AAD = chunk ID; manifest encryption same scheme.
  Keyfile export/import: Argon2id (crate `argon2`) passphrase-derived KEK,
  versioned file format with magic bytes. Tests: roundtrip; tampered
  ciphertext fails; wrong passphrase fails cleanly; exported keyfile
  re-imports to identical key (FR6 groundwork, FR7 groundwork). Deps: S0.

- [ ] **S5 — Protocol + gRPC skeleton.** `proto/busyncr.proto`: services —
  `Enroll(token, csr) → cert`, `ListSnapshots`, `HasChunks(batch of ids) →
  missing set`, `UploadChunks(client-stream)`, `PutManifest`, `GetManifest`,
  `GetChunks(ids) → server-stream`. tonic-build in busyncr-proto build.rs
  (vendored protoc via `protoc-bin-vendored`). Daemon serves on localhost
  plain TCP (TLS comes in S6) backed by S3 store; integration test drives a
  real client↔daemon roundtrip in-process. Deps: S3.

- [ ] **S6 — mTLS + enrollment (FR1).** Daemon first-run bootstraps internal
  CA (crate `rcgen`); `busyncr-daemon enroll-token` prints one-time token;
  client `enroll` connects over TLS (server cert pinned via printed
  fingerprint or provided CA cert), presents token + CSR, receives client
  cert; all other RPCs require mTLS (rustls via tonic). Revocation: daemon
  `revoke <client>` marks cert rejected. FR1 integration test: fresh daemon →
  enroll → authenticated call succeeds; un-enrolled client rejected; revoked
  client rejected. Deps: S5.

- [ ] **S7 — Backup end-to-end (FR2, FR3).** Client `backup`: walk configured
  folders (config file TOML), chunk (committed size from config; refuse if
  unset → point at bench-chunking, allow `--default-chunking` 1M), encrypt,
  `HasChunks` dedup, upload only missing, `PutManifest` (encrypted).
  Integration tests: FR2 snapshot listed after backup; FR3 second backup
  after small edit ships only new chunks (byte-accounting assertion on
  uploaded volume). Deps: S2, S4, S6.

- [ ] **S8 — Restore end-to-end (FR4, FR9).** Client `restore <snapshot>
  <target-dir>`: fetch manifest + chunks, decrypt, verify every chunk ID,
  reassemble byte-exact incl. mtime/permissions. Tests: FR4 full-tree
  BLAKE3-compare against original; FR9 corrupt one stored blob on daemon →
  restore fails with IntegrityError naming the chunk, no silent corruption.
  Deps: S7.

- [ ] **S9 — Retention grid + prune + GC (FR5).** In core: pure
  `retention::plan(now, snapshot_times, tiers) → keep/drop` implementing PRD
  §3.5 (tiers: <24h→3h, <4d→24h, <16d→4d, else 16d; keep newest per cell).
  Property/unit tests against hand-computed 60-day simulation (FR5a). Daemon:
  `prune` applies plan (drop manifests, decrement refcounts), `gc` deletes
  zero-ref chunks with grace period + lock against concurrent backup.
  Integration: simulated clock 60 days of 3-hourly snapshots → surviving set
  == plan output exactly; every survivor still restores byte-exact; disk
  usage shrinks (FR5). Deps: S8.

- [ ] **S10 — Scheduler + restart robustness (FR8, non-Windows part).**
  Client `run` mode: 3 h (configurable) jittered schedule via tokio,
  injectable clock for tests; daemon `serve` long-running with graceful
  shutdown. Integration: kill daemon mid-upload → restart → next backup
  converges, store consistent (no orphaned partials counted as live);
  client restart resumes schedule. Deps: S9.

- [ ] **S11 — Windows service + CI Windows gates (FR8 Windows part).**
  `#[cfg(windows)]` service wrapper (`windows-service` crate): install/
  uninstall/start/stop, event-log logging; CI windows job extended with
  service install/start/stop smoke test (PowerShell step). Linux-side: code
  must compile with `cargo check` (cfg-gated, so trivially) and unit tests
  for service-arg parsing. **Full verification only on `windows-latest` CI —
  blocked on GitHub repo binding.** Deps: S10.

- [ ] **S12 — Migration flow (FR6).** Integration test as spec: machine A
  backs up history; simulate new machine (fresh client state dir) → `enroll`
  with new token (new cert) → `import-key` from A's exported keyfile →
  `list` shows history → `restore` byte-exact. CLI polish for
  export-key/import-key UX. Deps: S9.

- [ ] **S13 — Acceptance sweep + docs.** FR1–FR10 traceability: each FR
  covered by ≥1 test named `fr<N>_*`; `tests/acceptance.rs` (or per-crate)
  asserts the full matrix compiles into the suite; README.md with quickstart
  (daemon setup, enroll, bench-chunking → commit size, backup, restore,
  migration); CHANGELOG. Full gate green. Deps: S11, S12 (S11's Windows CI
  portion may be pending repo binding — everything else must be green).

---

## Verification gate (every slice, run from repo root)

```
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Status log

| Slice | Status | Commit | Notes |
|-------|--------|--------|-------|
| S0    | done   | (bootstrap) | skeleton green |
| S1    | done   | 4e2fd84 | chunking module in core; fastcdc 4.0.1 caps sizes (min<=1MiB, target<=4MiB, max<=16MiB) — 4M-target bench candidate is the largest valid config |
| S2    | done   | 8853148 | bench engine in core::bench + core::index (IndexEntry::WIRE_SIZE=48, S3 must reuse); deviations: default N = grid occupancy over a documented 1-year horizon (=36) since the >=16d tier is unbounded; manifest layout constants (header 28 B, per-file fixed 32 B) defined in core::bench — S3 must serialize to match; serde_json added to client (justified in Cargo.toml) for the PRD-mandated --json |
