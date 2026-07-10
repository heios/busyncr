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

- [x] **S3 — Manifest + content-addressed chunk store.** In core: `Manifest`
  (serde + bincode or postcard): snapshot id (ULID), created_at, files
  (relative path, size, mtime, unix mode/windows attrs, ordered chunk IDs).
  In daemon: `ChunkStore`: CAS layout `objects/<first2hex>/<hex>`, atomic
  writes (tmp + rename), `redb` index (chunk → len, refcount; snapshot →
  manifest blob). On-read hash verification → typed `IntegrityError` (FR9
  groundwork). Store/load/delete + refcount unit tests incl. crash-safety
  (tmp file left behind is ignored/cleaned). Deps: S1.

- [x] **S4 — Client-side crypto + keyfile.** In core: `DataKey` (32-byte
  random); chunk encryption XChaCha20-Poly1305 (`chacha20poly1305` crate),
  nonce random per blob, AAD = chunk ID; manifest encryption same scheme.
  Keyfile export/import: Argon2id (crate `argon2`) passphrase-derived KEK,
  versioned file format with magic bytes. Tests: roundtrip; tampered
  ciphertext fails; wrong passphrase fails cleanly; exported keyfile
  re-imports to identical key (FR6 groundwork, FR7 groundwork). Deps: S0.

- [x] **S5 — Protocol + gRPC skeleton.** `proto/busyncr.proto`: services —
  `Enroll(token, csr) → cert`, `ListSnapshots`, `HasChunks(batch of ids) →
  missing set`, `UploadChunks(client-stream)`, `PutManifest`, `GetManifest`,
  `GetChunks(ids) → server-stream`. tonic-build in busyncr-proto build.rs
  (vendored protoc via `protoc-bin-vendored`). Daemon serves on localhost
  plain TCP (TLS comes in S6) backed by S3 store; integration test drives a
  real client↔daemon roundtrip in-process. Deps: S3.

- [x] **S6 — mTLS + enrollment (FR1).** Daemon first-run bootstraps internal
  CA (crate `rcgen`); `busyncr-daemon enroll-token` prints one-time token;
  client `enroll` connects over TLS (server cert pinned via printed
  fingerprint or provided CA cert), presents token + CSR, receives client
  cert; all other RPCs require mTLS (rustls via tonic). Revocation: daemon
  `revoke <client>` marks cert rejected. FR1 integration test: fresh daemon →
  enroll → authenticated call succeeds; un-enrolled client rejected; revoked
  client rejected. Deps: S5.

- [x] **S7 — Backup end-to-end (FR2, FR3).** Client `backup`: walk configured
  folders (config file TOML), chunk (committed size from config; refuse if
  unset → point at bench-chunking, allow `--default-chunking` 1M), encrypt,
  `HasChunks` dedup, upload only missing, `PutManifest` (encrypted).
  Integration tests: FR2 snapshot listed after backup; FR3 second backup
  after small edit ships only new chunks (byte-accounting assertion on
  uploaded volume). Deps: S2, S4, S6.

- [x] **S8 — Restore end-to-end (FR4, FR9).** Client `restore <snapshot>
  <target-dir>`: fetch manifest + chunks, decrypt, verify every chunk ID,
  reassemble byte-exact incl. mtime/permissions. Tests: FR4 full-tree
  BLAKE3-compare against original; FR9 corrupt one stored blob on daemon →
  restore fails with IntegrityError naming the chunk, no silent corruption.
  Deps: S7.

- [x] **S9 — Retention grid + prune + GC (FR5).** In core: pure
  `retention::plan(now, snapshot_times, tiers) → keep/drop` implementing PRD
  §3.5 (tiers: <24h→3h, <4d→24h, <16d→4d, else 16d; keep newest per cell).
  Property/unit tests against hand-computed 60-day simulation (FR5a). Daemon:
  `prune` applies plan (drop manifests, decrement refcounts), `gc` deletes
  zero-ref chunks with grace period + lock against concurrent backup.
  Integration: simulated clock 60 days of 3-hourly snapshots → surviving set
  == plan output exactly; every survivor still restores byte-exact; disk
  usage shrinks (FR5). Deps: S8.

- [x] **S10 — Scheduler + restart robustness (FR8, non-Windows part).**
  Client `run` mode: 3 h (configurable) jittered schedule via tokio,
  injectable clock for tests; daemon `serve` long-running with graceful
  shutdown. Integration: kill daemon mid-upload → restart → next backup
  converges, store consistent (no orphaned partials counted as live);
  client restart resumes schedule. Deps: S9.

- [x] **S11 — Windows service + CI Windows gates (FR8 Windows part).**
  `#[cfg(windows)]` service wrapper (`windows-service` crate): install/
  uninstall/start/stop, event-log logging; CI windows job extended with
  service install/start/stop smoke test (PowerShell step). Linux-side: code
  must compile with `cargo check` (cfg-gated, so trivially) and unit tests
  for service-arg parsing. **Full verification only on `windows-latest` CI —
  blocked on GitHub repo binding.** Deps: S10.

- [x] **S12 — Migration flow (FR6).** Integration test as spec: machine A
  backs up history; simulate new machine (fresh client state dir) → `enroll`
  with new token (new cert) → `import-key` from A's exported keyfile →
  `list` shows history → `restore` byte-exact. CLI polish for
  export-key/import-key UX. Deps: S9.

- [x] **S13 — Acceptance sweep + docs.** FR1–FR10 traceability: each FR
  covered by ≥1 test named `fr<N>_*`; `tests/acceptance.rs` (or per-crate)
  asserts the full matrix compiles into the suite; README.md with quickstart
  (daemon setup, enroll, bench-chunking → commit size, backup, restore,
  migration); CHANGELOG. Full gate green. Deps: S11, S12 (S11's Windows CI
  portion may be pending repo binding — everything else must be green).

---

## Phase 2 — FR-K1 (keyed identity) + FR-C1 (compression). Ships in v0.1.0.

Specs: FR-K1.md and FR-C1.md are normative; entries below are the slice cuts.
Same gate, same rules (AGENTS.md). Order is binding: K1 lands first — both
FRs touch the chunk pipeline and the store format must be born final.

- [x] **K1 — Keyed chunk identity + keyfile v2 (FR-K1a–d).** Chunk ID becomes
  blake3::keyed_hash(chunk_id_key, uncompressed plaintext) per FR-K1 §2.
  chunk_id_key: 32-byte, generated at backup-set creation, stored in state
  dir, carried in keyfile format v2 (magic retained, version bump; v1 import
  fails with clear versioned error — no silent misinterpretation, no v1
  migration path needed). Daemon/protocol untouched (IDs opaque).
  bench-chunking stays keyless (note in --help). Tests: FR-K1a determinism/
  key-separation; FR-K1b confirmation-attack (full store + exact plaintext +
  wrong/no key ⇒ zero ID matches); FR-K1c full regression (FR2/3/4/5/6 green
  with keyed IDs; migration keeps dedup continuity); FR-K1d keyfile v2
  roundtrip + v1 rejection. Deps: v1 complete.

- [x] **C1 — Codec framing + compression policy engine (FR-C1 §2–§3).**
  1-byte codec ID (0=raw, 1=zstd; 2–255 reserved, decoder errors on unknown)
  prepended to plaintext before encryption; codec byte encrypted with payload.
  Pure policy fn (chunk, phase, cfg) -> (codec_id, Cow<[u8]>) with injected
  counters. Policies: zstd3 (default, keep iff len <= 0.95*raw); probe+zstd3
  (lz4_flex block probe, threshold 1.02, output discarded — never stored);
  +escalate (ratio >= 2.0 ⇒ retry zstd-9, keep smaller; MUST be phase-gated
  off during initial full backup). Thresholds/levels config-surfaced, not
  scattered literals. Crates: zstd (static libzstd), lz4_flex. Tests:
  FR-C1 roundtrip incl. unknown-codec error; policy unit tests incl.
  keep-threshold boundary; FR-C6 phase-gate unit level. Deps: K1.

- [x] **C2 — Pipeline integration (FR-C2, C4, C6, C7).** Wire policy engine
  into backup (phase detection: first completed snapshot of the set) and
  restore (decode codec after decrypt+verify). Tests: FR-C2 pre-compressed
  corpus ≥99% raw, stored ≤1.01×; FR-C3 compressible corpus ≥2× smaller than
  raw-only (golden bound from corpus); FR-C4 mixed-codec history restores
  byte-exact, dedup hit across policy change, prune/GC unaffected; FR-C6
  e2e counters (initial backup: zero level-9 invocations; incremental with
  escalation: >0 for qualifying chunks); FR-C7 zero-knowledge extension
  (codec invisible in stored blobs; document ciphertext-length leak in
  threat-model note). Deps: C1.

- [x] **C3 — bench-chunking --compression policy simulation (FR-C5).**
  Per FR-C1 §4: policies raw-only / zstd3-always / zstd3 / probe+zstd3 /
  zstd3+escalate on the unique-chunk stream (single-pass guarantee holds —
  extend FR10a accounting); per-policy stored bytes + AEAD arithmetic,
  compression MB/s, §4.4 pipeline speed model (measured read/cdc/blake3/
  compress + synthetic encrypt microbench; --threads; --net-mbps 50,200,1000
  default; initial + incremental rows; incremental requires --baseline else
  'n/a', --assume-churn labeled as assumed); §4.3 file-class diagnostics;
  --json under compression_policies key; §4.5 recommendation heuristic in
  --help. Tests: FR-C5a single-pass; FR-C5b sim-vs-real-backup stored bytes
  (same zstd version ⇒ exact); FR-C5c baseline projection within ±5% of real
  second backup; FR-C5d internal consistency (CPU floor ≤ finite-bandwidth
  times, monotone in bandwidth). Deps: C1 (policy fn reuse), C2 (real-backup
  comparison).

- [x] **C4 — Phase-2 acceptance sweep + docs.** Traceability: frk1_* and
  frc*_ tests all present and green (extend the S13 scanner); README:
  compression policy + keyed-identity user docs, config reference update;
  CHANGELOG; threat-model section (confirmation channel closed by K1;
  ciphertext-length leak documented per FR-C7). Full gate green. Deps: C2, C3.

- [ ] **M1 — CLI monitoring + explicit manual/auto control (FR-M1).**
  Normative spec: FR-M1.md. (a) `auto_prune` daemon config (default true:
  grid prune after each completed backup + daily timer; false = manual
  `prune` only; manual always available; prune records log auto|manual).
  (b) Live progress on client `backup`/`restore` to stderr: files, chunks
  to-ship/shipped, bytes, MB/s, coarse ETA; TTY carriage-return line vs
  log-safe line-per-interval; `--quiet`; `--json-progress` NDJSON; counters
  sourced from the same byte-accounting FR3 uses. (c) `busyncr-client
  status` (identity, committed chunk size, persisted last-backup record,
  last N snapshots when daemon reachable) and `busyncr-daemon status`
  (snapshot counts, unique chunks, store bytes, zero-ref chunks, last
  prune/gc time+mode, CA fingerprint), both with `--json`, daemon-status
  safe while serve runs. (d) README "manual vs scheduled operation"
  subsection. Tests FR-M1a–d per FR-M1.md §4. Deps: C4.

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
| S3    | done   | be4f840 | core::manifest (Manifest/FileEntry) + daemon lib with store::ChunkStore (CAS objects/<2hex>/<hex>, tmp+fsync+rename, redb chunks/snapshots tables reusing IndexEntry wire layout, refcounts, typed IntegrityError on read, .tmp- sweep on open); deviation: manifest wire format is a hand-rolled fixed-width LE codec instead of bincode/postcard so encode().len() equals the S2 bench projection constants exactly (types stay serde-derivable; postcard roundtrip covered in dev test); layout constants moved to core::manifest and re-exported from core::bench |
| S4    | done   | 9395224 | core::crypto: DataKey (injected CryptoRng), XChaCha20-Poly1305 blob format nonce(24)+ct+tag(16), AAD = chunk ID for chunks / snapshot ULID for manifests; keyfile v1 (magic BUSYNCRK, Argon2id KEK m=64MiB/t=3/p=1 default, header incl. KDF params+salt bound as AAD, 109 B); FR6/FR7 groundwork tests; pinned chacha20poly1305 0.10 + argon2 0.5 (0.11/0.6 are rc/unsettled API lines); want: zeroize-on-drop for DataKey (zeroize crate not in palette) |
| S5    | done   | c02c035 | proto/busyncr.proto (busyncr.v1, all 7 RPCs incl. streaming) + tonic stubs in busyncr-proto (vendored protoc); daemon service module maps ChunkStore onto RPCs (spawn_blocking, status table in module docs), `serve` subcommand loopback-only plain TCP; in-process client<->daemon integration tests incl. dedup counts, FR9-groundwork DATA_LOSS on corrupted blob; deviations: tonic/prost pinned 0.13 (0.14 needs tonic-prost* crates outside palette), tokio-stream added with Cargo.toml justification; Enroll answers UNIMPLEMENTED until S6; want: S7 must revisit PutManifest — daemon decodes plaintext manifests for chunk-ref validation, impossible once manifests are encrypted |
| S6    | done   | 4940673 | daemon identity module: CA + server cert bootstrap under <store>/identity (rcgen, persists across restarts), one-time tokens as per-file BLAKE3-hash spend records, CSR signing forced to client-auth profile, per-client TOML registry keyed by cert BLAKE3 fingerprint; serve_tls (tonic tls-aws-lc, client_auth_optional so Enroll works cert-less) + per-RPC registry check (no cert/unknown=UNAUTHENTICATED, revoked=PERMISSION_DENIED); client enroll module + CLI writes client-key/cert, pinned ca-cert, and creates data.key (FR1 "keyfile creation"; passphrase export lands S12); deviations: Enroll proto fields switched DER->PEM (same tags, RPC was UNIMPLEMENTED pre-S6); pinning implemented via provided CA cert file (spec's fingerprint-pin alternative not built); revocation is registry-side per-RPC rejection, TLS handshake still completes; plain serve() kept lib-only for in-process tests, binary serves mTLS only; hand-rolled minimal base64 (PEM->DER for CA fingerprint) — no palette crate for it |
| S7    | done   | 0696802 | client backup+config modules (TOML config w/ relative-folder resolution; refuses without committed chunk_target_size pointing at bench-chunking, --default-chunking = 1 MiB; injected snapshot ULID/created_at/rng; batched HasChunks dedup + encrypted UploadChunks with exact ciphertext-byte ledger; encrypted PutManifest) + `backup` CLI; FR2/FR3 integration tests over real mTLS incl. byte-exact FR3 transfer assertion vs independently recomputed chunk diff; resolved S5's PutManifest want: request now carries snapshot_id + chunk refs (proto fields 2/3), daemon stores blobs opaque (new snapshot_refs redb table drives delete/prune without decoding); deviations forced by zero-knowledge (PRD §3.4): daemon put_chunk no longer verifies data-hashes-to-ID (impossible for ciphertext) — object files carry a BLAKE3-of-blob header instead, FR9 length/hash checks now verify stored-bytes integrity (S3/S5 tests updated accordingly, honest-address tests replaced by opaque-blob tests); manifest paths are `<root-basename>/<rel>` with duplicate root basenames rejected; symlinks/non-regular files skipped (v1); tokio-stream+toml+ulid added to client (palette/justified) |
| S7    | fix r1 | 7872d13 | gRPC message limit raised to 32 MiB (`busyncr_proto::MAX_MESSAGE_SIZE`, applied to daemon server + every client stub): tonic's 4 MiB decode default rejected max-size chunk blobs — at the 1 MiB --default-chunking target a >=4 MiB boundary-free run (zeros) emits exactly-4 MiB chunks whose ciphertext (+40 B AEAD) aborted backup with OutOfRange; regression test fr2_default_chunking_backs_up_max_size_chunks (12 MiB zero run over mTLS + GetChunks round-trip of the >4 MiB blob, covers the S8 restore decode side) + const guard that the limit fits MAX_SIZE_CEILING+BLOB_OVERHEAD; known ceiling noted: PutManifest is a single message, so one snapshot caps at ~900k chunk refs until it is streamed |
| S8    | done   | f1192af | client::restore: GetManifest+decrypt(AAD=snapshot ULID)+decode, then per file GetChunks its ordered/duplicated chunk list, decrypt(AAD=chunk ID) + recompute BLAKE3 against the declared ChunkId (FR9 client-side plaintext verification — the daemon cannot do this, zero-knowledge), reassemble byte-exact + restore mtime (`filetime` crate, added to palette use) and permissions (Unix mode bits / Windows readonly attribute via `Permissions::set_readonly`, the only attribute std can restore without a non-palette crate); target dir created-if-missing but must be empty, manifest paths sanitized against traversal; daemon DATA_LOSS and client-side ChunkIdMismatch both surface as typed errors naming the chunk. FR4/FR9 integration tests over real mTLS incl. corruption-is-scoped-to-affected-chunk regression; deviation: per-file GetChunks calls are not cross-file deduped (a chunk shared by two files in one snapshot is fetched twice) — noted as a want for a later slice, not required by S8's acceptance text; want: Windows can only restore the readonly bit, not the fuller FILE_ATTRIBUTE_* set, without a non-palette crate |
| S9    | done   | c5f9b4c | core::retention: pure plan(now_ms, &[(time_ms,id)], policy) — epoch-aligned cells, first-tier-where-age<max_age (last tier catch-all), newest-per-cell (equal-time tiebreak = later input entry); RetentionPolicy default_grid (3h/24h/4d/16d) + from_tiers validation. FR5a hand-computed 60-day 3-hourly sim asserts the exact 19-survivor set, plus grid-invariant/idempotence/future-dated property tests. daemon store: ChunkStore::prune (snapshot times from ULID.timestamp_ms — decryption-free, PRD §3.4) drops manifests + decrements refs via delete_snapshot; ChunkStore::gc = grace-period mark-and-sweep over a new gc_marks table (only sweeps chunks continuously zero-ref for >= grace, drops marks on re-reference), index mutations in one write txn + blobs unlinked post-commit (crash-safe); daemon CLI prune|gc. Integration: fr5_retention (store-level 60-day 3-hourly sim → survivors == plan, every survivor reassembles byte-exact, GC shrinks disk 482→20 objects, grace protects unmanifested chunks) + fr5_retention_e2e (prune/GC over real mTLS encrypted backups, survivor restores byte-exact, pruned snapshot → NOT_FOUND). Deviations/notes: the full 3-hourly 60-day acceptance sim runs at the store level (no per-snapshot TLS round trip) for speed — restore-over-mTLS of survivors is proven by the leaner E2E test; the residual dedup-then-GC race (HasChunks says present → GC deletes past grace → PutManifest) is resolved by put_snapshot's atomic existence check failing the backup cleanly (no silent corruption), grace narrows the window; retention tiers are default-only from the CLI (RetentionPolicy is configurable in code) — daemon config plumbing is a want |
| S10   | done   | 25392c1 | core::scheduler: pure SchedulePolicy (interval + jitter fraction in [0,1], default 3h/±10% per PRD §3.5) — next_delay draws from an injected rand::Rng, reads no clock/entropy itself. busyncr-client::run: Clock trait (now_ms + boxed-future sleep) with SystemClock (tokio::time::sleep) for production and a virtual clock in unit tests that advances instantly, letting cadence be asserted without real waits; run_scheduler backs up immediately then loops on schedule.next_delay until a shutdown future resolves, reporting every tick's Result via an on_tick callback that never stops the loop on error (FR8: a daemon outage or restart must not wedge the client). Wired as `busyncr-client run --config --state [--interval] [--jitter]`. Daemon `serve`'s shutdown future now selects on Ctrl-C *or* SIGTERM (Unix), not Ctrl-C alone (smoke-tested manually with `kill -TERM`/`kill -INT` against the built binary). FR8 integration (crates/busyncr-client/tests/fr8_scheduler_restart.rs): fr8_daemon_restart_mid_upload_converges_and_stays_consistent runs the daemon on its own dedicated tokio runtime and kills it via shutdown_timeout (abrupt — every open connection dies mid-request, unlike tonic's graceful drain) partway through a many-chunk upload, then reopens the same on-disk store fresh (exercising S3's crash-recovery path for real) and proves the next attempt converges, dedups whatever survived, and that every live-manifest chunk is referenced while every zero-ref chunk is one the manifest does *not* need; fr8_client_run_scheduler_survives_restart runs the scheduler for a few ticks, stops it, and starts a fresh run_scheduler call (simulating a client restart) — every tick across both "lifetimes" lands a distinct, listed, restorable snapshot. Deviation: no last-run timestamp is persisted across client restarts — every `run` invocation starts with an immediate backup instead, which is what makes restart-resumption correct without its own recovery path; recorded here rather than assumed. |
| S11   | done   | bbf3b1b | `busyncr-client service <install\|uninstall\|start\|stop\|restart\|run>` (`#[cfg(windows)]`, `windows-service` crate) wraps the S10 scheduled loop as a real Windows service: `install` registers auto-start with the SCM launch command `service run` + the install-time args baked in (Windows launches a service via the *whole* stored command line, so those become ordinary process argv next time — no custom argv channel needed); `run` is the SCM entry point (`define_windows_service!`), reporting StartPending→Running→Stopped and bridging the control handler's Stop event into `run_scheduler`'s async shutdown future; lifecycle + per-tick outcomes logged to the Windows Event Log via direct `RegisterEventSourceW`/`ReportEventW`/`DeregisterEventSource` calls (`windows-sys`, feature-gated, already pulled in transitively by `windows-service` at the same pinned version — the palette's `windows-service` crate has no Event Log wrapper of its own). `ServiceRunArgs`/`ServiceAction`/`launch_argv`/interval parsing are ordinary cross-platform Rust, unit-tested on Linux via real clap round-trips (`service::tests::fr8_*`) per the slice's "Linux-side ... unit tests for service-arg parsing" text; every action has a `#[cfg(not(windows))]` fallback returning `UnsupportedPlatform`. CI: windows job gains a PowerShell install/start(wait Running)/stop(wait Stopped)/uninstall smoke test. Deviation/limitation: none of the Windows-specific code (SCM calls, event log FFI, the CI smoke test itself) could be compiled or run in this sandbox (no Windows target, no windows-latest runner) — written against the real `windows-service` 0.8.1 crate source and its own README examples (fetched from crates.io) for API fidelity, but **full verification remains blocked on GitHub repo binding**, exactly as the slice spec anticipates; only `cargo fmt/clippy/test --workspace` on Linux (where the cfg(windows) code is entirely elided) is confirmed green here. |
| S12   | done   | e27931d | client keys module (export_key refuses to overwrite an existing keyfile; import_key preserves any differing pre-existing data.key as data.key.old-<n> — never destroys key material, wrong passphrase/corrupt file leave state untouched, re-import no-op) + snapshots module (`list` over mTLS, keyless — ULIDs are plaintext — with hand-rolled UTC formatting since no calendar crate is in the palette); CLI adds list / export-key / import-key (passphrase via --passphrase, --passphrase-file, or stdin line) and enroll's hint now names the real commands. FR6 integration: machine A two-snapshot history + export → fresh machine B enrolls on a new token (distinct cert asserted), pre-import restore fails with Decrypt (history sealed) and wrong passphrase changes nothing, post-import list == A's history and both snapshots restore byte-exact vs copies captured at backup time; second test proves the migrated machine continues the set (unchanged tree → 0 chunks uploaded, new snapshot listed + restored). Deviations: none of substance; note the stdin passphrase prompt echoes (no rpassword-style crate in the palette) — --passphrase-file is the documented non-echoing path; note `list` shows the daemon's whole snapshot set (single backup set per daemon store in v1). |
| S13   | done   | 8a9a543 | added `crates/busyncr-client/tests/acceptance.rs`: a hand-rolled (no `regex` in the palette) string scanner walks every `.rs` file under `crates/` and asserts every FR1–FR10 has >=1 compiled `fn fr<N>_...` test, so the traceability matrix is enforced by `cargo test --workspace` rather than only documented — confirmed all ten already existed from S1–S12, no test gaps found or needed filling; scanner itself has its own regression test against look-alike names (`from_str`, `fresh`, `fr_helper`, `frobnicate`) to guard against false "covered" results. README.md gained a full Quickstart (daemon serve, enroll-token/enroll, bench-chunking → commit chunk_target_size in config, backup/run/service, list/restore, export-key/import-key migration, prune/gc) written against the real CLI flags in main.rs/service.rs/bench_cmd.rs as of this slice. Added CHANGELOG.md, one entry per slice S0–S13. Deviation: `tests/acceptance.rs` lives under `busyncr-client` rather than a bare workspace-root `tests/` directory — the root `Cargo.toml` is a virtual manifest with no package of its own, so a root-level `tests/` dir has nowhere to attach; the slice text's "(or per-crate)" alternative is what's implemented, scanning the whole workspace from that one location. |
| S13   | fix r1 | 61990e9 | the FR1–FR10 sweep walked `crates/` including its own source file, so the scanner's `acceptance_scanner_matches_only_true_fr_test_names` regression fixture — whose sample text literally contains `fn fr1_enrolls_successfully() {}` and `fn fr10_reads_each_file_once() {}` as test data for the string matcher — was itself always counted as an FR1/FR10 hit, silently satisfying those two FRs even with zero real `fr1_*`/`fr10_*` tests in the tree (proved by deleting every real one and watching the sweep still pass). Fixed by excluding `tests/acceptance.rs`'s own resolved path (`CARGO_MANIFEST_DIR`-relative, computed once) from the directory walk in `collect_fr_tests`; re-verified by renaming away all real `fr1_*` (`fr1_enrollment.rs`, `identity.rs`) and `fr10_*` (`fr10_bench_chunking_cli.rs`, `bench.rs`) tests and confirming `acceptance_fr1_through_fr10_each_have_a_named_test` now fails-as-expected (missing FR1/FR10), then restored the originals — full gate green again. |
| K1    | done   | a82fe3f + 04078fb | keyed chunk identity (`blake3::keyed_hash`) via new `core::chunking::ChunkIdKey` + `ChunkId::keyed`/`chunk_reader_keyed`/`chunk_bytes_keyed`; the unkeyed `ChunkId::of`/`chunk_reader`/`chunk_bytes` are kept **bench-only** (FR-K1 K1.5, documented as MUST-NOT on the backup path) rather than removed, so S2 bench + its tests are untouched and stay keyless. Keyfile bumped to v2 (magic retained): sealed payload is now data key ‖ chunk-ID key (64 B); a v1 file fails import with `KeyfileVersion(1)` — no silent reinterpret, no v1 migration path (nothing released). State dir gains `chunk-id.key` beside `data.key`; both are created together at enrollment (folded into the existing `ensure_data_key` so every S1–S13 test harness that already called it gets the new key for free — no rename/signature churn) and neither is rotated on re-enroll; `import-key` installs both and preserves pre-existing pairs as `<name>.old-<n>`. Daemon/proto untouched (IDs opaque, K1.3). Deviations/notes: (1) chose additive keyed API variants over threading a required key param through `chunk_reader`/`chunk_bytes`, to avoid editing S1/S2 tests per the "don't refactor other slices" rule — the trade-off is the unkeyed fns remain callable, mitigated by doc-comments + the FR-K1b test proving the real store holds only keyed IDs; (2) FR-K1c forced two same-slice-adjacent edits: `fr2_fr3`/`fr8` independently recompute expected chunk IDs and had to switch to `chunk_bytes_keyed` with the state's chunk-id key (still exact-ID assertions, not weakened), and one now-stale "dedup is key-independent" comment in `fr6` was corrected. New `frk1_keyed_identity.rs`: FR-K1b confirmation attack over the real `HasChunks` RPC (unkeyed + wrong-key recomputation ⇒ 0 stored matches; real key ⇒ all), per-backup-set dedup isolation between two clients, and a store-level keyed-vs-plain proof. Full gate green. |
| C1    | done   | (pending commit) | new `core::compression` module: `CodecId` (0=raw,1=zstd; `from_byte` errors on 2–255, cf. FR9) + `frame`/`unframe` (C1.1/C1.2 — the 1-byte codec prefix on the plaintext handed to `crypto::encrypt_chunk`, so it's encrypted with the payload) + `compress_zstd`/`decompress_zstd` (`zstd::stream::encode_all`/`decode_all`) + `decode_chunk` (unframe+decompress, the restore-side inverse); pure policy engine `choose_codec(chunk, Phase, &PolicyConfig, &mut PolicyCounters) -> (CodecId, Cow<[u8]>)` implementing C2.1 zstd3 default (keep iff `len <= raw*0.95`, from actual zstd output), C2.2 `probe+zstd3` (`lz4_flex::compress` block-mode probe, output discarded per C1.4, threshold 1.02), C2.3 `+escalate` (ratio >= 2.0 ⇒ retry level 9, keep smaller) **hard phase-gated off whenever `Phase::InitialFull`, regardless of `cfg.escalate`** (FR-C6); all thresholds/levels are named `PolicyConfig` fields with `DEFAULT_*` consts, no scattered literals (C2.4); `PolicyCounters` (raw/zstd3/escalated + a non-spec `escalation_attempts` for precise invocation-level FR-C6 assertions + bytes_in/out) is caller-injected so the future bench-chunking simulator (C3) can reuse `choose_codec` verbatim (FR-C5b). Added `zstd`/`lz4_flex` to `busyncr-core` (phase-2 approved palette, justified in Cargo.toml). Tests (21, all in `compression.rs`): FR-C1 roundtrip for both codec bytes + empty chunk through the real frame→encrypt→decrypt→decode path, and the unknown-codec-byte integrity-error case (2/200/255) at that same encrypted layer; keep-threshold and probe-threshold boundary tests computed from each fixture's *actual* achieved ratio (not magic constants); FR-C6 unit-level phase gate (zero `escalation_attempts` under `InitialFull` regardless of config, >0 and a kept level-9 result under `Incremental` for a fixture engineered so level 9 measurably beats level 3 — verified empirically against the pinned zstd 0.13.3/libzstd 1.5.7, direction-only assertion so it isn't byte-brittle across zstd point releases). Not in scope for C1 (deferred to C2 per SLICES.md): wiring `choose_codec`/`decode_chunk` into `client::backup`/`client::restore`, and real phase *detection* (first-completed-snapshot) — `Phase` here is a caller-supplied pure input. No deviations from the slice text. |
| C2    | done   | ec47893 | Phase detection lives in `client::backup::run_backup`: one `ListSnapshots` call before chunking starts (empty ⇒ `Phase::InitialFull`, else `Incremental`) — no persisted "is this the first snapshot" flag needed. `ClientConfig` gains an optional `[compression]` TOML table deserializing straight into `core::compression::PolicyConfig` (container-level `#[serde(default)]`, so any/all fields may be omitted); `BackupRequest`/`RunRequest` carry it through to `run_backup`/`run_scheduler`. `backup::Session::flush` runs every chunk `HasChunks` reports missing through `choose_codec` + `frame` before `encrypt_chunk` (dedup still happens first — C1.3: each unique chunk is compressed at most once, ever); `BackupReport.compression: PolicyCounters` surfaces the run's raw/zstd3/escalated counts (FR-C6 e2e assertions) and is also printed by the `backup` CLI. `client::restore::restore_file` decodes (`compression::decode_chunk`) the decrypted plaintext before recomputing the keyed `ChunkId` — identity is always over the *decompressed* bytes (C1.3) — with a new `RestoreError::CodecDecode` variant (unknown codec byte / broken frame is an FR9-class integrity error naming the chunk, not silent output). Daemon/proto untouched (chunks stay opaque ciphertext blobs). New `tests/frc2_frc7_compression_pipeline.rs` (5 tests) covers the pipeline-level acceptance FR-C1.md §5 bullets the C1 unit tests couldn't reach: `frc2_*` pre-compressed corpus (>=99% raw chunks, stored <=1.01x source bytes); `frc3_*` compressible corpus >=2x smaller under `zstd3` than a forced-raw policy, with the 2x bound derived from the corpus's own independently-measured zstd ratio rather than hardcoded; `frc4_*` one manifest referencing raw+zstd3+escalated-zstd9 chunks restores byte-exact, `ChunkStore::delete_snapshot`+`gc` (called directly, bypassing the grid-based `prune`) leave the surviving mixed-codec snapshot intact and still byte-exact, and a same-content backup under a *different* (raw-only) policy still hits full dedup (`chunks_uploaded == 0`); `frc6_*` a standalone minimal escalation-counter case (0 `escalation_attempts` on the set's first completed snapshot, >0 and a kept level-9 result on a later qualifying incremental); `frc7_*` a wrong data key fails to decrypt either a raw- or zstd-coded stored blob at all (codec is unreachable without the key), the correct key recovers the expected codec byte from each, and the accepted ciphertext-length leak (compressed blobs are measurably shorter — coarse compressibility only, FR-C1 §5) is asserted explicitly as documented/accepted rather than hidden. Deviations: (1) wire-format consequence of C1.1 landing in the real pipeline for the first time — every stored chunk plaintext now carries a 1-byte codec prefix pre-encryption, so the pre-existing FR2/FR3 byte-exact transfer-size assertions in `fr2_fr3_backup.rs` had to switch from `len + BLOB_OVERHEAD` to recomputing the real `choose_codec`+`frame` output per chunk (still byte-exact, not weakened) — and the S7 max-chunk-size gRPC regression test (whose boundary-free CDC run depends on all-zero data, which zstd would otherwise compress away and defeat the >4 MiB-ciphertext point of that regression) now backs up under an explicit raw-only policy override (`keep_threshold: 0.0`, documented inline as the mechanism, not a new policy variant — C2.1's keep condition is unsatisfiable at that threshold for any non-empty chunk); (2) "chosen policy is committed to config alongside chunk size" (FR-C1 §4.5) is honored at the config-schema level (`[compression]` in `busyncr-client.toml`) but the *recommendation* half of that sentence (bench-chunking choosing it for the operator) is C3's job, not C2's — this slice only wires whatever policy is already in config into the real pipeline. |
| C3    | done   | 0ec88c4 | new `core::policy_bench` module: `PolicyKind` (raw-only/zstd3-always/zstd3/probe+zstd3/zstd3+escalate, FR-C1 §4.1) maps each simulated policy onto the real `PolicyConfig` — raw-only/zstd3-always are `zstd3`'s own keep-threshold pushed to its two extremes (0.0 / +INFINITY), not separate branches, so `choose_codec` is reused verbatim for every policy (FR-C5b); `simulate_policy` runs it over a unique-chunk set under an injected `Phase`, deriving `stored_bytes` with the same codec-byte + `BLOB_OVERHEAD` arithmetic a real backup uses; `chunk_tree_with_bytes` is a single-pass (FR-C5a) sibling of S2's `bench::chunk_tree` that retains full chunk bytes (not just `ChunkMeta`) plus real I/O-wait time via a new `TimingReader`, so `--compression` costs no second disk read; `StageRates`/`measure_cdc_mbps`/`measure_blake3_mbps`/`measure_encrypt_mbps` are genuine wall-clock measurements (CDC/BLAKE3 timed in-memory over already-read bytes, AEAD via a synthetic 1 MiB-buffer microbenchmark) feeding the §4.4 pipeline model `client_throughput = min(read_MBps, threads × harmonic(cdc,blake3,compress,encrypt))`; `bandwidth_projection` computes `max(cpu_bound_floor, stored_bytes/bandwidth)` per `--net-mbps` point — floor-bounded and monotone by construction (FR-C5d); `FileClass`/`file_class_diagnostics` cover §4.3; `build_compression_report`/`recommend_policy` assemble the full per-policy report and the §4.5 heuristic (smallest projected steady-state store among policies within 1.5× zstd3's initial-backup CPU-bound time). Client `bench-chunking` gains `--compression [--threads N] [--net-mbps 50,200,1000] [--assume-churn PCT]`, table + `--json` (`compression_policies` key, FR-C1 §4.5), `--help` documents the model and heuristic. Tests: core unit tests incl. FR-C5a (single-pass + exact match against the in-memory reference chunker) and FR-C5d (bandwidth monotonicity/floor); new `tests/frc5_bench_compression.rs` — FR-C5a at the CLI/JSON level, FR-C5b (simulated `stored_bytes` exactly equals a real first backup's `upload_bytes`, all five policies), FR-C5c (`--baseline` incremental projection within ±5% of a real second backup's shipped bytes). Deviations: (1) primary report columns (stored bytes/ratio, initial-backup speed) are computed under `Phase::InitialFull` — the tool runs before any backup history exists, and this is what lets FR-C5b compare directly against a real first backup — so escalation's effect is invisible there by construction (matching FR-C6's real phase gate) and only shows up in the `--baseline`-gated incremental row; documented in `--help` and the module docs, not silently surprising; (2) `--compression` requires `--sizes` to resolve to exactly one candidate (rejected with a clear error otherwise) rather than simulating across every chunk-size candidate in one pass — FR-C1 §4's "the selected (or each candidate) chunk size" text permits either reading; the single-candidate form was the one in scope here, keeps the single-pass guarantee simple to state and test, and is documented in `--help`; (3) the incremental row's whole-tree "scan" cost is modeled as `total_bytes / read_MBps` only (per FR-C1 §4.4's literal text), not the fuller CDC+hash cost of re-chunking unchanged files, which the spec itself flags as an assumption pending mtime-gated scanning; (4) `--assume-churn` (no `--baseline`) scales the whole-corpus policy result by the assumed percentage rather than compressing real "new" bytes (none exist to compress), labeled `assumed` in the report, never presented as measured. Full workspace gate green. |
| C4    | done   | 8056a48 | extended `crates/busyncr-client/tests/acceptance.rs` (the S13 sweep): new `FrId` enum (`V1(u32)`/`K(u32)`/`C(u32)`) and `parse_numbered_prefix` classify `fn frk<N>[letters]_...` / `fn frc<N>[letters]_...` identifiers (letters allow multiple tests per FR sub-criterion, e.g. FR-C5's `frc5a_`/`frc5b_`) alongside the untouched v1 `fn fr<N>_...` matcher; new `acceptance_phase2_frk1_and_frc1_through_frc7_each_have_a_named_test` asserts every phase-2 FR (FR-K1, FR-C1-C7) already has >=1 compiled test — confirmed all eight already existed from K1/C1/C2/C3, no gaps found or needed filling; scanner's own regression fixture extended with frk1/frk1b/frc1/frc5a/frc5b sample names to prove the new classification (not just v1) is exercised. README gained: keyed-chunk-identity explanation folded into the enrollment step (what FR-K1 buys, cost is nil); a new "Compression" section (the `[compression]` config table, each policy's behavior and phase gate, `bench-chunking --compression` usage) — the config-reference update the slice text calls for; a new "Threat model" section (FR-K1's confirmation-channel closure, FR-C7's zero-knowledge codec guarantee, the accepted-and-documented ciphertext-length leak, what's explicitly out of scope). CHANGELOG gained dated K1/C1/C2/C3/C4 entries, replacing the stale "deferred to a second phase" footer now that phase 2 has shipped. No deviations: `bench-chunking --compression`'s `--help` text (FR-C1 §4.5 recommendation heuristic) was already written in C3, so C4 only added the README-level user-facing walkthrough on top of it. Full gate green. |
