# Changelog

All notable changes to BusyNCR are recorded here, one entry per vertical
slice (see SLICES.md for the full spec each slice implements and AGENTS.md
for the rules every entry was built under). Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); dates are UTC.

The project has not tagged a release yet — everything below is `[Unreleased]`
against `0.1.0`. FR references point at PRD.md §4.

## [Unreleased]

### S13 — Acceptance sweep + docs
- Added `crates/busyncr-client/tests/acceptance.rs`: a workspace-wide sweep
  that scans every `.rs` file under `crates/` for `fn fr<N>_...` test names
  and asserts FR1–FR10 (PRD §4) each have at least one, so the full
  traceability matrix is enforced by `cargo test --workspace` itself, not
  just documented.
- Added this CHANGELOG and the README quickstart (daemon setup, enroll,
  `bench-chunking` → commit chunk size, backup, restore, key export/import
  migration, prune/gc).

### S12 — Migration flow (FR6)
- `busyncr-client export-key` / `import-key`: passphrase-protected keyfile
  export and import, wired into the CLI with `--passphrase`,
  `--passphrase-file`, or an interactive stdin prompt. Import never destroys
  an existing differing key — it is preserved as `data.key.old-<n>`.
- `busyncr-client list`: shows the daemon's retained snapshot history
  (works without the data key, since snapshot IDs are plaintext ULIDs).
- Integration coverage: a fresh machine enrolled with a new certificate,
  after importing an exported keyfile, lists and restores the *old*
  machine's full history byte-exact, and can continue backing up into the
  same set.

### S11 — Windows service + CI Windows gates (FR8, Windows part)
- `busyncr-client service <install|uninstall|start|stop|restart|run>`
  (`#[cfg(windows)]`, `windows-service` crate): registers the client as a
  real Windows service wrapping the S10 scheduled backup loop, with
  lifecycle and per-tick logging to the Windows Event Log.
- CI: the `windows-latest` job gained a PowerShell install/start/stop/
  uninstall smoke test.
- Every service action has a `#[cfg(not(windows))]` fallback that fails
  cleanly with an "unsupported platform" error; CLI arg parsing is
  unit-tested cross-platform.

### S10 — Scheduler + restart robustness (FR8, non-Windows part)
- `busyncr-core::scheduler`: pure, clock/RNG-injected jittered-interval
  policy (default 3 h ± 10 %, PRD §3.5).
- `busyncr-client run`: backs up immediately, then loops on the schedule
  until shutdown; a failed attempt (daemon unreachable, daemon restarted
  mid-upload, ...) is logged but never stops the schedule.
- `busyncr-daemon serve`: graceful shutdown on Ctrl-C or SIGTERM.
- Integration coverage: daemon killed mid-upload and restarted converges on
  the next attempt with a consistent store; a restarted client scheduler
  picks up right where it left off.

### S9 — Retention grid + prune + GC (FR5)
- `busyncr-core::retention::plan`: pure implementation of the PRD §3.5
  exponential thinning grid (< 24 h → 3 h cells, < 4 d → 24 h, < 16 d → 4 d,
  else 16 d; newest survives per cell).
- `busyncr-daemon prune` / `gc`: applies the plan (drops manifests,
  decrements refcounts) and reclaims zero-ref chunks after a grace period,
  safe against a concurrent backup.
- Integration coverage: a simulated 60-day, 3-hourly backup history prunes
  to exactly the hand-computed survivor set, every survivor still restores
  byte-exact, and GC measurably shrinks disk usage.

### S8 — Restore end-to-end (FR4, FR9)
- `busyncr-client restore`: fetches a snapshot's manifest and every chunk it
  references, decrypts, verifies each chunk's content address against the
  daemon's (zero-knowledge, ciphertext-only) storage, and reassembles the
  tree byte-exact including mtime and permissions.
- Corrupt or truncated stored chunks are detected and reported as a typed
  integrity error naming the offending chunk — never silent corruption
  (FR9); corruption in one chunk is scoped to the files that reference it.

### S7 — Backup end-to-end (FR2, FR3)
- `busyncr-client backup`: walks configured folders (TOML config), chunks
  with the committed target size (refusing to run without one, per PRD
  §3.7, unless `--default-chunking` is passed), encrypts client-side,
  dedups via `HasChunks`, and ships only missing chunks plus an encrypted
  manifest.
- Daemon storage and protocol reworked so it never needs to decode
  plaintext manifests or verify chunk hashes against ciphertext — true
  zero-knowledge storage (PRD §3.4).
- Integration coverage: a snapshot appears in the daemon's version list
  right after backup (FR2); a second backup after a small edit ships
  exactly the new/changed chunks, verified by an exact transfer-size
  assertion (FR3).
- Fix: raised the gRPC message size limit so maximum-size chunk blobs (at
  small chunk-target sizes, a boundary-free run can hit the configured max)
  fit on the wire without aborting the backup.

### S6 — mTLS + enrollment (FR1)
- Daemon bootstraps an internal CA and server certificate on first run
  (`rcgen`); `busyncr-daemon enroll-token` mints one-time enrollment tokens;
  `busyncr-client enroll` presents a token and CSR over TLS and receives a
  signed client certificate. Every other RPC requires an enrolled,
  non-revoked client certificate; `busyncr-daemon revoke` rejects a client
  from its next connection on.
- Integration coverage: fresh daemon → enroll → authenticated call
  succeeds; an un-enrolled client is rejected; a revoked client is
  rejected.

### S5 — Protocol + gRPC skeleton
- `proto/busyncr.proto`: the full `busyncr.v1` service surface (Enroll,
  ListSnapshots, HasChunks, UploadChunks, PutManifest, GetManifest,
  GetChunks), compiled via `tonic-build` with vendored `protoc`.
- Daemon serves the RPCs backed by the S3 chunk store; an in-process
  integration test drives a real client↔daemon roundtrip, including dedup
  counts and an FR9-groundwork integrity error on a corrupted blob.

### S4 — Client-side crypto + keyfile
- `busyncr-core::crypto`: random 32-byte data key; XChaCha20-Poly1305
  encryption for chunks (AAD = chunk ID) and manifests (AAD = snapshot ID);
  Argon2id-derived, passphrase-protected keyfile export/import format.
- Coverage: encryption roundtrips; tampered ciphertext fails to decrypt;
  a wrong passphrase fails cleanly; an exported keyfile re-imports to an
  identical key (FR6/FR7 groundwork).

### S3 — Manifest + content-addressed chunk store
- `busyncr-core::manifest`: a versioned snapshot manifest (ULID id,
  creation time, ordered per-file chunk lists plus size/mtime/permission
  metadata) with an exact, projection-matching wire format.
- `busyncr-daemon::store::ChunkStore`: content-addressed object layout with
  atomic (tmp + rename) writes, a `redb`-backed chunk/snapshot index with
  refcounts, and on-read hash verification surfaced as a typed integrity
  error (FR9 groundwork). Crash-safe: leftover tmp files from an
  interrupted write are ignored and swept on open.

### S2 — `bench-chunking` offline sizing tool (FR10)
- `busyncr-client bench-chunking <path>`: single read pass per file, fanned
  out to one content-defined chunker per candidate size; reports measured
  total/unique chunks, dedup ratio, chunk-size percentiles, and exact
  projected daemon-index and manifest bookkeeping for a configurable
  retained-snapshot count. `--baseline <path>` measures real cross-version
  chunk overlap. Human table or `--json` output; a documented heuristic
  highlights a recommended size.
- Coverage: an instrumented reader proves each file is read exactly once
  despite multiple candidates; per-candidate counts match independent
  single-candidate reference runs; projection arithmetic is exact; baseline
  overlap is correct for a corpus with a known mutation rate.

### S1 — CDC chunking engine
- `busyncr-core::chunking`: a `fastcdc`-backed content-defined chunker with
  configurable min/target/max sizes, streaming over any `Read` without
  loading whole files, and BLAKE3-based `ChunkId`.
- Coverage: determinism; boundary-shift resistance (a 1-byte insert at the
  start of a 10 MiB file leaves the large majority of chunk IDs unchanged);
  size bounds honored; empty/undersized files handled; streaming matches
  the in-memory result.

### S0 — Workspace skeleton + CI scaffolding
- Cargo workspace (`busyncr-core`, `busyncr-proto`, `busyncr-client`,
  `busyncr-daemon`); GitHub Actions CI (Linux, macOS, and Windows gates);
  PRD, ROADMAP, AGENTS, and SLICES documents establishing the build's rules
  and vertical-slice plan.

---

Deferred to a second phase, specced but not yet implemented (see FR-C1.md,
FR-K1.md, ROADMAP.md): a compression subsystem with policy simulation
(FR-C1), keyed chunk identity to close a known-plaintext confirmation
channel (FR-K1), and the longer-horizon roadmap items (WebDAV secondary
target, real-time fs-notification triggers, multi-daemon replication,
bandwidth shaping, a web UI, and finer-grained restore).
