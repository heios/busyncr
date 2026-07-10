# Changelog

All notable changes to BusyNCR are recorded here, one entry per vertical
slice (see SLICES.md for the full spec each slice implements and AGENTS.md
for the rules every entry was built under). Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); dates are UTC.

The first tagged release is `0.1.0` (below). FR references point at PRD.md §4.

## [0.1.0] - 2026-07-10

### C4 — Phase-2 acceptance sweep + docs
- Extended the S13 `acceptance.rs` sweep to also cover phase-2's FR-K1.md
  and FR-C1.md numbering (`frk1<letter?>_*` / `frc<N><letter?>_*`), so
  `cargo test --workspace` itself proves every phase-2 FR (FR-K1, FR-C1–C7)
  has at least one compiled test, exactly as it already did for FR1–FR10.
- README: documented keyed chunk identity (what it buys you, cost is
  practically nil) inline with enrollment; a new "Compression" section
  covering the `[compression]` config table, each policy
  (`zstd3`/`probe+zstd3`/`+escalate`) and its phase gate, and
  `bench-chunking --compression` usage; a new "Threat model" section
  covering the confirmation channel FR-K1 closes, what FR-C7 keeps hidden
  (codec choice, compressibility beyond ciphertext length), and what's
  explicitly out of scope.
- Removed the old "deferred to a second phase" CHANGELOG footer now that
  K1/C1–C4 have shipped; replaced with dated entries below.

### C3 — bench-chunking --compression policy simulation (FR-C5)
- `busyncr-client bench-chunking --compression [--threads N] [--net-mbps ...]
  [--assume-churn PCT]`: simulates `raw-only`/`zstd3-always`/`zstd3`/
  `probe+zstd3`/`zstd3+escalate` over the real unique-chunk stream (still one
  read per file), reporting measured stored bytes/ratio, compression MB/s,
  and a backup-speed projection (measured read/CDC/BLAKE3/compress/encrypt
  throughput) at the CPU-bound floor and at configurable bandwidth points.
  `--baseline` unlocks a real incremental-update row; a recommended policy
  is highlighted.
- Coverage: single-pass I/O guarantee holds with simulation enabled;
  simulated stored bytes match a real first backup under the same policy
  exactly; `--baseline` incremental projection matches a real second
  backup's shipped bytes within ±5%; speed projections are internally
  consistent (CPU-bound floor ≤ every finite-bandwidth figure, monotone in
  bandwidth).

### C2 — Pipeline integration (FR-C2, C4, C6, C7)
- Wired the C1 compression policy engine into the real `backup`/`restore`
  pipeline: phase detection (first completed snapshot of a backup set),
  per-chunk codec choice before encryption, codec decode after
  decrypt+verify on restore. `[compression]` in client config selects the
  policy; a run's raw/zstd3/escalated counters are reported.
- Coverage: a pre-compressed corpus stores ≥99% raw chunks at ≤1.01× input
  size; a compressible corpus stores ≥2× smaller under the default policy
  than a forced raw-only policy; a mixed-codec (raw + zstd-3 + escalated
  zstd-9) manifest restores byte-exact and survives prune/GC; dedup still
  hits across a policy change between two backups of identical data;
  escalation counters are zero on an initial backup and nonzero on a
  qualifying incremental; a wrong data key can't recover the codec byte
  from either a raw or compressed stored blob.

### C1 — Codec framing + compression policy engine (FR-C1 §2–§3)
- `busyncr-core::compression`: a 1-byte codec ID (`0 = raw`, `1 = zstd`;
  `2–255` reserved and rejected as an integrity error) prepended to a
  chunk's plaintext before encryption, so the daemon never sees which codec
  was used. A pure `choose_codec(chunk, phase, cfg) -> (codec, bytes)`
  policy function implements the baseline `zstd3` policy (keep the
  compressed form iff it's ≤95% of raw), the optional `probe+zstd3` policy
  (a discarded lz4 probe skips zstd on chunks that don't look
  compressible), and the optional `+escalate` policy (retry at zstd level 9
  when zstd-3 already compresses well) — escalation is hard-disabled during
  a backup set's first (initial full) backup regardless of config.
  Thresholds and levels are config-surfaced, never scattered literals.
- Coverage: round-trip byte-exact under both codec bytes including the
  empty-chunk edge case, an unknown codec byte is an integrity error at the
  encrypted layer, keep/probe-threshold boundaries computed from each
  fixture's actual achieved ratio, and the escalation phase gate is proven
  at the unit level.

### K1 — Keyed chunk identity + keyfile v2 (FR-K1a–d)
- Chunk ID becomes `blake3::keyed_hash(chunk_id_key, uncompressed
  plaintext)` instead of plain BLAKE3, closing a known-plaintext
  confirmation channel: a daemon that already possesses a candidate file's
  bytes can no longer chunk+hash it and check the store for a match,
  because it never holds the key. `chunk_id_key` is a 32-byte key generated
  alongside the data key at backup-set creation, stored in the client state
  dir, and carried in a version-bumped keyfile format (magic retained; a v1
  keyfile fails import with a clear versioned error, no silent
  misinterpretation).
- Daemon and protocol are untouched — chunk IDs were always opaque 32-byte
  handles to the daemon. `bench-chunking` stays keyless/offline, since dedup
  *ratios* are key-invariant and the tool must work before enrollment
  exists.
- Coverage: determinism and key-separation (same plaintext, different keys
  ⇒ different IDs); a confirmation-attack test proving zero stored-ID
  matches without the real key; the full v1 regression suite (FR2–FR6)
  green under keyed IDs; keyfile v2 round-trip plus v1-rejection.

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

v0.1.0 (unreleased) ships v1 (S0–S13) plus phase 2 (K1, C1–C4): keyed chunk
identity and the compression subsystem are both complete and green, per
FR-K1.md and FR-C1.md above. Still deferred, per ROADMAP.md: WebDAV
secondary target, real-time fs-notification triggers, multi-daemon
replication, bandwidth shaping, a web UI, and finer-grained restore.
