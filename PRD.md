# BusyNCR — Product Requirements Document

Status: **Locked v1.1** (decisions finalized 2026-07-10 via wayfinder session; v1.1 adds chunk-size benchmark tool)
Owner: Alexander · Autonomous build: fable-driven, full spec, unattended until acceptance green

## 1. Problem

Windows hosts need continuous, versioned, space-efficient backups to a self-hosted backup server, with the ability to restore any retained point-in-time byte-exactly, survive machine loss, and migrate to new hardware.

## 2. Product shape

Two Rust binaries from one workspace:

- **busyncr-daemon** — runs on the backup server. Listens for gRPC connections, stores versioned backups in a content-addressed chunk store, enforces retention, garbage-collects.
- **busyncr-client** — runs on the Windows host (Windows service; also runs on Linux for dev/test). Scans configured folders on a schedule, chunks changed data, ships only missing chunks, writes a version manifest.

## 3. Locked architecture decisions

### 3.1 Stack
Rust (stable). Cross-platform core; Windows-specific integration behind `#[cfg(windows)]`. Local dev/test on Linux; Windows validation on GitHub Actions `windows-latest`.

### 3.2 Transport: gRPC over TLS
- Protocol defined in protobuf (`proto/busyncr.proto`); tonic-generated client/server stubs, prost message types.
- Streaming RPCs for chunk upload/download; unary RPCs for control plane (enroll, list versions, prune, restore manifest).
- Rationale: typed, schema-checked protocol = compile-time feedback for the autonomous loop; natural fit for bidirectional streaming.

### 3.3 Storage: content-addressed chunk store
- Content-defined chunking (FastCDC or equivalent rolling-hash CDC); target chunk size **selected empirically via the offline chunk-size benchmark (§3.7) before first backup**, then committed in config. Changing chunk size later resets dedup continuity (boundaries shift; old chunks stop matching) — client warns and treats it as starting a new backup set.
- Chunk ID = BLAKE3 hash of *plaintext* chunk content (client-side, pre-encryption) → dedup across files, versions, and time.
- A **snapshot** = manifest listing files → ordered chunk IDs + metadata (path, size, mtime, permissions).
- Daemon stores encrypted chunks keyed by chunk ID; maintains a refcount/index.
- **Prune = drop manifest + GC chunks with zero references.** This is O(manifest), which is what makes the retention grid cheap. GC must be safe under concurrent backup (grace period / lock).
- Note: this generalizes the rsync rolling-checksum idea to a versioned store (borg/restic lineage) rather than pairwise file deltas; chosen because the retention grid (3.5) requires cheap deletion of arbitrary mid-history versions, which chained rsync deltas cannot do cheaply.

### 3.4 Security: mTLS + client-held at-rest key
- **Identity**: internal CA on the daemon; each client machine enrolls and receives a client cert. Mutual TLS on every connection. Certs are per-machine and revocable. Identity is never migrated.
- **Data confidentiality**: client-held data key (per backup set). Chunks encrypted client-side (AES-256-GCM or XChaCha20-Poly1305) before upload; manifests encrypted too. Daemon is zero-knowledge: it sees chunk IDs and encrypted blobs only.
- **Key export / migration**: data key exportable as a passphrase-protected keyfile (Argon2id KDF). Migration to a new machine = enroll new cert + import keyfile → full access to existing history. Losing a machine loses nothing if the keyfile export exists.

### 3.5 Scheduling & retention: exponential thinning grid
- Client backs up on a schedule (default every 3 h; jittered).
- Retention tiers (defaults, configurable):
  - age < 24 h → keep one per 3 h
  - 24 h – 4 d → keep one per 24 h
  - 4 d – 16 d → keep one per 4 d
  - ≥ 16 d → keep one per 16 d
- As snapshots age across tier boundaries, snapshots that collide in the same grid cell are pruned (keep the newest in each cell). Prune runs on the daemon after each backup and daily.

### 3.6 Windows integration
- Client installable as a Windows service (`windows-service` crate); start/stop/restart, event-log logging.
- No fs-watcher in v1 (scheduled model chosen instead); `ReadDirectoryChangesW` is out of scope (see ROADMAP.md R2).

### 3.7 Offline chunk-size benchmark (pre-commit sizing tool)
- CLI: `busyncr-client bench-chunking <path> [--sizes 256K,512K,1M,2M,4M] [--baseline <older-copy-path>] [--snapshots N]`. Fully offline; no daemon, no keys, no network.
- **Single-pass design**: each file is read from disk exactly once; the byte stream is fanned out to one CDC chunker per candidate target size running concurrently, with BLAKE3 hashing at each chunker's boundaries. Cost ≈ one full dataset read (I/O-bound) regardless of the number of candidates.
- **Per-candidate report** (measured, not estimated):
  - total chunks, unique chunks, intra-dataset dedup ratio, mean/median/p95 actual chunk size;
  - daemon index metadata: unique_chunks × (32 B chunk ID + length + refcount + index-entry overhead) — exact per-entry cost from the real index record layout;
  - manifest size per snapshot: Σ over files (path bytes + fixed metadata + 32 B × chunk count);
  - projected total bookkeeping for N retained snapshots under the §3.5 retention grid (default N = steady-state grid occupancy).
- **Cross-version mode**: optional `--baseline` pointing at an older copy of the same data measures real chunk overlap between the two states — the honest proxy for cross-snapshot dedup. Report notes explicitly that without a baseline, dedup figures are intra-snapshot only and understate versioned savings.
- Output: human-readable table + `--json` for machine consumption. Recommended size highlighted using a documented heuristic (best storage×metadata trade-off), but the choice stays with the user.
- On first `backup` run, if no chunk size is committed in config, the client refuses and points at `bench-chunking` (or accepts `--default-chunking` to skip with the 1 MiB default).

## 4. Functional requirements (acceptance-level)

FR1. Enroll a client against a fresh daemon (CA bootstrap, cert issuance, keyfile creation).
FR2. Back up a configured folder tree → snapshot appears in daemon version list.
FR3. Second backup after edits ships only new/changed chunks (verified by transfer-size assertion).
FR4. Restore any retained snapshot to an empty directory → byte-exact tree (hash-verified), including metadata.
FR5. Retention grid prunes correctly: simulated clock advancing 60 days yields exactly the grid-predicted snapshot set; GC reclaims unreferenced chunks; all surviving snapshots still restore byte-exact.
FR6. Keyfile export + import on a "new machine" (fresh client state, new cert) restores old history.
FR7. Daemon never possesses plaintext: test asserts stored blobs are not decryptable without client key.
FR8. Client runs as a Windows service; daemon runs as a long-lived process; both survive restart mid-history.
FR9. Corrupt/truncated chunk on disk is detected on restore (integrity error, not silent corruption).
FR10. `bench-chunking` over a generated test corpus: (a) reads each file exactly once (verified by I/O accounting); (b) per-candidate chunk counts match single-candidate reference runs; (c) metadata projections match the real index/manifest record layouts within exact arithmetic; (d) `--baseline` mode correctly reports overlap for a corpus with known mutation rate.

## 5. Verification strategy (the autonomous loop's feedback)

- **Tier 1 — local (every loop iteration)**: `cargo build`, `cargo clippy -D warnings`, `cargo test` (unit + integration; integration tests run real client↔daemon over localhost TLS with generated certs). Full suite must run on Linux.
- **Tier 2 — GitHub Actions, cross gates**: on push — Linux suite + native `cargo build` + full test suite on `windows-latest`.
- **Tier 3 — Windows-behavior gates**: Windows service install/start/stop smoke test in CI on `windows-latest`.
- **Done** = all FR1–FR10 covered by automated tests, green on Linux locally and on `windows-latest` CI.

## 6. Out of scope (v1)

Planned/deferred features live in ROADMAP.md. Highlights:

- Real-time fs-notification triggers (R2).
- WebDAV secondary backup target with full-mirror or quota-bounded recent-history modes (R1).
- Web UI / GUI (R5). CLI only: `busyncr-client backup|restore|list|bench-chunking|export-key|import-key|enroll`, `busyncr-daemon serve|prune|gc|enroll-token`.
- Multi-daemon replication (R3); cloud storage backends.
- Bandwidth throttling, compression tuning (R4; basic zstd-before-encrypt is in scope for v1).
- Cross-file rename detection heuristics (dedup already makes renames cheap).

## 7. Development process

Matt Pocock-style agentic workflow, fable-orchestrated:
grill (done) → PRD (this doc) → vertical-slice issue DAG → autonomous implement/verify loop per slice (fresh-context review agent per slice) → Windows CI gates → done when §5 acceptance is green. Slice DAG lives in `SLICES.md`; each slice must leave the tree green. Agent rules: `AGENTS.md`.
