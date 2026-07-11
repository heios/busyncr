# BusyNCR — Functionality Request FR-C1: Compression subsystem + policy simulation

Status: **Requested** (grilled 2026-07-10; measurements in Appendix A)
Target: extends PRD §3.3/§3.7; supersedes the "basic zstd-before-encrypt" line in PRD §6
Depends on: chunk store format, `bench-chunking` single-pass fan-out (PRD §3.7)
Non-goals: see §6
Scheduling: **phase 2 — implementation begins only after the v1 slice DAG (S0–S13) is complete and green.**

## 1. Summary

Add per-chunk compression between BLAKE3 hashing and encryption, with a
store-raw fallback and an optional escalation policy; extend `bench-chunking`
with a `--compression` mode that simulates candidate compression *policies*
over the user's real data and reports, per policy: total stored bytes,
CPU cost, effective ratio, and **projected backup speed** (initial full backup
and steady-state incremental update).

Rationale (measured, Appendix A): real user corpora are bimodal — databases,
source, logs compress 2–2.6× under zstd-3, while docx/xlsx/jpeg/png compress
at exactly 1.00× (deflate/DCT inside). A blended ratio is meaningless to
users; total-bytes and time projections per policy are the decision-support
numbers.

## 2. Chunk format changes (persistent, normative)

- **C1.1** Prepend a 1-byte codec ID to the *plaintext* chunk payload before
  encryption: `0 = raw`, `1 = zstd`. Values 2–255 reserved; decoder MUST
  error on unknown codec (integrity path, cf. FR9).
- **C1.2** Codec byte + payload are encrypted together; the daemon never sees
  the codec byte (zero-knowledge preserved, PRD §3.4).
- **C1.3** Chunk identity remains the BLAKE3 of the *uncompressed plaintext*
  (PRD §3.3). Consequence, and this is load-bearing: the compression decision
  is **non-normative** — it affects stored bytes only, never identity, dedup,
  or protocol. Policies may be heuristic, non-deterministic, and changed
  between releases with no migration. Each unique chunk is compressed at most
  once, ever.
- **C1.4** lz4 (or any probe codec) output is NEVER stored. Persistent format
  surface is exactly `{raw, zstd}`.

## 3. Client compression policy engine

- **C2.1 Baseline policy `zstd3` (default):** compress each new unique chunk
  with zstd level 3; keep the compressed form iff
  `compressed_len <= raw_len * 0.95`, else store raw. The keep/raw decision is
  made from the *actual* zstd output, not a prediction.
- **C2.2 Optional policy `probe+zstd3` (config flag):** lz4-level probe first
  (lz4 fast, full chunk, output discarded); if probe ratio < threshold
  (default 1.02), store raw without invoking zstd; else proceed as C2.1.
  - Document the known false negative: entropy-only-compressible data
    (base64-like, hex-heavy) reads ~1.00 to lz4 but ~1.33 to zstd (Appendix
    A.3). This policy trades those bytes for probe speed.
  - Implementation MAY substitute the probe with zstd `--fast` over a 64 KiB
    sample of the chunk (catches entropy skew; chunks never span files per
    PRD §3.3 manifest model, so samples are class-homogeneous). If both are
    implemented, probe kind is a config enum.
- **C2.3 Optional escalation `+escalate` (config flag, composable with C2.1
  or C2.2):** if the zstd-3 result compressed the chunk beyond an escalation
  threshold (default ratio ≥ 2.0), recompress with zstd level 9 and keep the
  smaller. Escalation MUST be disabled during the initial full backup (the
  only phase where compression sits on the wall-clock critical path) and
  enabled during steady-state incremental runs. Phase detection: first
  completed snapshot of a backup set.
- **C2.4** zstd levels/thresholds configurable; defaults as above. All
  decisions logged at debug level with per-run counters (chunks raw / zstd3 /
  escalated, bytes saved).

## 4. `bench-chunking --compression`: policy simulation report

Extends the existing single-pass benchmark (PRD §3.7). Compression measurement
runs on the **unique-chunk stream** of the selected (or each candidate) chunk
size, preserving the read-each-file-once guarantee: fan unique chunks through
the codecs the same way bytes fan through CDC candidates today.

### 4.1 Policies simulated

At minimum: `raw-only`, `zstd3-always` (no raw fallback — shows what the
fallback saves), `zstd3` (C2.1), `probe+zstd3` (C2.2), `zstd3+escalate`
(C2.3). Table layout, one row per policy.

### 4.2 Per-policy columns (all measured on the user's data, not estimated)

1. **Total stored bytes** for the snapshot (post-policy, pre-encryption; AEAD
   overhead added arithmetically per chunk) and effective ratio vs raw.
2. **Compression CPU** — wall seconds and MB/s over unique bytes, measured on
   the machine running the tool.
3. **Projected initial full backup time** — pipeline model of §4.4.
4. **Projected incremental update time and bytes shipped** — requires
   `--baseline` (PRD §3.7 cross-version mode) to obtain a real new-unique-chunk
   volume; without `--baseline`, this column reads `n/a (run with --baseline)`
   rather than printing an intra-snapshot guess. Optionally accept
   `--assume-churn <pct>` to model it explicitly; output must label the number
   as assumed.
5. **Projected steady-state store size** under the §3.5 retention grid at
   grid occupancy N (reuses the existing bookkeeping projection, now applied
   to post-compression chunk sizes).

### 4.3 Diagnostics section (the "why")

Per file-class breakdown (by extension group: db/sqlite, office-zip, pdf,
image, text/code, other): bytes in, bytes out under the recommended policy,
class share of total savings. Explicitly annotate classes at ratio ~1.00 as
"already compressed internally". This section explains the totals; it is not
the decision surface.

### 4.4 Backup-speed projection model (new)

Goal: answer "how long will my backup take" per policy, honestly separating
what the tool can measure from what it cannot know (network).

- **Measured on the target dataset during the same single pass:**
  `read_MBps` (cold-ish sequential read as observed), `cdc_MBps`,
  `blake3_MBps`, and per-policy `compress_MBps` (on unique bytes) — plus a
  synthetic in-memory `encrypt_MBps` microbenchmark (AEAD over 1 MiB buffers).
- **Pipeline model:** stages overlap; projected client-side throughput is
  `min(read_MBps, 1 / (1/cdc + 1/blake3 + 1/compress + 1/encrypt) per CPU
  budget)` with the CPU term scaled by `--threads` (default: physical cores,
  matching the client's pipeline concurrency). Keep the model simple and
  documented in `--help`; it is an estimate, label it as such.
- **Network term:** the tool is offline (PRD §3.7) and MUST NOT probe the
  network. Report bytes-to-upload per policy, then wall-clock at the
  CPU-bound floor and at bandwidth points `--net-mbps <list>`
  (default `50,200,1000`). The dominant effect to surface: compression
  multiplies effective upload bandwidth by the policy's ratio, so on slow
  links a stronger policy *speeds up* backup — the report should make that
  visible (e.g. at 50 Mbit/s, zstd3 vs raw-only initial backup time).
- **Two rows per policy:** initial full backup (all unique bytes) and
  incremental update (baseline-measured new bytes; includes scan time of the
  full tree at `read_MBps` since incremental still reads to detect change per
  the scheduled-scan model, unless/until mtime-gated scanning exists — state
  which assumption the number uses).

### 4.5 Output

Human table + `--json` (extend the existing schema; policy simulation under a
`compression_policies` key). Recommended policy highlighted with the
documented heuristic: smallest steady-state store among policies whose
initial-backup CPU-bound time is within 1.5× of `zstd3`. Choice stays with the
user; chosen policy is committed to config alongside chunk size.

## 5. Acceptance criteria (extend PRD §4)

- **FR-C1.** Round-trip: chunks stored under each codec byte value restore
  byte-exact; unknown codec byte yields an integrity error, not silent output.
- **FR-C2.** Raw fallback: a corpus of pre-compressed files (zip/jpeg) backs
  up with ≥ 99% of unique bytes stored raw; total stored size ≤ 1.01× input
  (codec byte + AEAD overhead only).
- **FR-C3.** Compressible corpus (generated text/DB-like) stores at least 2×
  smaller under default policy than under `raw-only` (assert against a
  corpus-specific golden bound, not a magic constant).
- **FR-C4.** Mixed-codec history: snapshots containing raw, zstd-3, and
  escalated zstd-9 chunks in one manifest restore byte-exact; prune/GC
  unaffected (identity is plaintext hash — test asserts dedup hit across a
  policy change between two backups of identical data).
- **FR-C5.** `--compression` report: (a) single-pass I/O guarantee still holds
  with policy simulation enabled (extend FR10a accounting); (b) per-policy
  stored-bytes figures match an end-to-end backup of the same corpus under
  that policy within codec-determinism tolerance (exact for same zstd version);
  (c) `--baseline` incremental projection matches a real second backup's
  shipped bytes within ±5%; (d) speed projections are internally consistent
  (CPU-bound floor ≤ any finite-bandwidth figure; monotone in bandwidth).
- **FR-C6.** Escalation phase gate: initial backup never invokes level-9 path
  (assert via counters); subsequent incremental with escalation enabled does,
  for qualifying chunks.
- **FR-C7.** Zero-knowledge preserved: FR7 test extended — stored blobs reveal
  neither codec choice nor compressibility (codec byte inside AEAD; padding is
  out of scope, note ciphertext length still leaks coarse compressibility —
  acceptable, document it in the threat model).

## 6. Out of scope

- lzo in any role (dominated: ≤48 KiB window, slower decode, GPL friction).
- Storing lz4 output (C1.4). lz4 exists only as an ephemeral probe, if at all.
- zstd dictionaries / long-range mode (window ≥ chunk size makes them moot at
  v1 chunk sizes; revisit under ROADMAP R4).
- Compression of the transport stream (chunks are already compressed;
  gRPC-level compression stays off).
- Network measurement inside bench-chunking (tool stays offline).
- Recompression of existing stored chunks (daemon can't; client won't —
  policy changes apply to new unique chunks only, per C1.3).

## 7. Implementation notes for the agent

- Rust crates: `zstd` (bindgen to libzstd) preferred over pure-Rust for level
  parity with reference numbers; `lz4_flex` (pure Rust, block mode) suffices
  for the probe since its output is discarded and its ratio, not its exact
  bytes, is the signal.
- The 0.95 keep-threshold, 1.02 probe threshold, and 2.0 escalation threshold
  are config-surfaced defaults; do not scatter them as literals.
- Determinism note for FR-C5b: pin the zstd crate/libzstd version in the
  lockfile; report tolerance exists because zstd output may differ across
  library versions, which is fine (C1.3) but breaks exact-match asserts.
- Keep the policy engine a pure function `(chunk: &[u8], phase, cfg) ->
  (codec_id, Cow<[u8]>)` with counters injected — trivially unit-testable and
  reusable verbatim by the simulator, which is the property FR-C5b leans on.

## Appendix A — Reference measurements (2026-07-10 sandbox, informative only;
re-measure on target data, do not encode as constants)

A.1 Mixed 64 MiB corpus (source + ELF), independent 1 MiB chunks: lz4 2.14×,
zstd-1 2.87×, zstd-3 3.20×, zstd-9 3.46×. lz4 ratio flat across 256K–4M
chunks (64 KiB format window, max offset 65535); zstd keeps gaining with
chunk size.

A.2 Per class (1 MiB chunks, zstd-3): sqlite 2.46×; xlsx/docx/jpeg/png 1.00×;
text-PDF 1.40× (real PDFs vary 1.0–5×). Native speeds on sqlite: lz4-1
537 MB/s @1.50×; zstd-3 162 MB/s @2.52×; zstd-9 34 MB/s @2.70×. On
incompressible data: lz4 11.7 GB/s, zstd-3 1.06 GB/s (zstd self-skips).

A.3 Probe false negative: base64 stream — lz4 0.996× (reads as
incompressible) vs zstd-3 1.33× @292 MB/s.

A.4 Escalation payoff (sqlite): 3→5 = +1.9% bytes at 2.1× CPU; 3→9 ≈ +7% at
~5× CPU — hence C2.3 escalates straight to 9.
