# 0001 — BLAKE3 for chunk identity and integrity

- Status: accepted
- Date: 2026-07-11 (recorded after the fact; effective since S1, reaffirmed
  by FR-K1)

## Context

BusyNCR is content-addressed: every chunk is named by a hash of its
plaintext, computed client-side before compression or encryption. That single
hash does three jobs at once, and the choice of function has to satisfy all
three:

1. **Deduplication** — identical content must yield identical IDs across
   files, snapshots, and time (PRD §3.3). Dedup and cheap arbitrary-version
   pruning both ride on it.
2. **Integrity** — restore re-derives each chunk's content address and
   rejects a blob that does not match, catching corruption or truncation
   (FR9; REQUIREMENTS §2 lists the hash as "chunk identity + integrity").
   The hash *is* the integrity guarantee; there is no separate checksum.
3. **Zero-knowledge confidentiality** — the daemon is untrusted and sees only
   chunk IDs and ciphertext. A plain content hash leaks a known-plaintext
   confirmation channel: a daemon that already holds a candidate file can
   chunk+hash it and check whether those IDs exist, confirming a client
   stores that exact content (FR-K1 §1). Closing this requires the identity
   hash to be *keyed* with a secret the daemon never receives.

Because identity doubles as integrity (job 2), the function must be
**cryptographically collision-resistant** — a non-cryptographic hash is
disqualified: a collision would let a corrupt or malicious blob masquerade as
a legitimate chunk and pass restore verification. Because of job 3, it must
also offer a keyed mode with MAC-grade security. And because the hash sits on
the hot path — every backed-up byte is hashed, and `bench-chunking` measures
BLAKE3 throughput as part of its backup-speed projection — it must be fast.

## Decision

Use **BLAKE3** (`blake3` crate, locked at 1.8.5, statically embedded — see
REQUIREMENTS §2) as the single chunk-identity and integrity function.

- The real backup/restore pipeline computes identity as
  `blake3::keyed_hash(chunk_id_key, uncompressed_plaintext)` — BLAKE3's
  **native keyed mode**, under the backup set's secret 32-byte
  `chunk_id_key` (FR-K1 K1.1). No HMAC construction is layered on top.
- The offline `bench-chunking` tool uses plain (unkeyed) BLAKE3, because
  dedup *ratios* are key-invariant and the tool must run before any keyfile
  exists (FR-K1 K1.5). It must never touch the real backup path.
- A `ChunkId` is the raw 32-byte digest (`ChunkId([u8; 32])`).

## Rationale

**Native keyed mode is the decisive property.** Job 3 needs a keyed hash.
BLAKE3 provides `keyed_hash(key, input)` as a first-class primitive with the
security of a MAC, so keying costs one function call and no extra construction
(FR-K1 K1.1). The obvious cryptographic alternative, SHA-256, has no keyed
mode of its own — it would require wrapping in HMAC-SHA-256 for the same
guarantee, more moving parts at a strictly worse performance profile.

**One function covers identity, integrity, and confidentiality.** BLAKE3 is
collision-resistant enough to be the integrity guarantee (job 2) *and* has the
keyed mode for confidentiality (job 3), so a single 32-byte value serves all
three roles — no separate checksum, no separate MAC.

**Performance on the hot path.** BLAKE3's SIMD/multi-threaded optimized
kernels (REQUIREMENTS §2 calls these out explicitly) keep hashing off the
critical path even on an initial full backup, where CPU work competes most
directly with wall-clock time.

**32-byte digest maps cleanly onto `ChunkId`.** The default 256-bit output is
the identity type verbatim — no truncation decision to justify, ~128-bit
collision resistance under the birthday bound across an unbounded chunk
population.

## Why not the alternatives

- **SHA-256 (+ HMAC for keying).** Cryptographically fine and ubiquitous, but
  no native keyed mode — closing the FR-K1 confirmation channel would mean an
  HMAC wrapper (more construction, more to get right) and it is materially
  slower than BLAKE3 on the hashing hot path. Strictly more work for strictly
  less speed, with no compensating benefit here.
- **SHA-1 / MD5.** Disqualified. Broken collision resistance is unacceptable
  *because identity is the integrity check* — a chosen-prefix collision would
  let a forged chunk pass FR9 restore verification.
- **xxHash / other non-cryptographic hashes.** Fast, but no collision
  resistance and no keyed-MAC security — fails both the integrity (job 2) and
  confidentiality (job 3) requirements. Fine only for a hash that *isn't* also
  the integrity and security boundary; here it is.
- **Convergent encryption / cross-client global dedup schemes.** Explicitly
  rejected (FR-K1 §4; README threat model): they reintroduce exactly the
  known-plaintext confirmation channel FR-K1 exists to close.

## Consequences

- **Dedup scope is per-backup-set (per `chunk_id_key`), not daemon-global.**
  This is the price of keying and is no practical loss for the single-user
  v1 model — clients sharing one keyfile still dedup against each other, and
  imported history (FR6; the keyfile carries the key) dedups against new
  backups exactly as before (FR-K1 K1.2, K1.4).
- **256-bit collision / preimage security**, keyed to a per-set secret; a
  daemon recomputing plain or wrong-key BLAKE3 gets zero store matches
  (FR-K1b).
- **The `blake3` crate is a locked, statically embedded runtime component**
  (REQUIREMENTS §2). Upgrades go through the same linkage-verification gates
  as every other embedded native dependency.
- **The keyed/unkeyed split is a load-bearing invariant.** Using the unkeyed
  path on the real backup pipeline would silently reopen the confirmation
  channel; enforced by construction (separate functions) and called out in
  the `chunking.rs` module docs.

## Research

- **BLAKE3 specification** — Jack O'Connor, Jean-Philippe Aumasson, Samuel
  Neves, Zooko Wilcox-O'Hearn (2020 origin; the `master` PDF is a living
  document, periodically revised). A Merkle-tree hash with a native keyed
  mode (spec §6.1 — a keyed variant of the compression function that
  "removes the need for a separate construction like HMAC", not an HMAC
  wrapper) and a derive-key mode; SIMD + multi-threaded reference kernels.
  The keyed mode is what makes FR-K1's identity construction a one-call
  primitive.
  - Spec paper: https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf
  - Reference implementation: https://github.com/BLAKE3-team/BLAKE3
- **Content-addressed-storage precedent for *keyed* chunk identity.**
  - **borg** keys its chunk IDs — `id = AUTHENTICATOR(id_key, data)` with a
    dedicated, independent `id_key`, the authenticator being HMAC-SHA-256 or
    keyed BLAKE2b (docs "Encryption" subsection) — so an attacker without the
    key cannot recompute a candidate file's chunk IDs; the "Fingerprinting"
    subsection then covers the residual chunk-size signal. FR-K1 follows this
    lineage, swapping the HMAC/keyed-BLAKE2b construction for BLAKE3's native
    keyed mode:
    https://borgbackup.readthedocs.io/en/stable/internals/security.html
  - **restic**, by contrast, names blobs by the *plain* (unkeyed) SHA-256 of
    their plaintext and authenticates stored data separately with
    Poly1305-AES; its content IDs do not close the confirmation channel —
    the gap FR-K1 exists to avoid:
    https://restic.readthedocs.io/en/stable/100_references.html

## References

- PRD.md §3.3 — chunk-ID definition and the dedup foundation
- FR-K1.md — keyed chunk identity (the confirmation-channel threat and fix)
- REQUIREMENTS.md §2 — BLAKE3 optimized kernels as an embedded component
- README.md "Threat model" — zero-knowledge daemon, keyed identity
- crates/busyncr-core/src/chunking.rs — `ChunkId`, keyed vs. unkeyed paths
- CHANGELOG.md (S1) — BLAKE3-based `ChunkId` introduced
