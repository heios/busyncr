# BusyNCR — Functionality Request FR-K1: Keyed chunk identity

Status: **Requested** (2026-07-10)
Target: amends PRD §3.3 chunk-ID definition; closes the known-plaintext
confirmation channel noted in the threat model
Scheduling: **phase 2**, alongside FR-C1 (both change what feeds the chunk ID
path; ship together in v0.1.0 so the on-disk format never migrates)
Depends on: S4 keyfile format (extended), FR-C1 C1.3 (composes: identity is
keyed hash of *uncompressed* plaintext)

## 1. Problem

Chunk IDs are currently the plain BLAKE3 of chunk plaintext. The daemon never
sees content, but a malicious daemon that already *possesses* a candidate file
can chunk+hash it and check whether those chunk IDs exist — confirming that a
client stores that exact content. Content-addressed dedup makes this inherent
unless the hash is keyed.

## 2. Change (normative)

- **K1.1** Chunk ID becomes `blake3::keyed_hash(chunk_id_key, uncompressed
  plaintext)` — BLAKE3's native keyed mode, no HMAC construction needed.
- **K1.2** `chunk_id_key` is a dedicated 32-byte key, generated with the data
  key at backup-set creation, stored in the client state dir, and **included
  in the keyfile export format** (version bump; magic retained). Migration
  (FR6) therefore preserves chunk identity — imported history dedups against
  new backups exactly as before.
- **K1.3** The daemon is untouched: chunk IDs were always opaque 32-byte
  handles to it. No protocol or store change.
- **K1.4** Consequence, documented: dedup scope narrows from
  "daemon-global" to "per-backup-set (per chunk_id_key)". For the v1
  single-user model this is no practical loss; clients sharing one keyfile
  still dedup against each other.
- **K1.5** `bench-chunking` stays offline/keyless (unkeyed BLAKE3): dedup
  *ratios* are key-invariant, and the tool must keep working before any
  enrollment exists. Note this in its --help.

## 3. Acceptance criteria

- **FR-K1a** Same plaintext under two different `chunk_id_key`s yields
  different chunk IDs; under the same key, identical IDs (determinism).
- **FR-K1b** Confirmation-attack test: given the full daemon store and the
  exact plaintext of a backed-up file but NOT the chunk_id_key, recomputing
  plain-BLAKE3 (and keyed with a wrong key) matches zero stored chunk IDs.
- **FR-K1c** Full regression: FR2/FR3 (dedup across snapshots), FR4 restore,
  FR5 prune/GC, FR6 migration (keyfile v2 carries chunk_id_key; imported
  history dedups with new backups) all green with keyed IDs.
- **FR-K1d** Keyfile v2: v2 export/import roundtrip; importing a v1 keyfile
  fails with a clear versioned error (no silent misinterpretation). (No v1
  migration path needed — nothing released yet.)

## 4. Out of scope

- Padding/length-hiding (ciphertext size still leaks coarse compressibility —
  unchanged from FR-C7's documented acceptance).
- Cross-client global dedup recovery schemes (convergent encryption etc.) —
  explicitly rejected; they reintroduce the confirmation channel.
