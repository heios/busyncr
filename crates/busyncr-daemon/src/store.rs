//! Content-addressed chunk store (PRD §3.3).
//!
//! # Layout
//!
//! ```text
//! <root>/
//!   index.redb                  redb database: chunk index + manifests
//!   objects/<first2hex>/<hex>   one file per chunk, named by its ChunkId
//! ```
//!
//! Each object file is `BLAKE3(blob) (32 bytes) || blob`. Since S7 the blob
//! is XChaCha20-Poly1305 ciphertext the daemon cannot relate to the chunk-ID
//! key (which hashes the *plaintext*, PRD §3.3/§3.4), so on-disk integrity
//! is anchored to a hash of the stored bytes themselves.
//!
//! # Index
//!
//! Three `redb` tables:
//!
//! * `chunks`: 32-byte chunk-ID key → 16-byte value in the canonical
//!   [`IndexEntry`] wire layout (`chunk_len` LE + `refcount` LE) — exactly
//!   the [`IndexEntry::WIRE_SIZE`] record the bench-chunking projections
//!   assume (PRD §3.7).
//! * `snapshots`: 16-byte snapshot ULID key → manifest blob (opaque:
//!   encrypted client-side from S7 onward).
//! * `snapshot_refs`: 16-byte snapshot ULID key → the snapshot's chunk
//!   references (concatenated 32-byte chunk IDs, manifest order, duplicates
//!   included). Kept outside the encrypted blob so prune/GC (S9) can
//!   decrement refcounts without ever decrypting a manifest.
//!
//! # Atomicity & crash safety
//!
//! Chunk blobs are written to a `.tmp-<ulid>` file in the destination shard
//! directory, fsynced, then renamed into place — a reader can never observe
//! a partially written object. Leftover `.tmp-` files from a crash are
//! ignored by every read path and swept on [`ChunkStore::open`]. Index
//! mutations are single redb transactions (commit or nothing).
//!
//! # Integrity (FR9 groundwork)
//!
//! Every chunk read checks the blob's length against the index and its
//! BLAKE3 hash against the header written at store time; any mismatch
//! surfaces as a typed [`IntegrityError`] naming the chunk — corruption is
//! never silent. (End-to-end plaintext verification against the chunk ID
//! happens on the client after decryption, where the plaintext exists.)

use std::fs;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};

use busyncr_core::chunking::ChunkId;
use busyncr_core::index::IndexEntry;
use busyncr_core::manifest::{Manifest, ManifestError};
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use ulid::Ulid;

/// Chunk index table: 32-byte chunk ID → 16-byte [`IndexEntry`] wire value.
const CHUNKS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("chunks");
/// Snapshot table: 16-byte ULID → opaque manifest blob.
const SNAPSHOTS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("snapshots");
/// Snapshot chunk-reference table: 16-byte ULID → concatenated 32-byte chunk
/// IDs (manifest order, duplicates included). The daemon's only view of a
/// snapshot's chunk usage once manifests are encrypted (S7).
const SNAPSHOT_REFS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("snapshot_refs");

/// Byte length of the BLAKE3-of-blob header prefixed to every object file.
const OBJECT_HEADER_LEN: usize = 32;

/// Prefix marking in-flight temporary object files; anything carrying it is
/// invisible to reads and swept on open.
const TMP_PREFIX: &str = ".tmp-";

/// A stored chunk failed verification: the store's contents do not match
/// what the index and the content address promise (FR9 groundwork).
#[derive(Debug, thiserror::Error)]
pub enum IntegrityError {
    /// The stored bytes' BLAKE3 hash does not match the integrity header
    /// written when the blob was stored.
    #[error("chunk {chunk} is corrupt: content hashes to {actual}")]
    HashMismatch {
        /// The chunk that failed verification.
        chunk: ChunkId,
        /// What the stored bytes actually hash to (hex BLAKE3).
        actual: ChunkId,
    },
    /// The blob's length does not match the indexed chunk length.
    #[error("chunk {chunk} is truncated or padded: expected {expected} bytes, found {actual}")]
    LengthMismatch {
        /// The chunk that failed verification.
        chunk: ChunkId,
        /// Length recorded in the index.
        expected: u64,
        /// Length of the blob on disk.
        actual: u64,
    },
    /// The chunk is indexed but its object file is gone.
    #[error("chunk {chunk} is indexed but its object file is missing")]
    MissingBlob {
        /// The chunk whose blob is missing.
        chunk: ChunkId,
    },
}

/// Errors produced by the chunk store.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// A stored blob failed on-read verification.
    #[error(transparent)]
    Integrity(#[from] IntegrityError),
    /// The requested chunk is not in the store.
    #[error("chunk {0} not found")]
    ChunkNotFound(ChunkId),
    /// The requested snapshot is not in the store.
    #[error("snapshot {0} not found")]
    SnapshotNotFound(Ulid),
    /// A snapshot with this ID is already stored.
    #[error("snapshot {0} already exists")]
    SnapshotExists(Ulid),
    /// A manifest references a chunk the store does not hold.
    #[error("snapshot {snapshot} references unknown chunk {chunk}")]
    UnknownChunkRef {
        /// The snapshot being stored.
        snapshot: Ulid,
        /// The chunk it references that is absent from the store.
        chunk: ChunkId,
    },
    /// The chunk cannot be deleted while manifests still reference it.
    #[error("chunk {chunk} still has {refcount} reference(s)")]
    StillReferenced {
        /// The chunk that was asked to be deleted.
        chunk: ChunkId,
        /// Its current reference count.
        refcount: u64,
    },
    /// A stored manifest blob failed to decode.
    #[error("manifest decode failed")]
    Manifest(#[from] ManifestError),
    /// Filesystem I/O failed.
    #[error("I/O error at {path}")]
    Io {
        /// The path the failing operation touched.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The redb index failed.
    #[error("index error")]
    Index(#[source] Box<redb::Error>),
}

impl StoreError {
    fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }
}

/// Routes every specific redb error type through the umbrella
/// [`redb::Error`] into [`StoreError::Index`].
macro_rules! from_redb {
    ($($ty:ty),+ $(,)?) => {$(
        impl From<$ty> for StoreError {
            fn from(e: $ty) -> Self {
                Self::Index(Box::new(redb::Error::from(e)))
            }
        }
    )+};
}
from_redb!(
    redb::DatabaseError,
    redb::TransactionError,
    redb::TableError,
    redb::StorageError,
    redb::CommitError,
);

/// The daemon's content-addressed chunk store: CAS object files plus a redb
/// index of chunk refcounts and snapshot manifests.
///
/// All methods take `&self`; redb serializes writers internally.
pub struct ChunkStore {
    root: PathBuf,
    objects: PathBuf,
    db: Database,
}

impl std::fmt::Debug for ChunkStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChunkStore")
            .field("root", &self.root)
            .finish_non_exhaustive()
    }
}

impl ChunkStore {
    /// Opens (creating if necessary) a chunk store rooted at `root`.
    ///
    /// Creates the directory layout and index tables on first use, and
    /// sweeps any `.tmp-` files a previous crash may have left behind.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Io`] on filesystem failure or
    /// [`StoreError::Index`] if the redb database cannot be opened.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, StoreError> {
        let root = root.into();
        let objects = root.join("objects");
        fs::create_dir_all(&objects).map_err(|e| StoreError::io(&objects, e))?;

        let db = Database::create(root.join("index.redb"))?;
        // Ensure both tables exist so read transactions never race a
        // missing-table error.
        let txn = db.begin_write()?;
        {
            txn.open_table(CHUNKS)?;
            txn.open_table(SNAPSHOTS)?;
            txn.open_table(SNAPSHOT_REFS)?;
        }
        txn.commit()?;

        let store = Self { root, objects, db };
        store.sweep_tmp_files()?;
        Ok(store)
    }

    /// Root directory of the store.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Removes leftover `.tmp-` files from interrupted writes (crash
    /// recovery). Object files proper are never touched.
    fn sweep_tmp_files(&self) -> Result<(), StoreError> {
        let shards = fs::read_dir(&self.objects).map_err(|e| StoreError::io(&self.objects, e))?;
        for shard in shards {
            let shard = shard.map_err(|e| StoreError::io(&self.objects, e))?;
            let shard_path = shard.path();
            if !shard_path.is_dir() {
                continue;
            }
            let entries = fs::read_dir(&shard_path).map_err(|e| StoreError::io(&shard_path, e))?;
            for entry in entries {
                let entry = entry.map_err(|e| StoreError::io(&shard_path, e))?;
                let is_tmp = entry
                    .file_name()
                    .to_str()
                    .is_some_and(|n| n.starts_with(TMP_PREFIX));
                if is_tmp {
                    let path = entry.path();
                    match fs::remove_file(&path) {
                        Ok(()) => {}
                        Err(e) if e.kind() == ErrorKind::NotFound => {}
                        Err(e) => return Err(StoreError::io(&path, e)),
                    }
                }
            }
        }
        Ok(())
    }

    /// Path of the object file for `id`: `objects/<first2hex>/<hex>`.
    fn object_path(&self, id: &ChunkId) -> PathBuf {
        let hex = id.to_string();
        self.objects.join(&hex[..2]).join(hex)
    }

    /// Stores a chunk blob under the chunk ID the client addressed it with.
    ///
    /// The blob is opaque: since S7 it is ciphertext whose relation to the
    /// (plaintext-hash) chunk ID the daemon cannot check (PRD §3.4). What
    /// the store guarantees instead is that whatever bytes were stored are
    /// returned bit-exact or flagged — a BLAKE3 header over the blob is
    /// written with it and re-verified on every read (FR9 groundwork).
    ///
    /// Returns `true` if the chunk was newly stored, `false` if it was
    /// already present (dedup no-op — the existing blob and refcount are
    /// left untouched).
    ///
    /// The object file is written to a temporary file in the destination
    /// shard, fsynced, then atomically renamed into place.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Io`]/[`StoreError::Index`] on storage failure.
    pub fn put_chunk(&self, id: ChunkId, data: &[u8]) -> Result<bool, StoreError> {
        let txn = self.db.begin_write()?;
        let newly_stored = {
            let mut chunks = txn.open_table(CHUNKS)?;
            if chunks.get(id.as_bytes().as_slice())?.is_some() {
                false
            } else {
                self.write_object(&id, data)?;
                let entry = IndexEntry {
                    chunk_len: data.len() as u64,
                    refcount: 0,
                };
                chunks.insert(id.as_bytes().as_slice(), entry.to_wire_value().as_slice())?;
                true
            }
        };
        txn.commit()?;
        Ok(newly_stored)
    }

    /// Writes `BLAKE3(data) || data` to the object file for `id` via
    /// tmp + fsync + rename.
    fn write_object(&self, id: &ChunkId, data: &[u8]) -> Result<(), StoreError> {
        let final_path = self.object_path(id);
        let shard = final_path.parent().unwrap_or(&self.objects).to_path_buf();
        fs::create_dir_all(&shard).map_err(|e| StoreError::io(&shard, e))?;

        let tmp_path = shard.join(format!("{TMP_PREFIX}{}", Ulid::new()));
        let mut file = fs::File::create(&tmp_path).map_err(|e| StoreError::io(&tmp_path, e))?;
        let header = blake3::hash(data);
        let write_result = file
            .write_all(header.as_bytes())
            .and_then(|()| file.write_all(data))
            .and_then(|()| file.sync_all())
            .map_err(|e| StoreError::io(&tmp_path, e));
        drop(file);
        if let Err(e) = write_result {
            let _ = fs::remove_file(&tmp_path);
            return Err(e);
        }

        match fs::rename(&tmp_path, &final_path) {
            Ok(()) => Ok(()),
            // On Windows, rename fails if the destination exists. The store
            // is content-addressed and finals only appear via completed
            // renames, so an existing destination already holds these exact
            // bytes — drop our tmp and succeed.
            Err(_) if final_path.exists() => {
                let _ = fs::remove_file(&tmp_path);
                Ok(())
            }
            Err(e) => {
                let _ = fs::remove_file(&tmp_path);
                Err(StoreError::io(&final_path, e))
            }
        }
    }

    /// Loads a chunk blob and verifies it byte-for-byte.
    ///
    /// The blob's length is checked against the index and its BLAKE3 hash
    /// against the integrity header written at store time; either mismatch
    /// is a typed [`IntegrityError`] naming the chunk (FR9 groundwork).
    ///
    /// # Errors
    ///
    /// [`StoreError::ChunkNotFound`] if `id` is not indexed;
    /// [`StoreError::Integrity`] if the stored blob is missing, truncated,
    /// or corrupt.
    pub fn get_chunk(&self, id: ChunkId) -> Result<Vec<u8>, StoreError> {
        let entry = self.chunk_entry(id)?.ok_or(StoreError::ChunkNotFound(id))?;

        let path = self.object_path(&id);
        let raw = match fs::read(&path) {
            Ok(raw) => raw,
            Err(e) if e.kind() == ErrorKind::NotFound => {
                return Err(IntegrityError::MissingBlob { chunk: id }.into());
            }
            Err(e) => return Err(StoreError::io(&path, e)),
        };

        // A file shorter than the header cannot even carry its checksum:
        // report it as the truncation it is (body length 0).
        if raw.len() < OBJECT_HEADER_LEN {
            return Err(IntegrityError::LengthMismatch {
                chunk: id,
                expected: entry.chunk_len,
                actual: (raw.len() as u64).saturating_sub(OBJECT_HEADER_LEN as u64),
            }
            .into());
        }
        let (header, data) = raw.split_at(OBJECT_HEADER_LEN);
        if data.len() as u64 != entry.chunk_len {
            return Err(IntegrityError::LengthMismatch {
                chunk: id,
                expected: entry.chunk_len,
                actual: data.len() as u64,
            }
            .into());
        }
        let actual = blake3::hash(data);
        if actual.as_bytes() != header {
            return Err(IntegrityError::HashMismatch {
                chunk: id,
                actual: ChunkId::from_bytes(*actual.as_bytes()),
            }
            .into());
        }
        Ok(data.to_vec())
    }

    /// Whether the store holds a chunk with this ID.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Index`] if the index cannot be read.
    pub fn has_chunk(&self, id: ChunkId) -> Result<bool, StoreError> {
        Ok(self.chunk_entry(id)?.is_some())
    }

    /// The index record for a chunk (length + refcount), if present.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Index`] if the index cannot be read.
    pub fn chunk_entry(&self, id: ChunkId) -> Result<Option<IndexEntry>, StoreError> {
        let txn = self.db.begin_read()?;
        let chunks = txn.open_table(CHUNKS)?;
        let Some(guard) = chunks.get(id.as_bytes().as_slice())? else {
            return Ok(None);
        };
        Ok(Some(decode_entry(guard.value())))
    }

    /// Stores an opaque snapshot manifest blob together with its declared
    /// chunk references, taking one reference per occurrence in `refs`.
    ///
    /// The blob is never decoded — since S7 it is encrypted client-side
    /// (PRD §3.4), so the client declares the chunk references separately
    /// (they are the IDs it just uploaded; the daemon sees those anyway).
    /// `refs` is persisted so prune/GC (S9) can decrement refcounts without
    /// decrypting anything.
    ///
    /// Atomic: if any referenced chunk is absent, nothing is stored and no
    /// refcount changes.
    ///
    /// # Errors
    ///
    /// [`StoreError::SnapshotExists`] if the snapshot ID is already stored;
    /// [`StoreError::UnknownChunkRef`] if `refs` names a chunk the store
    /// does not hold.
    pub fn put_snapshot(
        &self,
        snapshot: Ulid,
        blob: &[u8],
        refs: &[ChunkId],
    ) -> Result<(), StoreError> {
        let key = snapshot.to_bytes();

        let txn = self.db.begin_write()?;
        {
            let mut snapshots = txn.open_table(SNAPSHOTS)?;
            if snapshots.get(key.as_slice())?.is_some() {
                // Dropping the uncommitted txn aborts it.
                return Err(StoreError::SnapshotExists(snapshot));
            }
            let mut chunks = txn.open_table(CHUNKS)?;
            for &chunk in refs {
                let entry = {
                    let Some(guard) = chunks.get(chunk.as_bytes().as_slice())? else {
                        return Err(StoreError::UnknownChunkRef { snapshot, chunk });
                    };
                    decode_entry(guard.value())
                };
                let bumped = IndexEntry {
                    chunk_len: entry.chunk_len,
                    refcount: entry.refcount.saturating_add(1),
                };
                chunks.insert(
                    chunk.as_bytes().as_slice(),
                    bumped.to_wire_value().as_slice(),
                )?;
            }
            let mut ref_bytes = Vec::with_capacity(refs.len() * ChunkId::LEN);
            for chunk in refs {
                ref_bytes.extend_from_slice(chunk.as_bytes());
            }
            let mut snapshot_refs = txn.open_table(SNAPSHOT_REFS)?;
            snapshot_refs.insert(key.as_slice(), ref_bytes.as_slice())?;
            snapshots.insert(key.as_slice(), blob)?;
        }
        txn.commit()?;
        Ok(())
    }

    /// Stores a plaintext [`Manifest`]: encodes it and records its chunk
    /// references via [`Self::put_snapshot`].
    ///
    /// Test/tooling convenience — the production client sends encrypted
    /// blobs straight to [`Self::put_snapshot`].
    ///
    /// # Errors
    ///
    /// As [`Self::put_snapshot`], plus [`ManifestError`] (via
    /// [`StoreError::Manifest`]) if the manifest cannot be serialized.
    pub fn put_manifest(&self, manifest: &Manifest) -> Result<(), StoreError> {
        let blob = manifest.encode()?;
        let refs: Vec<ChunkId> = manifest.chunk_refs().collect();
        self.put_snapshot(manifest.snapshot_id, &blob, &refs)
    }

    /// Loads and decodes a snapshot manifest stored in plaintext (tests /
    /// tooling; production blobs are encrypted and only the client can
    /// decode them — fetch those with [`Self::get_manifest_blob`]).
    ///
    /// # Errors
    ///
    /// [`StoreError::SnapshotNotFound`] if absent; [`StoreError::Manifest`]
    /// if the stored blob does not decode (e.g. it is encrypted).
    pub fn get_manifest(&self, snapshot: Ulid) -> Result<Manifest, StoreError> {
        Ok(Manifest::decode(&self.get_manifest_blob(snapshot)?)?)
    }

    /// Loads a snapshot's raw manifest blob.
    ///
    /// # Errors
    ///
    /// [`StoreError::SnapshotNotFound`] if absent.
    pub fn get_manifest_blob(&self, snapshot: Ulid) -> Result<Vec<u8>, StoreError> {
        let txn = self.db.begin_read()?;
        let snapshots = txn.open_table(SNAPSHOTS)?;
        let guard = snapshots
            .get(snapshot.to_bytes().as_slice())?
            .ok_or(StoreError::SnapshotNotFound(snapshot))?;
        Ok(guard.value().to_vec())
    }

    /// Lists stored snapshot IDs in ascending (chronological ULID) order.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Index`] if the index cannot be read.
    pub fn list_snapshots(&self) -> Result<Vec<Ulid>, StoreError> {
        let txn = self.db.begin_read()?;
        let snapshots = txn.open_table(SNAPSHOTS)?;
        let mut out = Vec::new();
        for item in snapshots.iter()? {
            let (key, _) = item?;
            let mut bytes = [0u8; 16];
            let raw = key.value();
            if raw.len() == 16 {
                bytes.copy_from_slice(raw);
                out.push(Ulid::from_bytes(bytes));
            }
        }
        Ok(out)
    }

    /// Deletes a snapshot: removes its manifest blob and drops one reference
    /// per declared chunk occurrence (the inverse of [`Self::put_snapshot`]).
    /// References come from the `snapshot_refs` table, never from decoding
    /// the (possibly encrypted) blob. Chunk blobs are left in place even at
    /// refcount 0 — reclaiming them is [`Self::delete_chunk`]'s job (GC,
    /// slice S9).
    ///
    /// # Errors
    ///
    /// [`StoreError::SnapshotNotFound`] if absent.
    pub fn delete_snapshot(&self, snapshot: Ulid) -> Result<(), StoreError> {
        let key = snapshot.to_bytes();
        let txn = self.db.begin_write()?;
        {
            let mut snapshots = txn.open_table(SNAPSHOTS)?;
            if snapshots.remove(key.as_slice())?.is_none() {
                return Err(StoreError::SnapshotNotFound(snapshot));
            }
            let mut snapshot_refs = txn.open_table(SNAPSHOT_REFS)?;
            let ref_bytes = snapshot_refs
                .remove(key.as_slice())?
                .map(|guard| guard.value().to_vec())
                .unwrap_or_default();
            let mut chunks = txn.open_table(CHUNKS)?;
            for chunk_bytes in ref_bytes.chunks_exact(ChunkId::LEN) {
                let mut raw = [0u8; ChunkId::LEN];
                raw.copy_from_slice(chunk_bytes);
                let chunk = ChunkId::from_bytes(raw);
                let entry = {
                    let Some(guard) = chunks.get(chunk.as_bytes().as_slice())? else {
                        // Index inconsistency; the reference is already gone,
                        // nothing to decrement.
                        continue;
                    };
                    decode_entry(guard.value())
                };
                let dropped = IndexEntry {
                    chunk_len: entry.chunk_len,
                    refcount: entry.refcount.saturating_sub(1),
                };
                chunks.insert(
                    chunk.as_bytes().as_slice(),
                    dropped.to_wire_value().as_slice(),
                )?;
            }
        }
        txn.commit()?;
        Ok(())
    }

    /// Lists chunks whose refcount is zero — GC candidates (slice S9 adds
    /// the grace period and concurrency lock on top).
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Index`] if the index cannot be read.
    pub fn zero_ref_chunks(&self) -> Result<Vec<ChunkId>, StoreError> {
        let txn = self.db.begin_read()?;
        let chunks = txn.open_table(CHUNKS)?;
        let mut out = Vec::new();
        for item in chunks.iter()? {
            let (key, value) = item?;
            let raw = key.value();
            if raw.len() == ChunkId::LEN && decode_entry(value.value()).refcount == 0 {
                let mut bytes = [0u8; ChunkId::LEN];
                bytes.copy_from_slice(raw);
                out.push(ChunkId::from_bytes(bytes));
            }
        }
        Ok(out)
    }

    /// Deletes an unreferenced chunk: removes its index entry, then its
    /// object file.
    ///
    /// The index entry is removed (and committed) before the blob is
    /// unlinked, so a crash in between leaves only a harmless orphan blob,
    /// never an index entry pointing at nothing.
    ///
    /// # Errors
    ///
    /// [`StoreError::ChunkNotFound`] if `id` is not indexed;
    /// [`StoreError::StillReferenced`] if its refcount is above zero.
    pub fn delete_chunk(&self, id: ChunkId) -> Result<(), StoreError> {
        let txn = self.db.begin_write()?;
        {
            let mut chunks = txn.open_table(CHUNKS)?;
            let entry = {
                let guard = chunks
                    .get(id.as_bytes().as_slice())?
                    .ok_or(StoreError::ChunkNotFound(id))?;
                decode_entry(guard.value())
            };
            if entry.refcount > 0 {
                return Err(StoreError::StillReferenced {
                    chunk: id,
                    refcount: entry.refcount,
                });
            }
            chunks.remove(id.as_bytes().as_slice())?;
        }
        txn.commit()?;

        let path = self.object_path(&id);
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
            Err(e) => Err(StoreError::io(&path, e)),
        }
    }
}

/// Decodes an [`IndexEntry`] from a redb value slice; a malformed length
/// (impossible unless the database file was tampered with) yields a
/// zeroed entry rather than a panic.
fn decode_entry(raw: &[u8]) -> IndexEntry {
    let mut bytes = [0u8; 16];
    if raw.len() == 16 {
        bytes.copy_from_slice(raw);
    }
    IndexEntry::from_wire_value(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use busyncr_core::manifest::FileEntry;
    use std::io::{Read, Seek, SeekFrom};

    fn open_store(dir: &Path) -> ChunkStore {
        ChunkStore::open(dir.join("store")).unwrap()
    }

    fn manifest_for(snapshot_id: Ulid, files: Vec<FileEntry>) -> Manifest {
        Manifest {
            snapshot_id,
            created_at: 1_700_000_000,
            files,
        }
    }

    fn file_entry(path: &str, chunks: Vec<ChunkId>, size: u64) -> FileEntry {
        FileEntry {
            path: path.into(),
            size,
            mtime_secs: 1_699_999_999,
            mtime_nanos: 42,
            mode: 0o100644,
            chunks,
        }
    }

    #[test]
    fn put_get_roundtrip_and_dedup() {
        let dir = tempfile::tempdir().unwrap();
        let store = open_store(dir.path());
        let data = b"the quick brown fox".repeat(1000);
        let id = ChunkId::of(&data);

        assert!(store.put_chunk(id, &data).unwrap(), "first put stores");
        assert_eq!(store.get_chunk(id).unwrap(), data);
        assert!(store.has_chunk(id).unwrap());

        // Second put of identical content is a dedup no-op.
        assert!(!store.put_chunk(id, &data).unwrap());
        let entry = store.chunk_entry(id).unwrap().unwrap();
        assert_eq!(entry.chunk_len, data.len() as u64);
        assert_eq!(entry.refcount, 0, "puts alone take no references");

        // CAS layout: objects/<first2hex>/<hex>.
        let hex = id.to_string();
        let blob_path = store.root().join("objects").join(&hex[..2]).join(&hex);
        assert!(blob_path.is_file(), "blob at {}", blob_path.display());
    }

    #[test]
    fn get_missing_chunk_is_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let store = open_store(dir.path());
        let id = ChunkId::of(b"never stored");
        assert!(!store.has_chunk(id).unwrap());
        assert!(matches!(
            store.get_chunk(id),
            Err(StoreError::ChunkNotFound(missing)) if missing == id
        ));
    }

    #[test]
    fn put_accepts_opaque_blob_under_plaintext_address() {
        // Since S7 the uploaded bytes are ciphertext: they do NOT hash to
        // the chunk ID (which hashes the plaintext, PRD §3.3/§3.4). The
        // store must accept and round-trip them bit-exact anyway.
        let dir = tempfile::tempdir().unwrap();
        let store = open_store(dir.path());
        let id = ChunkId::of(b"the plaintext the client chunked");
        let ciphertext = b"utterly unrelated opaque bytes".to_vec();
        assert_ne!(ChunkId::of(&ciphertext), id);

        assert!(store.put_chunk(id, &ciphertext).unwrap());
        assert_eq!(store.get_chunk(id).unwrap(), ciphertext);
        assert_eq!(
            store.chunk_entry(id).unwrap().unwrap().chunk_len,
            ciphertext.len() as u64
        );
    }

    #[test]
    fn fr9_corrupt_blob_detected_on_read() {
        let dir = tempfile::tempdir().unwrap();
        let store = open_store(dir.path());
        let data = vec![7u8; 4096];
        let id = ChunkId::of(&data);
        store.put_chunk(id, &data).unwrap();

        // Flip one byte of the blob body in the stored object file, directly
        // on disk (offset past the 32-byte integrity header).
        let hex = id.to_string();
        let blob_path = store.root().join("objects").join(&hex[..2]).join(&hex);
        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&blob_path)
            .unwrap();
        let mut byte = [0u8; 1];
        file.seek(SeekFrom::Start(100)).unwrap();
        file.read_exact(&mut byte).unwrap();
        byte[0] ^= 0xFF;
        file.seek(SeekFrom::Start(100)).unwrap();
        file.write_all(&byte).unwrap();
        drop(file);

        // The corruption must surface as a typed IntegrityError naming the
        // chunk — never as silently wrong data (FR9).
        let err = store.get_chunk(id).unwrap_err();
        match err {
            StoreError::Integrity(IntegrityError::HashMismatch { chunk, actual }) => {
                assert_eq!(chunk, id, "error must name the corrupt chunk");
                assert_ne!(actual, id);
            }
            other => panic!("expected HashMismatch, got {other:?}"),
        }
    }

    #[test]
    fn fr9_truncated_blob_detected_on_read() {
        let dir = tempfile::tempdir().unwrap();
        let store = open_store(dir.path());
        let data = vec![9u8; 4096];
        let id = ChunkId::of(&data);
        store.put_chunk(id, &data).unwrap();

        let hex = id.to_string();
        let blob_path = store.root().join("objects").join(&hex[..2]).join(&hex);
        let file = fs::OpenOptions::new().write(true).open(&blob_path).unwrap();
        file.set_len(1000).unwrap();
        drop(file);

        // Object file = 32-byte header + blob, so a 1000-byte file leaves a
        // 968-byte body against the indexed 4096.
        let err = store.get_chunk(id).unwrap_err();
        assert!(matches!(
            err,
            StoreError::Integrity(IntegrityError::LengthMismatch {
                chunk,
                expected: 4096,
                actual: 968,
            }) if chunk == id
        ));

        // Truncation below even the header is still a typed integrity error.
        let file = fs::OpenOptions::new().write(true).open(&blob_path).unwrap();
        file.set_len(10).unwrap();
        drop(file);
        assert!(matches!(
            store.get_chunk(id).unwrap_err(),
            StoreError::Integrity(IntegrityError::LengthMismatch {
                expected: 4096,
                actual: 0,
                ..
            })
        ));
    }

    #[test]
    fn fr9_missing_blob_detected_on_read() {
        let dir = tempfile::tempdir().unwrap();
        let store = open_store(dir.path());
        let data = b"soon to vanish".to_vec();
        let id = ChunkId::of(&data);
        store.put_chunk(id, &data).unwrap();

        let hex = id.to_string();
        fs::remove_file(store.root().join("objects").join(&hex[..2]).join(&hex)).unwrap();

        assert!(matches!(
            store.get_chunk(id),
            Err(StoreError::Integrity(IntegrityError::MissingBlob { chunk })) if chunk == id
        ));
    }

    #[test]
    fn manifest_roundtrip_refcounts_and_listing() {
        let dir = tempfile::tempdir().unwrap();
        let store = open_store(dir.path());
        let a = b"chunk a".to_vec();
        let b = b"chunk b".to_vec();
        let (id_a, id_b) = (ChunkId::of(&a), ChunkId::of(&b));
        store.put_chunk(id_a, &a).unwrap();
        store.put_chunk(id_b, &b).unwrap();

        // `a` is referenced twice (two files), `b` once.
        let snap = Ulid::from_parts(1_700_000_000_000, 7);
        let manifest = manifest_for(
            snap,
            vec![
                file_entry("x/first.bin", vec![id_a, id_b], (a.len() + b.len()) as u64),
                file_entry("y/second.bin", vec![id_a], a.len() as u64),
            ],
        );
        store.put_manifest(&manifest).unwrap();

        assert_eq!(store.get_manifest(snap).unwrap(), manifest);
        assert_eq!(store.list_snapshots().unwrap(), vec![snap]);
        assert_eq!(store.chunk_entry(id_a).unwrap().unwrap().refcount, 2);
        assert_eq!(store.chunk_entry(id_b).unwrap().unwrap().refcount, 1);
        assert!(store.zero_ref_chunks().unwrap().is_empty());
    }

    #[test]
    fn opaque_snapshot_blob_roundtrip_refcounts_and_delete_without_decoding() {
        // S7: manifests arrive encrypted. The store must take references
        // from the declared list, return the blob byte-exact, and be able to
        // delete the snapshot (decrementing refcounts) without ever decoding
        // the blob.
        let dir = tempfile::tempdir().unwrap();
        let store = open_store(dir.path());
        let a = b"chunk a".to_vec();
        let b = b"chunk b".to_vec();
        let (id_a, id_b) = (ChunkId::of(&a), ChunkId::of(&b));
        store.put_chunk(id_a, &a).unwrap();
        store.put_chunk(id_b, &b).unwrap();

        let snap = Ulid::from_parts(5, 5);
        let opaque = b"\xde\xad\xbe\xef definitely not a decodable manifest".to_vec();
        // id_a referenced twice, duplicates must both count.
        store
            .put_snapshot(snap, &opaque, &[id_a, id_b, id_a])
            .unwrap();

        assert_eq!(store.get_manifest_blob(snap).unwrap(), opaque);
        assert!(
            matches!(store.get_manifest(snap), Err(StoreError::Manifest(_))),
            "an opaque blob must not decode as a manifest"
        );
        assert_eq!(store.chunk_entry(id_a).unwrap().unwrap().refcount, 2);
        assert_eq!(store.chunk_entry(id_b).unwrap().unwrap().refcount, 1);

        store.delete_snapshot(snap).unwrap();
        assert_eq!(store.chunk_entry(id_a).unwrap().unwrap().refcount, 0);
        assert_eq!(store.chunk_entry(id_b).unwrap().unwrap().refcount, 0);
        assert!(store.list_snapshots().unwrap().is_empty());
    }

    #[test]
    fn put_manifest_with_unknown_chunk_is_rejected_and_rolled_back() {
        let dir = tempfile::tempdir().unwrap();
        let store = open_store(dir.path());
        let known = b"known chunk".to_vec();
        let id_known = ChunkId::of(&known);
        let id_ghost = ChunkId::of(b"never uploaded");
        store.put_chunk(id_known, &known).unwrap();

        let snap = Ulid::from_parts(1, 1);
        let manifest = manifest_for(snap, vec![file_entry("f", vec![id_known, id_ghost], 100)]);
        let err = store.put_manifest(&manifest).unwrap_err();
        assert!(matches!(
            err,
            StoreError::UnknownChunkRef { snapshot, chunk }
                if snapshot == snap && chunk == id_ghost
        ));

        // Nothing stored, no refcount leaked (the transaction rolled back
        // even though id_known had already been incremented within it).
        assert!(store.list_snapshots().unwrap().is_empty());
        assert_eq!(store.chunk_entry(id_known).unwrap().unwrap().refcount, 0);
        assert!(matches!(
            store.get_manifest(snap),
            Err(StoreError::SnapshotNotFound(s)) if s == snap
        ));
    }

    #[test]
    fn put_manifest_rejects_duplicate_snapshot_id() {
        let dir = tempfile::tempdir().unwrap();
        let store = open_store(dir.path());
        let data = b"payload".to_vec();
        let id = ChunkId::of(&data);
        store.put_chunk(id, &data).unwrap();

        let snap = Ulid::from_parts(2, 2);
        let manifest = manifest_for(snap, vec![file_entry("f", vec![id], data.len() as u64)]);
        store.put_manifest(&manifest).unwrap();
        assert!(matches!(
            store.put_manifest(&manifest),
            Err(StoreError::SnapshotExists(s)) if s == snap
        ));
        // Refcount must not have been double-bumped by the failed attempt.
        assert_eq!(store.chunk_entry(id).unwrap().unwrap().refcount, 1);
    }

    #[test]
    fn delete_snapshot_decrements_refcounts_and_gc_reclaims() {
        let dir = tempfile::tempdir().unwrap();
        let store = open_store(dir.path());
        let shared = b"shared across snapshots".to_vec();
        let solo = b"only in snapshot two".to_vec();
        let (id_shared, id_solo) = (ChunkId::of(&shared), ChunkId::of(&solo));
        store.put_chunk(id_shared, &shared).unwrap();
        store.put_chunk(id_solo, &solo).unwrap();

        let snap1 = Ulid::from_parts(10, 1);
        let snap2 = Ulid::from_parts(20, 2);
        store
            .put_manifest(&manifest_for(
                snap1,
                vec![file_entry("a", vec![id_shared], shared.len() as u64)],
            ))
            .unwrap();
        store
            .put_manifest(&manifest_for(
                snap2,
                vec![file_entry(
                    "b",
                    vec![id_shared, id_solo],
                    (shared.len() + solo.len()) as u64,
                )],
            ))
            .unwrap();
        assert_eq!(store.chunk_entry(id_shared).unwrap().unwrap().refcount, 2);
        assert_eq!(store.list_snapshots().unwrap(), vec![snap1, snap2]);

        // A referenced chunk must refuse deletion.
        assert!(matches!(
            store.delete_chunk(id_solo),
            Err(StoreError::StillReferenced { chunk, refcount: 1 }) if chunk == id_solo
        ));

        // Prune snapshot 2: solo chunk drops to zero refs, shared stays live.
        store.delete_snapshot(snap2).unwrap();
        assert_eq!(store.list_snapshots().unwrap(), vec![snap1]);
        assert_eq!(store.chunk_entry(id_shared).unwrap().unwrap().refcount, 1);
        assert_eq!(store.zero_ref_chunks().unwrap(), vec![id_solo]);

        // GC the zero-ref chunk: index entry and blob file both go away.
        let hex = id_solo.to_string();
        let blob_path = store.root().join("objects").join(&hex[..2]).join(&hex);
        assert!(blob_path.is_file());
        store.delete_chunk(id_solo).unwrap();
        assert!(!store.has_chunk(id_solo).unwrap());
        assert!(!blob_path.exists(), "blob must be reclaimed");

        // The surviving snapshot still reads back fine.
        assert_eq!(store.get_chunk(id_shared).unwrap(), shared);
        assert!(matches!(
            store.delete_snapshot(snap2),
            Err(StoreError::SnapshotNotFound(s)) if s == snap2
        ));
    }

    #[test]
    fn crash_safety_leftover_tmp_files_are_ignored_and_cleaned() {
        let dir = tempfile::tempdir().unwrap();
        let store = open_store(dir.path());
        let data = b"survivor chunk".to_vec();
        let id = ChunkId::of(&data);
        store.put_chunk(id, &data).unwrap();

        // Simulate a crash mid-write: stray tmp files in an existing shard
        // and in a fresh one.
        let hex = id.to_string();
        let shard = store.root().join("objects").join(&hex[..2]);
        let stray1 = shard.join(format!("{TMP_PREFIX}deadbeef"));
        fs::write(&stray1, b"partial garbage").unwrap();
        let other_shard = store.root().join("objects").join("zz");
        fs::create_dir_all(&other_shard).unwrap();
        let stray2 = other_shard.join(format!("{TMP_PREFIX}cafef00d"));
        fs::write(&stray2, b"more garbage").unwrap();
        drop(store);

        // Reopen: tmp leftovers are swept, real data is untouched.
        let store = open_store(dir.path());
        assert!(!stray1.exists(), "tmp file in shard must be cleaned");
        assert!(!stray2.exists(), "tmp file in other shard must be cleaned");
        assert_eq!(store.get_chunk(id).unwrap(), data);
        assert!(
            !store.has_chunk(ChunkId::of(b"partial garbage")).unwrap(),
            "tmp leftovers must never be visible as chunks"
        );
    }

    #[test]
    fn store_persists_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let data = b"durable bytes".to_vec();
        let id = ChunkId::of(&data);
        let snap = Ulid::from_parts(30, 3);
        {
            let store = open_store(dir.path());
            store.put_chunk(id, &data).unwrap();
            store
                .put_manifest(&manifest_for(
                    snap,
                    vec![file_entry("keep/me.txt", vec![id], data.len() as u64)],
                ))
                .unwrap();
        }
        let store = open_store(dir.path());
        assert_eq!(store.get_chunk(id).unwrap(), data);
        assert_eq!(store.list_snapshots().unwrap(), vec![snap]);
        let manifest = store.get_manifest(snap).unwrap();
        assert_eq!(manifest.files[0].path, "keep/me.txt");
        assert_eq!(store.chunk_entry(id).unwrap().unwrap().refcount, 1);
    }
}
