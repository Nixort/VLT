// Copyright Nixort & Itan Winter <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 or later.

//! `SQLite` persistence for the VLT/1 immutable-version model.

use std::path::Path;

#[cfg(feature = "fault-injection")]
use std::cell::Cell;

use rusqlite::{params, Connection, ErrorCode, OptionalExtension, Transaction};

use crate::{
    backup::{create_snapshot, restore_snapshot, BackupManifest},
    crypto::{KdfParams, RootEnvelope},
    error::{Result, VaultError},
    format::{EncryptedChunk, ObjectId, SealedRecord, VersionId, FORMAT_VERSION},
    witness::WitnessReceipt,
};

/// Database row material required to verify and open an immutable version.
#[derive(Clone, Debug)]
pub(crate) struct StoredVersion {
    pub object_id: ObjectId,
    pub version_id: VersionId,
    pub wrapped_dek: SealedRecord,
    pub manifest: SealedRecord,
    pub plaintext_len: u64,
    pub chunk_size: u32,
    pub chunk_count: u32,
}

#[cfg(feature = "fault-injection")]
thread_local! {
    static FAIL_NEXT_PUBLICATION: Cell<bool> = const { Cell::new(false) };
    static FAIL_NEXT_WITNESS_FINALIZATION: Cell<bool> = const { Cell::new(false) };
}

/// Arms a one-shot deterministic storage-full simulation for the next publish on this test thread.
#[cfg(feature = "fault-injection")]
pub(crate) fn inject_next_publication_failure() {
    FAIL_NEXT_PUBLICATION.with(|failure| failure.set(true));
}

/// Arms a one-shot local-finalization failure for this test thread after a remote witness receipt.
#[cfg(feature = "fault-injection")]
pub(crate) fn inject_next_witness_finalization_failure() {
    FAIL_NEXT_WITNESS_FINALIZATION.with(|failure| failure.set(true));
}

/// `SQLite` backend owning a single local connection.
pub(crate) struct Storage {
    connection: Connection,
}

/// An uncommitted immutable version receiving encrypted chunks incrementally.
pub(crate) struct StreamingPublication<'connection> {
    transaction: Transaction<'connection>,
    object_id: ObjectId,
    version_id: VersionId,
    next_chunk_index: u32,
    plaintext_len: u64,
}

impl Storage {
    /// Creates and initializes a new `SQLite` database at `path`.
    pub(crate) fn create(path: &Path, envelope: &RootEnvelope) -> Result<Self> {
        let storage = Self::open_connection(path)?;
        storage.initialize_schema()?;
        storage.insert_envelope(envelope)?;
        Ok(storage)
    }

    /// Opens an existing VLT/1 database.
    pub(crate) fn open(path: &Path) -> Result<Self> {
        let storage = Self::open_connection(path)?;
        storage.initialize_schema()?;
        Ok(storage)
    }

    /// Reads the sole Root Key envelope from the database.
    pub(crate) fn root_envelope(&self) -> Result<RootEnvelope> {
        let row = self
            .connection
            .query_row(
                "SELECT format_version, vault_id, root_salt, argon_memory_kib, argon_iterations, \
                        argon_lanes, root_nonce, root_ciphertext FROM vault_meta WHERE singleton = 1",
                [],
                |row| {
                    Ok((
                        row.get::<_, u32>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, u32>(3)?,
                        row.get::<_, u32>(4)?,
                        row.get::<_, u32>(5)?,
                        row.get::<_, Vec<u8>>(6)?,
                        row.get::<_, Vec<u8>>(7)?,
                    ))
                },
            )
            .map_err(|error| map_read_error(&error))?;
        let (format_version, vault_id, salt, memory_kib, iterations, lanes, nonce, ciphertext) =
            row;
        if format_version != FORMAT_VERSION {
            return Err(VaultError::invalid_format(
                "unsupported vault format version",
            ));
        }
        let params = KdfParams {
            memory_kib,
            iterations,
            lanes,
        };
        params.validate_persisted()?;
        Ok(RootEnvelope {
            vault_id: crate::format::VaultId::from_slice(&vault_id)?,
            salt: bytes16(&salt)?,
            params,
            record: SealedRecord {
                nonce: bytes12(&nonce)?,
                ciphertext,
            },
        })
    }

    /// Replaces the Root Key envelope after a successful passphrase rotation.
    pub(crate) fn replace_root_envelope(&self, envelope: &RootEnvelope) -> Result<()> {
        let changed = self
            .connection
            .execute(
                "UPDATE vault_meta SET root_salt = ?1, argon_memory_kib = ?2, \
                 argon_iterations = ?3, argon_lanes = ?4, root_nonce = ?5, root_ciphertext = ?6 \
                 WHERE singleton = 1 AND vault_id = ?7",
                params![
                    envelope.salt.as_slice(),
                    envelope.params.memory_kib,
                    envelope.params.iterations,
                    envelope.params.lanes,
                    envelope.record.nonce.as_slice(),
                    envelope.record.ciphertext,
                    envelope.vault_id.as_bytes().as_slice(),
                ],
            )
            .map_err(|_| VaultError::Storage)?;
        if changed != 1 {
            return Err(VaultError::Invariant("Root Key envelope replacement"));
        }
        Ok(())
    }

    /// Creates a consistent encrypted `SQLite` online backup snapshot.
    pub(crate) fn create_backup(
        &self,
        vault_id: crate::format::VaultId,
        destination: &Path,
    ) -> Result<BackupManifest> {
        create_snapshot(&self.connection, vault_id, destination)
    }

    /// Restores a verified encrypted snapshot to a new inactive vault path.
    pub(crate) fn restore_backup(
        backup: &Path,
        manifest: &BackupManifest,
        destination: &Path,
    ) -> Result<()> {
        restore_snapshot(backup, manifest, destination)
    }

    /// Publishes an immutable version and advances the active pointer atomically.
    pub(crate) fn publish(
        &mut self,
        version: &StoredVersion,
        chunks: &[EncryptedChunk],
    ) -> Result<()> {
        self.publish_inner(version, chunks, None)
    }

    /// Starts an uncommitted immutable version for incremental encrypted chunks.
    ///
    /// The placeholder row is visible only inside the transaction. Callers must
    /// finish it with an authenticated Manifest before it can become active.
    pub(crate) fn begin_streaming_publication(
        &mut self,
        object_id: ObjectId,
        version_id: VersionId,
        wrapped_dek: &SealedRecord,
        chunk_size: u32,
    ) -> Result<StreamingPublication<'_>> {
        let transaction = self
            .connection
            .transaction()
            .map_err(|_| VaultError::Storage)?;
        Self::insert_streaming_placeholder(
            &transaction,
            object_id,
            version_id,
            wrapped_dek,
            chunk_size,
        )?;
        Ok(StreamingPublication {
            transaction,
            object_id,
            version_id,
            next_chunk_index: 0,
            plaintext_len: 0,
        })
    }

    /// Stages encrypted immutable data before its external witness acknowledgement.
    ///
    /// The active object pointer is not changed. This durable state closes the
    /// crash window between a remote conditional witness receipt and the local
    /// transaction that advances the active pointer.
    pub(crate) fn stage_witness_publication(
        &mut self,
        version: &StoredVersion,
        chunks: &[EncryptedChunk],
        expected_epoch: u64,
    ) -> Result<()> {
        if chunks.len() != version.chunk_count as usize {
            return Err(VaultError::Invariant(
                "chunk count does not match version metadata",
            ));
        }
        let transaction = self
            .connection
            .transaction()
            .map_err(|_| VaultError::Storage)?;
        Self::insert_version(&transaction, version)?;
        for chunk in chunks {
            Self::insert_chunk(&transaction, version.version_id, chunk)?;
        }
        transaction
            .execute(
                "INSERT INTO pending_witness_publications(version_id, expected_epoch) VALUES(?1, ?2)",
                params![version.version_id.as_bytes().as_slice(), expected_epoch],
            )
            .map_err(|_| VaultError::Storage)?;
        transaction.commit().map_err(|_| VaultError::Storage)?;
        Ok(())
    }

    /// Returns staged versions and their required predecessor witness epoch.
    pub(crate) fn pending_witness_publications(&self) -> Result<Vec<(StoredVersion, u64)>> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT version_id, expected_epoch FROM pending_witness_publications \
                 ORDER BY version_id ASC",
            )
            .map_err(|_| VaultError::Storage)?;
        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, u64>(1)?))
            })
            .map_err(|_| VaultError::Storage)?;
        let mut pending = Vec::new();
        for row in rows {
            let (version_id, expected_epoch) = row.map_err(|_| VaultError::Storage)?;
            pending.push((
                self.version(VersionId::from_slice(&version_id)?)?,
                expected_epoch,
            ));
        }
        Ok(pending)
    }

    /// Atomically persists a verified receipt, advances the pointer, and clears staging.
    pub(crate) fn finalize_witness_publication(
        &mut self,
        version: &StoredVersion,
        receipt: &WitnessReceipt,
    ) -> Result<()> {
        #[cfg(feature = "fault-injection")]
        if FAIL_NEXT_WITNESS_FINALIZATION.with(|failure| failure.replace(false)) {
            return Err(VaultError::Storage);
        }
        if receipt.object_id() != version.object_id || receipt.version_id() != version.version_id {
            return Err(VaultError::Invariant("freshness receipt version binding"));
        }
        let transaction = self
            .connection
            .transaction()
            .map_err(|_| VaultError::Storage)?;
        let staged: Option<u64> = transaction
            .query_row(
                "SELECT expected_epoch FROM pending_witness_publications WHERE version_id = ?1",
                params![version.version_id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| VaultError::Storage)?;
        if staged.is_none() {
            return Err(VaultError::Invariant("missing staged witness publication"));
        }
        Self::insert_receipt(&transaction, receipt)?;
        transaction
            .execute(
                "INSERT INTO objects(object_id, active_version_id) VALUES(?1, ?2) \
                 ON CONFLICT(object_id) DO UPDATE SET active_version_id = excluded.active_version_id",
                params![
                    version.object_id.as_bytes().as_slice(),
                    version.version_id.as_bytes().as_slice()
                ],
            )
            .map_err(|_| VaultError::Storage)?;
        transaction
            .execute(
                "DELETE FROM pending_witness_publications WHERE version_id = ?1",
                params![version.version_id.as_bytes().as_slice()],
            )
            .map_err(|_| VaultError::Storage)?;
        transaction.commit().map_err(|_| VaultError::Storage)?;
        Ok(())
    }

    /// Runs `SQLite` structural integrity checks before serving requests.
    ///
    /// This scan intentionally does not decrypt application records; callers
    /// must run an unlocked verification sweep for authenticated content checks.
    pub(crate) fn startup_integrity_check(&self) -> Result<()> {
        let integrity: String = self
            .connection
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))
            .map_err(|_| VaultError::Storage)?;
        if integrity != "ok" {
            return Err(VaultError::Invariant("SQLite integrity_check"));
        }
        let foreign_key_violation: Option<i64> = self
            .connection
            .query_row("PRAGMA foreign_key_check", [], |row| row.get(0))
            .optional()
            .map_err(|_| VaultError::Storage)?;
        if foreign_key_violation.is_some() {
            return Err(VaultError::Invariant("SQLite foreign-key check"));
        }
        let dangling_active_versions: i64 = self
            .connection
            .query_row(
                "SELECT COUNT(*) FROM objects AS objects \
                 LEFT JOIN versions AS versions \
                 ON objects.active_version_id = versions.version_id \
                 WHERE versions.version_id IS NULL OR versions.object_id != objects.object_id",
                [],
                |row| row.get(0),
            )
            .map_err(|_| VaultError::Storage)?;
        if dangling_active_versions != 0 {
            return Err(VaultError::Invariant("active version pointer binding"));
        }
        let dangling_pending_versions: i64 = self
            .connection
            .query_row(
                "SELECT COUNT(*) FROM pending_witness_publications AS pending \
                 LEFT JOIN versions AS versions ON pending.version_id = versions.version_id \
                 WHERE versions.version_id IS NULL",
                [],
                |row| row.get(0),
            )
            .map_err(|_| VaultError::Storage)?;
        if dangling_pending_versions != 0 {
            return Err(VaultError::Invariant("pending witness publication binding"));
        }
        Ok(())
    }

    /// Performs a FULL checkpoint and rejects a busy or incomplete result.
    pub(crate) fn full_checkpoint(&self) -> Result<()> {
        let (busy, _log_frames, _checkpointed_frames): (i64, i64, i64) = self
            .connection
            .query_row("PRAGMA wal_checkpoint(FULL)", [], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .map_err(|_| VaultError::Storage)?;
        if busy != 0 {
            return Err(VaultError::Storage);
        }
        Ok(())
    }

    /// Returns every active object identifier in canonical byte order.
    pub(crate) fn active_object_ids(&self) -> Result<Vec<ObjectId>> {
        let mut statement = self
            .connection
            .prepare("SELECT object_id FROM objects ORDER BY object_id ASC")
            .map_err(|_| VaultError::Storage)?;
        let rows = statement
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .map_err(|_| VaultError::Storage)?;
        let mut identifiers = Vec::new();
        for row in rows {
            identifiers.push(ObjectId::from_slice(
                &row.map_err(|_| VaultError::Storage)?,
            )?);
        }
        Ok(identifiers)
    }

    /// Returns a signature-validated receipt record for one version when present.
    pub(crate) fn receipt(&self, version_id: VersionId) -> Result<Option<WitnessReceipt>> {
        let row = self
            .connection
            .query_row(
                "SELECT vault_id, object_id, version_id, witness_epoch, commitment, \
                        witness_public_key, signature \
                 FROM freshness_receipts WHERE version_id = ?1",
                params![version_id.as_bytes().as_slice()],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, u64>(3)?,
                        row.get::<_, Vec<u8>>(4)?,
                        row.get::<_, Vec<u8>>(5)?,
                        row.get::<_, Vec<u8>>(6)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| VaultError::Storage)?;
        let Some((vault_id, object_id, version_id, epoch, commitment, public_key, signature)) = row
        else {
            return Ok(None);
        };
        WitnessReceipt::new(
            crate::format::VaultId::from_slice(&vault_id)?,
            ObjectId::from_slice(&object_id)?,
            VersionId::from_slice(&version_id)?,
            epoch,
            bytes32(&commitment)?,
            bytes32(&public_key)?,
            bytes64(&signature)?,
        )
        .map(Some)
    }

    /// Returns the receipt bound to an active object when it has one.
    pub(crate) fn active_receipt(&self, object_id: ObjectId) -> Result<Option<WitnessReceipt>> {
        let version = match self.active_version(object_id) {
            Ok(version) => version,
            Err(VaultError::NotFound) => return Ok(None),
            Err(error) => return Err(error),
        };
        self.receipt(version.version_id)
    }

    /// Loads the active version for an object.
    pub(crate) fn active_version(&self, object_id: ObjectId) -> Result<StoredVersion> {
        let version_id = self
            .connection
            .query_row(
                "SELECT active_version_id FROM objects WHERE object_id = ?1",
                params![object_id.as_bytes().as_slice()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(|_| VaultError::Storage)?
            .ok_or(VaultError::NotFound)?;
        self.version(VersionId::from_slice(&version_id)?)
    }

    /// Loads a selected immutable version.
    pub(crate) fn version(&self, version_id: VersionId) -> Result<StoredVersion> {
        let row = self
            .connection
            .query_row(
                "SELECT object_id, version_id, wrapped_dek_nonce, wrapped_dek_ciphertext, \
                        manifest_nonce, manifest_ciphertext, plaintext_len, chunk_size, chunk_count \
                 FROM versions WHERE version_id = ?1",
                params![version_id.as_bytes().as_slice()],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, Vec<u8>>(4)?,
                        row.get::<_, Vec<u8>>(5)?,
                        row.get::<_, u64>(6)?,
                        row.get::<_, u32>(7)?,
                        row.get::<_, u32>(8)?,
                    ))
                },
            )
            .map_err(|error| map_read_error(&error))?;
        let (
            object_id,
            version_id,
            wrapped_nonce,
            wrapped_ciphertext,
            manifest_nonce,
            manifest_ciphertext,
            plaintext_len,
            chunk_size,
            chunk_count,
        ) = row;
        Ok(StoredVersion {
            object_id: ObjectId::from_slice(&object_id)?,
            version_id: VersionId::from_slice(&version_id)?,
            wrapped_dek: SealedRecord {
                nonce: bytes12(&wrapped_nonce)?,
                ciphertext: wrapped_ciphertext,
            },
            manifest: SealedRecord {
                nonce: bytes12(&manifest_nonce)?,
                ciphertext: manifest_ciphertext,
            },
            plaintext_len,
            chunk_size,
            chunk_count,
        })
    }

    /// Visits encrypted chunks in canonical ascending index order without retaining them.
    pub(crate) fn visit_chunks<F>(&self, version_id: VersionId, mut visit: F) -> Result<()>
    where
        F: FnMut(EncryptedChunk) -> Result<()>,
    {
        let mut statement = self
            .connection
            .prepare(
                "SELECT chunk_index, nonce, ciphertext FROM chunks \
                 WHERE version_id = ?1 ORDER BY chunk_index ASC",
            )
            .map_err(|_| VaultError::Storage)?;
        let mut rows = statement
            .query(params![version_id.as_bytes().as_slice()])
            .map_err(|_| VaultError::Storage)?;
        while let Some(row) = rows.next().map_err(|_| VaultError::Storage)? {
            let index = row.get::<_, u32>(0).map_err(|_| VaultError::Storage)?;
            let nonce = row.get::<_, Vec<u8>>(1).map_err(|_| VaultError::Storage)?;
            let ciphertext = row.get::<_, Vec<u8>>(2).map_err(|_| VaultError::Storage)?;
            visit(EncryptedChunk {
                index,
                record: SealedRecord {
                    nonce: bytes12(&nonce)?,
                    ciphertext,
                },
            })?;
        }
        Ok(())
    }

    fn open_connection(path: &Path) -> Result<Self> {
        let connection = Connection::open(path).map_err(|_| VaultError::Storage)?;
        let journal_mode: String = connection
            .query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))
            .map_err(|_| VaultError::Storage)?;
        if !journal_mode.eq_ignore_ascii_case("wal") {
            return Err(VaultError::Storage);
        }
        connection
            .execute_batch(
                "PRAGMA foreign_keys = ON;\
                 PRAGMA synchronous = FULL;\
                 PRAGMA trusted_schema = OFF;",
            )
            .map_err(|_| VaultError::Storage)?;
        Ok(Self { connection })
    }

    fn initialize_schema(&self) -> Result<()> {
        self.connection
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS vault_meta (
                    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                    format_version INTEGER NOT NULL,
                    vault_id BLOB NOT NULL CHECK(length(vault_id) = 16),
                    root_salt BLOB NOT NULL CHECK(length(root_salt) = 16),
                    argon_memory_kib INTEGER NOT NULL,
                    argon_iterations INTEGER NOT NULL,
                    argon_lanes INTEGER NOT NULL,
                    root_nonce BLOB NOT NULL CHECK(length(root_nonce) = 12),
                    root_ciphertext BLOB NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS objects (
                    object_id BLOB PRIMARY KEY CHECK(length(object_id) = 16),
                    active_version_id BLOB NOT NULL CHECK(length(active_version_id) = 16)
                 );
                 CREATE TABLE IF NOT EXISTS versions (
                    version_id BLOB PRIMARY KEY CHECK(length(version_id) = 16),
                    object_id BLOB NOT NULL CHECK(length(object_id) = 16),
                    wrapped_dek_nonce BLOB NOT NULL CHECK(length(wrapped_dek_nonce) = 12),
                    wrapped_dek_ciphertext BLOB NOT NULL,
                    manifest_nonce BLOB NOT NULL CHECK(length(manifest_nonce) = 12),
                    manifest_ciphertext BLOB NOT NULL,
                    plaintext_len INTEGER NOT NULL CHECK(plaintext_len >= 0),
                    chunk_size INTEGER NOT NULL CHECK(chunk_size > 0),
                    chunk_count INTEGER NOT NULL CHECK(chunk_count >= 0)
                 );
                 CREATE INDEX IF NOT EXISTS versions_by_object ON versions(object_id);
                 CREATE TABLE IF NOT EXISTS chunks (
                    version_id BLOB NOT NULL CHECK(length(version_id) = 16),
                    chunk_index INTEGER NOT NULL CHECK(chunk_index >= 0),
                    nonce BLOB NOT NULL CHECK(length(nonce) = 12),
                    ciphertext BLOB NOT NULL,
                    PRIMARY KEY(version_id, chunk_index),
                    UNIQUE(version_id, nonce),
                    FOREIGN KEY(version_id) REFERENCES versions(version_id) ON DELETE RESTRICT
                 );
                 CREATE TABLE IF NOT EXISTS pending_witness_publications (
                    version_id BLOB PRIMARY KEY CHECK(length(version_id) = 16),
                    expected_epoch INTEGER NOT NULL CHECK(expected_epoch >= 0),
                    FOREIGN KEY(version_id) REFERENCES versions(version_id) ON DELETE RESTRICT
                 );
                 CREATE TABLE IF NOT EXISTS freshness_receipts (
                    version_id BLOB PRIMARY KEY CHECK(length(version_id) = 16),
                    vault_id BLOB NOT NULL CHECK(length(vault_id) = 16),
                    object_id BLOB NOT NULL CHECK(length(object_id) = 16),
                    witness_epoch INTEGER NOT NULL CHECK(witness_epoch >= 0),
                    commitment BLOB NOT NULL CHECK(length(commitment) = 32),
                    witness_public_key BLOB NOT NULL CHECK(length(witness_public_key) = 32),
                    signature BLOB NOT NULL CHECK(length(signature) = 64),
                    UNIQUE(witness_public_key, witness_epoch),
                    FOREIGN KEY(version_id) REFERENCES versions(version_id) ON DELETE RESTRICT
                 );",
            )
            .map_err(|_| VaultError::Storage)?;
        Ok(())
    }

    fn insert_envelope(&self, envelope: &RootEnvelope) -> Result<()> {
        self.connection
            .execute(
                "INSERT INTO vault_meta(singleton, format_version, vault_id, root_salt, \
                 argon_memory_kib, argon_iterations, argon_lanes, root_nonce, root_ciphertext) \
                 VALUES(1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    FORMAT_VERSION,
                    envelope.vault_id.as_bytes().as_slice(),
                    envelope.salt.as_slice(),
                    envelope.params.memory_kib,
                    envelope.params.iterations,
                    envelope.params.lanes,
                    envelope.record.nonce.as_slice(),
                    envelope.record.ciphertext,
                ],
            )
            .map_err(|_| VaultError::Storage)?;
        Ok(())
    }

    fn publish_inner(
        &mut self,
        version: &StoredVersion,
        chunks: &[EncryptedChunk],
        receipt: Option<&WitnessReceipt>,
    ) -> Result<()> {
        #[cfg(feature = "fault-injection")]
        if FAIL_NEXT_PUBLICATION.with(|failure| failure.replace(false)) {
            return Err(VaultError::Storage);
        }
        if chunks.len() != version.chunk_count as usize {
            return Err(VaultError::Invariant(
                "chunk count does not match version metadata",
            ));
        }
        let transaction = self
            .connection
            .transaction()
            .map_err(|_| VaultError::Storage)?;
        Self::insert_version(&transaction, version)?;
        for chunk in chunks {
            Self::insert_chunk(&transaction, version.version_id, chunk)?;
        }
        if let Some(receipt) = receipt {
            Self::insert_receipt(&transaction, receipt)?;
        }
        transaction
            .execute(
                "INSERT INTO objects(object_id, active_version_id) VALUES(?1, ?2) \
                 ON CONFLICT(object_id) DO UPDATE SET active_version_id = excluded.active_version_id",
                params![
                    version.object_id.as_bytes().as_slice(),
                    version.version_id.as_bytes().as_slice()
                ],
            )
            .map_err(|_| VaultError::Storage)?;
        transaction.commit().map_err(|_| VaultError::Storage)?;
        Ok(())
    }

    fn insert_streaming_placeholder(
        transaction: &Transaction<'_>,
        object_id: ObjectId,
        version_id: VersionId,
        wrapped_dek: &SealedRecord,
        chunk_size: u32,
    ) -> Result<()> {
        transaction
            .execute(
                "INSERT INTO versions(version_id, object_id, wrapped_dek_nonce, wrapped_dek_ciphertext, \
                 manifest_nonce, manifest_ciphertext, plaintext_len, chunk_size, chunk_count) \
                 VALUES(?1, ?2, ?3, ?4, ?5, ?6, 0, ?7, 0)",
                params![
                    version_id.as_bytes().as_slice(),
                    object_id.as_bytes().as_slice(),
                    wrapped_dek.nonce.as_slice(),
                    wrapped_dek.ciphertext,
                    [0u8; 12].as_slice(),
                    Vec::<u8>::new(),
                    chunk_size,
                ],
            )
            .map_err(|_| VaultError::Storage)?;
        Ok(())
    }

    fn insert_version(transaction: &Transaction<'_>, version: &StoredVersion) -> Result<()> {
        transaction
            .execute(
                "INSERT INTO versions(version_id, object_id, wrapped_dek_nonce, wrapped_dek_ciphertext, \
                 manifest_nonce, manifest_ciphertext, plaintext_len, chunk_size, chunk_count) \
                 VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    version.version_id.as_bytes().as_slice(),
                    version.object_id.as_bytes().as_slice(),
                    version.wrapped_dek.nonce.as_slice(),
                    version.wrapped_dek.ciphertext,
                    version.manifest.nonce.as_slice(),
                    version.manifest.ciphertext,
                    version.plaintext_len,
                    version.chunk_size,
                    version.chunk_count,
                ],
            )
            .map_err(|_| VaultError::Storage)?;
        Ok(())
    }

    fn insert_receipt(transaction: &Transaction<'_>, receipt: &WitnessReceipt) -> Result<()> {
        transaction
            .execute(
                "INSERT INTO freshness_receipts(version_id, vault_id, object_id, witness_epoch, \
                 commitment, witness_public_key, signature) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    receipt.version_id().as_bytes().as_slice(),
                    receipt.vault_id().as_bytes().as_slice(),
                    receipt.object_id().as_bytes().as_slice(),
                    receipt.witness_epoch(),
                    receipt.commitment().as_slice(),
                    receipt.public_key().as_slice(),
                    receipt.signature().as_slice(),
                ],
            )
            .map_err(|_| VaultError::Storage)?;
        Ok(())
    }

    fn insert_chunk(
        transaction: &Transaction<'_>,
        version_id: VersionId,
        chunk: &EncryptedChunk,
    ) -> Result<()> {
        transaction
            .execute(
                "INSERT INTO chunks(version_id, chunk_index, nonce, ciphertext) VALUES(?1, ?2, ?3, ?4)",
                params![
                    version_id.as_bytes().as_slice(),
                    chunk.index,
                    chunk.record.nonce.as_slice(),
                    chunk.record.ciphertext,
                ],
            )
            .map_err(|_| VaultError::Storage)?;
        Ok(())
    }
}

impl StreamingPublication<'_> {
    /// Inserts the next encrypted chunk while preserving canonical index order.
    pub(crate) fn append_chunk(
        &mut self,
        chunk: &EncryptedChunk,
        plaintext_len: u32,
    ) -> Result<()> {
        if chunk.index != self.next_chunk_index {
            return Err(VaultError::Invariant("streamed chunk index"));
        }
        Storage::insert_chunk(&self.transaction, self.version_id, chunk)?;
        self.next_chunk_index = self
            .next_chunk_index
            .checked_add(1)
            .ok_or(VaultError::Invariant("streamed chunk count"))?;
        self.plaintext_len = self
            .plaintext_len
            .checked_add(u64::from(plaintext_len))
            .ok_or(VaultError::Invariant("streamed plaintext length"))?;
        Ok(())
    }

    /// Authenticates the final metadata, advances the active pointer, and commits.
    pub(crate) fn finish(self, manifest: &SealedRecord, chunk_count: u32) -> Result<()> {
        if chunk_count != self.next_chunk_index {
            return Err(VaultError::Invariant("streamed Manifest chunk count"));
        }
        let changed = self
            .transaction
            .execute(
                "UPDATE versions SET manifest_nonce = ?1, manifest_ciphertext = ?2, \
                 plaintext_len = ?3, chunk_count = ?4 WHERE version_id = ?5 AND object_id = ?6",
                params![
                    manifest.nonce.as_slice(),
                    manifest.ciphertext,
                    self.plaintext_len,
                    chunk_count,
                    self.version_id.as_bytes().as_slice(),
                    self.object_id.as_bytes().as_slice(),
                ],
            )
            .map_err(|_| VaultError::Storage)?;
        if changed != 1 {
            return Err(VaultError::Invariant("streamed version finalization"));
        }
        self.transaction
            .execute(
                "INSERT INTO objects(object_id, active_version_id) VALUES(?1, ?2) \
                 ON CONFLICT(object_id) DO UPDATE SET active_version_id = excluded.active_version_id",
                params![
                    self.object_id.as_bytes().as_slice(),
                    self.version_id.as_bytes().as_slice(),
                ],
            )
            .map_err(|_| VaultError::Storage)?;
        self.transaction.commit().map_err(|_| VaultError::Storage)
    }
}

fn bytes12(bytes: &[u8]) -> Result<[u8; 12]> {
    bytes
        .try_into()
        .map_err(|_| VaultError::invalid_format("invalid 96-bit nonce length"))
}

fn bytes16(bytes: &[u8]) -> Result<[u8; 16]> {
    bytes
        .try_into()
        .map_err(|_| VaultError::invalid_format("invalid 128-bit identifier length"))
}

fn bytes32(bytes: &[u8]) -> Result<[u8; 32]> {
    bytes
        .try_into()
        .map_err(|_| VaultError::invalid_format("invalid 256-bit length"))
}

fn bytes64(bytes: &[u8]) -> Result<[u8; 64]> {
    bytes
        .try_into()
        .map_err(|_| VaultError::invalid_format("invalid 512-bit signature length"))
}

fn map_read_error(error: &rusqlite::Error) -> VaultError {
    if let rusqlite::Error::SqliteFailure(code, _) = error {
        if code.code == ErrorCode::DatabaseBusy {
            return VaultError::Storage;
        }
    }
    if matches!(error, rusqlite::Error::QueryReturnedNoRows) {
        VaultError::NotFound
    } else {
        VaultError::Storage
    }
}
