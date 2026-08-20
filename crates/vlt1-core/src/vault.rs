// Copyright Nixort & Itan Winter <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 or later.

//! Capability-scoped VLT/1 operations.

use std::{
    io::{Read, Write},
    path::Path,
};

use zeroize::{Zeroize, Zeroizing};

use crate::{
    cde::{decode_manifest, encode_manifest},
    crypto::{
        chunk_aad, derive_kek, derive_manifest_key, generate_dek, generate_root_key, manifest_aad,
        open, open_root_key, seal, seal_root_key, wrapped_dek_aad, ChunkDigestBuilder, KdfParams,
    },
    error::{Result, VaultError},
    format::{EncryptedChunk, Manifest, ObjectId, VaultId, VersionId, FORMAT_VERSION},
    storage::{Storage, StoredVersion},
    witness::{WitnessProvider, WitnessRequest},
};

/// Default VLT/1 plaintext chunk size.
pub const DEFAULT_CHUNK_SIZE: usize = 4 * 1024 * 1024;
/// Maximum number of chunks encrypted under one version DEK.
pub const MAX_CHUNKS_PER_VERSION: u32 = 1 << 24;

/// Observable lifecycle state of a VLT/1 instance.
///
/// The `VaultStatus` name remains explicit in the root public API.
#[allow(clippy::module_name_repetitions)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VaultStatus {
    /// The Root Key is unavailable and secret operations are rejected.
    Locked,
    /// The Root Key is held only in process memory for authorized operations.
    Unlocked,
}

/// A local VLT/1 vault with an explicit locked/unlocked lifecycle.
pub struct Vault {
    storage: Storage,
    envelope: crate::crypto::RootEnvelope,
    root_key: Option<Zeroizing<[u8; 32]>>,
}

struct PreparedVersion {
    stored_version: StoredVersion,
    chunks: Vec<EncryptedChunk>,
}

impl Vault {
    /// Initializes a fresh vault database with a CSPRNG Root Key.
    ///
    /// # Errors
    ///
    /// Returns an error when the passphrase is empty or the `SQLite` backend
    /// cannot create and initialize the vault database.
    pub fn create(path: impl AsRef<Path>, passphrase: &str) -> Result<Self> {
        validate_passphrase(passphrase)?;
        let vault_id = VaultId::random();
        let root_key = generate_root_key();
        let envelope = seal_root_key(passphrase, vault_id, &root_key, KdfParams::interactive())?;
        let storage = Storage::create(path.as_ref(), &envelope)?;
        Ok(Self {
            storage,
            envelope,
            root_key: Some(root_key),
        })
    }

    /// Opens an existing vault in the `Locked` state.
    ///
    /// # Errors
    ///
    /// Returns an error when the database cannot be opened or its Root Key
    /// envelope does not satisfy the VLT/1 format contract.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let storage = Storage::open(path.as_ref())?;
        storage.startup_integrity_check()?;
        let envelope = storage.root_envelope()?;
        Ok(Self {
            storage,
            envelope,
            root_key: None,
        })
    }

    /// Unlocks the vault by decrypting its Root Key envelope.
    ///
    /// # Errors
    ///
    /// Returns an error when the passphrase is empty or does not authenticate
    /// the stored Root Key envelope.
    pub fn unlock(&mut self, passphrase: &str) -> Result<()> {
        validate_passphrase(passphrase)?;
        let root_key = open_root_key(passphrase, &self.envelope)?;
        self.root_key = Some(root_key);
        Ok(())
    }

    /// Clears the in-memory Root Key and returns to `Locked` state.
    pub fn lock(&mut self) {
        if let Some(mut root_key) = self.root_key.take() {
            root_key.zeroize();
        }
    }

    /// Returns the current lifecycle state.
    #[must_use]
    pub const fn status(&self) -> VaultStatus {
        if self.root_key.is_some() {
            VaultStatus::Unlocked
        } else {
            VaultStatus::Locked
        }
    }

    /// Returns the immutable vault identifier.
    #[must_use]
    pub const fn vault_id(&self) -> VaultId {
        self.envelope.vault_id
    }

    /// Publishes a new immutable version and makes it active for `object_id`.
    ///
    /// # Errors
    ///
    /// Returns an error when the vault is locked, an input exceeds the nonce
    /// budget, cryptographic processing fails or publication cannot commit.
    pub fn put(&mut self, object_id: ObjectId, plaintext: &[u8]) -> Result<VersionId> {
        self.put_with_chunk_size(object_id, plaintext, DEFAULT_CHUNK_SIZE)
    }

    /// Publishes a version with an explicit chunk size for tests and benchmarking.
    ///
    /// # Errors
    ///
    /// Returns the same classes of errors as [`Self::put`], plus an error for a
    /// zero or out-of-range chunk size.
    pub fn put_with_chunk_size(
        &mut self,
        object_id: ObjectId,
        plaintext: &[u8],
        chunk_size: usize,
    ) -> Result<VersionId> {
        let result = self.put_inner(object_id, plaintext, chunk_size);
        self.lock_after_failure(&result);
        result
    }

    /// Encrypts and publishes one immutable version from a streaming plaintext reader.
    ///
    /// The reader is consumed in bounded plaintext chunks. Encrypted chunks are
    /// retained only by the `SQLite` transaction, so input size does not determine
    /// the vault process's peak plaintext allocation.
    ///
    /// # Errors
    ///
    /// Returns an error when the vault is locked, the reader fails, an input
    /// exceeds the chunk policy, cryptographic processing fails, or publication
    /// cannot commit.
    pub fn put_from_reader<R: Read>(
        &mut self,
        object_id: ObjectId,
        reader: &mut R,
    ) -> Result<VersionId> {
        self.put_from_reader_with_chunk_size(object_id, reader, DEFAULT_CHUNK_SIZE)
    }

    /// Streaming `put` variant with an explicit chunk size for tests and benchmarks.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::put_from_reader`], plus an error for an
    /// invalid chunk size.
    pub fn put_from_reader_with_chunk_size<R: Read>(
        &mut self,
        object_id: ObjectId,
        reader: &mut R,
        chunk_size: usize,
    ) -> Result<VersionId> {
        let result = self.put_from_reader_inner(object_id, reader, chunk_size);
        self.lock_after_failure(&result);
        result
    }

    /// Publishes a new immutable version only after a witness signs its commitment.
    ///
    /// The receipt is verified locally and committed in the same `SQLite`
    /// transaction as the version data and active pointer. The supplied provider
    /// must be independently operated for the receipt to provide rollback
    /// evidence beyond this local machine.
    ///
    /// # Errors
    ///
    /// Returns an error when the vault is locked, version preparation fails, the
    /// provider cannot issue a valid receipt, or the atomic publication fails.
    pub fn put_with_witness<P: WitnessProvider>(
        &mut self,
        object_id: ObjectId,
        plaintext: &[u8],
        provider: &mut P,
    ) -> Result<VersionId> {
        let result = self.put_with_witness_inner(object_id, plaintext, provider);
        self.lock_after_failure(&result);
        result
    }

    /// Verifies every active immutable version without returning its plaintext.
    ///
    /// # Errors
    ///
    /// Returns an error when the vault is locked or a version's metadata,
    /// receipt, chunks, or AEAD authentication checks fail.
    pub fn verify_active_objects(&mut self) -> Result<u64> {
        let result = self.verify_active_objects_inner();
        self.lock_after_failure(&result);
        result
    }

    /// Reconciles all crash-persisted witness publications before serving data.
    ///
    /// Each pending version is issued again with the original expected epoch.
    /// The external witness either returns the same idempotent receipt or
    /// rejects contradictory remote state; on success the local active pointer
    /// and receipt are finalized atomically.
    ///
    /// # Errors
    ///
    /// Returns an error when the vault is locked, the witness is unavailable,
    /// or a pending version contradicts independently persisted witness state.
    pub fn recover_pending_witness_publications<P: WitnessProvider>(
        &mut self,
        provider: &mut P,
    ) -> Result<u64> {
        let result = self.recover_pending_witness_publications_inner(provider);
        self.lock_after_failure(&result);
        result
    }

    /// Verifies active encrypted data and its fresh independent witness heads.
    ///
    /// Each active version must have a locally stored receipt and the external
    /// witness head, bound to a new random challenge, must exactly equal it.
    ///
    /// # Errors
    ///
    /// Returns an error when the vault is locked, a stored receipt is missing,
    /// the provider is unavailable, or remote witness state contradicts local
    /// authenticated state. A conflict locks the vault fail closed.
    pub fn verify_active_objects_with_witness<P: WitnessProvider>(
        &mut self,
        provider: &mut P,
    ) -> Result<u64> {
        let result = self.verify_active_objects_with_witness_inner(provider);
        self.lock_after_failure(&result);
        result
    }

    /// Creates a consistent encrypted online backup and a checksum sidecar.
    ///
    /// This operation never decrypts object plaintext and is safe while the
    /// daemon serializes vault mutations through its existing state mutex.
    ///
    /// # Errors
    ///
    /// Returns an error when the destination or sidecar already exists, the
    /// online `SQLite` backup API fails, or the produced snapshot fails an
    /// independent read-only integrity check.
    pub fn backup_to(
        &self,
        destination: impl AsRef<std::path::Path>,
    ) -> Result<crate::backup::BackupManifest> {
        self.storage
            .create_backup(self.envelope.vault_id, destination.as_ref())
    }

    /// Restores a verified encrypted snapshot to a new inactive vault path.
    ///
    /// The destination must not exist; replacement of a daemon-owned live
    /// database is deliberately outside this API and requires an operator to
    /// stop the daemon first.
    ///
    /// # Errors
    ///
    /// Returns an error when the manifest does not authenticate the source
    /// snapshot, the destination already exists, or restore integrity checks
    /// fail.
    pub fn restore_from_backup(
        backup: impl AsRef<std::path::Path>,
        manifest: &crate::backup::BackupManifest,
        destination: impl AsRef<std::path::Path>,
    ) -> Result<()> {
        Storage::restore_backup(backup.as_ref(), manifest, destination.as_ref())
    }

    /// Runs a `SQLite` FULL WAL checkpoint while the vault is unlocked.
    ///
    /// # Errors
    ///
    /// Returns an error when the vault is locked or `SQLite` cannot complete the
    /// requested checkpoint.
    pub fn full_checkpoint(&mut self) -> Result<()> {
        let result = (|| {
            let _ = self.require_root_key()?;
            self.storage.full_checkpoint()
        })();
        self.lock_after_failure(&result);
        result
    }

    /// Returns the plaintext of the active immutable version after full verification.
    ///
    /// # Errors
    ///
    /// Returns an error when the vault is locked, the object is absent or any
    /// key, Manifest, metadata or chunk verification step fails.
    pub fn get(&mut self, object_id: ObjectId) -> Result<Vec<u8>> {
        let result = self.get_inner(object_id);
        self.lock_after_failure(&result);
        result
    }

    /// Verifies and writes the active immutable version to a plaintext sink.
    ///
    /// The caller receives data only after the encrypted chunk layout and digest
    /// have been verified. A sink can still contain a verified prefix if a later
    /// chunk fails authentication, so file callers should write to a temporary
    /// path and publish it only after this operation succeeds.
    ///
    /// # Errors
    ///
    /// Returns an error when the vault is locked, the object is absent, a reader
    /// record fails verification, or the output sink cannot be written.
    pub fn get_to_writer<W: Write>(&mut self, object_id: ObjectId, writer: &mut W) -> Result<()> {
        let result = self.get_to_writer_inner(object_id, writer);
        self.lock_after_failure(&result);
        result
    }

    /// Changes the passphrase while retaining the existing random Root Key.
    ///
    /// # Errors
    ///
    /// Returns an error when either passphrase is invalid, the current
    /// passphrase cannot open the Root Key envelope or the new envelope cannot
    /// be committed.
    pub fn rotate_passphrase(&mut self, current: &str, replacement: &str) -> Result<()> {
        validate_passphrase(replacement)?;
        let result = (|| {
            let mut root_key = open_root_key(current, &self.envelope)?;
            let new_envelope = seal_root_key(
                replacement,
                self.envelope.vault_id,
                &root_key,
                KdfParams::interactive(),
            )?;
            self.storage.replace_root_envelope(&new_envelope)?;
            root_key.zeroize();
            self.envelope = new_envelope;
            self.root_key = None;
            Ok(())
        })();
        self.lock_after_failure(&result);
        result
    }

    fn put_inner(
        &mut self,
        object_id: ObjectId,
        plaintext: &[u8],
        chunk_size: usize,
    ) -> Result<VersionId> {
        let prepared = self.prepare_version(object_id, plaintext, chunk_size)?;
        let version_id = prepared.stored_version.version_id;
        self.storage
            .publish(&prepared.stored_version, &prepared.chunks)?;
        Ok(version_id)
    }

    fn put_from_reader_inner<R: Read>(
        &mut self,
        object_id: ObjectId,
        reader: &mut R,
        chunk_size: usize,
    ) -> Result<VersionId> {
        if chunk_size == 0 {
            return Err(VaultError::InvalidInput("invalid chunk size"));
        }
        let chunk_size_u32 = u32::try_from(chunk_size)
            .map_err(|_| VaultError::InvalidInput("invalid chunk size"))?;
        let root_key = Zeroizing::new(*self.require_root_key()?);
        let version_id = VersionId::random();
        let mut data_key = generate_dek();
        let result = (|| {
            let mut wrapping_key = derive_kek(&root_key, self.envelope.vault_id)?;
            let wrapped_dek = seal(
                &wrapping_key[..],
                &wrapped_dek_aad(self.envelope.vault_id, object_id, version_id),
                &data_key[..],
            )?;
            wrapping_key.zeroize();

            let mut publication = self.storage.begin_streaming_publication(
                object_id,
                version_id,
                &wrapped_dek,
                chunk_size_u32,
            )?;
            let mut buffer = Zeroizing::new(vec![0u8; chunk_size]);
            let mut digest = ChunkDigestBuilder::new();
            let mut chunk_count = 0u32;
            let mut plaintext_len = 0u64;
            loop {
                let read = read_next_chunk(reader, &mut buffer[..])?;
                if read == 0 {
                    break;
                }
                if chunk_count >= MAX_CHUNKS_PER_VERSION {
                    buffer[..read].zeroize();
                    return Err(VaultError::InvalidInput("nonce budget exceeded"));
                }
                let chunk_len =
                    u32::try_from(read).map_err(|_| VaultError::InvalidInput("chunk length"))?;
                let aad = chunk_aad(
                    self.envelope.vault_id,
                    object_id,
                    version_id,
                    chunk_count,
                    chunk_len,
                );
                let record = seal(&data_key[..], &aad, &buffer[..read])?;
                buffer[..read].zeroize();
                digest.update(chunk_count, &record);
                publication.append_chunk(
                    &EncryptedChunk {
                        index: chunk_count,
                        record,
                    },
                    chunk_len,
                )?;
                plaintext_len = plaintext_len
                    .checked_add(u64::from(chunk_len))
                    .ok_or(VaultError::InvalidInput("plaintext length exceeds u64"))?;
                chunk_count = chunk_count
                    .checked_add(1)
                    .ok_or(VaultError::InvalidInput("too many chunks"))?;
            }
            buffer.zeroize();

            let manifest = Manifest {
                format_version: FORMAT_VERSION,
                object_id,
                version_id,
                plaintext_len,
                chunk_size: chunk_size_u32,
                chunk_count,
                chunk_digest: digest.finalize(),
            };
            let manifest_bytes = encode_manifest(&manifest);
            let mut manifest_key = derive_manifest_key(&data_key, version_id)?;
            let manifest = seal(
                &manifest_key[..],
                &manifest_aad(self.envelope.vault_id, object_id, version_id),
                &manifest_bytes,
            )?;
            manifest_key.zeroize();
            publication.finish(&manifest, chunk_count)?;
            Ok(version_id)
        })();
        data_key.zeroize();
        result
    }

    fn put_with_witness_inner<P: WitnessProvider>(
        &mut self,
        object_id: ObjectId,
        plaintext: &[u8],
        provider: &mut P,
    ) -> Result<VersionId> {
        let prepared = self.prepare_version(object_id, plaintext, DEFAULT_CHUNK_SIZE)?;
        let version_id = prepared.stored_version.version_id;
        let request = WitnessRequest::new(
            self.envelope.vault_id,
            object_id,
            version_id,
            &prepared.stored_version.manifest,
        );
        let expected_epoch = self
            .storage
            .active_receipt(object_id)?
            .map_or(0, |receipt| receipt.witness_epoch());
        self.storage.stage_witness_publication(
            &prepared.stored_version,
            &prepared.chunks,
            expected_epoch,
        )?;
        let receipt = provider.issue_receipt(&request, expected_epoch)?;
        receipt.verify_request(&request)?;
        self.storage
            .finalize_witness_publication(&prepared.stored_version, &receipt)?;
        Ok(version_id)
    }

    fn recover_pending_witness_publications_inner<P: WitnessProvider>(
        &mut self,
        provider: &mut P,
    ) -> Result<u64> {
        let _ = self.require_root_key()?;
        let pending = self.storage.pending_witness_publications()?;
        for (version, expected_epoch) in &pending {
            let request = WitnessRequest::new(
                self.envelope.vault_id,
                version.object_id,
                version.version_id,
                &version.manifest,
            );
            let receipt = provider.issue_receipt(&request, *expected_epoch)?;
            receipt.verify_request(&request)?;
            self.storage
                .finalize_witness_publication(version, &receipt)?;
        }
        u64::try_from(pending.len())
            .map_err(|_| VaultError::Invariant("pending witness publication count exceeds u64"))
    }

    fn verify_active_objects_inner(&mut self) -> Result<u64> {
        let _ = self.require_root_key()?;
        let object_ids = self.storage.active_object_ids()?;
        for object_id in &object_ids {
            let mut sink = std::io::sink();
            self.get_to_writer_inner(*object_id, &mut sink)?;
        }
        u64::try_from(object_ids.len())
            .map_err(|_| VaultError::Invariant("active object count exceeds u64"))
    }

    fn verify_active_objects_with_witness_inner<P: WitnessProvider>(
        &mut self,
        provider: &mut P,
    ) -> Result<u64> {
        let _ = self.require_root_key()?;
        let object_ids = self.storage.active_object_ids()?;
        for object_id in &object_ids {
            let receipt = self
                .storage
                .active_receipt(*object_id)?
                .ok_or(VaultError::WitnessConflict)?;
            let challenge = crate::witness::random_witness_challenge();
            let head = provider.object_head(self.envelope.vault_id, *object_id, challenge)?;
            if !head.present()
                || head.version_id() != Some(receipt.version_id())
                || head.witness_epoch() != receipt.witness_epoch()
                || head.commitment() != Some(receipt.commitment())
                || head.public_key() != receipt.public_key()
            {
                return Err(VaultError::WitnessConflict);
            }
            let mut sink = std::io::sink();
            self.get_to_writer_inner(*object_id, &mut sink)?;
        }
        u64::try_from(object_ids.len())
            .map_err(|_| VaultError::Invariant("active object count exceeds u64"))
    }

    fn prepare_version(
        &mut self,
        object_id: ObjectId,
        plaintext: &[u8],
        chunk_size: usize,
    ) -> Result<PreparedVersion> {
        let root_key = self.require_root_key()?;
        if chunk_size == 0 {
            return Err(VaultError::InvalidInput("invalid chunk size"));
        }
        let chunk_size_u32 = u32::try_from(chunk_size)
            .map_err(|_| VaultError::InvalidInput("invalid chunk size"))?;
        let plaintext_len = u64::try_from(plaintext.len())
            .map_err(|_| VaultError::InvalidInput("plaintext length exceeds u64"))?;
        let chunk_count_usize = if plaintext.is_empty() {
            0
        } else {
            plaintext.len().div_ceil(chunk_size)
        };
        let chunk_count = u32::try_from(chunk_count_usize)
            .map_err(|_| VaultError::InvalidInput("too many chunks"))?;
        if chunk_count > MAX_CHUNKS_PER_VERSION {
            return Err(VaultError::InvalidInput("nonce budget exceeded"));
        }

        let version_id = VersionId::random();
        let mut data_key = generate_dek();
        let mut chunks = Vec::with_capacity(chunk_count_usize);
        let mut digest = ChunkDigestBuilder::new();
        for (offset, chunk) in plaintext.chunks(chunk_size).enumerate() {
            let index =
                u32::try_from(offset).map_err(|_| VaultError::InvalidInput("chunk index"))?;
            let chunk_len =
                u32::try_from(chunk.len()).map_err(|_| VaultError::InvalidInput("chunk length"))?;
            let aad = chunk_aad(
                self.envelope.vault_id,
                object_id,
                version_id,
                index,
                chunk_len,
            );
            let record = seal(&data_key[..], &aad, chunk)?;
            digest.update(index, &record);
            chunks.push(EncryptedChunk { index, record });
        }
        let manifest = Manifest {
            format_version: FORMAT_VERSION,
            object_id,
            version_id,
            plaintext_len,
            chunk_size: chunk_size_u32,
            chunk_count,
            chunk_digest: digest.finalize(),
        };
        let manifest_bytes = encode_manifest(&manifest);
        let mut manifest_key = derive_manifest_key(&data_key, version_id)?;
        let manifest = seal(
            &manifest_key[..],
            &manifest_aad(self.envelope.vault_id, object_id, version_id),
            &manifest_bytes,
        )?;
        manifest_key.zeroize();

        let mut wrapping_key = derive_kek(root_key, self.envelope.vault_id)?;
        let wrapped_dek = seal(
            &wrapping_key[..],
            &wrapped_dek_aad(self.envelope.vault_id, object_id, version_id),
            &data_key[..],
        )?;
        wrapping_key.zeroize();
        data_key.zeroize();

        Ok(PreparedVersion {
            stored_version: StoredVersion {
                object_id,
                version_id,
                wrapped_dek,
                manifest,
                plaintext_len,
                chunk_size: chunk_size_u32,
                chunk_count,
            },
            chunks,
        })
    }

    fn get_inner(&mut self, object_id: ObjectId) -> Result<Vec<u8>> {
        let mut plaintext = Vec::new();
        self.get_to_writer_inner(object_id, &mut plaintext)?;
        Ok(plaintext)
    }

    fn get_to_writer_inner<W: Write>(&mut self, object_id: ObjectId, writer: &mut W) -> Result<()> {
        let root_key = self.require_root_key()?;
        let version = self.storage.active_version(object_id)?;
        if version.object_id != object_id {
            return Err(VaultError::Invariant("object pointer binding"));
        }
        let mut wrapping_key = derive_kek(root_key, self.envelope.vault_id)?;
        let mut data_key_bytes = open(
            &wrapping_key[..],
            &wrapped_dek_aad(self.envelope.vault_id, object_id, version.version_id),
            &version.wrapped_dek,
        )?;
        wrapping_key.zeroize();
        let data_key: [u8; 32] = data_key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| VaultError::invalid_format("wrapped DEK length"))?;
        data_key_bytes.zeroize();
        let mut data_key = Zeroizing::new(data_key);
        let result = (|| {
            let mut manifest_key = derive_manifest_key(&data_key, version.version_id)?;
            let mut manifest_bytes = open(
                &manifest_key[..],
                &manifest_aad(self.envelope.vault_id, object_id, version.version_id),
                &version.manifest,
            )?;
            manifest_key.zeroize();
            let manifest = decode_manifest(&manifest_bytes)?;
            manifest_bytes.zeroize();
            validate_manifest_binding(&manifest, &version)?;
            if let Some(receipt) = self.storage.receipt(version.version_id)? {
                let request = WitnessRequest::new(
                    self.envelope.vault_id,
                    object_id,
                    version.version_id,
                    &version.manifest,
                );
                receipt.verify_request(&request)?;
            }

            let mut digest = ChunkDigestBuilder::new();
            let mut expected_index = 0u32;
            self.storage.visit_chunks(version.version_id, |chunk| {
                if chunk.index != expected_index {
                    return Err(VaultError::Invariant("stored chunk indices"));
                }
                digest.update(chunk.index, &chunk.record);
                expected_index = expected_index
                    .checked_add(1)
                    .ok_or(VaultError::Invariant("stored chunk count"))?;
                Ok(())
            })?;
            if expected_index != manifest.chunk_count {
                return Err(VaultError::Invariant("stored chunk count"));
            }
            if digest.finalize() != manifest.chunk_digest {
                return Err(VaultError::Authentication);
            }

            let mut written_len = 0u64;
            self.storage.visit_chunks(version.version_id, |chunk| {
                let expected_chunk_len = expected_plaintext_chunk_len(&manifest, chunk.index)?;
                let aad = chunk_aad(
                    self.envelope.vault_id,
                    object_id,
                    version.version_id,
                    chunk.index,
                    expected_chunk_len,
                );
                let mut part = open(&data_key[..], &aad, &chunk.record)?;
                if part.len() != expected_chunk_len as usize {
                    part.zeroize();
                    return Err(VaultError::invalid_format("authenticated chunk length"));
                }
                writer.write_all(&part).map_err(|_| VaultError::Storage)?;
                written_len = written_len
                    .checked_add(u64::from(expected_chunk_len))
                    .ok_or(VaultError::Invariant(
                        "plaintext length after chunk assembly",
                    ))?;
                part.zeroize();
                Ok(())
            })?;
            if written_len != manifest.plaintext_len {
                return Err(VaultError::Invariant(
                    "plaintext length after chunk assembly",
                ));
            }
            Ok(())
        })();
        data_key.zeroize();
        result
    }

    fn require_root_key(&self) -> Result<&[u8; 32]> {
        self.root_key.as_deref().ok_or(VaultError::Locked)
    }

    fn lock_after_failure<T>(&mut self, result: &Result<T>) {
        if let Err(error) = result {
            if error.requires_lock() {
                self.lock();
            }
        }
    }
}

fn read_next_chunk<R: Read>(reader: &mut R, buffer: &mut [u8]) -> Result<usize> {
    let mut filled = 0;
    while filled < buffer.len() {
        match reader.read(&mut buffer[filled..]) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => {
                buffer[..filled].zeroize();
                return Err(VaultError::Storage);
            }
        }
    }
    Ok(filled)
}

fn validate_passphrase(passphrase: &str) -> Result<()> {
    if passphrase.is_empty() {
        return Err(VaultError::InvalidInput("passphrase must not be empty"));
    }
    Ok(())
}

fn validate_manifest_binding(manifest: &Manifest, stored: &StoredVersion) -> Result<()> {
    if manifest.format_version != FORMAT_VERSION
        || manifest.object_id != stored.object_id
        || manifest.version_id != stored.version_id
        || manifest.plaintext_len != stored.plaintext_len
        || manifest.chunk_size != stored.chunk_size
        || manifest.chunk_count != stored.chunk_count
    {
        return Err(VaultError::Invariant(
            "Manifest and SQLite metadata binding",
        ));
    }
    if manifest.chunk_size == 0 || manifest.chunk_count > MAX_CHUNKS_PER_VERSION {
        return Err(VaultError::invalid_format("Manifest chunk policy"));
    }
    Ok(())
}

fn expected_plaintext_chunk_len(manifest: &Manifest, index: u32) -> Result<u32> {
    if index >= manifest.chunk_count {
        return Err(VaultError::invalid_format("chunk index outside Manifest"));
    }
    if index + 1 < manifest.chunk_count {
        return Ok(manifest.chunk_size);
    }
    let prefix = u64::from(manifest.chunk_size) * u64::from(manifest.chunk_count - 1);
    let tail = manifest
        .plaintext_len
        .checked_sub(prefix)
        .ok_or(VaultError::invalid_format("Manifest plaintext length"))?;
    u32::try_from(tail).map_err(|_| VaultError::invalid_format("final chunk length"))
}
