// Copyright Nixort & Itan Winter <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 or later.

//! Regression tests for VLT/1 lifecycle and tamper-detection invariants.

use std::io::Read;

use rusqlite::Connection;
use tempfile::tempdir;
use vlt1_core::{ObjectId, Vault, VaultError, VaultStatus};

fn create_vault() -> (tempfile::TempDir, std::path::PathBuf, Vault) {
    let directory = tempdir().expect("temporary test directory");
    let path = directory.path().join("vault.sqlite");
    let vault = Vault::create(&path, "correct horse battery staple").expect("vault initialization");
    (directory, path, vault)
}

struct FragmentedReader {
    bytes: Vec<u8>,
    offset: usize,
    maximum_read: usize,
}

impl FragmentedReader {
    fn new(bytes: Vec<u8>, maximum_read: usize) -> Self {
        Self {
            bytes,
            offset: 0,
            maximum_read,
        }
    }
}

impl Read for FragmentedReader {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if self.offset == self.bytes.len() {
            return Ok(0);
        }
        let read = self
            .maximum_read
            .min(buffer.len())
            .min(self.bytes.len() - self.offset);
        buffer[..read].copy_from_slice(&self.bytes[self.offset..self.offset + read]);
        self.offset += read;
        Ok(read)
    }
}

#[test]
fn immutable_versions_round_trip_and_advance_the_active_pointer() {
    let (_directory, _path, mut vault) = create_vault();
    let object = ObjectId::random();

    let first_version = vault.put(object, b"first value").expect("first write");
    assert_eq!(vault.get(object).expect("first read"), b"first value");

    let second_version = vault.put(object, b"second value").expect("second write");
    assert_ne!(first_version, second_version);
    assert_eq!(vault.get(object).expect("active read"), b"second value");
}

#[test]
fn streaming_round_trip_handles_fragmented_readers_and_bounded_chunks() {
    let (_directory, _path, mut vault) = create_vault();
    let object = ObjectId::random();
    let payload: Vec<u8> = (0usize..(32 * 1024 + 37))
        .map(|index| u8::try_from(index % 251).expect("bounded byte fixture"))
        .collect();
    let mut reader = FragmentedReader::new(payload.clone(), 97);

    vault
        .put_from_reader_with_chunk_size(object, &mut reader, 1024)
        .expect("streaming write");
    let mut recovered = Vec::new();
    vault
        .get_to_writer(object, &mut recovered)
        .expect("streaming read");

    assert_eq!(recovered, payload);
}

#[test]
fn streaming_read_writes_nothing_before_digest_verification() {
    let (_directory, path, mut vault) = create_vault();
    let object = ObjectId::random();
    vault
        .put_from_reader_with_chunk_size(object, &mut std::io::Cursor::new(vec![7; 4096]), 1024)
        .expect("streaming write");
    drop(vault);

    let connection = Connection::open(&path).expect("open SQLite for tamper fixture");
    connection
        .execute(
            "UPDATE chunks SET ciphertext = zeroblob(length(ciphertext)) WHERE chunk_index = 0",
            [],
        )
        .expect("tamper first ciphertext");
    drop(connection);

    let mut reopened = Vault::open(path).expect("reopen tampered vault");
    reopened
        .unlock("correct horse battery staple")
        .expect("unlock before streaming verification");
    let mut output = Vec::new();
    assert!(reopened.get_to_writer(object, &mut output).is_err());
    assert!(output.is_empty());
    assert_eq!(reopened.status(), VaultStatus::Locked);
}

#[test]
fn wrong_passphrase_does_not_unlock_the_vault() {
    let (_directory, path, _vault) = create_vault();
    let mut reopened = Vault::open(path).expect("reopen vault");

    assert!(reopened.unlock("wrong passphrase").is_err());
    assert_eq!(reopened.status(), VaultStatus::Locked);
}

#[test]
fn passphrase_rotation_preserves_ciphertexts_and_changes_unlock_secret() {
    let (_directory, path, mut vault) = create_vault();
    let object = ObjectId::random();
    vault
        .put(object, b"rotation-safe plaintext")
        .expect("write");

    vault
        .rotate_passphrase("correct horse battery staple", "new passphrase")
        .expect("rotate passphrase");
    assert_eq!(vault.status(), VaultStatus::Locked);

    let mut reopened = Vault::open(path).expect("reopen vault");
    assert!(reopened.unlock("correct horse battery staple").is_err());
    reopened
        .unlock("new passphrase")
        .expect("new passphrase unlock");
    assert_eq!(
        reopened.get(object).expect("read after rotation"),
        b"rotation-safe plaintext"
    );
}

#[test]
fn tampered_chunk_fails_authentication_and_locks_the_instance() {
    let (_directory, path, mut vault) = create_vault();
    let object = ObjectId::random();
    vault.put(object, b"authenticated payload").expect("write");
    drop(vault);

    let connection = Connection::open(&path).expect("open SQLite for tamper fixture");
    connection
        .execute(
            "UPDATE chunks SET ciphertext = zeroblob(length(ciphertext)) WHERE chunk_index = 0",
            [],
        )
        .expect("tamper first ciphertext");
    drop(connection);

    let mut reopened = Vault::open(path).expect("reopen tampered vault");
    reopened
        .unlock("correct horse battery staple")
        .expect("unlock before verification");
    assert!(reopened.get(object).is_err());
    assert_eq!(reopened.status(), VaultStatus::Locked);
}

#[test]
fn witness_receipt_is_persisted_verified_and_tamper_locks_the_vault() {
    let (_directory, path, mut vault) = create_vault();
    let object = ObjectId::random();
    let mut provider = vlt1_core::InMemoryTestProvider::from_seed([9; 32]);

    vault
        .put_with_witness(object, b"witness-bound payload", &mut provider)
        .expect("witness-backed write");
    assert_eq!(
        vault.verify_active_objects().expect("verification sweep"),
        1
    );
    vault.full_checkpoint().expect("full checkpoint");
    drop(vault);

    let mut reopened = Vault::open(&path).expect("reopen witness-backed vault");
    reopened
        .unlock("correct horse battery staple")
        .expect("unlock witness-backed vault");
    assert_eq!(
        reopened.get(object).expect("receipt-verified read"),
        b"witness-bound payload"
    );
    drop(reopened);

    let connection = Connection::open(&path).expect("open SQLite for receipt tamper fixture");
    connection
        .execute("UPDATE freshness_receipts SET signature = zeroblob(64)", [])
        .expect("tamper receipt signature");
    drop(connection);

    let mut tampered = Vault::open(path).expect("reopen receipt-tampered vault");
    tampered
        .unlock("correct horse battery staple")
        .expect("unlock before receipt verification");
    assert!(tampered.get(object).is_err());
    assert_eq!(tampered.status(), VaultStatus::Locked);
}

#[test]
fn startup_integrity_scan_rejects_a_dangling_active_version_pointer() {
    let (_directory, path, mut vault) = create_vault();
    let object = ObjectId::random();
    vault
        .put(object, b"recovery fixture")
        .expect("write fixture");
    drop(vault);

    let connection = Connection::open(&path).expect("open SQLite for pointer tamper fixture");
    connection
        .execute(
            "UPDATE objects SET active_version_id = randomblob(16) WHERE object_id = ?1",
            [object.as_bytes().as_slice()],
        )
        .expect("tamper active pointer");
    drop(connection);

    assert!(Vault::open(path).is_err());
}

#[test]
fn startup_rejects_excessive_persisted_kdf_parameters() {
    let (_directory, path, vault) = create_vault();
    drop(vault);

    let connection = Connection::open(&path).expect("open SQLite for KDF tamper fixture");
    connection
        .execute("UPDATE vault_meta SET argon_memory_kib = 262145", [])
        .expect("tamper persisted Argon2id memory cost");
    drop(connection);

    assert!(matches!(
        Vault::open(path),
        Err(VaultError::InvalidFormat("Argon2id KDF parameter policy"))
    ));
}

#[cfg(feature = "fault-injection")]
#[test]
fn storage_full_fault_rejects_publication_and_locks_the_vault() {
    let (_directory, _path, mut vault) = create_vault();

    vlt1_core::inject_next_publication_failure();
    assert!(vault
        .put(ObjectId::random(), b"storage-full fixture")
        .is_err());
    assert_eq!(vault.status(), VaultStatus::Locked);
}

#[cfg(feature = "fault-injection")]
#[test]
fn witness_receipt_crash_window_is_reconciled_idempotently_after_reopen() {
    let (_directory, path, mut vault) = create_vault();
    let object = ObjectId::random();
    let mut provider = vlt1_core::InMemoryTestProvider::from_seed([12; 32]);

    vlt1_core::inject_next_witness_finalization_failure();
    assert!(vault
        .put_with_witness(object, b"pending witness publication", &mut provider)
        .is_err());
    assert_eq!(vault.status(), VaultStatus::Locked);
    drop(vault);

    let mut reopened = Vault::open(path).expect("open pending witness vault");
    reopened
        .unlock("correct horse battery staple")
        .expect("unlock pending witness vault");
    assert_eq!(
        reopened
            .recover_pending_witness_publications(&mut provider)
            .expect("idempotent recovery"),
        1
    );
    assert_eq!(
        reopened.get(object).expect("recovered active data"),
        b"pending witness publication"
    );
    assert_eq!(
        reopened
            .verify_active_objects_with_witness(&mut provider)
            .expect("fresh recovered witness head"),
        1
    );
}

#[test]
fn online_backup_restores_verified_encrypted_vault_and_rejects_tampering() {
    let (directory, _path, mut vault) = create_vault();
    let object = ObjectId::random();
    vault
        .put(object, b"backup recovery plaintext")
        .expect("write fixture");
    let backup = directory.path().join("vault-backup.sqlite");
    let manifest = vault.backup_to(&backup).expect("online backup");
    assert!(backup.exists());
    assert!(vlt1_core::manifest_path(&backup).exists());
    manifest
        .verify_backup(&backup)
        .expect("backup verification");

    let restored = directory.path().join("restored.sqlite");
    Vault::restore_from_backup(&backup, &manifest, &restored).expect("verified restore");
    let mut reopened = Vault::open(&restored).expect("open restored vault");
    reopened
        .unlock("correct horse battery staple")
        .expect("unlock restored vault");
    assert_eq!(
        reopened.get(object).expect("restored object"),
        b"backup recovery plaintext"
    );

    let tampered_backup = directory.path().join("tampered-backup.sqlite");
    std::fs::copy(&backup, &tampered_backup).expect("copy backup tamper fixture");
    let connection = Connection::open(&tampered_backup).expect("open backup tamper fixture");
    connection
        .execute(
            "UPDATE vault_meta SET root_ciphertext = zeroblob(length(root_ciphertext))",
            [],
        )
        .expect("tamper backup");
    drop(connection);
    let rejected_restore = directory.path().join("rejected.sqlite");
    assert!(Vault::restore_from_backup(&tampered_backup, &manifest, &rejected_restore).is_err());
    assert!(!rejected_restore.exists());
}
