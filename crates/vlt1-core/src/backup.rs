// Copyright Nixort & Itan Winter <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 or later.

//! Consistent encrypted VLT/1 `SQLite` snapshots and verified offline restore.
//!
//! Plain filesystem copying of a live WAL database is intentionally not a
//! supported backup mechanism. VLT/1 uses the `SQLite` online backup API and
//! stores a checksum manifest next to the resulting immutable snapshot.

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use rusqlite::{Connection, DatabaseName, OpenFlags, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{error::Result, format::VaultId, VaultError};

const BACKUP_FORMAT: &str = "VLT/1 encrypted SQLite backup v1";

/// Non-secret integrity metadata stored beside a VLT/1 encrypted backup.
///
/// The public type name deliberately retains the `Backup` prefix so callers can
/// distinguish it from the encrypted object Manifest without importing this module.
#[allow(clippy::module_name_repetitions)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BackupManifest {
    format: String,
    vault_id: String,
    database_sha256: String,
    database_bytes: u64,
}

impl BackupManifest {
    /// Returns the VLT/1 backup format marker.
    #[must_use]
    pub fn format(&self) -> &str {
        &self.format
    }

    /// Returns the lowercase hexadecimal VLT/1 vault identifier.
    #[must_use]
    pub fn vault_id(&self) -> &str {
        &self.vault_id
    }

    /// Returns the lowercase hexadecimal SHA-256 of the backup database.
    #[must_use]
    pub fn database_sha256(&self) -> &str {
        &self.database_sha256
    }

    /// Returns the exact backup database file length.
    #[must_use]
    pub const fn database_bytes(&self) -> u64 {
        self.database_bytes
    }

    /// Reads and validates a non-secret VLT/1 backup manifest.
    ///
    /// # Errors
    ///
    /// Returns an error when JSON is malformed or required fields do not obey
    /// VLT/1 fixed-width format constraints.
    pub fn read_from(path: impl AsRef<Path>) -> Result<Self> {
        let bytes = fs::read(path).map_err(|_| VaultError::Storage)?;
        let manifest: Self = serde_json::from_slice(&bytes)
            .map_err(|_| VaultError::invalid_format("backup manifest JSON"))?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// Verifies manifest format, SHA-256, byte length, and `SQLite` structure.
    ///
    /// # Errors
    ///
    /// Returns an error when the backup does not match its manifest or fails
    /// read-only database structural integrity checks.
    pub fn verify_backup(&self, backup_path: impl AsRef<Path>) -> Result<()> {
        self.validate()?;
        let backup_path = backup_path.as_ref();
        let (sha256, bytes) = checksum_file(backup_path)?;
        if bytes != self.database_bytes || sha256 != self.database_sha256 {
            return Err(VaultError::Authentication);
        }
        let snapshot_vault_id = verify_snapshot_database(backup_path)?;
        if snapshot_vault_id.to_hex() != self.vault_id {
            return Err(VaultError::Invariant("backup manifest vault binding"));
        }
        Ok(())
    }

    fn from_snapshot(vault_id: VaultId, path: &Path) -> Result<Self> {
        let (database_sha256, database_bytes) = checksum_file(path)?;
        Ok(Self {
            format: BACKUP_FORMAT.to_owned(),
            vault_id: vault_id.to_hex(),
            database_sha256,
            database_bytes,
        })
    }

    fn write_to(&self, path: &Path) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(self).map_err(|_| VaultError::Storage)?;
        write_new_file(path, &bytes)
    }

    fn validate(&self) -> Result<()> {
        if self.format != BACKUP_FORMAT
            || !is_lower_hex(&self.vault_id, 16)
            || !is_lower_hex(&self.database_sha256, 32)
        {
            return Err(VaultError::invalid_format("backup manifest fields"));
        }
        Ok(())
    }
}

/// Creates a consistent online `SQLite` snapshot and writes a sidecar manifest.
///
/// # Errors
///
/// Returns an error when the destination already exists, the online backup API
/// fails, or the generated snapshot does not pass read-only integrity checks.
pub(crate) fn create_snapshot(
    connection: &Connection,
    vault_id: VaultId,
    destination: &Path,
) -> Result<BackupManifest> {
    ensure_new_destination(destination)?;
    let temporary = temporary_path(destination);
    remove_if_exists(&temporary)?;
    connection
        .backup(DatabaseName::Main, &temporary, None)
        .map_err(|_| VaultError::Storage)?;
    sync_file(&temporary)?;
    let snapshot_vault_id = verify_snapshot_database(&temporary)?;
    if snapshot_vault_id != vault_id {
        return Err(VaultError::Invariant("backup vault ID binding"));
    }
    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))
        .map_err(|_| VaultError::Storage)?;
    fs::rename(&temporary, destination).map_err(|_| VaultError::Storage)?;
    sync_parent(destination)?;

    let manifest = BackupManifest::from_snapshot(vault_id, destination)?;
    let manifest_path = manifest_path(destination);
    ensure_new_destination(&manifest_path)?;
    manifest.write_to(&manifest_path)?;
    Ok(manifest)
}

/// Verifies a source snapshot and restores it to a new database destination.
///
/// # Errors
///
/// Returns an error when the source manifest/database is invalid, the output
/// exists, or the restored `SQLite` database fails integrity checks.
pub(crate) fn restore_snapshot(
    backup: &Path,
    manifest: &BackupManifest,
    destination: &Path,
) -> Result<()> {
    manifest.verify_backup(backup)?;
    ensure_new_destination(destination)?;
    let temporary = temporary_path(destination);
    remove_if_exists(&temporary)?;
    let source = Connection::open_with_flags(
        backup,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| VaultError::Storage)?;
    source
        .backup(DatabaseName::Main, &temporary, None)
        .map_err(|_| VaultError::Storage)?;
    sync_file(&temporary)?;
    verify_snapshot_database(&temporary)?;
    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))
        .map_err(|_| VaultError::Storage)?;
    fs::rename(&temporary, destination).map_err(|_| VaultError::Storage)?;
    sync_parent(destination)
}

/// Returns the manifest path paired with one encrypted `SQLite` snapshot.
#[must_use]
pub fn manifest_path(backup: impl AsRef<Path>) -> PathBuf {
    PathBuf::from(format!("{}.vlt1-backup.json", backup.as_ref().display()))
}

fn verify_snapshot_database(path: &Path) -> Result<VaultId> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| VaultError::Storage)?;
    let integrity: String = connection
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .map_err(|_| VaultError::Storage)?;
    if integrity != "ok" {
        return Err(VaultError::Invariant("backup SQLite integrity_check"));
    }
    let foreign_key_violation: Option<i64> = connection
        .query_row("PRAGMA foreign_key_check", [], |row| row.get(0))
        .optional()
        .map_err(|_| VaultError::Storage)?;
    if foreign_key_violation.is_some() {
        return Err(VaultError::Invariant("backup SQLite foreign-key check"));
    }
    let vault_id: Vec<u8> = connection
        .query_row(
            "SELECT vault_id FROM vault_meta WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .map_err(|_| VaultError::Storage)?;
    VaultId::from_slice(&vault_id)
}

fn checksum_file(path: &Path) -> Result<(String, u64)> {
    let mut file = File::open(path).map_err(|_| VaultError::Storage)?;
    let mut digest = Sha256::new();
    let mut bytes = 0u64;
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|_| VaultError::Storage)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
        bytes = bytes
            .checked_add(u64::try_from(read).map_err(|_| VaultError::Storage)?)
            .ok_or(VaultError::Invariant("backup size exceeds u64"))?;
    }
    Ok((hex_encode(&digest.finalize()), bytes))
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| VaultError::Storage)?;
    file.write_all(bytes).map_err(|_| VaultError::Storage)?;
    file.sync_all().map_err(|_| VaultError::Storage)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|_| VaultError::Storage)?;
    sync_parent(path)
}

fn ensure_new_destination(path: &Path) -> Result<()> {
    let Some(parent) = path.parent() else {
        return Err(VaultError::InvalidInput("backup destination path"));
    };
    if path.exists() || !parent.is_dir() {
        return Err(VaultError::InvalidInput("backup destination path"));
    }
    Ok(())
}

fn temporary_path(destination: &Path) -> PathBuf {
    PathBuf::from(format!(
        "{}.tmp.{}",
        destination.display(),
        std::process::id()
    ))
}

fn remove_if_exists(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(VaultError::Storage),
    }
}

fn sync_file(path: &Path) -> Result<()> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|_| VaultError::Storage)
}

fn sync_parent(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .ok_or(VaultError::InvalidInput("backup destination path"))?;
    File::open(parent)
        .and_then(|file| file.sync_all())
        .map_err(|_| VaultError::Storage)
}

fn hex_encode(value: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn is_lower_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes * 2
        && value
            .bytes()
            .all(|item| item.is_ascii_hexdigit() && !item.is_ascii_uppercase())
}
