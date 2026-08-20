// Copyright Nixort & Itan Winter <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 or later.
//
// VLT/1 — owner-private persistent state files.

//! Owner-private file enforcement for VLT/1 persistent state.

use std::{fs, os::unix::fs::PermissionsExt, path::Path};

use crate::{Result, VaultError};

/// Restricts a VLT/1 regular state file to its owner.
///
/// The helper refuses symlinks, directories, sockets and other special files so
/// a caller cannot silently harden an unexpected path. Existing regular files
/// are repaired to mode `0600`; callers invoke it after opening or creating
/// VLT/1 `SQLite` state and any companion files.
///
/// # Errors
///
/// Returns an error when `path` cannot be inspected, is not a regular file, or
/// its permissions cannot be restricted to owner read/write access.
pub fn enforce_owner_private_file(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|_| VaultError::Storage)?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(VaultError::InvalidInput("VLT/1 state file type"));
    }
    let mode = metadata.permissions().mode();
    if mode & 0o077 != 0 || mode & 0o600 != 0o600 {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|_| VaultError::Storage)?;
    }
    Ok(())
}

/// Restricts the main database and present SQLite companion files to its owner.
///
/// SQLite can create and remove `-wal` and `-shm` files as connections open and
/// close. The primary database is required; missing companion files are safe.
///
/// # Errors
///
/// Returns an error when the primary database or a present companion is not a
/// regular file or cannot be restricted to owner read/write access.
pub fn enforce_owner_private_sqlite_state(path: &Path) -> Result<()> {
    enforce_owner_private_file(path)?;
    for suffix in ["-wal", "-shm"] {
        let mut companion = path.as_os_str().to_os_string();
        companion.push(suffix);
        enforce_owner_private_optional_file(Path::new(&companion))?;
    }
    Ok(())
}

/// Restricts an optional `SQLite` companion file when it is present.
///
/// The function intentionally treats a missing companion as success because
/// SQLite can create and remove WAL/SHM files as connections open and close.
///
/// # Errors
///
/// Returns an error when a present companion is not a regular file or cannot
/// be restricted to owner read/write access.
pub fn enforce_owner_private_optional_file(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => enforce_owner_private_file(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(VaultError::Storage),
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt};

    use tempfile::tempdir;

    use super::{
        enforce_owner_private_file, enforce_owner_private_optional_file,
        enforce_owner_private_sqlite_state,
    };

    #[test]
    fn regular_file_permissions_are_repaired_to_owner_private() {
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("state.sqlite");
        fs::write(&path, b"state").expect("state fixture");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
            .expect("permissive fixture mode");

        enforce_owner_private_file(&path).expect("private file enforcement");
        let mode = fs::metadata(&path)
            .expect("private metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn missing_optional_sqlite_companion_is_accepted() {
        let directory = tempdir().expect("temporary directory");
        enforce_owner_private_optional_file(&directory.path().join("state.sqlite-wal"))
            .expect("missing companion");
    }

    #[test]
    fn sqlite_state_repairs_database_and_present_companions() {
        let directory = tempdir().expect("temporary directory");
        let database = directory.path().join("state.sqlite");
        let wal = directory.path().join("state.sqlite-wal");
        let shm = directory.path().join("state.sqlite-shm");
        for path in [&database, &wal, &shm] {
            fs::write(path, b"state").expect("state fixture");
            fs::set_permissions(path, fs::Permissions::from_mode(0o644))
                .expect("permissive fixture mode");
        }

        enforce_owner_private_sqlite_state(&database).expect("private SQLite state");
        for path in [&database, &wal, &shm] {
            let mode = fs::metadata(path)
                .expect("private metadata")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }
}
