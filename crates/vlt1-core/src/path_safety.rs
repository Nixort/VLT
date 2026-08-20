// SPDX-License-Identifier: GPL-3.0-or-later
//
// License: GNU General Public License v3.0 or later.

//! Fail-closed validation for VLT/1 filesystem paths.
//!
//! The helpers in this module validate path type before an operation opens or
//! creates a security-sensitive vault artifact. They intentionally reject
//! symlinks rather than resolving them, so an operator must provide a direct,
//! stable path inside a real existing directory.

use std::{fs, path::Path};

use crate::{error::Result, VaultError};

/// Validates a direct existing regular file and its direct parent directory.
///
/// # Errors
///
/// Returns [`VaultError::InvalidInput`] when `path` is missing, a symlink, a
/// non-regular file, or has a missing, symlinked, or non-directory parent.
pub(crate) fn validate_existing_regular_file(path: &Path, input: &'static str) -> Result<()> {
    validate_parent_directory(path, input)?;
    let metadata = fs::symlink_metadata(path).map_err(|_| VaultError::InvalidInput(input))?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(VaultError::InvalidInput(input));
    }
    Ok(())
}

/// Validates a direct new-file destination and its direct parent directory.
///
/// # Errors
///
/// Returns [`VaultError::InvalidInput`] when the destination exists (including
/// as a symlink) or its parent is missing, symlinked, or not a directory.
pub(crate) fn validate_new_regular_file(path: &Path, input: &'static str) -> Result<()> {
    validate_parent_directory(path, input)?;
    match fs::symlink_metadata(path) {
        Ok(_) => Err(VaultError::InvalidInput(input)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(VaultError::Storage),
    }
}

/// Validates that a path has a direct existing, non-symlink directory parent.
///
/// # Errors
///
/// Returns [`VaultError::InvalidInput`] when `path` lacks a parent or the
/// direct parent is missing, symlinked, or not a directory.
pub(crate) fn validate_parent_directory(path: &Path, input: &'static str) -> Result<()> {
    let parent = path.parent().ok_or(VaultError::InvalidInput(input))?;
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    for ancestor in parent.ancestors() {
        let metadata =
            fs::symlink_metadata(ancestor).map_err(|_| VaultError::InvalidInput(input))?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
            return Err(VaultError::InvalidInput(input));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::symlink};

    use tempfile::tempdir;

    use super::{validate_existing_regular_file, validate_new_regular_file};

    #[test]
    fn rejects_symlink_files_and_symlink_parent_directories() {
        let directory = tempdir().expect("temporary directory");
        let file = directory.path().join("fixture");
        fs::write(&file, b"fixture").expect("fixture write");
        let file_link = directory.path().join("fixture-link");
        symlink(&file, &file_link).expect("file symlink");
        assert!(validate_existing_regular_file(&file_link, "fixture").is_err());
        assert!(validate_new_regular_file(&file_link, "fixture").is_err());

        let parent_link = directory.path().join("parent-link");
        symlink(directory.path(), &parent_link).expect("parent symlink");
        assert!(validate_new_regular_file(&parent_link.join("new"), "fixture").is_err());
    }
}
