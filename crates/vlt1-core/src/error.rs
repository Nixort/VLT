// Copyright Nixort & Itan Winter <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 or later.

//! Error categories for the VLT/1 security boundary.

use thiserror::Error;

/// Result type used by VLT/1 public operations.
pub type Result<T> = std::result::Result<T, VaultError>;

/// Errors returned without plaintext, passphrases or key material.
#[derive(Debug, Error)]
pub enum VaultError {
    /// The caller must unlock the vault before using it.
    #[error("vault is locked")]
    Locked,
    /// Passphrase verification or root-key envelope decryption failed.
    #[error("unlock failed")]
    UnlockFailed,
    /// An authenticated record could not be verified.
    #[error("authenticated record verification failed")]
    Authentication,
    /// A persistent record violated the VLT/1 format contract.
    #[error("invalid VLT/1 format: {0}")]
    InvalidFormat(&'static str),
    /// A VLT/1 lifecycle invariant was violated.
    #[error("VLT/1 invariant failed: {0}")]
    Invariant(&'static str),
    /// The requested object or version does not exist.
    #[error("requested item was not found")]
    NotFound,
    /// A persistent backend operation failed.
    #[error("storage operation failed")]
    Storage,
    /// Input violates an explicit public API limit.
    #[error("invalid input: {0}")]
    InvalidInput(&'static str),
    /// An independently configured freshness witness could not be reached.
    #[error("freshness witness is unavailable")]
    WitnessUnavailable,
    /// Remote witness state contradicts the locally authenticated witness head.
    #[error("freshness witness conflict")]
    WitnessConflict,
}

impl VaultError {
    /// Returns whether the current vault instance must transition to `Locked`.
    #[must_use]
    pub const fn requires_lock(&self) -> bool {
        matches!(
            self,
            Self::Authentication
                | Self::InvalidFormat(_)
                | Self::Invariant(_)
                | Self::Storage
                | Self::WitnessUnavailable
                | Self::WitnessConflict
        )
    }

    /// Creates a format error while keeping the concrete untrusted bytes private.
    #[must_use]
    pub const fn invalid_format(message: &'static str) -> Self {
        Self::InvalidFormat(message)
    }
}
