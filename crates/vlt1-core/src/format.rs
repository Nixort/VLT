// Copyright Nixort & Itan Winter <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 or later.

//! Format identifiers and immutable record types.

use rand::{rngs::OsRng, RngCore};

use crate::error::{Result, VaultError};

/// The current VLT/1 on-disk format version.
pub const FORMAT_VERSION: u32 = 1;

macro_rules! identifier {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
        pub struct $name([u8; 16]);

        impl $name {
            /// Generates a fresh CSPRNG-backed identifier.
            #[must_use]
            pub fn random() -> Self {
                let mut bytes = [0u8; 16];
                OsRng.fill_bytes(&mut bytes);
                Self(bytes)
            }

            /// Reconstructs an identifier from exactly sixteen bytes.
            ///
            /// # Errors
            ///
            /// Returns [`VaultError::InvalidFormat`] when `bytes` is not sixteen bytes long.
            pub fn from_slice(bytes: &[u8]) -> Result<Self> {
                let bytes: [u8; 16] = bytes
                    .try_into()
                    .map_err(|_| VaultError::invalid_format("invalid identifier length"))?;
                Ok(Self(bytes))
            }

            /// Returns the canonical byte representation.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 16] {
                &self.0
            }

            /// Returns a lowercase hexadecimal presentation for CLI output.
            #[must_use]
            pub fn to_hex(self) -> String {
                self.0.iter().map(|byte| format!("{byte:02x}")).collect()
            }
        }
    };
}

identifier!(
    VaultId,
    "A random identifier bound into every VLT/1 key domain."
);
identifier!(ObjectId, "A caller-selected logical object identifier.");
identifier!(VersionId, "A random immutable object-version identifier.");

/// A sealed AEAD record with a 96-bit nonce.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedRecord {
    /// The 96-bit AES-GCM-SIV nonce.
    pub nonce: [u8; 12],
    /// Ciphertext followed by the 128-bit authentication tag.
    pub ciphertext: Vec<u8>,
}

/// Metadata that binds a version to its encrypted contents.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Manifest {
    /// The VLT/1 format version.
    pub format_version: u32,
    /// The logical object represented by this version.
    pub object_id: ObjectId,
    /// The immutable version identifier.
    pub version_id: VersionId,
    /// Total plaintext length in bytes.
    pub plaintext_len: u64,
    /// Fixed chunk size used while publishing the version.
    pub chunk_size: u32,
    /// Number of authenticated chunks.
    pub chunk_count: u32,
    /// SHA-256 digest over canonical chunk metadata and ciphertexts.
    pub chunk_digest: [u8; 32],
}

/// One encrypted chunk prepared for transactional publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncryptedChunk {
    /// Zero-based chunk index.
    pub index: u32,
    /// AEAD nonce and ciphertext.
    pub record: SealedRecord,
}
