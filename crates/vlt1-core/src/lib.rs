// Copyright Nixort & Itan Winter <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 or later.
//
// VLT/1 — local encrypted vault reference implementation.

//! # VLT/1 core
//!
//! `vlt1-core` implements the security-sensitive local-vault boundary: password
//! unlock, Root Key and DEK lifecycle, AES-256-GCM-SIV records, deterministic
//! metadata, `SQLite` publication and verification-first reads.
//!
//! The crate deliberately exposes object-oriented operations rather than a
//! generic decrypt API. See `docs/ARCHITECTURE.md` for the threat model and
//! non-goals of this reference implementation.
#![forbid(unsafe_code)]

mod backup;
mod cde;
mod crypto;
mod error;
mod format;
mod storage;
mod vault;
mod witness;

pub use crate::backup::{manifest_path, BackupManifest};
pub use crate::error::{Result, VaultError};
pub use crate::format::{ObjectId, VaultId, VersionId};
pub use crate::vault::{Vault, VaultStatus, DEFAULT_CHUNK_SIZE, MAX_CHUNKS_PER_VERSION};
pub use crate::witness::{
    random_witness_challenge, HttpsWitnessProvider, InMemoryTestProvider, WitnessHead,
    WitnessProvider, WitnessReceipt, WitnessRequest,
};

/// Exercises the canonical Manifest decoder with untrusted bytes for fuzzing.
///
/// This hook intentionally discards parser errors and never exposes decoded
/// metadata. It exists solely because the decoder is an otherwise private
/// implementation detail of the VLT/1 verification boundary.
#[doc(hidden)]
pub fn fuzz_decode_manifest(input: &[u8]) {
    let _ = cde::decode_manifest(input);
}

/// Forces the next atomic publication to fail with [`VaultError::Storage`].
///
/// This test-only fault injector is compiled exclusively with the
/// `fault-injection` feature and models a storage-full or lower-layer write
/// failure before any transaction commits.
#[cfg(feature = "fault-injection")]
pub fn inject_next_publication_failure() {
    storage::inject_next_publication_failure();
}

/// Forces final local receipt persistence to fail after a remote witness issue.
///
/// This test-only injector models the cross-system crash window between the
/// external receipt and VLT/1's local active-pointer transaction.
#[cfg(feature = "fault-injection")]
pub fn inject_next_witness_finalization_failure() {
    storage::inject_next_witness_finalization_failure();
}
