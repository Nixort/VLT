// Copyright Nixort & Itan Winter <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 or later.

//! Key hierarchy and authenticated-encryption primitives for VLT/1.
//!
//! This module composes reviewed crates; it does not implement AES, POLYVAL,
//! Argon2id, HKDF or SHA-256 itself.

use aes_gcm_siv::{
    aead::{Aead, KeyInit, Payload},
    Aes256GcmSiv, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    error::{Result, VaultError},
    format::{ObjectId, SealedRecord, VaultId, VersionId},
};

/// Default Argon2id memory cost in KiB.
pub const DEFAULT_ARGON2_MEMORY_KIB: u32 = 65_536;
/// Default Argon2id time cost.
pub const DEFAULT_ARGON2_ITERATIONS: u32 = 3;
/// Default Argon2id parallelism, matching the RFC 9106 64-MiB profile.
pub const DEFAULT_ARGON2_LANES: u32 = 4;

/// Parameters stored with an encrypted Root Key envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KdfParams {
    /// Argon2id memory cost in KiB.
    pub memory_kib: u32,
    /// Argon2id time cost.
    pub iterations: u32,
    /// Argon2id lane count.
    pub lanes: u32,
}

impl KdfParams {
    /// Returns the VLT/1 interactive password profile.
    #[must_use]
    pub const fn interactive() -> Self {
        Self {
            memory_kib: DEFAULT_ARGON2_MEMORY_KIB,
            iterations: DEFAULT_ARGON2_ITERATIONS,
            lanes: DEFAULT_ARGON2_LANES,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        open_root_key, seal_root_key, KdfParams, DEFAULT_ARGON2_ITERATIONS, DEFAULT_ARGON2_LANES,
        DEFAULT_ARGON2_MEMORY_KIB,
    };
    use crate::format::VaultId;

    #[test]
    fn interactive_profile_matches_the_documented_rfc_9106_64_mib_profile() {
        assert_eq!(
            KdfParams::interactive(),
            KdfParams {
                memory_kib: DEFAULT_ARGON2_MEMORY_KIB,
                iterations: DEFAULT_ARGON2_ITERATIONS,
                lanes: DEFAULT_ARGON2_LANES,
            }
        );
        assert_eq!(DEFAULT_ARGON2_MEMORY_KIB, 65_536);
        assert_eq!(DEFAULT_ARGON2_ITERATIONS, 3);
        assert_eq!(DEFAULT_ARGON2_LANES, 4);
    }

    #[test]
    fn persisted_legacy_one_lane_descriptor_remains_unlockable() {
        let root_key = [0x5au8; 32];
        let envelope = seal_root_key(
            "test passphrase",
            VaultId::random(),
            &root_key,
            KdfParams {
                memory_kib: 8,
                iterations: 1,
                lanes: 1,
            },
        )
        .expect("legacy descriptor envelope");
        assert_eq!(envelope.params.lanes, 1);
        let opened = open_root_key("test passphrase", &envelope).expect("legacy descriptor unlock");
        assert_eq!(*opened, root_key);
    }
}

/// Metadata and ciphertext required to unwrap the random Root Key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootEnvelope {
    /// The vault identifier bound into the root-envelope AAD.
    pub vault_id: VaultId,
    /// CSPRNG-generated Argon2id salt.
    pub salt: [u8; 16],
    /// Persisted Argon2id parameters.
    pub params: KdfParams,
    /// AES-GCM-SIV nonce and encrypted Root Key.
    pub record: SealedRecord,
}

/// Generates a fresh 256-bit Root Key.
#[must_use]
pub fn generate_root_key() -> Zeroizing<[u8; 32]> {
    let mut root_key = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(&mut *root_key);
    root_key
}

/// Creates a password-protected Root Key envelope.
pub fn seal_root_key(
    passphrase: &str,
    vault_id: VaultId,
    root_key: &[u8; 32],
    params: KdfParams,
) -> Result<RootEnvelope> {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let mut passphrase_key = derive_passphrase_key(passphrase, &salt, params)?;
    let aad = root_aad(vault_id);
    let record = seal(&passphrase_key[..], &aad, root_key)?;
    passphrase_key.zeroize();
    Ok(RootEnvelope {
        vault_id,
        salt,
        params,
        record,
    })
}

/// Decrypts a Root Key envelope after deriving the passphrase key.
pub fn open_root_key(passphrase: &str, envelope: &RootEnvelope) -> Result<Zeroizing<[u8; 32]>> {
    let mut passphrase_key = derive_passphrase_key(passphrase, &envelope.salt, envelope.params)?;
    let aad = root_aad(envelope.vault_id);
    let Ok(mut plaintext) = open(&passphrase_key[..], &aad, &envelope.record) else {
        passphrase_key.zeroize();
        return Err(VaultError::UnlockFailed);
    };
    passphrase_key.zeroize();
    let root_key: [u8; 32] = plaintext
        .as_slice()
        .try_into()
        .map_err(|_| VaultError::UnlockFailed)?;
    plaintext.zeroize();
    Ok(Zeroizing::new(root_key))
}

/// Derives the per-vault key-encryption key from the Root Key.
pub fn derive_kek(root_key: &[u8; 32], vault_id: VaultId) -> Result<Zeroizing<[u8; 32]>> {
    derive_domain_key(root_key, vault_id.as_bytes(), b"VLT1/KEK")
}

/// Derives a distinct Manifest key from a version DEK.
pub fn derive_manifest_key(dek: &[u8; 32], version_id: VersionId) -> Result<Zeroizing<[u8; 32]>> {
    derive_domain_key(dek, version_id.as_bytes(), b"VLT1/MANIFEST")
}

/// Generates a fresh version DEK.
#[must_use]
pub fn generate_dek() -> Zeroizing<[u8; 32]> {
    let mut dek = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(&mut *dek);
    dek
}

/// Encrypts a plaintext with AES-256-GCM-SIV and a fresh 96-bit nonce.
pub fn seal(key: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<SealedRecord> {
    if key.len() != 32 {
        return Err(VaultError::Invariant("AES-256 key length"));
    }
    let cipher = Aes256GcmSiv::new_from_slice(key)
        .map_err(|_| VaultError::Invariant("AES-GCM-SIV construction"))?;
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| VaultError::Authentication)?;
    Ok(SealedRecord { nonce, ciphertext })
}

/// Decrypts an AES-256-GCM-SIV record after authenticating its AAD.
pub fn open(key: &[u8], aad: &[u8], record: &SealedRecord) -> Result<Vec<u8>> {
    if key.len() != 32 {
        return Err(VaultError::Invariant("AES-256 key length"));
    }
    let cipher = Aes256GcmSiv::new_from_slice(key)
        .map_err(|_| VaultError::Invariant("AES-GCM-SIV construction"))?;
    cipher
        .decrypt(
            Nonce::from_slice(&record.nonce),
            Payload {
                msg: &record.ciphertext,
                aad,
            },
        )
        .map_err(|_| VaultError::Authentication)
}

/// Builds a collision-resistant AAD transcript for an encrypted object chunk.
#[must_use]
pub fn chunk_aad(
    vault_id: VaultId,
    object_id: ObjectId,
    version_id: VersionId,
    chunk_index: u32,
    plaintext_len: u32,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(16 * 3 + 8 + 32);
    aad.extend_from_slice(b"VLT1/CHUNK\0");
    aad.extend_from_slice(vault_id.as_bytes());
    aad.extend_from_slice(object_id.as_bytes());
    aad.extend_from_slice(version_id.as_bytes());
    aad.extend_from_slice(&chunk_index.to_be_bytes());
    aad.extend_from_slice(&plaintext_len.to_be_bytes());
    aad
}

/// Builds AAD for a sealed version Manifest.
#[must_use]
pub fn manifest_aad(vault_id: VaultId, object_id: ObjectId, version_id: VersionId) -> Vec<u8> {
    let mut aad = Vec::with_capacity(16 * 3 + 24);
    aad.extend_from_slice(b"VLT1/MANIFEST\0");
    aad.extend_from_slice(vault_id.as_bytes());
    aad.extend_from_slice(object_id.as_bytes());
    aad.extend_from_slice(version_id.as_bytes());
    aad
}

/// Builds AAD for a DEK wrapped under the per-vault KEK.
#[must_use]
pub fn wrapped_dek_aad(vault_id: VaultId, object_id: ObjectId, version_id: VersionId) -> Vec<u8> {
    let mut aad = Vec::with_capacity(16 * 3 + 24);
    aad.extend_from_slice(b"VLT1/WRAPPED-DEK\0");
    aad.extend_from_slice(vault_id.as_bytes());
    aad.extend_from_slice(object_id.as_bytes());
    aad.extend_from_slice(version_id.as_bytes());
    aad
}

/// Computes the digest committed by a Manifest over every encrypted chunk.
#[must_use]
pub fn chunk_digest(chunks: &[(u32, SealedRecord)]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"VLT1/CHUNK-DIGEST\0");
    for (index, record) in chunks {
        hasher.update(index.to_be_bytes());
        hasher.update(record.nonce);
        hasher.update((record.ciphertext.len() as u64).to_be_bytes());
        hasher.update(&record.ciphertext);
    }
    hasher.finalize().into()
}

fn derive_passphrase_key(
    passphrase: &str,
    salt: &[u8; 16],
    params: KdfParams,
) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(params.memory_kib, params.iterations, params.lanes, Some(32))
        .map_err(|_| VaultError::InvalidInput("invalid Argon2id parameters"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut *output)
        .map_err(|_| VaultError::UnlockFailed)?;
    Ok(output)
}

fn derive_domain_key(root: &[u8; 32], salt: &[u8], label: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), root);
    let mut output = Zeroizing::new([0u8; 32]);
    hkdf.expand(label, &mut *output)
        .map_err(|_| VaultError::Invariant("HKDF expansion"))?;
    Ok(output)
}

fn root_aad(vault_id: VaultId) -> Vec<u8> {
    let mut aad = Vec::with_capacity(32);
    aad.extend_from_slice(b"VLT1/ROOT\0");
    aad.extend_from_slice(vault_id.as_bytes());
    aad
}
