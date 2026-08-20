// Copyright Nixort & Itan Winter <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 or later.
//
// VLT/1 — optional external freshness witness capability.

//! Signed freshness receipts and challenge-bound object heads for VLT/1.
//!
//! A receipt confirms one immutable version commitment. A head confirms the
//! witness's currently durable commitment for one `(vault, object)` namespace
//! and binds a caller-generated random challenge, preventing replay of a stale
//! response as a fresh observation. These objects become rollback protection
//! only when the witness signing key and persistent state are operated outside
//! the vault host's trust domain.

use std::{io::Read, time::Duration};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use ureq::{Agent, AgentBuilder, Error as UreqError};

use crate::{
    error::{Result, VaultError},
    format::{ObjectId, SealedRecord, VaultId, VersionId},
};

const COMMITMENT_DOMAIN: &[u8] = b"VLT/1 witness commitment v1";
const RECEIPT_DOMAIN: &[u8] = b"VLT/1 witness receipt v1";
const HEAD_DOMAIN: &[u8] = b"VLT/1 witness head v1";
const HTTP_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_HTTP_BODY: u64 = 16 * 1024;

/// A request for a witness to acknowledge one immutable VLT/1 version.
///
/// The explicit prefix keeps the root public API clear when requests from
/// multiple service boundaries are used together.
#[allow(clippy::module_name_repetitions)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WitnessRequest {
    vault_id: VaultId,
    object_id: ObjectId,
    version_id: VersionId,
    commitment: [u8; 32],
}

impl WitnessRequest {
    /// Creates a request with the commitment bound to encrypted manifest data.
    #[must_use]
    pub(crate) fn new(
        vault_id: VaultId,
        object_id: ObjectId,
        version_id: VersionId,
        manifest: &SealedRecord,
    ) -> Self {
        Self {
            vault_id,
            object_id,
            version_id,
            commitment: version_commitment(vault_id, object_id, version_id, manifest),
        }
    }

    /// Reconstructs a request from already validated fixed-width components.
    #[must_use]
    pub fn from_parts(
        vault_id: VaultId,
        object_id: ObjectId,
        version_id: VersionId,
        commitment: [u8; 32],
    ) -> Self {
        Self {
            vault_id,
            object_id,
            version_id,
            commitment,
        }
    }

    /// Returns the vault bound into this request.
    #[must_use]
    pub const fn vault_id(&self) -> VaultId {
        self.vault_id
    }

    /// Returns the object bound into this request.
    #[must_use]
    pub const fn object_id(&self) -> ObjectId {
        self.object_id
    }

    /// Returns the immutable version bound into this request.
    #[must_use]
    pub const fn version_id(&self) -> VersionId {
        self.version_id
    }

    /// Returns the 256-bit encrypted-version commitment.
    #[must_use]
    pub const fn commitment(&self) -> &[u8; 32] {
        &self.commitment
    }
}

/// An Ed25519-signed acknowledgement of an immutable VLT/1 version.
///
/// The explicit prefix keeps the root public API clear when receipts from
/// multiple service boundaries are used together.
#[allow(clippy::module_name_repetitions)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WitnessReceipt {
    vault_id: VaultId,
    object_id: ObjectId,
    version_id: VersionId,
    witness_epoch: u64,
    commitment: [u8; 32],
    public_key: [u8; 32],
    signature: [u8; 64],
}

impl WitnessReceipt {
    /// Constructs a receipt after verifying its Ed25519 signature and bindings.
    ///
    /// # Errors
    ///
    /// Returns an error when the public key or signature is not valid for the
    /// receipt's fixed canonical signing bytes.
    pub fn new(
        vault_id: VaultId,
        object_id: ObjectId,
        version_id: VersionId,
        witness_epoch: u64,
        commitment: [u8; 32],
        public_key: [u8; 32],
        signature: [u8; 64],
    ) -> Result<Self> {
        let receipt = Self {
            vault_id,
            object_id,
            version_id,
            witness_epoch,
            commitment,
            public_key,
            signature,
        };
        receipt.verify_signature()?;
        Ok(receipt)
    }

    /// Signs a receipt for a validated request using the witness's private key.
    ///
    /// This constructor is for independently operated witness implementations;
    /// the VLT/1 daemon never receives a `SigningKey`.
    #[must_use]
    pub fn issue(request: &WitnessRequest, witness_epoch: u64, signing_key: &SigningKey) -> Self {
        let public_key = signing_key.verifying_key().to_bytes();
        let signature = signing_key
            .sign(&receipt_signing_bytes(
                request.vault_id,
                request.object_id,
                request.version_id,
                witness_epoch,
                &request.commitment,
            ))
            .to_bytes();
        Self {
            vault_id: request.vault_id,
            object_id: request.object_id,
            version_id: request.version_id,
            witness_epoch,
            commitment: request.commitment,
            public_key,
            signature,
        }
    }

    /// Returns the vault identifier bound to this receipt.
    #[must_use]
    pub const fn vault_id(&self) -> VaultId {
        self.vault_id
    }

    /// Returns the object identifier bound to this receipt.
    #[must_use]
    pub const fn object_id(&self) -> ObjectId {
        self.object_id
    }

    /// Returns the immutable version identifier bound to this receipt.
    #[must_use]
    pub const fn version_id(&self) -> VersionId {
        self.version_id
    }

    /// Returns the witness' monotonically increasing acknowledgement epoch.
    #[must_use]
    pub const fn witness_epoch(&self) -> u64 {
        self.witness_epoch
    }

    /// Returns the encrypted-version commitment.
    #[must_use]
    pub const fn commitment(&self) -> &[u8; 32] {
        &self.commitment
    }

    /// Returns the witness Ed25519 public key.
    #[must_use]
    pub const fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    /// Returns the Ed25519 signature over this receipt's canonical bytes.
    #[must_use]
    pub const fn signature(&self) -> &[u8; 64] {
        &self.signature
    }

    /// Verifies this receipt's Ed25519 signature without consulting storage.
    ///
    /// # Errors
    ///
    /// Returns an error when the public key cannot be parsed or verification
    /// fails for the canonical receipt message.
    pub fn verify_signature(&self) -> Result<()> {
        verify_signature(&self.public_key, &self.signing_bytes(), &self.signature)
    }

    /// Verifies that this receipt acknowledges exactly `request`.
    ///
    /// # Errors
    ///
    /// Returns an error when the vault, object, version or commitment differs,
    /// or when the Ed25519 signature does not verify.
    pub fn verify_request(&self, request: &WitnessRequest) -> Result<()> {
        if self.vault_id != request.vault_id
            || self.object_id != request.object_id
            || self.version_id != request.version_id
            || self.commitment != request.commitment
        {
            return Err(VaultError::Invariant("witness receipt binding"));
        }
        self.verify_signature()
    }

    fn signing_bytes(&self) -> Vec<u8> {
        receipt_signing_bytes(
            self.vault_id,
            self.object_id,
            self.version_id,
            self.witness_epoch,
            &self.commitment,
        )
    }
}

/// A challenge-bound signed view of one witness object head.
///
/// The explicit prefix keeps the root public API clear when heads from
/// multiple service boundaries are used together.
#[allow(clippy::module_name_repetitions)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WitnessHead {
    vault_id: VaultId,
    object_id: ObjectId,
    present: bool,
    version_id: Option<VersionId>,
    witness_epoch: u64,
    commitment: Option<[u8; 32]>,
    challenge: [u8; 32],
    public_key: [u8; 32],
    signature: [u8; 64],
}

impl WitnessHead {
    /// Constructs and verifies one witness head.
    ///
    /// # Errors
    ///
    /// Returns an error when presence fields are inconsistent or the signature
    /// does not cover the fixed canonical head representation.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        vault_id: VaultId,
        object_id: ObjectId,
        present: bool,
        version_id: Option<VersionId>,
        witness_epoch: u64,
        commitment: Option<[u8; 32]>,
        challenge: [u8; 32],
        public_key: [u8; 32],
        signature: [u8; 64],
    ) -> Result<Self> {
        if present != (version_id.is_some() && commitment.is_some()) {
            return Err(VaultError::invalid_format("witness head presence fields"));
        }
        if !present && witness_epoch != 0 {
            return Err(VaultError::invalid_format("absent witness head epoch"));
        }
        let head = Self {
            vault_id,
            object_id,
            present,
            version_id,
            witness_epoch,
            commitment,
            challenge,
            public_key,
            signature,
        };
        head.verify_signature()?;
        Ok(head)
    }

    /// Signs a witness head for the supplied caller challenge.
    #[must_use]
    pub fn issue(
        vault_id: VaultId,
        object_id: ObjectId,
        receipt: Option<&WitnessReceipt>,
        challenge: [u8; 32],
        signing_key: &SigningKey,
    ) -> Self {
        let present = receipt.is_some();
        let version_id = receipt.map(WitnessReceipt::version_id);
        let witness_epoch = receipt.map_or(0, WitnessReceipt::witness_epoch);
        let commitment = receipt.map(|item| *item.commitment());
        let public_key = signing_key.verifying_key().to_bytes();
        let signature = signing_key
            .sign(&head_signing_bytes(
                vault_id,
                object_id,
                present,
                version_id,
                witness_epoch,
                commitment.as_ref(),
                &challenge,
            ))
            .to_bytes();
        Self {
            vault_id,
            object_id,
            present,
            version_id,
            witness_epoch,
            commitment,
            challenge,
            public_key,
            signature,
        }
    }

    /// Returns whether the witness has a recorded head for this object.
    #[must_use]
    pub const fn present(&self) -> bool {
        self.present
    }

    /// Returns the bound vault identifier.
    #[must_use]
    pub const fn vault_id(&self) -> VaultId {
        self.vault_id
    }

    /// Returns the bound object identifier.
    #[must_use]
    pub const fn object_id(&self) -> ObjectId {
        self.object_id
    }

    /// Returns the version identifier when a head is present.
    #[must_use]
    pub const fn version_id(&self) -> Option<VersionId> {
        self.version_id
    }

    /// Returns the durable witness epoch for this object, or zero when absent.
    #[must_use]
    pub const fn witness_epoch(&self) -> u64 {
        self.witness_epoch
    }

    /// Returns the commitment when a head is present.
    #[must_use]
    pub const fn commitment(&self) -> Option<&[u8; 32]> {
        self.commitment.as_ref()
    }

    /// Returns the challenge the caller must compare with its request.
    #[must_use]
    pub const fn challenge(&self) -> &[u8; 32] {
        &self.challenge
    }

    /// Returns the witness public key.
    #[must_use]
    pub const fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    /// Returns the signature over canonical head bytes.
    #[must_use]
    pub const fn signature(&self) -> &[u8; 64] {
        &self.signature
    }

    /// Verifies the Ed25519 signature over the full canonical head.
    ///
    /// # Errors
    ///
    /// Returns an error when the key or signature is invalid.
    pub fn verify_signature(&self) -> Result<()> {
        verify_signature(&self.public_key, &self.signing_bytes(), &self.signature)
    }

    fn signing_bytes(&self) -> Vec<u8> {
        head_signing_bytes(
            self.vault_id,
            self.object_id,
            self.present,
            self.version_id,
            self.witness_epoch,
            self.commitment.as_ref(),
            &self.challenge,
        )
    }
}

/// Issues and reads receipts from an independently operated freshness witness.
///
/// Implementations must preserve a conditional monotonic epoch per object and
/// keep their Ed25519 signing key outside the VLT/1 local trust boundary.
/// The explicit prefix distinguishes this interface from unrelated providers.
#[allow(clippy::module_name_repetitions)]
pub trait WitnessProvider {
    /// Conditionally obtains one signed receipt for `request`.
    ///
    /// `expected_epoch` is the witness epoch of the caller's previously
    /// authenticated object head, or zero when the object has never been
    /// witnessed. A stale expected epoch must not advance witness state.
    ///
    /// # Errors
    ///
    /// Returns a VLT/1 error when the provider is unavailable, rejects a stale
    /// state transition, or returns an invalid receipt.
    fn issue_receipt(
        &mut self,
        request: &WitnessRequest,
        expected_epoch: u64,
    ) -> Result<WitnessReceipt>;

    /// Obtains a challenge-bound signed head for one witnessed object.
    ///
    /// # Errors
    ///
    /// Returns a VLT/1 error when the provider is unavailable or the returned
    /// head cannot be verified and bound to `challenge`.
    fn object_head(
        &mut self,
        vault_id: VaultId,
        object_id: ObjectId,
        challenge: [u8; 32],
    ) -> Result<WitnessHead>;
}

/// A pinned HTTPS implementation of [`WitnessProvider`].
///
/// The supplied endpoint must use HTTPS. A primary witness public key is pinned
/// for every receipt and head independently of TLS. During an explicit key
/// rollover, one optional previous key can be trusted as a bounded overlap.
pub struct HttpsWitnessProvider {
    issue_url: String,
    head_url: String,
    authorization: String,
    primary_public_key: [u8; 32],
    previous_public_key: Option<[u8; 32]>,
    agent: Agent,
}

impl HttpsWitnessProvider {
    /// Creates a provider for an HTTPS witness endpoint.
    ///
    /// # Errors
    ///
    /// Returns an invalid-input error for a non-HTTPS endpoint or an empty
    /// bearer credential.
    pub fn new(endpoint: &str, bearer_token: &str, pinned_public_key: [u8; 32]) -> Result<Self> {
        Self::new_with_previous(endpoint, bearer_token, pinned_public_key, None)
    }

    /// Creates a provider with one bounded previous trust anchor during rollover.
    ///
    /// The previous key remains trusted only until an operator removes it from
    /// configuration after every vault has observed the primary key.
    ///
    /// # Errors
    ///
    /// Returns an invalid-input error for an invalid endpoint, empty bearer
    /// credential, or a previous key equal to the primary key.
    pub fn new_with_previous(
        endpoint: &str,
        bearer_token: &str,
        primary_public_key: [u8; 32],
        previous_public_key: Option<[u8; 32]>,
    ) -> Result<Self> {
        Self::build(
            endpoint,
            bearer_token,
            primary_public_key,
            previous_public_key,
            false,
        )
    }

    /// Creates an HTTP loopback provider for deterministic integration tests.
    ///
    /// This constructor is not a production transport and rejects all non-
    /// loopback endpoint forms.
    #[doc(hidden)]
    pub fn for_loopback_test(
        endpoint: &str,
        bearer_token: &str,
        pinned_public_key: [u8; 32],
    ) -> Result<Self> {
        Self::for_loopback_test_with_previous(endpoint, bearer_token, pinned_public_key, None)
    }

    /// Creates a loopback test provider with an optional previous trust anchor.
    ///
    /// This constructor is not a production transport and exists only for
    /// deterministic rollover integration tests.
    #[doc(hidden)]
    pub fn for_loopback_test_with_previous(
        endpoint: &str,
        bearer_token: &str,
        primary_public_key: [u8; 32],
        previous_public_key: Option<[u8; 32]>,
    ) -> Result<Self> {
        if !(endpoint.starts_with("http://127.0.0.1") || endpoint.starts_with("http://[::1]")) {
            return Err(VaultError::InvalidInput("loopback witness endpoint"));
        }
        Self::build(
            endpoint,
            bearer_token,
            primary_public_key,
            previous_public_key,
            true,
        )
    }

    fn build(
        endpoint: &str,
        bearer_token: &str,
        primary_public_key: [u8; 32],
        previous_public_key: Option<[u8; 32]>,
        allow_http: bool,
    ) -> Result<Self> {
        if (!allow_http && !endpoint.starts_with("https://"))
            || bearer_token.is_empty()
            || previous_public_key == Some(primary_public_key)
        {
            return Err(VaultError::InvalidInput("witness endpoint configuration"));
        }
        let endpoint = endpoint.trim_end_matches('/');
        if endpoint.is_empty() || endpoint.len() > 2048 {
            return Err(VaultError::InvalidInput("witness endpoint length"));
        }
        let agent = AgentBuilder::new()
            .timeout_connect(HTTP_TIMEOUT)
            .timeout_read(HTTP_TIMEOUT)
            .timeout_write(HTTP_TIMEOUT)
            .build();
        Ok(Self {
            issue_url: format!("{endpoint}/v1/issue"),
            head_url: format!("{endpoint}/v1/head"),
            authorization: format!("Bearer {bearer_token}"),
            primary_public_key,
            previous_public_key,
            agent,
        })
    }

    fn post_issue(&self, request: &IssueWireRequest) -> Result<IssueWireResponse> {
        let response = self
            .agent
            .post(&self.issue_url)
            .set("Authorization", &self.authorization)
            .set("Content-Type", "application/json")
            .send_json(request);
        match response {
            Ok(response) => read_json(response.into_reader()),
            Err(UreqError::Status(409, _)) => Err(VaultError::WitnessConflict),
            Err(_) => Err(VaultError::WitnessUnavailable),
        }
    }

    fn post_head(&self, request: &HeadWireRequest) -> Result<HeadWireResponse> {
        let response = self
            .agent
            .post(&self.head_url)
            .set("Authorization", &self.authorization)
            .set("Content-Type", "application/json")
            .send_json(request);
        match response {
            Ok(response) => read_json(response.into_reader()),
            Err(UreqError::Status(409, _)) => Err(VaultError::WitnessConflict),
            Err(_) => Err(VaultError::WitnessUnavailable),
        }
    }

    fn check_trusted_key(&self, public_key: &[u8; 32]) -> Result<()> {
        if public_key != &self.primary_public_key
            && self.previous_public_key.as_ref() != Some(public_key)
        {
            return Err(VaultError::WitnessConflict);
        }
        Ok(())
    }
}

impl WitnessProvider for HttpsWitnessProvider {
    fn issue_receipt(
        &mut self,
        request: &WitnessRequest,
        expected_epoch: u64,
    ) -> Result<WitnessReceipt> {
        let response = self.post_issue(&IssueWireRequest::from_request(request, expected_epoch))?;
        let receipt = response.into_receipt()?;
        self.check_trusted_key(receipt.public_key())?;
        receipt.verify_request(request)?;
        if receipt.witness_epoch() <= expected_epoch {
            return Err(VaultError::WitnessConflict);
        }
        Ok(receipt)
    }

    fn object_head(
        &mut self,
        vault_id: VaultId,
        object_id: ObjectId,
        challenge: [u8; 32],
    ) -> Result<WitnessHead> {
        let response = self.post_head(&HeadWireRequest {
            vault_id: vault_id.to_hex(),
            object_id: object_id.to_hex(),
            challenge: hex_encode(&challenge),
        })?;
        let head = response.into_head()?;
        self.check_trusted_key(head.public_key())?;
        if head.vault_id() != vault_id
            || head.object_id() != object_id
            || head.challenge() != &challenge
        {
            return Err(VaultError::WitnessConflict);
        }
        Ok(head)
    }
}

/// Deterministic in-process witness for tests and development only.
///
/// This provider is not an external freshness witness and therefore offers no
/// rollback protection against a local attacker who can alter the vault.
pub struct InMemoryTestProvider {
    signing_key: SigningKey,
    next_epoch: u64,
    heads: Vec<WitnessReceipt>,
}

impl InMemoryTestProvider {
    /// Creates a development provider with a freshly generated Ed25519 key.
    #[must_use]
    pub fn random() -> Self {
        Self {
            signing_key: SigningKey::generate(&mut OsRng),
            next_epoch: 1,
            heads: Vec::new(),
        }
    }

    /// Creates a development provider from a fixed signing seed.
    #[must_use]
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(&seed),
            next_epoch: 1,
            heads: Vec::new(),
        }
    }

    fn current_receipt(&self, vault_id: VaultId, object_id: ObjectId) -> Option<&WitnessReceipt> {
        self.heads
            .iter()
            .find(|receipt| receipt.vault_id() == vault_id && receipt.object_id() == object_id)
    }
}

impl WitnessProvider for InMemoryTestProvider {
    fn issue_receipt(
        &mut self,
        request: &WitnessRequest,
        expected_epoch: u64,
    ) -> Result<WitnessReceipt> {
        if let Some(current) = self.current_receipt(request.vault_id, request.object_id) {
            if current.version_id() == request.version_id
                && current.commitment() == request.commitment()
                && current.witness_epoch() > expected_epoch
            {
                return Ok(current.clone());
            }
            if current.witness_epoch() != expected_epoch {
                return Err(VaultError::WitnessConflict);
            }
        } else if expected_epoch != 0 {
            return Err(VaultError::WitnessConflict);
        }
        let epoch = self.next_epoch;
        self.next_epoch = self
            .next_epoch
            .checked_add(1)
            .ok_or(VaultError::Invariant("witness epoch exhausted"))?;
        let receipt = WitnessReceipt::issue(request, epoch, &self.signing_key);
        if let Some(current) = self.heads.iter_mut().find(|item| {
            item.vault_id() == request.vault_id && item.object_id() == request.object_id
        }) {
            *current = receipt.clone();
        } else {
            self.heads.push(receipt.clone());
        }
        Ok(receipt)
    }

    fn object_head(
        &mut self,
        vault_id: VaultId,
        object_id: ObjectId,
        challenge: [u8; 32],
    ) -> Result<WitnessHead> {
        Ok(WitnessHead::issue(
            vault_id,
            object_id,
            self.current_receipt(vault_id, object_id),
            challenge,
            &self.signing_key,
        ))
    }
}

#[derive(Serialize)]
struct IssueWireRequest {
    vault_id: String,
    object_id: String,
    version_id: String,
    commitment: String,
    expected_epoch: u64,
}

impl IssueWireRequest {
    fn from_request(request: &WitnessRequest, expected_epoch: u64) -> Self {
        Self {
            vault_id: request.vault_id.to_hex(),
            object_id: request.object_id.to_hex(),
            version_id: request.version_id.to_hex(),
            commitment: hex_encode(&request.commitment),
            expected_epoch,
        }
    }
}

#[derive(Deserialize)]
struct IssueWireResponse {
    vault_id: String,
    object_id: String,
    version_id: String,
    witness_epoch: u64,
    commitment: String,
    public_key: String,
    signature: String,
}

impl IssueWireResponse {
    fn into_receipt(self) -> Result<WitnessReceipt> {
        WitnessReceipt::new(
            parse_vault_id(&self.vault_id)?,
            parse_object_id(&self.object_id)?,
            parse_version_id(&self.version_id)?,
            self.witness_epoch,
            parse_fixed::<32>(&self.commitment, "witness commitment")?,
            parse_fixed::<32>(&self.public_key, "witness public key")?,
            parse_fixed::<64>(&self.signature, "witness signature")?,
        )
    }
}

#[derive(Serialize)]
struct HeadWireRequest {
    vault_id: String,
    object_id: String,
    challenge: String,
}

#[derive(Deserialize)]
struct HeadWireResponse {
    vault_id: String,
    object_id: String,
    present: bool,
    version_id: Option<String>,
    witness_epoch: u64,
    commitment: Option<String>,
    challenge: String,
    public_key: String,
    signature: String,
}

impl HeadWireResponse {
    fn into_head(self) -> Result<WitnessHead> {
        let version_id = self
            .version_id
            .map(|value| parse_version_id(&value))
            .transpose()?;
        let commitment = self
            .commitment
            .map(|value| parse_fixed::<32>(&value, "witness head commitment"))
            .transpose()?;
        WitnessHead::new(
            parse_vault_id(&self.vault_id)?,
            parse_object_id(&self.object_id)?,
            self.present,
            version_id,
            self.witness_epoch,
            commitment,
            parse_fixed::<32>(&self.challenge, "witness head challenge")?,
            parse_fixed::<32>(&self.public_key, "witness public key")?,
            parse_fixed::<64>(&self.signature, "witness head signature")?,
        )
    }
}

fn read_json<T: for<'de> Deserialize<'de>>(reader: impl Read) -> Result<T> {
    let mut bytes = Vec::with_capacity(1024);
    let mut limited = reader.take(MAX_HTTP_BODY + 1);
    limited
        .read_to_end(&mut bytes)
        .map_err(|_| VaultError::WitnessUnavailable)?;
    if bytes.len() as u64 > MAX_HTTP_BODY {
        return Err(VaultError::invalid_format(
            "witness HTTP response too large",
        ));
    }
    serde_json::from_slice(&bytes).map_err(|_| VaultError::invalid_format("witness HTTP response"))
}

fn verify_signature(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> Result<()> {
    let public_key = VerifyingKey::from_bytes(public_key)
        .map_err(|_| VaultError::invalid_format("witness public key"))?;
    let signature = Signature::from_bytes(signature);
    public_key
        .verify(message, &signature)
        .map_err(|_| VaultError::Authentication)
}

fn version_commitment(
    vault_id: VaultId,
    object_id: ObjectId,
    version_id: VersionId,
    manifest: &SealedRecord,
) -> [u8; 32] {
    let ciphertext_len = u64::try_from(manifest.ciphertext.len()).unwrap_or(u64::MAX);
    let mut digest = Sha256::new();
    digest.update(COMMITMENT_DOMAIN);
    digest.update(vault_id.as_bytes());
    digest.update(object_id.as_bytes());
    digest.update(version_id.as_bytes());
    digest.update(manifest.nonce);
    digest.update(ciphertext_len.to_be_bytes());
    digest.update(&manifest.ciphertext);
    digest.finalize().into()
}

fn receipt_signing_bytes(
    vault_id: VaultId,
    object_id: ObjectId,
    version_id: VersionId,
    witness_epoch: u64,
    commitment: &[u8; 32],
) -> Vec<u8> {
    let mut message = Vec::with_capacity(
        RECEIPT_DOMAIN.len()
            + vault_id.as_bytes().len()
            + object_id.as_bytes().len()
            + version_id.as_bytes().len()
            + std::mem::size_of::<u64>()
            + commitment.len(),
    );
    message.extend_from_slice(RECEIPT_DOMAIN);
    message.extend_from_slice(vault_id.as_bytes());
    message.extend_from_slice(object_id.as_bytes());
    message.extend_from_slice(version_id.as_bytes());
    message.extend_from_slice(&witness_epoch.to_be_bytes());
    message.extend_from_slice(commitment);
    message
}

fn head_signing_bytes(
    vault_id: VaultId,
    object_id: ObjectId,
    present: bool,
    version_id: Option<VersionId>,
    witness_epoch: u64,
    commitment: Option<&[u8; 32]>,
    challenge: &[u8; 32],
) -> Vec<u8> {
    let version = version_id.map_or([0u8; 16], |value| *value.as_bytes());
    let commitment = commitment.copied().unwrap_or([0u8; 32]);
    let mut message = Vec::with_capacity(
        HEAD_DOMAIN.len()
            + vault_id.as_bytes().len()
            + object_id.as_bytes().len()
            + 1
            + version.len()
            + std::mem::size_of::<u64>()
            + commitment.len()
            + challenge.len(),
    );
    message.extend_from_slice(HEAD_DOMAIN);
    message.extend_from_slice(vault_id.as_bytes());
    message.extend_from_slice(object_id.as_bytes());
    message.push(u8::from(present));
    message.extend_from_slice(&version);
    message.extend_from_slice(&witness_epoch.to_be_bytes());
    message.extend_from_slice(&commitment);
    message.extend_from_slice(challenge);
    message
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

fn parse_fixed<const N: usize>(value: &str, error: &'static str) -> Result<[u8; N]> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(VaultError::invalid_format(error));
    }
    let mut result = [0u8; N];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let pair = std::str::from_utf8(pair).map_err(|_| VaultError::invalid_format(error))?;
        result[index] =
            u8::from_str_radix(pair, 16).map_err(|_| VaultError::invalid_format(error))?;
    }
    Ok(result)
}

fn parse_vault_id(value: &str) -> Result<VaultId> {
    VaultId::from_slice(&parse_fixed::<16>(value, "witness vault ID")?)
}

fn parse_object_id(value: &str) -> Result<ObjectId> {
    ObjectId::from_slice(&parse_fixed::<16>(value, "witness object ID")?)
}

fn parse_version_id(value: &str) -> Result<VersionId> {
    VersionId::from_slice(&parse_fixed::<16>(value, "witness version ID")?)
}

/// Returns a fresh 256-bit random challenge for a witness head query.
#[must_use]
pub fn random_witness_challenge() -> [u8; 32] {
    let mut challenge = [0u8; 32];
    OsRng.fill_bytes(&mut challenge);
    challenge
}

#[cfg(test)]
mod tests {
    use super::{random_witness_challenge, InMemoryTestProvider, WitnessProvider, WitnessRequest};
    use crate::{format::SealedRecord, ObjectId, VaultError, VaultId, VersionId};

    #[test]
    fn issued_receipt_and_challenge_bound_head_verify() {
        let request = WitnessRequest::new(
            VaultId::random(),
            ObjectId::random(),
            VersionId::random(),
            &SealedRecord {
                nonce: [7; 12],
                ciphertext: b"encrypted-manifest".to_vec(),
            },
        );
        let mut provider = InMemoryTestProvider::from_seed([3; 32]);
        let receipt = provider.issue_receipt(&request, 0).expect("receipt");
        receipt.verify_request(&request).expect("binding");
        assert_eq!(receipt.witness_epoch(), 1);

        let challenge = random_witness_challenge();
        let head = provider
            .object_head(request.vault_id(), request.object_id(), challenge)
            .expect("head");
        assert!(head.present());
        assert_eq!(head.version_id(), Some(request.version_id()));
        assert_eq!(head.challenge(), &challenge);
    }

    #[test]
    fn stale_epoch_does_not_advance_a_witness_head() {
        let vault_id = VaultId::random();
        let object_id = ObjectId::random();
        let mut provider = InMemoryTestProvider::from_seed([9; 32]);
        let first = WitnessRequest::from_parts(vault_id, object_id, VersionId::random(), [1; 32]);
        provider.issue_receipt(&first, 0).expect("first receipt");
        let conflicting =
            WitnessRequest::from_parts(vault_id, object_id, VersionId::random(), [2; 32]);
        assert!(matches!(
            provider.issue_receipt(&conflicting, 0),
            Err(VaultError::WitnessConflict)
        ));
    }
}
