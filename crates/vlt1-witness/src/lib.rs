// Copyright Nixort & Itan Winter <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 or later.

//! Durable independently deployable VLT/1 freshness witness state machine.
//!
//! The HTTP listener is intentionally implemented by the binary crate. This
//! library holds the small auditable transition core: a `SQLite` transaction
//! conditionally advances one object head, signs the receipt, and stores enough
//! material to return the same receipt after an uncertain client retry.
#![forbid(unsafe_code)]

use std::{
    fs,
    path::{Path, PathBuf},
};

use ed25519_dalek::SigningKey;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use vlt1_core::{
    enforce_owner_private_sqlite_state, ObjectId, VaultError, VaultId, VersionId, WitnessHead,
    WitnessReceipt, WitnessRequest,
};

/// Maximum accepted JSON body size for either witness endpoint.
pub const MAX_WIRE_BODY: u64 = 16 * 1024;

/// JSON request for `POST /v1/issue`.
#[derive(Debug, Deserialize)]
pub struct IssueRequest {
    /// Lowercase hexadecimal vault ID.
    pub vault_id: String,
    /// Lowercase hexadecimal object ID.
    pub object_id: String,
    /// Lowercase hexadecimal immutable version ID.
    pub version_id: String,
    /// Lowercase hexadecimal 256-bit encrypted-version commitment.
    pub commitment: String,
    /// Previously verified witness epoch for this object, or zero if absent.
    pub expected_epoch: u64,
}

/// JSON response for `POST /v1/issue`.
#[derive(Debug, Serialize)]
pub struct IssueResponse {
    /// Lowercase hexadecimal vault ID.
    pub vault_id: String,
    /// Lowercase hexadecimal object ID.
    pub object_id: String,
    /// Lowercase hexadecimal immutable version ID.
    pub version_id: String,
    /// Durable witness epoch allocated to this receipt.
    pub witness_epoch: u64,
    /// Lowercase hexadecimal commitment.
    pub commitment: String,
    /// Lowercase hexadecimal Ed25519 verification key.
    pub public_key: String,
    /// Lowercase hexadecimal Ed25519 signature.
    pub signature: String,
}

/// JSON request for `POST /v1/head`.
#[derive(Debug, Deserialize)]
pub struct HeadRequest {
    /// Lowercase hexadecimal vault ID.
    pub vault_id: String,
    /// Lowercase hexadecimal object ID.
    pub object_id: String,
    /// Fresh lowercase hexadecimal 256-bit caller challenge.
    pub challenge: String,
}

/// JSON response for `POST /v1/head`.
#[derive(Debug, Serialize)]
pub struct HeadResponse {
    /// Lowercase hexadecimal vault ID.
    pub vault_id: String,
    /// Lowercase hexadecimal object ID.
    pub object_id: String,
    /// Whether a durable witness head exists.
    pub present: bool,
    /// Lowercase hexadecimal version ID when `present`.
    pub version_id: Option<String>,
    /// Durable witness epoch, or zero when absent.
    pub witness_epoch: u64,
    /// Lowercase hexadecimal commitment when `present`.
    pub commitment: Option<String>,
    /// Exact caller challenge bound into the signature.
    pub challenge: String,
    /// Lowercase hexadecimal Ed25519 verification key.
    pub public_key: String,
    /// Lowercase hexadecimal Ed25519 signature.
    pub signature: String,
}

/// Independently persisted witness state and signing capability.
pub struct WitnessService {
    connection: Connection,
    path: PathBuf,
    signing_key: SigningKey,
}

impl WitnessService {
    /// Opens or creates a durable witness state database.
    ///
    /// # Errors
    ///
    /// Returns an error when the database cannot be opened or initialized.
    pub fn open(path: impl AsRef<Path>, signing_key: SigningKey) -> Result<Self, VaultError> {
        let path = path.as_ref();
        validate_state_path(path)?;
        let connection = Connection::open(path).map_err(|_| VaultError::Storage)?;
        let journal_mode: String = connection
            .query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))
            .map_err(|_| VaultError::Storage)?;
        if !journal_mode.eq_ignore_ascii_case("wal") {
            return Err(VaultError::Storage);
        }
        connection
            .execute_batch(
                "PRAGMA foreign_keys = ON;\
                 PRAGMA synchronous = FULL;\
                 PRAGMA trusted_schema = OFF;\
                 CREATE TABLE IF NOT EXISTS vault_epochs (\
                    vault_id BLOB PRIMARY KEY CHECK(length(vault_id) = 16),\
                    next_epoch INTEGER NOT NULL CHECK(next_epoch > 0)\
                 );\
                 CREATE TABLE IF NOT EXISTS object_heads (\
                    vault_id BLOB NOT NULL CHECK(length(vault_id) = 16),\
                    object_id BLOB NOT NULL CHECK(length(object_id) = 16),\
                    version_id BLOB NOT NULL CHECK(length(version_id) = 16),\
                    witness_epoch INTEGER NOT NULL CHECK(witness_epoch > 0),\
                    commitment BLOB NOT NULL CHECK(length(commitment) = 32),\
                    signature BLOB NOT NULL CHECK(length(signature) = 64),\
                    PRIMARY KEY(vault_id, object_id)\
                 );",
            )
            .map_err(|_| VaultError::Storage)?;
        enforce_owner_private_sqlite_state(path)?;
        Ok(Self {
            connection,
            path: path.to_owned(),
            signing_key,
        })
    }

    /// Returns the public signing key provisioned for this witness.
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Processes and conditionally signs an issue request.
    ///
    /// Repeating an already advanced identical request returns its original
    /// receipt. A different stale request returns `WitnessConflict` without
    /// changing durable state.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed fields, stale state, signing failure, or
    /// `SQLite` failure.
    pub fn issue_wire(&mut self, request: &IssueRequest) -> Result<IssueResponse, VaultError> {
        let request = parse_issue(request)?;
        let public_key = self.public_key();
        let transaction = self
            .connection
            .transaction()
            .map_err(|_| VaultError::Storage)?;
        let current = load_receipt(
            &transaction,
            request.request.vault_id(),
            request.request.object_id(),
            public_key,
        )?;

        if let Some(receipt) = current.as_ref() {
            if receipt.version_id() == request.request.version_id()
                && receipt.commitment() == request.request.commitment()
                && receipt.witness_epoch() > request.expected_epoch
            {
                return Ok(IssueResponse::from(receipt));
            }
            if receipt.witness_epoch() != request.expected_epoch {
                return Err(VaultError::WitnessConflict);
            }
        } else if request.expected_epoch != 0 {
            return Err(VaultError::WitnessConflict);
        }

        let epoch = next_epoch(&transaction, request.request.vault_id())?;
        let receipt = WitnessReceipt::issue(&request.request, epoch, &self.signing_key);
        transaction
            .execute(
                "INSERT INTO object_heads(vault_id, object_id, version_id, witness_epoch, commitment, signature) \
                 VALUES(?1, ?2, ?3, ?4, ?5, ?6) \
                 ON CONFLICT(vault_id, object_id) DO UPDATE SET \
                    version_id = excluded.version_id, \
                    witness_epoch = excluded.witness_epoch, \
                    commitment = excluded.commitment, \
                    signature = excluded.signature",
                params![
                    receipt.vault_id().as_bytes().as_slice(),
                    receipt.object_id().as_bytes().as_slice(),
                    receipt.version_id().as_bytes().as_slice(),
                    receipt.witness_epoch(),
                    receipt.commitment().as_slice(),
                    receipt.signature().as_slice(),
                ],
            )
            .map_err(|_| VaultError::Storage)?;
        transaction.commit().map_err(|_| VaultError::Storage)?;
        enforce_owner_private_sqlite_state(&self.path)?;
        Ok(IssueResponse::from(&receipt))
    }

    /// Processes one fresh signed object-head request.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed fields or `SQLite` failure.
    pub fn head_wire(&self, request: &HeadRequest) -> Result<HeadResponse, VaultError> {
        let request = parse_head(request)?;
        let receipt = load_receipt(
            &self.connection,
            request.vault_id,
            request.object_id,
            self.public_key(),
        )?;
        let head = WitnessHead::issue(
            request.vault_id,
            request.object_id,
            receipt.as_ref(),
            request.challenge,
            &self.signing_key,
        );
        Ok(HeadResponse::from(&head))
    }
}

struct ParsedIssue {
    request: WitnessRequest,
    expected_epoch: u64,
}

struct ParsedHead {
    vault_id: VaultId,
    object_id: ObjectId,
    challenge: [u8; 32],
}

impl From<&WitnessReceipt> for IssueResponse {
    fn from(receipt: &WitnessReceipt) -> Self {
        Self {
            vault_id: receipt.vault_id().to_hex(),
            object_id: receipt.object_id().to_hex(),
            version_id: receipt.version_id().to_hex(),
            witness_epoch: receipt.witness_epoch(),
            commitment: hex::encode(receipt.commitment()),
            public_key: hex::encode(receipt.public_key()),
            signature: hex::encode(receipt.signature()),
        }
    }
}

impl From<&WitnessHead> for HeadResponse {
    fn from(head: &WitnessHead) -> Self {
        Self {
            vault_id: head.vault_id().to_hex(),
            object_id: head.object_id().to_hex(),
            present: head.present(),
            version_id: head.version_id().map(VersionId::to_hex),
            witness_epoch: head.witness_epoch(),
            commitment: head.commitment().map(hex::encode),
            challenge: hex::encode(head.challenge()),
            public_key: hex::encode(head.public_key()),
            signature: hex::encode(head.signature()),
        }
    }
}

fn next_epoch(
    transaction: &rusqlite::Transaction<'_>,
    vault_id: VaultId,
) -> Result<u64, VaultError> {
    let next: Option<u64> = transaction
        .query_row(
            "SELECT next_epoch FROM vault_epochs WHERE vault_id = ?1",
            params![vault_id.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| VaultError::Storage)?;
    let epoch = next.unwrap_or(1);
    let after = epoch
        .checked_add(1)
        .ok_or(VaultError::Invariant("witness epoch exhausted"))?;
    transaction
        .execute(
            "INSERT INTO vault_epochs(vault_id, next_epoch) VALUES(?1, ?2) \
             ON CONFLICT(vault_id) DO UPDATE SET next_epoch = excluded.next_epoch",
            params![vault_id.as_bytes().as_slice(), after],
        )
        .map_err(|_| VaultError::Storage)?;
    Ok(epoch)
}

fn load_receipt(
    connection: &Connection,
    vault_id: VaultId,
    object_id: ObjectId,
    public_key: [u8; 32],
) -> Result<Option<WitnessReceipt>, VaultError> {
    let row = connection
        .query_row(
            "SELECT version_id, witness_epoch, commitment, signature FROM object_heads \
             WHERE vault_id = ?1 AND object_id = ?2",
            params![
                vault_id.as_bytes().as_slice(),
                object_id.as_bytes().as_slice()
            ],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, u64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            },
        )
        .optional()
        .map_err(|_| VaultError::Storage)?;
    let Some((version_id, epoch, commitment, signature)) = row else {
        return Ok(None);
    };
    WitnessReceipt::new(
        vault_id,
        object_id,
        VersionId::from_slice(&version_id)?,
        epoch,
        fixed::<32>(&commitment)?,
        public_key,
        fixed::<64>(&signature)?,
    )
    .map(Some)
}

fn parse_issue(request: &IssueRequest) -> Result<ParsedIssue, VaultError> {
    let vault_id = parse_id::<16>(&request.vault_id, "witness vault ID")?;
    let object_id = parse_id::<16>(&request.object_id, "witness object ID")?;
    let version_id = parse_id::<16>(&request.version_id, "witness version ID")?;
    Ok(ParsedIssue {
        request: WitnessRequest::from_parts(
            VaultId::from_slice(&vault_id)?,
            ObjectId::from_slice(&object_id)?,
            VersionId::from_slice(&version_id)?,
            parse_id::<32>(&request.commitment, "witness commitment")?,
        ),
        expected_epoch: request.expected_epoch,
    })
}

fn parse_head(request: &HeadRequest) -> Result<ParsedHead, VaultError> {
    Ok(ParsedHead {
        vault_id: VaultId::from_slice(&parse_id::<16>(&request.vault_id, "witness vault ID")?)?,
        object_id: ObjectId::from_slice(&parse_id::<16>(&request.object_id, "witness object ID")?)?,
        challenge: parse_id::<32>(&request.challenge, "witness challenge")?,
    })
}

fn parse_id<const N: usize>(value: &str, error: &'static str) -> Result<[u8; N], VaultError> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|item| item.is_ascii_hexdigit() && !item.is_ascii_uppercase())
    {
        return Err(VaultError::invalid_format(error));
    }
    let bytes = hex::decode(value).map_err(|_| VaultError::invalid_format(error))?;
    fixed::<N>(&bytes)
}

fn validate_state_path(path: &Path) -> Result<(), VaultError> {
    const INPUT: &str = "witness state path";
    let parent = path.parent().ok_or(VaultError::InvalidInput(INPUT))?;
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    for ancestor in parent
        .ancestors()
        .filter(|path| !path.as_os_str().is_empty())
    {
        let metadata =
            fs::symlink_metadata(ancestor).map_err(|_| VaultError::InvalidInput(INPUT))?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
            return Err(VaultError::InvalidInput(INPUT));
        }
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() && !metadata.file_type().is_symlink() => {
            Ok(())
        }
        Ok(_) => Err(VaultError::InvalidInput(INPUT)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(VaultError::Storage),
    }
}

fn fixed<const N: usize>(value: &[u8]) -> Result<[u8; N], VaultError> {
    value
        .try_into()
        .map_err(|_| VaultError::invalid_format("witness fixed-width field"))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use ed25519_dalek::SigningKey;
    use tempfile::tempdir;
    use vlt1_core::{ObjectId, VaultError, VaultId, VersionId};

    use super::{HeadRequest, IssueRequest, WitnessService};

    fn issue_request(
        vault_id: VaultId,
        object_id: ObjectId,
        version_id: VersionId,
    ) -> IssueRequest {
        IssueRequest {
            vault_id: vault_id.to_hex(),
            object_id: object_id.to_hex(),
            version_id: version_id.to_hex(),
            commitment: "11".repeat(32),
            expected_epoch: 0,
        }
    }

    #[test]
    fn witness_state_rejects_symlink_paths_and_symlinked_parent_directories() {
        let directory = tempdir().expect("directory");
        let target = directory.path().join("target.sqlite");
        let state_link = directory.path().join("state-link.sqlite");
        symlink(&target, &state_link).expect("state symlink");
        assert!(WitnessService::open(&state_link, SigningKey::from_bytes(&[7; 32])).is_err());

        let parent_link = directory.path().join("state-parent-link");
        symlink(directory.path(), &parent_link).expect("parent symlink");
        assert!(WitnessService::open(
            parent_link.join("witness.sqlite"),
            SigningKey::from_bytes(&[7; 32]),
        )
        .is_err());
    }

    #[test]
    fn issue_is_idempotent_and_stale_requests_do_not_advance_state() {
        let directory = tempdir().expect("directory");
        let mut service = WitnessService::open(
            directory.path().join("witness.sqlite"),
            SigningKey::from_bytes(&[7; 32]),
        )
        .expect("witness open");
        let vault_id = VaultId::random();
        let object_id = ObjectId::random();
        let version_id = VersionId::random();
        let first = service
            .issue_wire(&issue_request(vault_id, object_id, version_id))
            .expect("first issue");
        let repeated = service
            .issue_wire(&issue_request(vault_id, object_id, version_id))
            .expect("idempotent issue");
        assert_eq!(first.witness_epoch, repeated.witness_epoch);

        let stale = IssueRequest {
            version_id: VersionId::random().to_hex(),
            ..issue_request(vault_id, object_id, version_id)
        };
        assert!(matches!(
            service.issue_wire(&stale),
            Err(VaultError::WitnessConflict)
        ));
        let head = service
            .head_wire(&HeadRequest {
                vault_id: vault_id.to_hex(),
                object_id: object_id.to_hex(),
                challenge: "22".repeat(32),
            })
            .expect("head");
        assert!(head.present);
        assert_eq!(head.witness_epoch, first.witness_epoch);
    }
}
