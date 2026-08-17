// Copyright Nixort & Itan Winter <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 or later.
//
// VLT/1 — bounded local daemon protocol.

//! # VLT/1 local IPC protocol
//!
//! The protocol carries one JSON request and one JSON response per local
//! Unix-domain connection. Each message is framed by a four-byte big-endian
//! length and is rejected before decoding if it exceeds [`MAX_FRAME_BYTES`].
//! Unknown command fields are rejected by `serde`.
#![forbid(unsafe_code)]

use std::io::{Read, Write};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Maximum accepted request or response frame size.
pub const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

/// Closed set of client operations accepted by `vlt1d`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    /// Returns non-secret daemon and vault metadata.
    Status,
    /// Unlocks the daemon-held vault with a local passphrase.
    Unlock {
        /// Passphrase transported only over the protected local socket.
        passphrase: String,
    },
    /// Explicitly clears the daemon-held Root Key.
    Lock,
    /// Publishes a base64 plaintext as a new immutable version.
    Put {
        /// 32-character lowercase hexadecimal object identifier.
        object_id: String,
        /// Standard base64 plaintext payload.
        plaintext_b64: String,
    },
    /// Fully verifies and returns the active object version as base64 plaintext.
    Get {
        /// 32-character lowercase hexadecimal object identifier.
        object_id: String,
    },
    /// Re-wraps the Root Key under a replacement passphrase and locks the vault.
    RotatePassphrase {
        /// Current passphrase used to authenticate the Root Key envelope.
        current_passphrase: String,
        /// Replacement passphrase used for a new Root Key envelope.
        replacement_passphrase: String,
    },
    /// Verifies all active object versions after the vault is unlocked.
    Verify,
    /// Runs a `SQLite` FULL WAL checkpoint after the vault is unlocked.
    Checkpoint,
    /// Creates a consistent encrypted online backup and sidecar manifest.
    Backup {
        /// New backup `SQLite` destination path; daemon refuses to overwrite it.
        destination: String,
    },
    /// Stops the daemon. Disabled unless the daemon was explicitly configured for it.
    Shutdown,
}

/// Closed set of successful result payloads.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Success {
    /// A no-payload operation completed.
    Empty,
    /// Non-secret daemon status.
    Status {
        /// VLT/1 format label.
        format: String,
        /// Stable lowercase hexadecimal vault identifier.
        vault_id: String,
        /// `locked` or `unlocked` lifecycle state.
        lifecycle: String,
        /// Database integrity scan state observed during startup.
        recovery: String,
        /// Number of verified active objects when known.
        verified_active_objects: Option<u64>,
    },
    /// A new immutable version was published.
    Published {
        /// New 32-character lowercase hexadecimal version identifier.
        version_id: String,
    },
    /// Fully verified base64 plaintext.
    Plaintext {
        /// Standard base64 plaintext payload.
        plaintext_b64: String,
    },
    /// Result of an all-active-object verification pass.
    Verified {
        /// Number of active object versions verified.
        active_objects: u64,
    },
    /// Metadata for a successfully created encrypted online backup.
    Backup {
        /// Stable backup format marker.
        format: String,
        /// Lowercase hexadecimal SHA-256 of the encrypted snapshot database.
        database_sha256: String,
        /// Exact encrypted snapshot file length.
        database_bytes: u64,
    },
}

/// Error response that deliberately avoids sensitive diagnostics.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Failure {
    /// Stable machine-readable error category.
    pub code: ErrorCode,
    /// Safe, non-secret explanatory message.
    pub message: String,
}

/// Stable error categories returned by the daemon.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// Protocol framing or JSON was malformed.
    Protocol,
    /// Caller peer credentials were not permitted.
    Unauthorized,
    /// Requested operation needs an unlocked vault.
    Locked,
    /// Requested item was absent.
    NotFound,
    /// Input was not valid for the requested operation.
    InvalidInput,
    /// Authentication or integrity verification failed.
    Verification,
    /// A storage operation failed.
    Storage,
    /// Independently configured freshness witness could not be reached.
    WitnessUnavailable,
    /// Witness state contradicted the locally authenticated active state.
    WitnessConflict,
    /// Daemon admission controls rejected the connection without dispatching it.
    Overloaded,
    /// The requested operation is disabled by daemon policy.
    Policy,
    /// An internal failure occurred; details are retained only in daemon logs.
    Internal,
}

/// One protocol response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum Response {
    /// Successful response.
    Ok {
        /// Operation-specific successful result.
        result: Success,
    },
    /// Failed response.
    Error {
        /// Stable error category and safe message.
        error: Failure,
    },
}

/// Framing or JSON serialization error.
#[derive(Debug, Error)]
pub enum ProtocolError {
    /// The peer ended a frame before all bytes arrived.
    #[error("truncated protocol frame")]
    Truncated,
    /// The frame length was zero or exceeded the fixed protocol limit.
    #[error("invalid protocol frame length")]
    InvalidLength,
    /// JSON did not match the closed request or response schema.
    #[error("invalid protocol JSON")]
    InvalidJson,
    /// A stream operation failed without exposing an implementation-specific error.
    #[error("protocol stream I/O failed")]
    Io,
}

/// Reads and decodes one bounded request or response frame.
///
/// # Errors
///
/// Returns [`ProtocolError`] when the peer truncates a frame, sends an invalid
/// length, supplies malformed JSON or the stream cannot be read.
pub fn read_frame<T: for<'de> Deserialize<'de>, R: Read>(
    reader: &mut R,
) -> Result<T, ProtocolError> {
    let mut length_bytes = [0u8; 4];
    read_exact(reader, &mut length_bytes)?;
    let length = usize::try_from(u32::from_be_bytes(length_bytes))
        .map_err(|_| ProtocolError::InvalidLength)?;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(ProtocolError::InvalidLength);
    }
    let mut body = vec![0u8; length];
    read_exact(reader, &mut body)?;
    serde_json::from_slice(&body).map_err(|_| ProtocolError::InvalidJson)
}

/// Serializes and writes one bounded request or response frame.
///
/// # Errors
///
/// Returns [`ProtocolError`] when serialization exceeds the fixed frame limit
/// or the stream cannot be written and flushed.
pub fn write_frame<T: Serialize, W: Write>(writer: &mut W, value: &T) -> Result<(), ProtocolError> {
    let body = serde_json::to_vec(value).map_err(|_| ProtocolError::InvalidJson)?;
    if body.is_empty() || body.len() > MAX_FRAME_BYTES {
        return Err(ProtocolError::InvalidLength);
    }
    let length = u32::try_from(body.len()).map_err(|_| ProtocolError::InvalidLength)?;
    writer
        .write_all(&length.to_be_bytes())
        .map_err(|_| ProtocolError::Io)?;
    writer.write_all(&body).map_err(|_| ProtocolError::Io)?;
    writer.flush().map_err(|_| ProtocolError::Io)
}

fn read_exact<R: Read>(reader: &mut R, buffer: &mut [u8]) -> Result<(), ProtocolError> {
    reader.read_exact(buffer).map_err(|error| {
        if error.kind() == std::io::ErrorKind::UnexpectedEof {
            ProtocolError::Truncated
        } else {
            ProtocolError::Io
        }
    })
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::{read_frame, write_frame, ProtocolError, Request, MAX_FRAME_BYTES};

    #[test]
    fn request_round_trip_is_stable() {
        let request = Request::Get {
            object_id: "00".repeat(16),
        };
        let mut bytes = Cursor::new(Vec::new());
        write_frame(&mut bytes, &request).expect("write request");
        bytes.set_position(0);
        assert_eq!(
            read_frame::<Request, _>(&mut bytes).expect("read request"),
            request
        );
    }

    #[test]
    fn oversize_length_is_rejected_before_allocation() {
        let length = u32::try_from(MAX_FRAME_BYTES + 1)
            .expect("protocol maximum must fit into u32")
            .to_be_bytes();
        let mut bytes = Cursor::new(length.to_vec());
        assert!(matches!(
            read_frame::<Request, _>(&mut bytes),
            Err(ProtocolError::InvalidLength)
        ));
    }
}
