// Copyright Nixort & Itan Winter <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 or later.
//
// VLT/1 — local Unix-socket vault daemon.

//! # VLT/1 daemon
//!
//! `vlt1d` owns a local vault and exposes only a bounded Unix-domain socket
//! protocol. The daemon validates Linux peer UID credentials, serializes vault
//! state through a mutex and never exposes Root Key, KEK or DEK material.
#![forbid(unsafe_code)]

use std::{
    fs, io,
    os::unix::{
        fs::{FileTypeExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use nix::{
    sys::socket::{getsockopt, sockopt::PeerCredentials},
    unistd::Uid,
};
use vlt1_core::{HttpsWitnessProvider, ObjectId, Vault, VaultError, VaultStatus};
use vlt1_protocol::{
    read_frame, read_stream_item, write_frame, write_stream_chunk, write_stream_end,
    write_stream_error, ErrorCode, Failure, Request, Response, StreamItem, Success,
    MAX_STREAM_CHUNK_BYTES,
};
use zeroize::Zeroize;

const DEFAULT_MAX_CONNECTIONS: usize = 32;
const DEFAULT_IO_TIMEOUT: Duration = Duration::from_secs(5);

/// Runtime configuration for one daemon-owned VLT/1 vault.
#[derive(Clone, Debug)]
pub struct DaemonConfig {
    /// Local Unix-domain socket path.
    pub socket_path: PathBuf,
    /// Persistent VLT/1 `SQLite` database path.
    pub vault_path: PathBuf,
    /// Linux UID permitted by the peer-credential check.
    pub allowed_uid: u32,
    /// Enables the test/maintenance `shutdown` request.
    pub allow_shutdown: bool,
    /// Optional independently operated external freshness witness policy.
    pub witness: Option<WitnessConfig>,
    /// Maximum concurrently admitted local socket connections.
    pub max_connections: usize,
    /// Nonzero read and write deadline applied to every admitted connection.
    pub io_timeout: Duration,
}

/// Pinned authentication material for one external VLT/1 freshness witness.
///
/// The optional previous key is a temporary, operator-controlled rollover
/// overlap. It must be removed after every vault observes the primary key.
#[derive(Clone, Debug)]
pub struct WitnessConfig {
    /// Canonical HTTPS witness endpoint without a trailing path.
    pub endpoint: String,
    /// High-entropy request authorization credential.
    pub bearer_token: String,
    /// Independently provisioned primary Ed25519 verification key.
    pub public_key: [u8; 32],
    /// One optional previous Ed25519 key accepted only during planned rollover.
    pub previous_public_key: Option<[u8; 32]>,
}

impl DaemonConfig {
    /// Builds a same-user local configuration.
    #[must_use]
    pub fn for_current_user(socket_path: PathBuf, vault_path: PathBuf) -> Self {
        Self {
            socket_path,
            vault_path,
            allowed_uid: Uid::current().as_raw(),
            allow_shutdown: false,
            witness: None,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            io_timeout: DEFAULT_IO_TIMEOUT,
        }
    }
}

/// An owned VLT/1 daemon state machine.
#[derive(Clone)]
pub struct Daemon {
    state: Arc<DaemonState>,
}

struct DaemonState {
    config: DaemonConfig,
    vault: Mutex<Vault>,
    recovery: Mutex<RecoveryState>,
    witness: Option<Mutex<HttpsWitnessProvider>>,
    active_connections: AtomicUsize,
    long_operation_active: AtomicBool,
    shutdown: AtomicBool,
}

struct RecoveryState {
    startup_scan: &'static str,
    verified_active_objects: Option<u64>,
}

struct ConnectionPermit {
    state: Arc<DaemonState>,
}

struct LongOperationPermit {
    state: Arc<DaemonState>,
}

struct StreamReader<'stream> {
    stream: &'stream mut UnixStream,
    current: Vec<u8>,
    offset: usize,
    finished: bool,
}

struct StreamWriter<'stream> {
    stream: &'stream mut UnixStream,
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        self.state
            .active_connections
            .fetch_sub(1, Ordering::Release);
    }
}

impl Drop for LongOperationPermit {
    fn drop(&mut self) {
        self.state
            .long_operation_active
            .store(false, Ordering::Release);
    }
}

impl Daemon {
    /// Opens a vault database in the locked daemon state.
    ///
    /// # Errors
    ///
    /// Returns an error when the vault database cannot be opened or its Root Key
    /// envelope violates the VLT/1 format contract.
    pub fn open(config: DaemonConfig) -> Result<Self, VaultError> {
        if config.max_connections == 0 || config.io_timeout.is_zero() {
            return Err(VaultError::InvalidInput("daemon resource configuration"));
        }
        let vault = Vault::open(&config.vault_path)?;
        let witness = config
            .witness
            .as_ref()
            .map(|policy| {
                HttpsWitnessProvider::new_with_previous(
                    &policy.endpoint,
                    &policy.bearer_token,
                    policy.public_key,
                    policy.previous_public_key,
                )
            })
            .transpose()?
            .map(Mutex::new);
        Ok(Self {
            state: Arc::new(DaemonState {
                config,
                vault: Mutex::new(vault),
                recovery: Mutex::new(RecoveryState {
                    startup_scan: "startup_integrity_ok",
                    verified_active_objects: None,
                }),
                witness,
                active_connections: AtomicUsize::new(0),
                long_operation_active: AtomicBool::new(false),
                shutdown: AtomicBool::new(false),
            }),
        })
    }

    /// Runs the blocking Unix-socket accept loop until an authorised shutdown.
    ///
    /// # Errors
    ///
    /// Returns an error when the socket cannot be prepared, bound or accepted.
    pub fn serve(&self) -> io::Result<()> {
        let listener = bind_socket(&self.state.config.socket_path)?;
        listener.set_nonblocking(true)?;
        while !self.state.shutdown.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    if let Some(permit) = self.try_acquire_connection() {
                        let daemon = self.clone();
                        thread::spawn(move || {
                            let _permit = permit;
                            let _ = daemon.serve_stream(stream);
                        });
                    } else {
                        reject_overloaded(&mut stream);
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(std::time::Duration::from_millis(5));
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
        fs::remove_file(&self.state.config.socket_path).or_else(ignore_not_found)?;
        Ok(())
    }

    /// Handles exactly one stream exchange; exposed for deterministic integration tests.
    ///
    /// # Errors
    ///
    /// Returns an error only when a response cannot be written. Protocol and
    /// vault failures are converted into safe response frames.
    pub fn serve_stream(&self, mut stream: UnixStream) -> io::Result<()> {
        stream.set_read_timeout(Some(self.state.config.io_timeout))?;
        stream.set_write_timeout(Some(self.state.config.io_timeout))?;
        match self.authorize(&stream) {
            Ok(()) => match read_frame::<Request, _>(&mut stream) {
                Ok(Request::PutStream { object_id }) => self.put_stream(&mut stream, &object_id),
                Ok(Request::GetStream { object_id }) => self.get_stream(&mut stream, &object_id),
                Ok(request) => write_response(&mut stream, &self.dispatch(request)),
                Err(_) => write_response(
                    &mut stream,
                    &Response::Error {
                        error: failure(ErrorCode::Protocol, "invalid local protocol request"),
                    },
                ),
            },
            Err(()) => write_response(
                &mut stream,
                &Response::Error {
                    error: failure(ErrorCode::Unauthorized, "local peer is not authorized"),
                },
            ),
        }
    }

    fn try_acquire_long_operation(&self) -> Option<LongOperationPermit> {
        self.state
            .long_operation_active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| LongOperationPermit {
                state: Arc::clone(&self.state),
            })
    }

    fn try_acquire_connection(&self) -> Option<ConnectionPermit> {
        let active = &self.state.active_connections;
        loop {
            let observed = active.load(Ordering::Acquire);
            if observed >= self.state.config.max_connections {
                return None;
            }
            if active
                .compare_exchange_weak(observed, observed + 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Some(ConnectionPermit {
                    state: Arc::clone(&self.state),
                });
            }
        }
    }

    /// Returns whether an authorised shutdown has been requested.
    #[must_use]
    pub fn shutdown_requested(&self) -> bool {
        self.state.shutdown.load(Ordering::SeqCst)
    }

    fn authorize(&self, stream: &UnixStream) -> Result<(), ()> {
        let credential = getsockopt(stream, PeerCredentials).map_err(|_| ())?;
        if credential.uid() == self.state.config.allowed_uid {
            Ok(())
        } else {
            Err(())
        }
    }

    fn dispatch(&self, request: Request) -> Response {
        if self.state.long_operation_active.load(Ordering::Acquire)
            && !matches!(request, Request::Shutdown)
        {
            return overloaded_response("daemon long operation is in progress");
        }
        match request {
            Request::Status => self.status(),
            Request::Unlock { passphrase } => self.unlock(&passphrase),
            Request::Lock => self.with_vault(|vault| {
                vault.lock();
                Ok(Success::Empty)
            }),
            Request::Put {
                object_id,
                plaintext_b64,
            } => self.put(&object_id, &plaintext_b64),
            Request::Get { object_id } => self.get(&object_id),
            Request::PutStream { .. } | Request::GetStream { .. } => Response::Error {
                error: failure(
                    ErrorCode::Protocol,
                    "streaming request was not handled as a stream",
                ),
            },
            Request::RotatePassphrase {
                current_passphrase,
                replacement_passphrase,
            } => self.with_vault(|vault| {
                vault.rotate_passphrase(&current_passphrase, &replacement_passphrase)?;
                Ok(Success::Empty)
            }),
            Request::Verify => self.verify(),
            Request::Checkpoint => self.with_vault(|vault| {
                vault.full_checkpoint()?;
                Ok(Success::Empty)
            }),
            Request::Backup { destination } => self.backup(Path::new(&destination)),
            Request::Shutdown => {
                if self.state.config.allow_shutdown {
                    self.state.shutdown.store(true, Ordering::SeqCst);
                    Response::Ok {
                        result: Success::Empty,
                    }
                } else {
                    Response::Error {
                        error: failure(ErrorCode::Policy, "daemon shutdown is disabled by policy"),
                    }
                }
            }
        }
    }

    fn status(&self) -> Response {
        if self.state.long_operation_active.load(Ordering::Acquire) {
            return overloaded_response("daemon long operation is in progress");
        }
        let (vault_id, lifecycle) = {
            let Ok(vault) = self.state.vault.lock() else {
                return Response::Error {
                    error: failure(ErrorCode::Internal, "daemon state is unavailable"),
                };
            };
            let lifecycle = match vault.status() {
                VaultStatus::Locked => "locked",
                VaultStatus::Unlocked => "unlocked",
            };
            (vault.vault_id().to_hex(), lifecycle.to_owned())
        };
        let Ok(recovery) = self.state.recovery.lock() else {
            return Response::Error {
                error: failure(ErrorCode::Internal, "daemon recovery state is unavailable"),
            };
        };
        Response::Ok {
            result: Success::Status {
                format: "VLT/1".to_owned(),
                vault_id,
                lifecycle,
                recovery: recovery.startup_scan.to_owned(),
                verified_active_objects: recovery.verified_active_objects,
            },
        }
    }

    fn unlock(&self, passphrase: &str) -> Response {
        if self.state.witness.is_some() {
            self.with_witness(|vault, witness| {
                vault.unlock(passphrase)?;
                vault.recover_pending_witness_publications(witness)?;
                vault.verify_active_objects_with_witness(witness)?;
                Ok(Success::Empty)
            })
        } else {
            self.with_vault(|vault| {
                vault.unlock(passphrase)?;
                Ok(Success::Empty)
            })
        }
    }

    fn verify(&self) -> Response {
        let Some(_permit) = self.try_acquire_long_operation() else {
            return overloaded_response("daemon long operation is in progress");
        };
        let result = if self.state.witness.is_some() {
            self.with_witness_result(|vault, witness| {
                vault.verify_active_objects_with_witness(witness)
            })
        } else {
            self.with_vault_result(Vault::verify_active_objects)
        };
        match result {
            Ok(active_objects) => {
                let Ok(mut recovery) = self.state.recovery.lock() else {
                    return Response::Error {
                        error: failure(ErrorCode::Internal, "daemon recovery state is unavailable"),
                    };
                };
                recovery.verified_active_objects = Some(active_objects);
                Response::Ok {
                    result: Success::Verified { active_objects },
                }
            }
            Err(error) => Response::Error {
                error: map_vault_error(&error),
            },
        }
    }

    fn backup(&self, destination: &Path) -> Response {
        let Some(_permit) = self.try_acquire_long_operation() else {
            return overloaded_response("daemon long operation is in progress");
        };
        self.with_vault(|vault| {
            let manifest = vault.backup_to(destination)?;
            Ok(Success::Backup {
                format: manifest.format().to_owned(),
                database_sha256: manifest.database_sha256().to_owned(),
                database_bytes: manifest.database_bytes(),
            })
        })
    }

    fn put(&self, object_id: &str, plaintext_b64: &str) -> Response {
        let object_id = match parse_object_id(object_id) {
            Ok(object_id) => object_id,
            Err(response) => return response,
        };
        let Ok(plaintext) = STANDARD.decode(plaintext_b64) else {
            return Response::Error {
                error: failure(ErrorCode::InvalidInput, "plaintext is not valid base64"),
            };
        };
        if self.state.witness.is_some() {
            self.with_witness(|vault, witness| {
                let version = vault.put_with_witness(object_id, &plaintext, witness)?;
                Ok(Success::Published {
                    version_id: version.to_hex(),
                })
            })
        } else {
            self.with_vault(|vault| {
                let version = vault.put(object_id, &plaintext)?;
                Ok(Success::Published {
                    version_id: version.to_hex(),
                })
            })
        }
    }

    fn put_stream(&self, stream: &mut UnixStream, object_id: &str) -> io::Result<()> {
        let Some(_permit) = self.try_acquire_long_operation() else {
            return write_response(
                stream,
                &overloaded_response("daemon long operation is in progress"),
            );
        };
        let object_id = match parse_object_id(object_id) {
            Ok(object_id) => object_id,
            Err(response) => return write_response(stream, &response),
        };
        write_response(
            stream,
            &Response::Ok {
                result: Success::StreamReady,
            },
        )?;
        let result = {
            let Ok(mut vault) = self.state.vault.lock() else {
                return write_stream_failure(
                    stream,
                    ErrorCode::Internal,
                    "daemon state is unavailable",
                );
            };
            let mut reader = StreamReader::new(stream);
            vault.put_from_reader(object_id, &mut reader)
        };
        match result {
            Ok(version_id) => write_response(
                stream,
                &Response::Ok {
                    result: Success::Published {
                        version_id: version_id.to_hex(),
                    },
                },
            ),
            Err(error) => write_stream_response(
                stream,
                &Response::Error {
                    error: map_vault_error(&error),
                },
            ),
        }
    }

    fn get_stream(&self, stream: &mut UnixStream, object_id: &str) -> io::Result<()> {
        let Some(_permit) = self.try_acquire_long_operation() else {
            return write_response(
                stream,
                &overloaded_response("daemon long operation is in progress"),
            );
        };
        let object_id = match parse_object_id(object_id) {
            Ok(object_id) => object_id,
            Err(response) => return write_response(stream, &response),
        };
        write_response(
            stream,
            &Response::Ok {
                result: Success::StreamReady,
            },
        )?;
        let result = {
            let Ok(mut vault) = self.state.vault.lock() else {
                return write_stream_failure(
                    stream,
                    ErrorCode::Internal,
                    "daemon state is unavailable",
                );
            };
            let mut writer = StreamWriter::new(stream);
            vault.get_to_writer(object_id, &mut writer)
        };
        match result {
            Ok(()) => write_stream_end(stream)
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "stream end write failed")),
            Err(error) => write_stream_response(
                stream,
                &Response::Error {
                    error: map_vault_error(&error),
                },
            ),
        }
    }

    fn get(&self, object_id: &str) -> Response {
        let object_id = match parse_object_id(object_id) {
            Ok(object_id) => object_id,
            Err(response) => return response,
        };
        if self.state.witness.is_some() {
            self.with_witness(|vault, witness| {
                vault.verify_active_objects_with_witness(witness)?;
                let plaintext = vault.get(object_id)?;
                Ok(Success::Plaintext {
                    plaintext_b64: STANDARD.encode(plaintext),
                })
            })
        } else {
            self.with_vault(|vault| {
                let plaintext = vault.get(object_id)?;
                Ok(Success::Plaintext {
                    plaintext_b64: STANDARD.encode(plaintext),
                })
            })
        }
    }

    fn with_witness<F>(&self, operation: F) -> Response
    where
        F: FnOnce(&mut Vault, &mut HttpsWitnessProvider) -> Result<Success, VaultError>,
    {
        let Some(witness) = &self.state.witness else {
            return Response::Error {
                error: failure(ErrorCode::Policy, "external witness is not configured"),
            };
        };
        let Ok(mut witness) = witness.lock() else {
            return Response::Error {
                error: failure(ErrorCode::Internal, "witness state is unavailable"),
            };
        };
        let Ok(mut vault) = self.state.vault.lock() else {
            return Response::Error {
                error: failure(ErrorCode::Internal, "daemon state is unavailable"),
            };
        };
        match operation(&mut vault, &mut witness) {
            Ok(result) => Response::Ok { result },
            Err(error) => Response::Error {
                error: map_vault_error(&error),
            },
        }
    }

    fn with_witness_result<F>(&self, operation: F) -> Result<u64, VaultError>
    where
        F: FnOnce(&mut Vault, &mut HttpsWitnessProvider) -> Result<u64, VaultError>,
    {
        let witness = self
            .state
            .witness
            .as_ref()
            .ok_or(VaultError::WitnessUnavailable)?;
        let mut witness = witness.lock().map_err(|_| VaultError::Storage)?;
        let mut vault = self.state.vault.lock().map_err(|_| VaultError::Storage)?;
        operation(&mut vault, &mut witness)
    }

    fn with_vault_result<F>(&self, operation: F) -> Result<u64, VaultError>
    where
        F: FnOnce(&mut Vault) -> Result<u64, VaultError>,
    {
        let mut vault = self.state.vault.lock().map_err(|_| VaultError::Storage)?;
        operation(&mut vault)
    }

    fn with_vault<F>(&self, operation: F) -> Response
    where
        F: FnOnce(&mut Vault) -> Result<Success, VaultError>,
    {
        let Ok(mut vault) = self.state.vault.lock() else {
            return Response::Error {
                error: failure(ErrorCode::Internal, "daemon state is unavailable"),
            };
        };
        match operation(&mut vault) {
            Ok(result) => Response::Ok { result },
            Err(error) => Response::Error {
                error: map_vault_error(&error),
            },
        }
    }
}

impl Drop for StreamReader<'_> {
    fn drop(&mut self) {
        self.current.zeroize();
    }
}

impl StreamReader<'_> {
    fn new(stream: &mut UnixStream) -> StreamReader<'_> {
        StreamReader {
            stream,
            current: Vec::new(),
            offset: 0,
            finished: false,
        }
    }
}

impl io::Read for StreamReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        while self.offset == self.current.len() {
            self.current.zeroize();
            self.current.clear();
            self.offset = 0;
            if self.finished {
                return Ok(0);
            }
            match read_stream_item(self.stream) {
                Ok(StreamItem::Data(data)) => self.current = data,
                Ok(StreamItem::End) => {
                    self.finished = true;
                    return Ok(0);
                }
                Ok(StreamItem::Error(_)) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "client aborted binary stream",
                    ));
                }
                Err(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid binary stream frame",
                    ));
                }
            }
        }
        let available = &self.current[self.offset..];
        let copied = available.len().min(buffer.len());
        buffer[..copied].copy_from_slice(&available[..copied]);
        self.offset += copied;
        Ok(copied)
    }
}

impl StreamWriter<'_> {
    fn new(stream: &mut UnixStream) -> StreamWriter<'_> {
        StreamWriter { stream }
    }
}

impl io::Write for StreamWriter<'_> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        for chunk in buffer.chunks(MAX_STREAM_CHUNK_BYTES) {
            write_stream_chunk(self.stream, chunk).map_err(|_| {
                io::Error::new(io::ErrorKind::BrokenPipe, "binary stream write failed")
            })?;
        }
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn write_response(stream: &mut UnixStream, response: &Response) -> io::Result<()> {
    write_frame(stream, response)
        .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "response write failed"))
}

fn write_stream_response(stream: &mut UnixStream, response: &Response) -> io::Result<()> {
    write_stream_error(stream, response)
        .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "stream error write failed"))
}

fn write_stream_failure(stream: &mut UnixStream, code: ErrorCode, message: &str) -> io::Result<()> {
    write_stream_response(
        stream,
        &Response::Error {
            error: failure(code, message),
        },
    )
}

fn overloaded_response(message: &str) -> Response {
    Response::Error {
        error: failure(ErrorCode::Overloaded, message),
    }
}

fn reject_overloaded(stream: &mut UnixStream) {
    let _ = stream.set_write_timeout(Some(Duration::from_millis(100)));
    let response = overloaded_response("daemon connection limit reached");
    let _ = write_frame(stream, &response);
}

fn bind_socket(path: &Path) -> io::Result<UnixListener> {
    if path.exists() {
        let metadata = fs::symlink_metadata(path)?;
        if metadata.file_type().is_socket() {
            fs::remove_file(path)?;
        } else {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "refusing to replace a non-socket path",
            ));
        }
    }
    let listener = UnixListener::bind(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

fn ignore_not_found(error: io::Error) -> io::Result<()> {
    if error.kind() == io::ErrorKind::NotFound {
        Ok(())
    } else {
        Err(error)
    }
}

fn parse_object_id(text: &str) -> Result<ObjectId, Response> {
    if text.len() != 32 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Response::Error {
            error: failure(
                ErrorCode::InvalidInput,
                "object identifier must be 32 hexadecimal characters",
            ),
        });
    }
    let mut bytes = [0u8; 16];
    for (index, pair) in text.as_bytes().chunks_exact(2).enumerate() {
        let Ok(pair) = std::str::from_utf8(pair) else {
            return Err(Response::Error {
                error: failure(ErrorCode::InvalidInput, "object identifier is malformed"),
            });
        };
        bytes[index] = match u8::from_str_radix(pair, 16) {
            Ok(byte) => byte,
            Err(_) => {
                return Err(Response::Error {
                    error: failure(ErrorCode::InvalidInput, "object identifier is malformed"),
                })
            }
        };
    }
    ObjectId::from_slice(&bytes).map_err(|_| Response::Error {
        error: failure(ErrorCode::InvalidInput, "object identifier is malformed"),
    })
}

fn failure(code: ErrorCode, message: &str) -> Failure {
    Failure {
        code,
        message: message.to_owned(),
    }
}

fn map_vault_error(error: &VaultError) -> Failure {
    let (code, message) = match error {
        VaultError::Locked => (ErrorCode::Locked, "vault is locked"),
        VaultError::NotFound => (ErrorCode::NotFound, "requested object was not found"),
        VaultError::InvalidInput(_) => (ErrorCode::InvalidInput, "request input is invalid"),
        VaultError::UnlockFailed | VaultError::Authentication | VaultError::Invariant(_) => {
            (ErrorCode::Verification, "vault verification failed")
        }
        VaultError::InvalidFormat(_) => {
            (ErrorCode::Verification, "vault format verification failed")
        }
        VaultError::Storage => (ErrorCode::Storage, "vault storage operation failed"),
        VaultError::WitnessUnavailable => (
            ErrorCode::WitnessUnavailable,
            "freshness witness is unavailable",
        ),
        VaultError::WitnessConflict => (
            ErrorCode::WitnessConflict,
            "freshness witness state conflicts with local vault state",
        ),
    };
    failure(code, message)
}
