// Copyright Nixort & Itan Winter <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 or later.

//! VLT/1 local daemon client and direct vault bootstrap command.

use std::{
    fs::{self, File},
    io::Write,
    os::unix::{fs::PermissionsExt, net::UnixStream},
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use clap::{Parser, Subcommand};
use rpassword::prompt_password;
use tempfile::NamedTempFile;
use vlt1_core::{manifest_path, BackupManifest, Vault};
use vlt1_protocol::{read_frame, write_frame, Request, Response, Success};

#[derive(Debug, Parser)]
#[command(name = "vlt1", version, about = "VLT/1 local daemon client")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create a new VLT/1 `SQLite` vault. Run `vlt1d` afterwards to access it.
    Init { vault: PathBuf },
    /// Return non-secret daemon and vault metadata.
    Status {
        /// Local Unix-domain daemon socket.
        #[arg(long)]
        socket: PathBuf,
    },
    /// Unlock the daemon-owned vault.
    Unlock {
        /// Local Unix-domain daemon socket.
        #[arg(long)]
        socket: PathBuf,
    },
    /// Explicitly lock the daemon-owned vault.
    Lock {
        /// Local Unix-domain daemon socket.
        #[arg(long)]
        socket: PathBuf,
    },
    /// Encrypt a file as a new immutable active object version.
    Put {
        /// Local Unix-domain daemon socket.
        #[arg(long)]
        socket: PathBuf,
        /// 32-character lowercase hexadecimal object identifier.
        #[arg(long)]
        object: String,
        /// Plaintext input file.
        #[arg(long)]
        input: PathBuf,
    },
    /// Verify and decrypt an active object into a new output file.
    Get {
        /// Local Unix-domain daemon socket.
        #[arg(long)]
        socket: PathBuf,
        /// 32-character lowercase hexadecimal object identifier.
        #[arg(long)]
        object: String,
        /// New plaintext output path; this command refuses to overwrite it.
        #[arg(long)]
        output: PathBuf,
    },
    /// Re-wrap the Root Key under a replacement passphrase and lock the daemon.
    RotatePassphrase {
        /// Local Unix-domain daemon socket.
        #[arg(long)]
        socket: PathBuf,
    },
    /// Verify every active object version after unlock.
    Verify {
        /// Local Unix-domain daemon socket.
        #[arg(long)]
        socket: PathBuf,
    },
    /// Request a full local `SQLite` WAL checkpoint after unlock.
    Checkpoint {
        /// Local Unix-domain daemon socket.
        #[arg(long)]
        socket: PathBuf,
    },
    /// Create a consistent encrypted online backup through the daemon.
    Backup {
        /// Local Unix-domain daemon socket.
        #[arg(long)]
        socket: PathBuf,
        /// New encrypted backup `SQLite` output path; refuses to overwrite it.
        #[arg(long)]
        output: PathBuf,
    },
    /// Restore a checksum-verified encrypted backup while the daemon is stopped.
    Restore {
        /// Encrypted backup `SQLite` input path.
        #[arg(long)]
        backup: PathBuf,
        /// Optional sidecar manifest path; defaults to the standard sidecar name.
        #[arg(long)]
        manifest: Option<PathBuf>,
        /// New inactive vault database output path; refuses to overwrite it.
        #[arg(long)]
        output: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Init { vault } => init(&vault),
        Command::Status { socket } => status(&socket),
        Command::Unlock { socket } => unlock(&socket),
        Command::Lock { socket } => empty(&socket, &Request::Lock, "vault locked"),
        Command::Put {
            socket,
            object,
            input,
        } => put(&socket, &object, &input),
        Command::Get {
            socket,
            object,
            output,
        } => get(&socket, &object, &output),
        Command::RotatePassphrase { socket } => rotate_passphrase(&socket),
        Command::Verify { socket } => verify(&socket),
        Command::Checkpoint { socket } => {
            empty(&socket, &Request::Checkpoint, "checkpoint completed")
        }
        Command::Backup { socket, output } => backup(&socket, &output),
        Command::Restore {
            backup,
            manifest,
            output,
        } => restore(&backup, manifest.as_deref(), &output),
    }
}

fn init(path: &Path) -> Result<()> {
    if path.exists() {
        bail!("refusing to overwrite existing vault: {}", path.display());
    }
    let parent = path
        .parent()
        .context("vault path has no parent directory")?;
    if !parent.exists() {
        bail!(
            "vault parent directory does not exist: {}",
            parent.display()
        );
    }
    let passphrase = prompt_new_passphrase()?;
    let vault = Vault::create(path, &passphrase).context("could not create VLT/1 vault")?;
    println!("created VLT/1 vault");
    println!("vault-id: {}", vault.vault_id().to_hex());
    println!("next: start vlt1d with this vault and a protected local socket");
    Ok(())
}

fn status(socket: &Path) -> Result<()> {
    match request(socket, &Request::Status)? {
        Success::Status {
            format,
            vault_id,
            lifecycle,
            recovery,
            verified_active_objects,
        } => {
            println!("format: {format}");
            println!("vault-id: {vault_id}");
            println!("lifecycle: {lifecycle}");
            println!("recovery: {recovery}");
            if let Some(active_objects) = verified_active_objects {
                println!("verified-active-objects: {active_objects}");
            }
            Ok(())
        }
        _ => bail!("daemon returned an unexpected status payload"),
    }
}

fn unlock(socket: &Path) -> Result<()> {
    let passphrase = prompt_password("Vault passphrase: ")?;
    empty(socket, &Request::Unlock { passphrase }, "vault unlocked")
}

fn put(socket: &Path, object_id: &str, input: &Path) -> Result<()> {
    let plaintext =
        fs::read(input).with_context(|| format!("could not read {}", input.display()))?;
    match request(
        socket,
        &Request::Put {
            object_id: object_id.to_owned(),
            plaintext_b64: STANDARD.encode(plaintext),
        },
    )? {
        Success::Published { version_id } => {
            println!("published immutable version: {version_id}");
            Ok(())
        }
        _ => bail!("daemon returned an unexpected put payload"),
    }
}

fn get(socket: &Path, object_id: &str, output: &Path) -> Result<()> {
    match request(
        socket,
        &Request::Get {
            object_id: object_id.to_owned(),
        },
    )? {
        Success::Plaintext { plaintext_b64 } => {
            let plaintext = STANDARD
                .decode(plaintext_b64)
                .context("daemon returned invalid plaintext base64")?;
            write_new_plaintext(output, &plaintext)?;
            println!("verified and wrote {}", output.display());
            Ok(())
        }
        _ => bail!("daemon returned an unexpected get payload"),
    }
}

fn backup(socket: &Path, output: &Path) -> Result<()> {
    if output.exists() || manifest_path(output).exists() {
        bail!(
            "refusing to overwrite backup output or sidecar: {}",
            output.display()
        );
    }
    match request(
        socket,
        &Request::Backup {
            destination: output.to_string_lossy().into_owned(),
        },
    )? {
        Success::Backup {
            format,
            database_sha256,
            database_bytes,
        } => {
            println!("backup format: {format}");
            println!("backup database SHA-256: {database_sha256}");
            println!("backup bytes: {database_bytes}");
            println!("backup sidecar: {}", manifest_path(output).display());
            Ok(())
        }
        _ => bail!("daemon returned an unexpected backup payload"),
    }
}

fn restore(backup: &Path, manifest: Option<&Path>, output: &Path) -> Result<()> {
    let manifest_path = manifest.map_or_else(|| manifest_path(backup), Path::to_path_buf);
    let manifest = BackupManifest::read_from(&manifest_path)
        .with_context(|| format!("could not validate {}", manifest_path.display()))?;
    Vault::restore_from_backup(backup, &manifest, output)
        .with_context(|| format!("could not restore verified backup {}", backup.display()))?;
    println!("restored verified encrypted vault to {}", output.display());
    Ok(())
}

fn write_new_plaintext(output: &Path, plaintext: &[u8]) -> Result<()> {
    let parent = output
        .parent()
        .filter(|parent| parent.is_dir())
        .context("plaintext output parent directory does not exist")?;
    let mut temporary = NamedTempFile::new_in(parent).with_context(|| {
        format!(
            "could not create temporary output beside {}",
            output.display()
        )
    })?;
    temporary
        .as_file_mut()
        .set_permissions(fs::Permissions::from_mode(0o600))
        .with_context(|| {
            format!(
                "could not protect temporary output for {}",
                output.display()
            )
        })?;
    temporary
        .write_all(plaintext)
        .with_context(|| format!("could not write temporary output for {}", output.display()))?;
    temporary
        .as_file()
        .sync_all()
        .with_context(|| format!("could not sync temporary output for {}", output.display()))?;
    fs::hard_link(temporary.path(), output).with_context(|| {
        format!(
            "refusing to overwrite plaintext output: {}",
            output.display()
        )
    })?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .with_context(|| {
            format!(
                "could not sync plaintext output directory: {}",
                parent.display()
            )
        })?;
    Ok(())
}

fn rotate_passphrase(socket: &Path) -> Result<()> {
    let current_passphrase = prompt_password("Current passphrase: ")?;
    let replacement_passphrase = prompt_new_passphrase()?;
    empty(
        socket,
        &Request::RotatePassphrase {
            current_passphrase,
            replacement_passphrase,
        },
        "passphrase rotated; daemon vault is locked",
    )
}

fn verify(socket: &Path) -> Result<()> {
    match request(socket, &Request::Verify)? {
        Success::Verified { active_objects } => {
            println!("verified active object versions: {active_objects}");
            Ok(())
        }
        _ => bail!("daemon returned an unexpected verify payload"),
    }
}

fn empty(socket: &Path, operation: &Request, message: &str) -> Result<()> {
    match request(socket, operation)? {
        Success::Empty => {
            println!("{message}");
            Ok(())
        }
        _ => bail!("daemon returned an unexpected empty payload"),
    }
}

fn request(socket: &Path, operation: &Request) -> Result<Success> {
    let mut stream = UnixStream::connect(socket)
        .with_context(|| format!("could not connect to {}", socket.display()))?;
    write_frame(&mut stream, operation).context("could not write daemon request")?;
    match read_frame::<Response, _>(&mut stream).context("could not read daemon response")? {
        Response::Ok { result } => Ok(result),
        Response::Error { error } => bail!("daemon {}: {}", error.code_to_text(), error.message),
    }
}

fn prompt_new_passphrase() -> Result<String> {
    let first = prompt_password("New passphrase: ")?;
    if first.is_empty() {
        bail!("passphrase must not be empty");
    }
    let second = prompt_password("Confirm passphrase: ")?;
    if first != second {
        bail!("passphrase confirmation does not match");
    }
    Ok(first)
}

trait ErrorCodeText {
    fn code_to_text(&self) -> &'static str;
}

impl ErrorCodeText for vlt1_protocol::Failure {
    fn code_to_text(&self) -> &'static str {
        match self.code {
            vlt1_protocol::ErrorCode::Protocol => "protocol error",
            vlt1_protocol::ErrorCode::Unauthorized => "unauthorized",
            vlt1_protocol::ErrorCode::Locked => "vault locked",
            vlt1_protocol::ErrorCode::NotFound => "not found",
            vlt1_protocol::ErrorCode::InvalidInput => "invalid input",
            vlt1_protocol::ErrorCode::Verification => "verification failed",
            vlt1_protocol::ErrorCode::Storage => "storage error",
            vlt1_protocol::ErrorCode::WitnessUnavailable => "freshness witness unavailable",
            vlt1_protocol::ErrorCode::WitnessConflict => "freshness witness conflict",
            vlt1_protocol::ErrorCode::Overloaded => "daemon connection limit reached",
            vlt1_protocol::ErrorCode::Policy => "policy denied",
            vlt1_protocol::ErrorCode::Internal => "internal error",
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt};

    use tempfile::tempdir;

    use super::write_new_plaintext;

    #[test]
    fn plaintext_output_is_private_and_matches_verified_bytes() {
        let directory = tempdir().expect("temporary directory");
        let output = directory.path().join("recovered.txt");

        write_new_plaintext(&output, b"verified plaintext").expect("write new plaintext");

        assert_eq!(
            fs::read(&output).expect("read output"),
            b"verified plaintext"
        );
        assert_eq!(
            fs::metadata(&output)
                .expect("output metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[test]
    fn plaintext_output_refuses_to_overwrite_existing_file() {
        let directory = tempdir().expect("temporary directory");
        let output = directory.path().join("existing.txt");
        fs::write(&output, b"existing plaintext").expect("write existing output");

        assert!(write_new_plaintext(&output, b"replacement").is_err());
        assert_eq!(
            fs::read(&output).expect("read existing output"),
            b"existing plaintext"
        );
    }
}
