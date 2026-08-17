// Copyright Nixort & Itan Winter <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 or later.

//! `vlt1d` daemon entry point.

use std::{fs, path::PathBuf};

use anyhow::{bail, Context, Result};
use clap::Parser;
use vlt1_daemon::{Daemon, DaemonConfig, WitnessConfig};

#[derive(Debug, Parser)]
#[command(name = "vlt1d", version, about = "VLT/1 local Unix-socket daemon")]
struct Arguments {
    /// Persistent VLT/1 `SQLite` vault path.
    #[arg(long)]
    vault: PathBuf,
    /// Local Unix-domain socket path.
    #[arg(long)]
    socket: PathBuf,
    /// Explicit Linux UID allowed to access the socket. Defaults to the daemon UID.
    #[arg(long)]
    allow_uid: Option<u32>,
    /// Permit a local authorised shutdown request; intended for integration tests.
    #[arg(long, default_value_t = false)]
    allow_shutdown: bool,
    /// Canonical HTTPS endpoint of an independently operated freshness witness.
    #[arg(long)]
    witness_endpoint: Option<String>,
    /// Root-owned file containing the witness bearer credential.
    #[arg(long)]
    witness_token_file: Option<PathBuf>,
    /// Root-owned file containing a lowercase hexadecimal Ed25519 public key.
    #[arg(long)]
    witness_public_key_file: Option<PathBuf>,
}

fn main() -> Result<()> {
    let arguments = Arguments::parse();
    let mut config = DaemonConfig::for_current_user(arguments.socket, arguments.vault);
    if let Some(uid) = arguments.allow_uid {
        config.allowed_uid = uid;
    }
    config.allow_shutdown = arguments.allow_shutdown;
    config.witness = witness_config(
        arguments.witness_endpoint,
        arguments.witness_token_file,
        arguments.witness_public_key_file,
    )?;
    let daemon = Daemon::open(config).context("could not open VLT/1 daemon vault")?;
    daemon.serve().context("VLT/1 daemon stopped with an error")
}

fn witness_config(
    endpoint: Option<String>,
    token_file: Option<PathBuf>,
    public_key_file: Option<PathBuf>,
) -> Result<Option<WitnessConfig>> {
    match (endpoint, token_file, public_key_file) {
        (None, None, None) => Ok(None),
        (Some(endpoint), Some(token_file), Some(public_key_file)) => {
            let token = read_secret(&token_file)?;
            let public_key_text = read_secret(&public_key_file)?;
            let public_key = parse_hex32(public_key_text.trim())?;
            Ok(Some(WitnessConfig {
                endpoint,
                bearer_token: token,
                public_key,
            }))
        }
        _ => bail!("witness endpoint, token file and public key file must be supplied together"),
    }
}

fn read_secret(path: &PathBuf) -> Result<String> {
    let metadata = fs::metadata(path).with_context(|| format!("cannot stat {}", path.display()))?;
    if !metadata.is_file() {
        bail!("{} is not a regular file", path.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!("{} must not be readable by group or other", path.display());
        }
    }
    let content =
        fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
    let content = content.trim().to_owned();
    if content.is_empty() {
        bail!("{} is empty", path.display());
    }
    Ok(content)
}

fn parse_hex32(value: &str) -> Result<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|item| item.is_ascii_hexdigit() && !item.is_ascii_uppercase())
    {
        bail!("witness public key must be 64 lowercase hexadecimal characters");
    }
    let mut bytes = [0u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let pair = std::str::from_utf8(pair).context("witness public key encoding")?;
        bytes[index] = u8::from_str_radix(pair, 16).context("witness public key encoding")?;
    }
    Ok(bytes)
}
