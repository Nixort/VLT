// Copyright Nixort & Itan Winter <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 or later.

//! Prints the Ed25519 public key corresponding to a protected witness seed.

use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};

use anyhow::{bail, Context, Result};
use clap::Parser;
use ed25519_dalek::SigningKey;

#[derive(Debug, Parser)]
#[command(
    name = "vlt1-witness-key",
    version,
    about = "Print the pinned Ed25519 public key for a VLT/1 witness seed"
)]
struct Arguments {
    /// 32-byte binary signing seed, mode 0600 or stricter.
    #[arg(long)]
    signing_seed: PathBuf,
}

fn main() -> Result<()> {
    let arguments = Arguments::parse();
    let metadata = fs::metadata(&arguments.signing_seed)
        .with_context(|| format!("cannot stat {}", arguments.signing_seed.display()))?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
        bail!("witness signing seed must be a regular mode-0600 file");
    }
    let seed = fs::read(&arguments.signing_seed)
        .with_context(|| format!("cannot read {}", arguments.signing_seed.display()))?;
    let seed: [u8; 32] = seed
        .try_into()
        .map_err(|_| anyhow::anyhow!("witness signing seed must be exactly 32 bytes"))?;
    println!(
        "{}",
        hex::encode(SigningKey::from_bytes(&seed).verifying_key().to_bytes())
    );
    Ok(())
}
