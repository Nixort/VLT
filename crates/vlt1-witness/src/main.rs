// Copyright Nixort & Itan Winter <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 or later.

//! `vlt1-witnessd` entry point.
//!
//! The process binds only a loopback listener. Place it behind an independently
//! operated TLS reverse proxy or mutually authenticated tunnel for production.

use std::{
    fs,
    io::Read,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
};

use anyhow::{bail, Context, Result};
use clap::Parser;
use constant_time_eq::constant_time_eq;
use ed25519_dalek::SigningKey;
use tiny_http::{Header, Method, Response, Server, StatusCode};
use vlt1_witness::{HeadRequest, IssueRequest, WitnessService, MAX_WIRE_BODY};

#[derive(Debug, Parser)]
#[command(
    name = "vlt1-witnessd",
    version,
    about = "VLT/1 external freshness witness"
)]
struct Arguments {
    /// `SQLite` path owned by this independently deployed witness.
    #[arg(long)]
    state: PathBuf,
    /// 32-byte binary Ed25519 signing seed file, mode 0600 or stricter.
    #[arg(long)]
    signing_seed: PathBuf,
    /// Bearer credential file, mode 0600 or stricter.
    #[arg(long)]
    auth_token_file: PathBuf,
    /// Loopback listener; expose only through a separately operated TLS proxy.
    #[arg(long, default_value = "127.0.0.1:9823")]
    listen: SocketAddr,
}

fn main() -> Result<()> {
    let arguments = Arguments::parse();
    if !is_loopback(arguments.listen.ip()) {
        bail!("vlt1-witnessd accepts only a loopback listener; terminate TLS outside it");
    }
    let signing_key = SigningKey::from_bytes(&read_fixed_secret::<32>(&arguments.signing_seed)?);
    let token = read_secret(&arguments.auth_token_file)?;
    let mut service = WitnessService::open(&arguments.state, signing_key)
        .context("could not open VLT/1 witness state")?;
    let server = Server::http(arguments.listen)
        .map_err(|error| anyhow::anyhow!("could not bind VLT/1 witness listener: {error}"))?;
    eprintln!("vlt1-witnessd listening on {}", server.server_addr());

    for mut request in server.incoming_requests() {
        let response = if authorized(&request, &token) {
            dispatch(&mut service, &mut request)
        } else {
            json_response(StatusCode(401), br#"{"error":"unauthorized"}"#)
        };
        let _ = request.respond(response);
    }
    Ok(())
}

fn dispatch(
    service: &mut WitnessService,
    request: &mut tiny_http::Request,
) -> Response<std::io::Cursor<Vec<u8>>> {
    match (request.method(), request.url()) {
        (&Method::Get, "/healthz") => json_response(StatusCode(200), br#"{"status":"ok"}"#),
        (&Method::Post, "/v1/issue") => match read_json::<IssueRequest>(request) {
            Ok(body) => match service.issue_wire(&body) {
                Ok(response) => serialize_response(StatusCode(200), &response),
                Err(vlt1_core::VaultError::WitnessConflict) => {
                    json_response(StatusCode(409), br#"{"error":"witness_conflict"}"#)
                }
                Err(_) => json_response(StatusCode(400), br#"{"error":"invalid_request"}"#),
            },
            Err(()) => json_response(StatusCode(400), br#"{"error":"invalid_request"}"#),
        },
        (&Method::Post, "/v1/head") => match read_json::<HeadRequest>(request) {
            Ok(body) => match service.head_wire(&body) {
                Ok(response) => serialize_response(StatusCode(200), &response),
                Err(_) => json_response(StatusCode(400), br#"{"error":"invalid_request"}"#),
            },
            Err(()) => json_response(StatusCode(400), br#"{"error":"invalid_request"}"#),
        },
        _ => json_response(StatusCode(404), br#"{"error":"not_found"}"#),
    }
}

fn authorized(request: &tiny_http::Request, token: &[u8]) -> bool {
    let expected = format!("Bearer {}", String::from_utf8_lossy(token));
    let Some(header) = request
        .headers()
        .iter()
        .find(|header| header.field.equiv("Authorization"))
    else {
        return false;
    };
    constant_time_eq(header.value.as_bytes(), expected.as_bytes())
}

fn read_json<T: serde::de::DeserializeOwned>(request: &mut tiny_http::Request) -> Result<T, ()> {
    let mut bytes = Vec::with_capacity(1024);
    let mut body = request.as_reader().take(MAX_WIRE_BODY + 1);
    body.read_to_end(&mut bytes).map_err(|_| ())?;
    if bytes.len() as u64 > MAX_WIRE_BODY {
        return Err(());
    }
    serde_json::from_slice(&bytes).map_err(|_| ())
}

fn serialize_response<T: serde::Serialize>(
    status: StatusCode,
    value: &T,
) -> Response<std::io::Cursor<Vec<u8>>> {
    match serde_json::to_vec(value) {
        Ok(body) => json_response(status, &body),
        Err(_) => json_response(StatusCode(500), br#"{"error":"internal"}"#),
    }
}

fn json_response(status: StatusCode, body: &[u8]) -> Response<std::io::Cursor<Vec<u8>>> {
    Response::from_data(body.to_vec())
        .with_status_code(status)
        .with_header(
            Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..])
                .expect("static header"),
        )
        .with_header(
            Header::from_bytes(&b"Cache-Control"[..], &b"no-store"[..]).expect("static header"),
        )
}

fn read_fixed_secret<const N: usize>(path: &PathBuf) -> Result<[u8; N]> {
    let bytes = read_secret(path)?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{} must contain exactly {N} raw bytes", path.display()))
}

fn read_secret(path: &PathBuf) -> Result<Vec<u8>> {
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
    fs::read(path).with_context(|| format!("cannot read {}", path.display()))
}

const fn is_loopback(address: IpAddr) -> bool {
    address.is_loopback()
}
