// Copyright Nixort & Itan Winter <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 or later.

//! VLT/1 machine-specific direct and local-RPC benchmark driver.

use std::{
    env, fs,
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use vlt1_core::{ObjectId, Vault};
use vlt1_daemon::{Daemon, DaemonConfig};
use vlt1_protocol::{read_frame, write_frame, Request, Response, Success};

fn main() -> Result<()> {
    let config = Config::parse()?;
    let directory = benchmark_directory();
    fs::create_dir_all(&directory)?;
    let result = run(&config, &directory);
    fs::remove_dir_all(&directory).context("could not remove benchmark temporary directory")?;
    result
}

fn run(config: &Config, directory: &Path) -> Result<()> {
    println!("mode,operation,payload_bytes,run,elapsed_ms,throughput_mib_s");
    if config.mode.includes_direct() {
        benchmark_direct(config, directory)?;
    }
    if config.mode.includes_rpc() {
        benchmark_rpc(config, directory)?;
    }
    Ok(())
}

fn benchmark_direct(config: &Config, directory: &Path) -> Result<()> {
    let vault_path = directory.join("direct.vlt.sqlite");
    let mut vault = Vault::create(vault_path, "benchmark-only-passphrase")
        .context("could not initialize direct benchmark vault")?;
    for payload_kib in &config.payloads_kib {
        let payload = payload_for(*payload_kib)?;
        for run in 0..config.runs {
            let object = ObjectId::random();
            let started = Instant::now();
            vault.put(object, &payload)?;
            emit("direct", "put", payload.len(), run, started.elapsed());

            let started = Instant::now();
            let recovered = vault.get(object)?;
            emit("direct", "get", payload.len(), run, started.elapsed());
            if recovered != payload {
                bail!("direct benchmark round-trip verification failed");
            }
        }
    }
    vault.lock();
    Ok(())
}

fn benchmark_rpc(config: &Config, directory: &Path) -> Result<()> {
    let vault_path = directory.join("rpc.vlt.sqlite");
    let socket_path = directory.join("vlt1-bench.sock");
    Vault::create(&vault_path, "benchmark-only-passphrase")
        .context("could not initialize RPC benchmark vault")?;

    let mut daemon_config = DaemonConfig::for_current_user(socket_path.clone(), vault_path);
    daemon_config.allow_shutdown = true;
    let daemon = Daemon::open(daemon_config).context("could not open RPC benchmark daemon")?;
    let server = {
        let daemon = daemon.clone();
        thread::spawn(move || daemon.serve())
    };
    wait_for_socket(&socket_path)?;

    let measurement = (|| {
        let unlock = rpc(
            &socket_path,
            &Request::Unlock {
                passphrase: "benchmark-only-passphrase".to_owned(),
            },
        )?;
        expect_empty(&unlock)?;
        for payload_kib in &config.payloads_kib {
            let payload = payload_for(*payload_kib)?;
            for run in 0..config.runs {
                let object_id = ObjectId::random().to_hex();
                let started = Instant::now();
                let result = rpc(
                    &socket_path,
                    &Request::Put {
                        object_id: object_id.clone(),
                        plaintext_b64: STANDARD.encode(&payload),
                    },
                )?;
                expect_published(&result)?;
                emit("rpc", "put", payload.len(), run, started.elapsed());

                let started = Instant::now();
                let result = rpc(&socket_path, &Request::Get { object_id })?;
                let recovered = expect_plaintext(result)?;
                emit("rpc", "get", payload.len(), run, started.elapsed());
                if recovered != payload {
                    bail!("RPC benchmark round-trip verification failed");
                }
            }
        }
        Ok(())
    })();

    let shutdown = rpc(&socket_path, &Request::Shutdown).and_then(|result| expect_empty(&result));
    let server_result = server
        .join()
        .map_err(|_| anyhow!("RPC benchmark daemon thread panicked"))?
        .context("RPC benchmark daemon stopped with an error");
    measurement?;
    shutdown?;
    server_result
}

fn rpc(socket_path: &Path, request: &Request) -> Result<Success> {
    let mut stream = UnixStream::connect(socket_path).with_context(|| {
        format!(
            "could not connect to benchmark socket {}",
            socket_path.display()
        )
    })?;
    write_frame(&mut stream, request).context("could not write benchmark RPC request")?;
    match read_frame::<Response, _>(&mut stream).context("could not read benchmark RPC response")? {
        Response::Ok { result } => Ok(result),
        Response::Error { error } => bail!("benchmark RPC error: {:?}", error.code),
    }
}

fn expect_empty(result: &Success) -> Result<()> {
    if matches!(result, Success::Empty) {
        Ok(())
    } else {
        bail!("daemon returned an unexpected empty benchmark response")
    }
}

fn expect_published(result: &Success) -> Result<()> {
    if matches!(result, Success::Published { .. }) {
        Ok(())
    } else {
        bail!("daemon returned an unexpected publish benchmark response")
    }
}

fn expect_plaintext(result: Success) -> Result<Vec<u8>> {
    let Success::Plaintext { plaintext_b64 } = result else {
        bail!("daemon returned an unexpected plaintext benchmark response");
    };
    STANDARD
        .decode(plaintext_b64)
        .context("daemon returned invalid benchmark plaintext base64")
}

struct Config {
    payloads_kib: Vec<u32>,
    runs: usize,
    mode: Mode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    Direct,
    Rpc,
    Both,
}

impl Mode {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "direct" => Ok(Self::Direct),
            "rpc" => Ok(Self::Rpc),
            "both" => Ok(Self::Both),
            _ => bail!("--mode must be one of: direct, rpc, both"),
        }
    }

    const fn includes_direct(self) -> bool {
        matches!(self, Self::Direct | Self::Both)
    }

    const fn includes_rpc(self) -> bool {
        matches!(self, Self::Rpc | Self::Both)
    }
}

impl Config {
    fn parse() -> Result<Self> {
        let mut payloads_kib = vec![4, 64, 1024, 4096];
        let mut runs = 5;
        let mut mode = Mode::Both;
        let mut arguments = env::args().skip(1);
        while let Some(argument) = arguments.next() {
            match argument.as_str() {
                "--payloads-kib" => {
                    let value = arguments
                        .next()
                        .context("--payloads-kib requires a value")?;
                    payloads_kib = value
                        .split(',')
                        .map(str::parse)
                        .collect::<std::result::Result<Vec<_>, _>>()
                        .context("invalid comma-separated payload list")?;
                }
                "--runs" => {
                    runs = arguments
                        .next()
                        .context("--runs requires a value")?
                        .parse()
                        .context("invalid --runs value")?;
                }
                "--mode" => {
                    mode = Mode::parse(&arguments.next().context("--mode requires a value")?)?;
                }
                "--help" | "-h" => {
                    println!(
                        "Usage: vlt1-bench [--payloads-kib 4,64,1024,4096] [--runs 5] \\\n                         [--mode direct|rpc|both]"
                    );
                    std::process::exit(0);
                }
                _ => bail!("unknown argument: {argument}"),
            }
        }
        if payloads_kib.is_empty() || payloads_kib.contains(&0) || runs == 0 {
            bail!("payload sizes and run count must be non-zero");
        }
        Ok(Self {
            payloads_kib,
            runs,
            mode,
        })
    }
}

fn payload_for(payload_kib: u32) -> Result<Vec<u8>> {
    let payload_bytes = payload_kib
        .checked_mul(1024)
        .context("payload size overflows KiB-to-byte conversion")?;
    let payload_bytes =
        usize::try_from(payload_bytes).context("payload size exceeds address space")?;
    Ok(deterministic_payload(payload_bytes))
}

fn emit(mode: &str, operation: &str, bytes: usize, run: usize, duration: Duration) {
    let elapsed_seconds = duration.as_secs_f64();
    let elapsed_ms = elapsed_seconds * 1_000.0;
    let throughput = if elapsed_seconds == 0.0 {
        f64::INFINITY
    } else {
        f64::from(u32::try_from(bytes).expect("benchmark payload must fit in u32"))
            / (1024.0 * 1024.0)
            / elapsed_seconds
    };
    println!("{mode},{operation},{bytes},{run},{elapsed_ms:.6},{throughput:.6}");
}

fn deterministic_payload(length: usize) -> Vec<u8> {
    (0..length)
        .map(|index| u8::try_from(index % 251).expect("modulo result fits in u8"))
        .collect()
}

fn benchmark_directory() -> PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_nanos();
    env::temp_dir().join(format!("vlt1-bench-{}-{nonce}", std::process::id()))
}

fn wait_for_socket(socket_path: &Path) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(3);
    while !socket_path.exists() {
        if Instant::now() >= deadline {
            bail!("benchmark daemon socket did not appear")
        }
        thread::sleep(Duration::from_millis(5));
    }
    Ok(())
}
