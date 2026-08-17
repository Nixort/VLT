// Copyright Nixort & Itan Winter <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 or later.

//! End-to-end local Unix-socket protocol tests for `vlt1d`.

use std::{
    os::unix::net::UnixStream,
    sync::{Arc, Barrier},
    thread,
    time::{Duration, Instant},
};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use tempfile::tempdir;
use vlt1_core::{manifest_path, BackupManifest, ObjectId, Vault};
use vlt1_daemon::{Daemon, DaemonConfig};
use vlt1_protocol::{read_frame, write_frame, ErrorCode, Request, Response, Success};

#[test]
fn authorised_local_client_executes_a_full_vault_flow() {
    let directory = tempdir().expect("temporary directory");
    let vault_path = directory.path().join("vault.sqlite");
    let socket_path = directory.path().join("vlt1.sock");
    Vault::create(&vault_path, "correct horse battery staple").expect("vault creation");

    let mut config = DaemonConfig::for_current_user(socket_path.clone(), vault_path);
    config.allow_shutdown = true;
    let daemon = Daemon::open(config).expect("daemon open");
    let server = {
        let daemon = daemon.clone();
        thread::spawn(move || daemon.serve().expect("daemon serve"))
    };
    wait_for_socket(&socket_path);

    let status = call(&socket_path, &Request::Status);
    let Success::Status {
        lifecycle,
        recovery,
        verified_active_objects,
        ..
    } = status
    else {
        panic!("daemon returned an unexpected status result");
    };
    assert_eq!(lifecycle, "locked");
    assert_eq!(recovery, "startup_integrity_ok");
    assert_eq!(verified_active_objects, None);

    assert_eq!(
        call(
            &socket_path,
            &Request::Unlock {
                passphrase: "correct horse battery staple".to_owned(),
            },
        ),
        Success::Empty
    );

    let object = ObjectId::random().to_hex();
    let payload = b"daemon-bound authenticated plaintext";
    let published = call(
        &socket_path,
        &Request::Put {
            object_id: object.clone(),
            plaintext_b64: STANDARD.encode(payload),
        },
    );
    assert!(matches!(published, Success::Published { .. }));

    let plaintext = call(&socket_path, &Request::Get { object_id: object });
    let Success::Plaintext { plaintext_b64 } = plaintext else {
        panic!("daemon returned an unexpected plaintext result");
    };
    assert_eq!(STANDARD.decode(plaintext_b64).expect("base64"), payload);

    assert_eq!(
        call(&socket_path, &Request::Verify),
        Success::Verified { active_objects: 1 }
    );
    assert_eq!(call(&socket_path, &Request::Checkpoint), Success::Empty);
    let backup_path = directory.path().join("daemon-backup.sqlite");
    assert!(matches!(
        call(
            &socket_path,
            &Request::Backup {
                destination: backup_path.to_string_lossy().into_owned(),
            },
        ),
        Success::Backup { .. }
    ));
    let backup_manifest =
        BackupManifest::read_from(manifest_path(&backup_path)).expect("backup sidecar");
    backup_manifest
        .verify_backup(&backup_path)
        .expect("daemon backup verification");
    let verification_status = call(&socket_path, &Request::Status);
    assert!(matches!(
        verification_status,
        Success::Status {
            verified_active_objects: Some(1),
            ..
        }
    ));

    assert_eq!(call(&socket_path, &Request::Lock), Success::Empty);
    let locked_read = call_response(
        &socket_path,
        &Request::Get {
            object_id: "00".repeat(16),
        },
    );
    assert!(matches!(locked_read, Response::Error { .. }));

    assert_eq!(call(&socket_path, &Request::Shutdown), Success::Empty);
    server.join().expect("daemon thread join");
    assert!(daemon.shutdown_requested());
}

#[test]
fn concurrent_local_clients_publish_and_verify_distinct_objects() {
    const CLIENTS: usize = 8;

    let directory = tempdir().expect("temporary directory");
    let vault_path = directory.path().join("vault.sqlite");
    let socket_path = directory.path().join("vlt1.sock");
    Vault::create(&vault_path, "correct horse battery staple").expect("vault creation");

    let mut config = DaemonConfig::for_current_user(socket_path.clone(), vault_path);
    config.allow_shutdown = true;
    let daemon = Daemon::open(config).expect("daemon open");
    let server = {
        let daemon = daemon.clone();
        thread::spawn(move || daemon.serve().expect("daemon serve"))
    };
    wait_for_socket(&socket_path);
    assert_eq!(
        call(
            &socket_path,
            &Request::Unlock {
                passphrase: "correct horse battery staple".to_owned(),
            },
        ),
        Success::Empty
    );

    let barrier = Arc::new(Barrier::new(CLIENTS + 1));
    let mut workers = Vec::with_capacity(CLIENTS);
    for worker in 0..CLIENTS {
        let socket_path = socket_path.clone();
        let barrier = Arc::clone(&barrier);
        workers.push(thread::spawn(move || {
            let object_id = ObjectId::random().to_hex();
            let payload = format!("concurrent payload {worker}").into_bytes();
            barrier.wait();
            assert!(matches!(
                call(
                    &socket_path,
                    &Request::Put {
                        object_id: object_id.clone(),
                        plaintext_b64: STANDARD.encode(&payload),
                    },
                ),
                Success::Published { .. }
            ));
            let plaintext = call(&socket_path, &Request::Get { object_id });
            let Success::Plaintext { plaintext_b64 } = plaintext else {
                panic!("daemon returned an unexpected concurrent read result");
            };
            assert_eq!(STANDARD.decode(plaintext_b64).expect("base64"), payload);
        }));
    }
    barrier.wait();
    for worker in workers {
        worker.join().expect("concurrent daemon client");
    }

    assert_eq!(
        call(&socket_path, &Request::Verify),
        Success::Verified {
            active_objects: CLIENTS as u64
        }
    );
    assert_eq!(call(&socket_path, &Request::Shutdown), Success::Empty);
    server.join().expect("daemon thread join");
}

#[test]
fn idle_peer_hits_io_deadline_and_releases_its_handler() {
    let directory = tempdir().expect("temporary directory");
    let vault_path = directory.path().join("vault.sqlite");
    Vault::create(&vault_path, "correct horse battery staple").expect("vault creation");
    let mut config =
        DaemonConfig::for_current_user(directory.path().join("unused.sock"), vault_path);
    config.io_timeout = Duration::from_millis(50);
    let daemon = Daemon::open(config).expect("daemon open");
    let (client, server) = UnixStream::pair().expect("Unix socket pair");
    let worker = {
        let daemon = daemon.clone();
        thread::spawn(move || daemon.serve_stream(server).expect("deadline response"))
    };
    let started = Instant::now();
    client
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("client read timeout");
    let mut client = client;
    let response: Response = read_frame(&mut client).expect("deadline response frame");
    assert!(started.elapsed() < Duration::from_millis(500));
    assert!(matches!(
        response,
        Response::Error {
            error: vlt1_protocol::Failure {
                code: ErrorCode::Protocol,
                ..
            }
        }
    ));
    worker.join().expect("deadline handler");
}

#[test]
fn saturated_daemon_rejects_extra_connection_without_dispatch() {
    let directory = tempdir().expect("temporary directory");
    let vault_path = directory.path().join("vault.sqlite");
    let socket_path = directory.path().join("vlt1.sock");
    Vault::create(&vault_path, "correct horse battery staple").expect("vault creation");
    let mut config = DaemonConfig::for_current_user(socket_path.clone(), vault_path);
    config.allow_shutdown = true;
    config.max_connections = 1;
    config.io_timeout = Duration::from_secs(1);
    let daemon = Daemon::open(config).expect("daemon open");
    let server = {
        let daemon = daemon.clone();
        thread::spawn(move || daemon.serve().expect("daemon serve"))
    };
    wait_for_socket(&socket_path);

    let slow_client = UnixStream::connect(&socket_path).expect("slow client connect");
    thread::sleep(Duration::from_millis(50));
    let response = call_response(&socket_path, &Request::Status);
    assert!(matches!(
        response,
        Response::Error {
            error: vlt1_protocol::Failure {
                code: ErrorCode::Overloaded,
                ..
            }
        }
    ));
    drop(slow_client);
    thread::sleep(Duration::from_millis(50));
    assert_eq!(call(&socket_path, &Request::Shutdown), Success::Empty);
    server.join().expect("daemon thread join");
}

fn call(socket_path: &std::path::Path, request: &Request) -> Success {
    match call_response(socket_path, request) {
        Response::Ok { result } => result,
        Response::Error { error } => panic!("daemon error: {error:?}"),
    }
}

fn call_response(socket_path: &std::path::Path, request: &Request) -> Response {
    let mut stream = UnixStream::connect(socket_path).expect("connect daemon socket");
    write_frame(&mut stream, request).expect("write request");
    read_frame(&mut stream).expect("read response")
}

fn wait_for_socket(socket_path: &std::path::Path) {
    let deadline = Instant::now() + Duration::from_secs(3);
    while !socket_path.exists() {
        assert!(Instant::now() < deadline, "daemon socket did not appear");
        thread::sleep(Duration::from_millis(10));
    }
}
