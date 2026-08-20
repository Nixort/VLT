// Copyright Nixort & Itan Winter <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 or later.

//! End-to-end validation of the pinned VLT/1 external witness HTTP provider.

use std::{
    fs,
    net::TcpListener,
    process::{Child, Command},
    thread,
    time::Duration,
};

use tempfile::tempdir;
use vlt1_core::{
    HttpsWitnessProvider, ObjectId, Vault, VaultId, VersionId, WitnessProvider, WitnessRequest,
};

fn start_witness() -> (tempfile::TempDir, Child, String, [u8; 32]) {
    let directory = tempdir().expect("temporary directory");
    let seed = [42u8; 32];
    let seed_path = directory.path().join("seed");
    let token_path = directory.path().join("token");
    fs::write(&seed_path, seed).expect("seed");
    fs::write(&token_path, b"integration-token").expect("token");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&seed_path, fs::Permissions::from_mode(0o600)).expect("seed mode");
        fs::set_permissions(&token_path, fs::Permissions::from_mode(0o600)).expect("token mode");
    }

    let listener = TcpListener::bind("127.0.0.1:0").expect("ephemeral listener");
    let address = listener.local_addr().expect("local address");
    drop(listener);
    let child = Command::new(env!("CARGO_BIN_EXE_vlt1-witnessd"))
        .args([
            "--state",
            directory
                .path()
                .join("witness.sqlite")
                .to_str()
                .expect("state path"),
            "--signing-seed",
            seed_path.to_str().expect("seed path"),
            "--auth-token-file",
            token_path.to_str().expect("token path"),
            "--listen",
            &address.to_string(),
        ])
        .spawn()
        .expect("witness daemon");
    let public_key = ed25519_dalek::SigningKey::from_bytes(&seed)
        .verifying_key()
        .to_bytes();
    (directory, child, format!("http://{address}"), public_key)
}

#[test]
fn rollover_provider_accepts_only_configured_previous_anchor() {
    let (_directory, mut child, endpoint, previous_public_key) = start_witness();
    thread::sleep(Duration::from_millis(100));

    let primary_public_key = ed25519_dalek::SigningKey::from_bytes(&[43; 32])
        .verifying_key()
        .to_bytes();
    let vault_id = VaultId::random();
    let object_id = ObjectId::random();
    let request = WitnessRequest::from_parts(vault_id, object_id, VersionId::random(), [7; 32]);
    let mut rollover = HttpsWitnessProvider::for_loopback_test_with_previous(
        &endpoint,
        "integration-token",
        primary_public_key,
        Some(previous_public_key),
    )
    .expect("bounded rollover provider");
    rollover
        .issue_receipt(&request, 0)
        .expect("configured previous anchor");

    let mut strict =
        HttpsWitnessProvider::for_loopback_test(&endpoint, "integration-token", primary_public_key)
            .expect("strict provider");
    assert!(strict.issue_receipt(&request, 0).is_err());

    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn external_witness_issues_idempotent_receipts_and_fresh_heads() {
    let (directory, mut child, endpoint, public_key) = start_witness();
    thread::sleep(Duration::from_millis(100));

    let vault_id = VaultId::random();
    let object_id = ObjectId::random();
    let request = WitnessRequest::from_parts(vault_id, object_id, VersionId::random(), [1; 32]);
    let mut provider =
        HttpsWitnessProvider::for_loopback_test(&endpoint, "integration-token", public_key)
            .expect("provider");
    let receipt = provider.issue_receipt(&request, 0).expect("receipt");
    let replay = provider
        .issue_receipt(&request, 0)
        .expect("idempotent retry");
    assert_eq!(receipt, replay);
    let challenge = [9; 32];
    let head = provider
        .object_head(vault_id, object_id, challenge)
        .expect("fresh head");
    assert!(head.present());
    assert_eq!(head.version_id(), Some(request.version_id()));
    assert_eq!(head.challenge(), &challenge);

    let mut vault = Vault::create(
        directory.path().join("vault.sqlite"),
        "correct horse battery staple",
    )
    .expect("vault");
    let vault_object = ObjectId::random();
    vault
        .put_with_witness(vault_object, b"external witness bound", &mut provider)
        .expect("witness-backed vault publish");
    assert_eq!(
        vault
            .verify_active_objects_with_witness(&mut provider)
            .expect("fresh external witness verification"),
        1
    );

    let _ = child.kill();
    let _ = child.wait();
}
