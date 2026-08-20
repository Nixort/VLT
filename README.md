# VLT/1

VLT/1 is a Rust implementation of a **single-user, single-machine encrypted vault**. It keeps immutable encrypted object versions in SQLite, serves an owner-only local Unix socket, and fails closed when storage, format, invariant, or authentication checks fail.

> VLT/1 is not a hardware-backed keystore, a multi-user service, or protection from root, a malicious kernel, memory extraction, or rollback without an independently operated freshness witness.

## Security model in one page

A passphrase derives an Argon2id key that unwraps a random 256-bit Root Key. HKDF derives the KEK; each immutable object version receives a fresh random DEK; AES-256-GCM-SIV seals every chunk and the canonical Manifest with context-bound AAD. SQLite WAL transactions publish a complete version and active pointer together. The design and its explicit boundaries are defined in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).[1] [2]

| Control | Current implementation |
|---|---|
| Passphrase protection | Argon2id with `m=65536 KiB`, `t=3`, `p=4` for new envelopes; persisted legacy parameters remain unlockable. |
| Key separation | Random Root Key, HKDF-derived KEK, and a fresh random DEK per immutable version. |
| Encrypted records | AES-256-GCM-SIV chunks and a separately sealed canonical Manifest. |
| Storage integrity | SQLite WAL, `synchronous=FULL`, atomic publication, startup structural checks, and unlocked end-to-end verification. |
| Local service boundary | Owner-only `0600` Unix socket, Linux peer-UID check, a 16 MiB frame cap, bounded admission, and I/O deadlines. |
| Rollback evidence | Optional Ed25519 witness receipts with durable conditional heads, restart reconciliation, and a strict independently operated HTTPS profile. |
| Recovery | SQLite online backup, SHA-256 sidecar, read-only pre-restore checks, and no-overwrite restore. |

## Repository map

| Path | Responsibility |
|---|---|
| `crates/vlt1-core/` | Key hierarchy, encrypted versions, SQLite persistence, recovery, and witness integration. |
| `crates/vlt1-protocol/` | Closed local IPC request and response contract. |
| `crates/vlt1-daemon/` | `vlt1d`, peer policy, resource limits, and Unix-socket service boundary. |
| `crates/vlt1-witness/` | Independently deployable witness state machine and key utility. |
| `crates/vlt1-cli/` | `vlt1` client, backup/restore commands, and benchmark executable. |
| `deploy/` | Hardened systemd units, installer, and deployment runbook. |
| `fuzz/` | Independent cargo-fuzz project and retained minimized corpora. |
| `results/` | Raw benchmark CSV, median summary, and deterministic chart. |

## Quick start

The passphrase is prompted for interactively; it is never accepted as a command-line argument.

```sh
cargo build --release --workspace

./target/release/vlt1 init ./vault.sqlite
SOCKET_DIR=$(mktemp -d)
./target/release/vlt1d --vault ./vault.sqlite --socket "$SOCKET_DIR/vlt1.sock" &

./target/release/vlt1 unlock --socket "$SOCKET_DIR/vlt1.sock"
OBJECT_ID=$(openssl rand -hex 16)
./target/release/vlt1 put --socket "$SOCKET_DIR/vlt1.sock" \
  --object "$OBJECT_ID" --input ./secret.txt
./target/release/vlt1 get --socket "$SOCKET_DIR/vlt1.sock" \
  --object "$OBJECT_ID" --output ./recovered.txt
cmp ./secret.txt ./recovered.txt
./target/release/vlt1 lock --socket "$SOCKET_DIR/vlt1.sock"
```

`vlt1 get` publishes verified plaintext only to a **new direct path** inside real existing directories. It refuses existing files, symlink output paths, and output paths whose lexical parent chain contains a symlink; choose a dedicated owner-controlled recovery directory.

## Verification

Run the complete release gate before a merge or release. The locked MSRV command is part of the support contract, not an optional compatibility check.

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo test -p vlt1-core --features fault-injection
cargo build --release --workspace
cargo +1.75.0 check --workspace --locked
```

Parser fuzzing and benchmark reproduction are deliberately separate workflows; use the focused guides below rather than treating a successful unit-test run as their substitute.

## Documentation

| Need | Canonical document |
|---|---|
| Cryptographic format, trust boundary, protocol surface, failure behavior, and non-goals | [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) |
| Build policy, contributor rules, MSRV gate, and required checks | [`CONTRIBUTING.md`](CONTRIBUTING.md) |
| Backup and no-overwrite restore procedure | [`docs/BACKUP_RESTORE.md`](docs/BACKUP_RESTORE.md) |
| Benchmark methodology, recorded result, and reproduction | [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md) |
| Witness trust bootstrap and wire contract | [`docs/WITNESS_PROTOCOL.md`](docs/WITNESS_PROTOCOL.md) |
| Release assets, checksums, SBOM, and provenance verification | [`docs/RELEASE.md`](docs/RELEASE.md) |
| Hardened systemd deployment and strict witness operation | [`deploy/README.md`](deploy/README.md) |
| Fuzz targets, corpus handling, and crash workflow | [`fuzz/README.md`](fuzz/README.md) |
| Private security reporting | [`SECURITY.md`](SECURITY.md) |

The checked-in direct/RPC benchmark is a machine-specific diagnostic, not a general performance guarantee. Its raw data and environment metadata are retained under `results/`; its interpretation belongs in [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md).

## License and disclosure

VLT/1 is licensed under **GPL-3.0-or-later**. Report suspected vulnerabilities privately as described in [`SECURITY.md`](SECURITY.md).

## References

[1] [RFC 8452 — AES-GCM-SIV](https://www.rfc-editor.org/rfc/rfc8452)  
[2] [RFC 9106 — Argon2](https://www.rfc-editor.org/rfc/rfc9106.html)
