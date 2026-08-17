# Contributing to VLT/1

VLT/1 accepts changes only when their security boundary, format impact, and validation evidence are clear. Keep patches narrow, reviewable, and consistent with the implemented local-vault scope. Use Conventional Commit prefixes: `feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`, and `build:`.

## Development contract

The supported minimum Rust version is **1.75.0**. The committed `Cargo.lock` is part of that promise: any dependency update must pass the locked MSRV gate as well as the current stable gates. A C compiler is required because SQLite is bundled. Python 3 plus `matplotlib` and `pandas` is needed only to render benchmark graphs.

Run this complete gate before requesting review or preparing a release:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo test -p vlt1-core --features fault-injection
cargo build --release --workspace
cargo +1.75.0 check --workspace --locked
```

Warnings are review blockers. The current workspace prohibits `unsafe`. A future platform-specific exception must isolate the unsafe boundary, include a `// SAFETY:` proof, document the changed trust boundary, and add focused regression coverage.

## Security-sensitive changes

| Change type | Required review and evidence |
|---|---|
| CDE, AAD, Manifest, identifier, key-envelope, or commitment change | State the format/versioning decision, add deterministic vectors, update `docs/ARCHITECTURE.md`, and document any migration. |
| Cryptographic dependency or parameter change | Preserve explicit algorithm and parameter rationale; add regression coverage; run the full gate, including locked MSRV. |
| Storage transaction, recovery, or verification change | Add an integration or fault-injection regression that exercises the failure path. |
| IPC request/response change | Keep the protocol closed and bounded; add decoder and daemon-boundary coverage. |
| Witness or deployment change | Update the canonical witness/deployment document and test the failure-closed path where applicable. |
| Benchmark-path change | Retain existing raw CSV or document why it is superseded; regenerate the summary and chart only from recorded data. |

Do not add passphrase arguments, passphrase environment variables, plaintext/key logging, production-like credentials in fixtures, ad-hoc cryptographic implementations, generic decrypt APIs, ambient mutable globals, or unbounded local IPC allocation. Treat database bytes, filenames, RPC data, and all decoder inputs as untrusted until validated. Public APIs require Rust documentation.

## Fuzzing and measurements

The parser fuzzers are separate from the normal workspace and require a nightly toolchain. Build and run them from the repository root:

```sh
cargo +nightly fuzz build manifest_decode
cargo +nightly fuzz build ipc_decode
cargo +nightly fuzz run manifest_decode -- -max_total_time=300
cargo +nightly fuzz run ipc_decode -- -max_total_time=300
```

Keep minimized, non-secret corpus inputs. Do not commit generated targets, crash artifacts, credentials, or recovered plaintext. Benchmark reproduction and interpretation are defined in [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md); it is not valid to replace a baseline with synthetic samples.

## Documentation ownership

The root README is the shortest entry point. `docs/ARCHITECTURE.md` is the single source of truth for security claims and non-goals. Operator procedures remain in the focused runbooks under `docs/` and `deploy/`. Update the canonical document rather than creating dated status notes or duplicating content across Markdown files.
