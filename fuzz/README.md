# VLT/1 fuzzing

**Author:** Itan Winter (NIxort) / Nixort  
**Scope:** untrusted parser and framing boundaries; no real vault, passphrase, or plaintext data belongs in a corpus.

The `fuzz/` directory is an independent Cargo project rather than a root-workspace member. It uses `cargo-fuzz` and `libFuzzer`; each target receives arbitrary byte slices repeatedly and must not panic, trigger an AddressSanitizer failure, or cause unbounded allocation.[1] [2]

## Targets

| Target | Entry boundary | Required property |
|---|---|---|
| `manifest_decode` | The private canonical CDE Manifest decoder, exposed only through a hidden fuzz hook. | Reject malformed, truncated, non-canonical, duplicate, and oversized logical inputs without panic. |
| `ipc_decode` | The 4-byte length-prefixed JSON request decoder. | Reject zero, truncated, oversized, and schema-invalid frames before unsafe allocation or panic. |

Both harnesses discard expected parser errors. A returned `Err` is a valid result; a crash, sanitizer finding, or hang is not.

## Prerequisites and commands

`cargo-fuzz` currently invokes `libFuzzer` through `libfuzzer-sys`.[1] The VLT/1 configuration requires a Rust nightly toolchain for AddressSanitizer instrumentation and a C++ compiler to build `libfuzzer-sys`.

```bash
cargo install cargo-fuzz --version 0.12.0 --locked
rustup toolchain install nightly --profile minimal
# Debian/Ubuntu only, if c++ is not available:
sudo apt-get install g++

cd /path/to/vlt1
cargo +nightly fuzz build manifest_decode
cargo +nightly fuzz build ipc_decode
cargo +nightly fuzz run manifest_decode -- -max_total_time=300 -print_final_stats=1
cargo +nightly fuzz run ipc_decode -- -max_total_time=300 -print_final_stats=1
```

Minimize the retained corpus after a successful campaign. Generated target binaries and crash artifacts are excluded from source control, while `fuzz/corpus/` is retained.

```bash
cargo +nightly fuzz cmin manifest_decode
cargo +nightly fuzz cmin ipc_decode
```

When a crash is found, preserve the generated `fuzz/artifacts/<target>/crash-*` input, reproduce it with `cargo +nightly fuzz run <target> <artifact>`, then add a deterministic regression test before accepting the corpus entry. Do not commit artefacts containing user data.

## Bounded CI regression

The `VLT/1 fuzz regression` workflow runs both existing targets for 60 seconds
with AddressSanitizer on pinned `nightly-2026-06-01`. It is manually dispatchable,
runs weekly, and also runs when a fuzz target or its parser boundary changes.
Each target has an independent 10-minute job limit and saves its final libFuzzer
statistics for 14 days. This bounded campaign detects crashes, sanitizer
findings, and hangs; it is deliberately not a replacement for longer manual
coverage campaigns or corpus minimization.

## Recorded baseline

On **2026-08-17**, VLT/1 ran final 60-second AddressSanitizer-backed campaigns for each target after the critical-hardening implementation. The IPC target completed 2,925,218 executions with 1,194 coverage edges and 3,434 features. The post-campaign minimized corpus retains 55 `manifest_decode` inputs (224 KiB) and 869 `ipc_decode` inputs (3.5 MiB). The campaigns produced **zero crash artifacts**. This is a bounded regression signal, not a proof that either parser is free of defects.

## References

[1] [Rust Fuzz Book — Fuzzing with cargo-fuzz](https://rust-fuzz.github.io/book/cargo-fuzz.html)  
[2] [Rust Fuzz Book — cargo-fuzz tutorial](https://rust-fuzz.github.io/book/cargo-fuzz/tutorial.html)
