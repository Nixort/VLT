# VLT/1 architecture and security boundary

VLT/1 is an implemented local encrypted-vault service for **one owner on one machine**. `vlt1d` owns one SQLite vault and exposes a closed Unix-domain-socket API; the CLI is its local client. The design intentionally keeps application policy, multi-user authorization, arbitrary streaming, and network serving outside the VLT/1 profile.

> This document describes what the repository implements. A future policy engine, sessions, quotas, partial reads, no-export semantics, and application-level request-id idempotency are not VLT/1 capabilities.

## Trust and process boundary

The trusted computing base includes the VLT/1 process while unlocked, RustCrypto and SQLite dependencies, the operating-system CSPRNG, the local OS/storage stack, and the user entering the passphrase. The daemon creates a mode-`0600` Unix socket and verifies the configured owner through Linux `SO_PEERCRED` before reading a request. It is a local capability boundary, not a network service.

Each connection carries exactly one UTF-8 JSON request and one response, prefixed by a four-byte big-endian length. The service rejects zero-length frames and frames above **16 MiB** before allocating their bodies. Closed enums and `deny_unknown_fields` prevent unknown request fields from silently acquiring meaning. Requests that need larger data must use a later streaming or descriptor-passing design rather than raising the JSON allocation limit.

| Request | Implemented behavior | Preconditions |
|---|---|---|
| `status` | Reports vault format, identifier, lifecycle, startup-recovery state, and prior verification count. | Authorized peer. |
| `unlock` / `lock` | Establishes or clears the in-memory Root Key. | Authorized peer. |
| `put` / `get` | Publishes a new immutable version or returns fully verified plaintext. | Unlocked vault. |
| `rotate_passphrase` | Re-wraps the unchanged Root Key and returns the vault to `locked`. | Authorized peer. |
| `verify` | Authenticates every active object and records the verified-object count. | Unlocked vault. |
| `checkpoint` | Runs `PRAGMA wal_checkpoint(FULL)` and rejects an incomplete or busy result. | Unlocked vault. |
| `backup` | Produces an online SQLite snapshot plus a SHA-256 sidecar. | Authorized peer. |
| `shutdown` | Stops the daemon only when explicit maintenance policy enables it. | Authorized peer and policy enabled. |

## Cryptographic model

| Key or record | Creation and use | Persistence |
|---|---|---|
| Root Key | 256 random bits at initialization; root of HKDF derivation. | Encrypted in `vault_meta` by the passphrase-derived key. |
| Passphrase key | Argon2id output; new envelopes use `m=65536 KiB`, `t=3`, `p=4`. | Derived only and zeroized after use. |
| KEK | HKDF-SHA-256 from Root Key, vault ID, and `VLT1/KEK`. | Derived only. |
| DEK | 256 random bits for each immutable object version. | Wrapped by the KEK in `versions`. |
| Chunk and Manifest | AES-256-GCM-SIV encryption with distinct context-bound AAD domains. | Nonce and ciphertext are stored in SQLite. |

A passphrase never becomes the Root Key. The Root Key never crosses the public library API, and a read returns plaintext only after every needed record has authenticated. AAD binds the vault, object, version, and chunk position so that a valid ciphertext cannot be swapped into a different context. AES-GCM-SIV and Argon2 are standardized in RFC 8452 and RFC 9106.[1] [2]

The Manifest uses a deliberately narrow, deterministic CBOR subset: integer map keys, unsigned integers, text strings, and byte strings with definite lengths. The encoder emits no tags, floating-point values, indefinite lengths, or duplicate keys; the decoder rejects non-canonical encodings.

## Persistence, recovery, and verification

SQLite opens with WAL mode, `synchronous=FULL`, foreign keys enabled, and `trusted_schema=OFF`. A publication transaction inserts the immutable version, its chunks, its optional witness receipt, and then advances the active-version pointer. A failure exposes neither a partial active version nor a partially committed pointer.

At startup VLT/1 runs `PRAGMA integrity_check`, `PRAGMA foreign_key_check`, and a VLT/1 active-pointer query. Failure prevents the daemon from listening. These are structural database checks, not ciphertext authentication: after unlock, `verify` traverses active objects in canonical order and verifies the wrapped DEK, sealed Manifest, row bindings, chunk layout, digest, and every ciphertext record. Storage, format, invariant, and authentication errors lock the in-memory vault and return no plaintext or key material.

Every chunk receives a CSPRNG-generated 96-bit nonce under the version-specific DEK. SQLite enforces nonce uniqueness within a version and VLT/1 caps a version at `2^24` chunks, or 64 TiB at the default 4 MiB chunk size. At that limit, the random 96-bit nonce collision bound is below `2^-49`; the cap is an operational guardrail, not a replacement for a CSPRNG. A further write must create a fresh version and DEK.

WAL permits a reader and writer to coexist but preserves committed state in `-wal` until checkpointing. A cold copy of a live vault must therefore treat the database, WAL, and shared-memory files as one unit. The supported path is the online backup operation; the exact restore procedure is in [`BACKUP_RESTORE.md`](BACKUP_RESTORE.md).[3]

## Freshness witness profile

VLT/1 can use an external `WitnessProvider` to obtain an Ed25519 receipt for a prepared immutable version. A receipt binds the vault ID, object ID, version ID, manifest commitment, witness epoch, public key, and signature. The vault verifies this binding before publication, persists the receipt in the publication transaction, verifies it again on reads and verification sweeps, and reconciles a staged receipt after restart.

The strict profile requires an independently operated HTTPS witness with durable conditional monotonic heads. A local or same-administrator witness does not provide meaningful rollback evidence. Network loss, invalid signature, stale epoch, or contradictory head locks a strict-profile vault rather than letting it continue under uncertain freshness. The full trust bootstrap and endpoint contract are defined in [`WITNESS_PROTOCOL.md`](WITNESS_PROTOCOL.md); deployment requirements are in [`../deploy/README.md`](../deploy/README.md).

## Threat boundary and operational baseline

| Addressed condition | VLT/1 response |
|---|---|
| Offline database copy | Argon2id protects the Root Key under the passphrase. |
| Modified ciphertext, nonce, Manifest, wrapped DEK, or metadata | Context-bound AEAD and Manifest/row checks fail before plaintext is returned. |
| Chunk deletion, insertion, or reordering | Manifest digest and expected chunk layout checks fail. |
| Repeated writes | A fresh immutable version and DEK are created. |
| Invalid passphrase or ambiguous backend failure | The vault remains or becomes locked. |
| Rollback to an authentic older database | Detected only by a correctly independent strict witness profile; otherwise out of scope. |

VLT/1 does not protect against root or kernel compromise, debugger access, process-memory disclosure, malicious dependencies, compromised randomness, physical side channels, or plaintext captured after an authorized read. It does not provide TPM, TEE, HSM, `mlock`, a policy engine, or multi-user authorization. Full-disk encryption, restricted database permissions, encrypted or disabled swap, disabled hibernation where practical, and disabled core dumps reduce surrounding risk but do not alter these boundaries.

## Validation boundary

The repository contains strict formatting/linting gates, unit and integration tests, feature-gated crash-window fault tests, parser fuzz targets, and reproducible direct/RPC benchmarks. These demonstrate engineering behavior for the exercised cases; they are not a cryptographic proof or an independent security audit. Run commands and contribution requirements are in [`../CONTRIBUTING.md`](../CONTRIBUTING.md).

## References

[1] [RFC 8452 — AES-GCM-SIV](https://www.rfc-editor.org/rfc/rfc8452)  
[2] [RFC 9106 — Argon2](https://www.rfc-editor.org/rfc/rfc9106.html)  
[3] [SQLite — Write-Ahead Logging](https://www.sqlite.org/wal.html)
