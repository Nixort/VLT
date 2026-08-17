# VLT/1 External Witness Protocol v1

**Author:** Itan Winter (NIxort) / Nixort  
**Transport:** HTTPS only from the VLT/1 client; HTTP is permitted only on a loopback listener behind an independently operated TLS reverse proxy.

This protocol turns the VLT/1 `WitnessProvider` extension point into an interoperable independently deployable service. It is intentionally narrow: one conditional acknowledgement endpoint and one challenge-bound object-head endpoint. It does not claim a quorum protocol, certificate-transparency log, TEE, or Byzantine availability.

## Trust bootstrap

The VLT/1 daemon must be configured with three independently provisioned values: a canonical HTTPS endpoint, a 32-byte Ed25519 **pinned witness public key**, and a high-entropy bearer credential stored in a root-owned/daemon-readable file. TLS authenticates the endpoint and protects the bearer credential in transit; the pinned Ed25519 key authenticates protocol objects independently of the Web PKI.

The bearer credential authorizes requests but is not a freshness signing key. Compromise of a client credential can at most create availability disruption by advancing the remote head; it cannot forge an acceptable receipt without the independently retained Ed25519 signing key. A production deployment should use a reverse proxy with mutual TLS or an equivalent stronger client-authentication mechanism instead of bearer credentials where feasible.

## JSON endpoints

All requests and responses use `Content-Type: application/json`, limit bodies to 16 KiB, and reject duplicate/unknown semantic values. Fixed-width binary values use lowercase hexadecimal encoding.

| Endpoint | Purpose | Required request fields |
|---|---|---|
| `POST /v1/issue` | Conditionally acknowledge an immutable version. | `vault_id`, `object_id`, `version_id`, `commitment`, `expected_epoch` |
| `POST /v1/head` | Obtain a fresh signed head for one object. | `vault_id`, `object_id`, `challenge` |
| `GET /healthz` | Non-secret liveness check for the reverse proxy and operator. | None |

`/v1/issue` returns HTTP 200 and a receipt when the supplied `expected_epoch` equals the service's current epoch for that object. The new receipt epoch is the next durable per-vault global epoch. Repeating the **same** `(vault, object, version, commitment, expected_epoch)` after an unknown network outcome returns the original receipt unchanged. A different request with a stale expected epoch returns HTTP 409 and a signed current object head.

`/v1/head` returns a signed current object head and copies the caller's 32-byte random challenge into the signing message. An absent object is represented explicitly with `present=false`, `epoch=0`, and all-zero version/commitment fields. The receiver must reject a response whose challenge differs from its random request challenge.

## Canonical signed messages

VLT/1 receipt signatures retain the existing domain-separated canonical byte sequence:

```text
"VLT/1 witness receipt v1" || vault_id || object_id || version_id ||
witness_epoch_be_u64 || commitment
```

Object-head signatures use a distinct unambiguous sequence:

```text
"VLT/1 witness head v1" || vault_id || object_id || present_u8 ||
version_id_or_zero || object_epoch_be_u64 || commitment_or_zero || challenge
```

The Ed25519 verifier rejects malformed public keys, invalid signatures, non-lowercase encodings, incorrect fixed widths, incorrect bindings, and signatures under a key other than the pinned public key. Ed25519 signing and verification use the RFC 8032 construction; VLT/1 supplies its own protocol-level domain separation because plain Ed25519 itself has an empty context.[1]

## Independent durable state

The witness has two SQLite-backed state dimensions under its own operator and storage boundary:

| Table role | Key | Value |
|---|---|---|
| Per-vault sequence | `vault_id` | Durable global monotonic epoch used to make receipts globally unique. |
| Per-object head | `(vault_id, object_id)` | Current version ID, commitment, and most recent global receipt epoch. |

Both rows are changed inside one `BEGIN IMMEDIATE` transaction for an issue. The signing key is outside this SQLite database and loaded from a private key file or a real HSM/KMS adapter. The witness database must be backed up independently and never restored jointly with a potentially compromised vault host.

## Client publish and verification behavior

A witness-enabled VLT/1 daemon obtains the current object head before publication, verifies it with a newly random challenge and the pinned key, and requires the local active receipt to equal the head. It then conditionally issues the next receipt and commits the validated receipt alongside the immutable version and active pointer. A stale/head mismatch, unsigned response, key mismatch, timeout, 409 conflict, or unavailable witness is a fail-closed error.

An updated implementation must use persistent pending versions to resolve the unavoidable cross-system crash window between remote acknowledgement and local commit. This protocol's idempotent `/v1/issue` response is specifically designed to make that reconciliation possible.

## References

[1] [RFC 8032 — EdDSA / Ed25519](https://www.rfc-editor.org/rfc/rfc8032)  
[2] [Angel et al., *Nimble*, OSDI 2023](https://www.usenix.org/system/files/osdi23-angel.pdf)
