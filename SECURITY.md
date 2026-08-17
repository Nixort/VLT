# Security policy

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability. Report it privately to the repository owner with a minimal reproduction, affected revision, operating system, Rust version, database artifact only when safe to share, and a clear statement of whether plaintext, key material or integrity was affected.

## Security boundary

VLT/1 protects encrypted local records against offline disclosure and modification within its documented threat boundary. It does not claim resistance to a malicious operating system, process-memory compromise, hardware side channels, previously exported plaintext, or rollback to a valid older database snapshot without an independently operated witness. See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Cryptographic changes

Cryptographic format changes require independent review. Do not replace AES-GCM-SIV, Argon2id, HKDF or SHA-256 implementations casually; do not implement these primitives in-tree. Security-relevant patches require a regression test and, where applicable, a format vector or fuzz reproducer.
