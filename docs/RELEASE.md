# VLT/1 release and verification

VLT/1 publishes a Linux x86_64 release only from a pushed tag of the form
`v<workspace-version>`. The release workflow rejects a tag that does not match
the workspace version, repeats formatting, clippy, workspace, fault-injection,
and locked MSRV checks, then builds with the committed `Cargo.lock`.

## Published assets

| Asset | Purpose |
|---|---|
| `VLT-vX.Y.Z-linux-x86_64.tar.gz` | Deterministic archive containing `vlt1`, `vlt1d`, `vlt1-witnessd`, `vlt1-witness-key`, and `vlt1-bench`. |
| `SHA256SUMS` | SHA-256 manifest for the binary archive. |
| `vlt1.spdx.json` | SPDX JSON software bill of materials generated during the release build. |

The tar archive has sorted entries, normalized numeric ownership, and a fixed
archive timestamp. It is reproducible at the packaging layer from the same
release binary outputs; it is not a claim of bit-for-bit reproducibility across
different Rust toolchains, linkers, operating systems, or build hosts.

## Consumer verification

Download all release assets into one directory, then verify the checksum and
GitHub build provenance before installing binaries:

```sh
sha256sum --check SHA256SUMS
gh attestation verify VLT-vX.Y.Z-linux-x86_64.tar.gz -R Nixort/VLT
```

Use the exact archive file name in the second command. The provenance check
requires an online GitHub CLI session. To inspect the release SBOM attestation,
use the SPDX predicate type:

```sh
gh attestation verify VLT-vX.Y.Z-linux-x86_64.tar.gz \
  -R Nixort/VLT \
  --predicate-type https://spdx.dev/Document/v2.3
```

> A successful checksum proves the downloaded archive equals the published
> release asset. A successful GitHub attestation verifies its recorded build
> provenance. Neither check changes VLT/1's local threat model; deploy the
> daemon, vault database, witness, and secret files according to the hardened
> requirements in [`../deploy/README.md`](../deploy/README.md).

## Maintainer release procedure

A maintainer releases only after `main` CI is green and the workspace version
has been deliberately selected:

```sh
git checkout main
git pull --ff-only origin main
git tag -a vX.Y.Z -m "VLT/1 vX.Y.Z"
git push origin vX.Y.Z
```

The tag-triggered workflow creates the release only after its quality, MSRV,
and dependency-policy jobs succeed. A failed release job must be corrected by a
new source commit and a new release tag; do not mutate a published release tag.

## References

[1] [GitHub — build provenance and SBOM attestations](https://docs.github.com/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds)  
[2] [GitHub CLI — attestation verification](https://cli.github.com/manual/gh_attestation_verify)
