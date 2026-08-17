# VLT/1 hardened deployment

**Author:** Itan Winter (NIxort) / Nixort  
**Target:** Linux system manager with systemd **247 or newer**.

VLT/1 provides two deliberately distinct local-daemon profiles. The default profile is strictly local and has no network address families. The witness-enforced profile may reach an independently operated HTTPS freshness witness and fails closed if fresh witness state cannot be verified. Do not treat the two profiles as equivalent.

> `systemd-analyze security` estimates exposure only from systemd controls; it is neither a vulnerability assessment nor evidence that the cryptographic protocol is correct.[1]

| Unit | Intended use | Network boundary |
|---|---|---|
| `vlt1d@OWNER.service` | Local encrypted vault without an external witness. | `AF_UNIX` only. |
| `vlt1d-witness@OWNER.service` | Strict freshness mode, required for rollback evidence. | `AF_UNIX`, `AF_INET`, and `AF_INET6` only for the configured HTTPS witness. |
| `vlt1-witnessd.service` | Witness state machine on an **independent host and administrative domain**. | Loopback HTTP only; a separately administered TLS proxy terminates HTTPS. |

## Local service installation

Build a release, verify it, then install only known binaries and hardened unit files. The installer does not create a vault, passphrase, signing seed, bearer token, or trust pin.

```bash
cargo build --release --workspace
sudo ./deploy/install.sh --user "$USER" --source ./target/release
sudo -u "$USER" /usr/local/libexec/vlt1/vlt1 init \
  --vault "/var/lib/vlt1-${USER}/vault.sqlite"
sudo systemctl enable --now "vlt1d@${USER}.service"
```

The owner receives a `0700` state directory at `/var/lib/vlt1-OWNER/`; the daemon uses `/run/vlt1-OWNER/vlt1.sock`, which has mode `0600` and is also checked with `SO_PEERCRED`. `RuntimeDirectory=` and `StateDirectory=` create system-managed private paths that remain writable with `ProtectSystem=strict`.[2]

## Strict external witness deployment

The witness must **not** run in the same VM, host administrator domain, backup domain, or cloud account as the vault if rollback resistance is a meaningful goal. The service keeps a durable conditional head per `(vault_id, object_id)`, signs receipts with Ed25519, and returns a random-challenge-bound head. A local daemon pins the witness Ed25519 public key and checks each receipt and head cryptographically.

### Witness host

On the independent witness host, install the witness unit and provision its service account and secrets under root-controlled operational procedures. The witness process must be able to read its seed, so a process compromise can access it; use host controls, disk encryption, and appropriate key rotation. The seed and token are **not** suitable for source control, shell history, unit `Environment=`, or shared backup media.

```bash
sudo useradd --system --home /var/lib/vlt1-witness --shell /usr/sbin/nologin vlt1-witness
sudo ./deploy/install.sh --user witness-admin --source ./target/release --install-witness-unit
sudo install -d -o vlt1-witness -g vlt1-witness -m 0700 /etc/vlt1-witness
sudo sh -c 'umask 077; head -c 32 /dev/urandom > /etc/vlt1-witness/signing.seed'
sudo sh -c 'umask 077; head -c 32 /dev/urandom > /etc/vlt1-witness/auth.token'
sudo chown vlt1-witness:vlt1-witness /etc/vlt1-witness/signing.seed /etc/vlt1-witness/auth.token
sudo systemctl enable --now vlt1-witnessd.service
```

The witness binary rejects non-loopback listeners. Terminate TLS in a separate, independently operated proxy and expose only the two authenticated endpoints, `POST /v1/issue` and `POST /v1/head`; the local witness listener must remain `127.0.0.1:9823`. The VLT/1 client requires an `https://` endpoint, uses normal TLS certificate validation, and cryptographically pins the separate Ed25519 receipt key. The bearer token authenticates requests; the pinned signature prevents a TLS proxy from forging a receipt without the witness signing key.

Obtain the public key through an authenticated out-of-band channel, verify its fingerprint with the witness operator, and then provision the local vault owner. Never copy the private seed to the vault host.

```bash
# Run on the witness host; transfer only this public output by an authenticated channel.
sudo -u vlt1-witness /usr/local/libexec/vlt1/vlt1-witness-key \
  --signing-seed /etc/vlt1-witness/signing.seed

# Run on the vault host as the intended local owner.
sudo -u "$USER" sh -c 'umask 077; cat > "/var/lib/vlt1-'"$USER"'/witness.token"'
sudo -u "$USER" sh -c 'umask 077; cat > "/var/lib/vlt1-'"$USER"'/witness-public.key"'
sudo install -d -o root -g root -m 0750 /etc/vlt1
sudo sh -c 'printf "%s\n" "VLT1_WITNESS_ENDPOINT=https://witness.example.invalid" > "/etc/vlt1/witness-'"$USER"'.conf"'
sudo chmod 0640 "/etc/vlt1/witness-${USER}.conf"
sudo systemctl enable --now "vlt1d-witness@${USER}.service"
```

`witness.token` and `witness-public.key` must be regular mode-`0600` files. The daemon refuses incomplete trust configuration. When strict witness mode is enabled, unlock reconciles durable pending publications and verifies fresh challenge-bound heads before serving; `put`, `get`, and `verify` continue to re-check witness state. A network outage, stale conditional epoch, invalid signature, or contradictory head locks the vault instead of silently operating on possibly rolled-back state.

## Resource and process hardening

The daemon itself limits concurrent admitted socket connections to 32 by default and sets a five-second read/write deadline; saturated connections receive a bounded `overloaded` response. The units add an independent cgroup boundary: `TasksMax=64`, `MemoryHigh=256M`, `MemoryMax=384M`, `MemorySwapMax=0`, `LimitCORE=0`, and `LimitNOFILE=4096`. Systemd documents `MemoryHigh=` as the normal throttling mechanism and `MemoryMax=` as a final OOM defense; `TasksMax=` bounds kernel-accounted tasks.[3]

| Control | Operational effect |
|---|---|
| `User=`, `UMask=0077`, empty capabilities | The services run unprivileged and create private files by default. |
| `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes` | Writable filesystem scope is restricted to managed state/runtime paths. |
| `ProtectProc=invisible`, `PrivateDevices=yes`, `NoNewPrivileges=yes` | Other users' process metadata and normal device access are restricted; privilege gain is blocked. |
| `RestrictAddressFamilies=` | The local profile can create only Unix sockets. Network families are enabled only in the witness-specific profiles. |
| `MemorySwapMax=0`, `LimitCORE=0` | Reduces swap and core-dump exposure, but does not replace application memory locking or hardware-backed key custody. |
| `MemoryDenyWriteExecute=`, `RestrictNamespaces=`, `RestrictSUIDSGID=` | Reduces common post-exploitation primitives, subject to target-host compatibility testing. |

Validate every installation and revalidate after changing a unit, kernel, proxy, or binary:

```bash
sudo systemd-analyze verify /etc/systemd/system/vlt1d@.service
sudo systemd-analyze verify /etc/systemd/system/vlt1d-witness@.service
sudo systemd-analyze verify /etc/systemd/system/vlt1-witnessd.service
sudo systemd-analyze security "vlt1d@${USER}.service"
sudo systemd-analyze security "vlt1d-witness@${USER}.service"
sudo systemctl status "vlt1d@${USER}.service"
```

## Backup, restore, and release drills

Use the supported online snapshot command rather than copying a live WAL database:

```bash
vlt1 backup --socket "/run/vlt1-${USER}/vlt1.sock" \
  --output /secure-backup/vault-$(date -u +%F).sqlite
```

The result is an encrypted SQLite snapshot plus a non-secret SHA-256 sidecar. The full restore procedure, verification checks, and limitations are in [`docs/BACKUP_RESTORE.md`](../docs/BACKUP_RESTORE.md). Test an offline restore into a new pathname before any live replacement, then unlock and verify it. For strict witness deployments, test fresh witness-head verification after restore before declaring recovery successful.

## References

[1] [systemd-analyze — `security` and `verify`](https://www.freedesktop.org/software/systemd/man/latest/systemd-analyze.html)  
[2] [systemd.exec — execution environment configuration](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html)  
[3] [systemd.resource-control — resource control settings](https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html)
