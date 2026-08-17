#!/usr/bin/env bash
# Copyright Nixort & Itan Winter <https://github.com/Nixort> 2026.
#
# License: GNU General Public License v3.0 or later.
#
# Install a pre-built VLT/1 release and hardened systemd units. This script
# never creates a vault, witness key, bearer credential, or passphrase.

set -euo pipefail
IFS=$'\n\t'

readonly INSTALL_ROOT='/usr/local/libexec/vlt1'
readonly LOCAL_UNIT='vlt1d@.service'
readonly WITNESS_CLIENT_UNIT='vlt1d-witness@.service'
readonly WITNESS_UNIT='vlt1-witnessd.service'

usage() {
    cat <<'EOF'
Usage:
  sudo deploy/install.sh --user LOCAL_USER [--source RELEASE_DIR] [--create-user]
                           [--enable-local | --enable-witness-client]
                           [--install-witness-unit] [--enable-witness-service]

Arguments:
  --user LOCAL_USER          Unix account that owns the local vault/socket.
  --source RELEASE_DIR       Directory containing release binaries.
                              Default: <repository>/target/release.
  --create-user              Create LOCAL_USER as a non-login system account if absent.
  --enable-local             Enable local-only vlt1d@LOCAL_USER.service (no network).
  --enable-witness-client    Enable vlt1d-witness@LOCAL_USER.service (HTTPS witness required).
  --install-witness-unit     Install the independently deployed vlt1-witnessd service unit.
  --enable-witness-service   Enable, but never start, vlt1-witnessd.service.
  --help                     Show this message.

The witness service must be installed on an independent host/administrative domain.
This installer never writes signing.seed, auth.token, witness.token, witness-public.key,
or /etc/vlt1/witness-LOCAL_USER.conf. Provision those mode-0600 files manually.
EOF
}

die() {
    printf 'install.sh: %s\n' "$*" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || die "required command is unavailable: $1"
}

validate_user_name() {
    [[ "$1" =~ ^[a-z_][a-z0-9_-]*[$]?$ ]] || die "invalid local user name: $1"
}

systemd_major_version() {
    systemd-analyze --version | awk 'NR == 1 { print $2 }'
}

install_unit() {
    local source="$1"
    local destination="/etc/systemd/system/$(basename -- "$source")"
    install -o root -g root -m 0644 "$source" "$destination"
    systemd-analyze verify "$destination"
}

main() {
    local owner=''
    local source_dir=''
    local create_user='false'
    local enable_local='false'
    local enable_witness_client='false'
    local install_witness_unit='false'
    local enable_witness_service='false'
    local script_dir repository_dir version owner_gid

    while (($# > 0)); do
        case "$1" in
            --user)
                (($# >= 2)) || die '--user needs an argument'
                owner="$2"
                shift 2
                ;;
            --source)
                (($# >= 2)) || die '--source needs an argument'
                source_dir="$2"
                shift 2
                ;;
            --create-user)
                create_user='true'
                shift
                ;;
            --enable-local)
                enable_local='true'
                shift
                ;;
            --enable-witness-client)
                enable_witness_client='true'
                shift
                ;;
            --install-witness-unit)
                install_witness_unit='true'
                shift
                ;;
            --enable-witness-service)
                enable_witness_service='true'
                install_witness_unit='true'
                shift
                ;;
            --help)
                usage
                exit 0
                ;;
            *)
                die "unknown argument: $1"
                ;;
        esac
    done

    [[ "${EUID}" -eq 0 ]] || die 'run this installer as root via sudo'
    [[ -n "$owner" ]] || die '--user is required'
    [[ "$enable_local" != 'true' || "$enable_witness_client" != 'true' ]] || die 'select only one local daemon profile'
    validate_user_name "$owner"
    require_command install
    require_command systemctl
    require_command systemd-analyze
    require_command id
    require_command awk

    version="$(systemd_major_version)"
    [[ "$version" =~ ^[0-9]+$ ]] || die 'could not determine systemd version'
    ((version >= 247)) || die 'systemd >= 247 is required for ProtectProc=invisible'

    script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
    repository_dir="$(cd -- "${script_dir}/.." && pwd -P)"
    if [[ -z "$source_dir" ]]; then
        source_dir="${repository_dir}/target/release"
    fi
    [[ -d "$source_dir" ]] || die "release directory does not exist: $source_dir"
    for binary in vlt1 vlt1d vlt1-witnessd vlt1-witness-key; do
        [[ -x "${source_dir}/${binary}" ]] || die "missing executable: ${source_dir}/${binary}"
    done

    if ! id --user "$owner" >/dev/null 2>&1; then
        [[ "$create_user" == 'true' ]] || die 'local user does not exist; use --create-user only for a non-login owner'
        require_command useradd
        useradd --system --create-home --shell /usr/sbin/nologin "$owner"
    fi

    install -d -o root -g root -m 0755 "$INSTALL_ROOT"
    for binary in vlt1 vlt1d vlt1-witnessd vlt1-witness-key; do
        install -o root -g root -m 0755 "${source_dir}/${binary}" "${INSTALL_ROOT}/${binary}"
    done
    install -d -o root -g root -m 0750 /etc/vlt1
    install_unit "${script_dir}/systemd/${LOCAL_UNIT}"
    install_unit "${script_dir}/systemd/${WITNESS_CLIENT_UNIT}"
    if [[ "$install_witness_unit" == 'true' ]]; then
        install_unit "${script_dir}/systemd/${WITNESS_UNIT}"
    fi

    owner_gid="$(id --group "$owner")"
    install -d -o "$owner" -g "$owner_gid" -m 0700 "/var/lib/vlt1-${owner}"
    systemctl daemon-reload

    if [[ "$enable_local" == 'true' ]]; then
        systemctl enable "vlt1d@${owner}.service"
    fi
    if [[ "$enable_witness_client" == 'true' ]]; then
        systemctl enable "vlt1d-witness@${owner}.service"
    fi
    if [[ "$enable_witness_service" == 'true' ]]; then
        systemctl enable "$WITNESS_UNIT"
    fi

    cat <<EOF
Installed VLT/1 binaries in ${INSTALL_ROOT}.

Next steps:
  1. Initialize exactly once as ${owner}:
     sudo -u ${owner} ${INSTALL_ROOT}/vlt1 init --vault /var/lib/vlt1-${owner}/vault.sqlite
  2. For local-only operation, start: vlt1d@${owner}.service
  3. For strict witness operation, provision witness credentials and endpoint config,
     then start: vlt1d-witness@${owner}.service
  4. Validate installed policy:
     sudo systemd-analyze security vlt1d@${owner}.service
     sudo systemd-analyze security vlt1d-witness@${owner}.service
EOF
}

main "$@"
