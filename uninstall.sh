#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
set -euo pipefail
umask 077

uninstall_work=""
trap '[[ -z "$uninstall_work" ]] || rm -rf -- "$uninstall_work"' EXIT
die() { echo "Elise: $*" >&2; exit 1; }

usage() {
    cat <<'EOF'
Usage: sudo bash uninstall.sh --yes
       bash uninstall.sh --help

Permanently remove all standalone Elise instances and their retained data:
  - Stop and disable Elise services, then remove their units and overrides.
  - Delete /etc/elise and /var/lib/elise, including certificates and backups.
  - Remove the Elise binaries, management tools, and installed licenses.

External certificate/log/state files and the system journal
are preserved. --yes is required; this cannot be undone.

Requires Linux with systemd, root, Bash, curl, CA certificates, and flock.
Downloads the current removal tool from github.com/phungvanquy/elise over HTTPS;
works even if the installed elisectl is missing or does not support purge.
EOF
}

ensure_uninstall_dependencies() {
    [[ $EUID -eq 0 ]] || die 'run as root: sudo bash uninstall.sh --yes'
    [[ $(uname -s) == Linux && -d /run/systemd/system ]] || die 'Linux with systemd is required'
    local command
    for command in curl systemctl flock; do
        command -v "$command" >/dev/null || die "install $command first"
    done
}

main() {
    [[ $# -eq 1 ]] || die 'full uninstall requires exactly --yes; see bash uninstall.sh --help'
    case "$1" in
        --help|-h|help) usage; return 0 ;;
        --yes) ;;
        *) die 'full uninstall requires --yes; see bash uninstall.sh --help' ;;
    esac
    ensure_uninstall_dependencies
    uninstall_work=$(mktemp -d /tmp/elise-uninstall.XXXXXX)
    curl --fail --location --silent --show-error --proto '=https' --proto-redir '=https' \
        --retry 3 --retry-delay 2 --connect-timeout 15 --max-time 300 \
        --output "$uninstall_work/elisectl" \
        https://raw.githubusercontent.com/phungvanquy/elise/refs/heads/main/scripts/elise.sh \
        || die 'could not download the removal tool; no Elise files changed'
    if [[ ! -s "$uninstall_work/elisectl" ]] || ! bash -n "$uninstall_work/elisectl"; then
        die 'invalid removal tool; no Elise files changed'
    fi
    bash "$uninstall_work/elisectl" purge --yes
}

if [[ -z "${BASH_SOURCE[0]:-}" || "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
