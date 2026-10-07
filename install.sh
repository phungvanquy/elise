#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
set -euo pipefail
umask 077

repo=phungvanquy/elise
manager=/usr/local/bin/elisectl
work=""
trap '[[ -z "$work" ]] || rm -rf -- "$work"' EXIT
die() { echo "Elise: $*" >&2; exit 1; }
fetch() {
    curl --fail --location --silent --show-error --proto '=https' --proto-redir '=https' \
        --retry 3 --retry-delay 2 --connect-timeout 15 --max-time 300 --output "$2" "$1"
}

download_release() {
    local tag=${1:-} arch=$2 asset expected actual
    work=$(mktemp -d /tmp/elise-install.XXXXXX)
    if [[ -n "$tag" ]]; then
        tag="v${tag#v}"
        [[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.-]+)?$ ]] || die 'Invalid Elise release version'
        fetch "https://api.github.com/repos/$repo/releases/tags/$tag" "$work/release.json"
    else
        fetch "https://api.github.com/repos/$repo/releases/latest" "$work/release.json"
    fi
    asset="elise-linux-${arch}.tar.gz"
    tag=$(python3 - "$work/release.json" "$repo" "$tag" "$asset" <<'PY'
import json, re, sys
release = json.load(open(sys.argv[1]))
repo, requested, asset = sys.argv[2:]
tag = release.get('tag_name', '')
if release.get('draft') or not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.-]+)?', tag):
    sys.exit('Invalid Elise release')
if (requested and tag != requested) or (not requested and release.get('prerelease')):
    sys.exit('Unexpected Elise release version')
expected = {f'https://github.com/{repo}/releases/download/{tag}/{name}' for name in (asset, asset + '.sha256')}
available = {item.get('browser_download_url') for item in release.get('assets', []) if item.get('state') == 'uploaded'}
if not expected <= available:
    sys.exit('Elise release archives or checksums are missing')
print(tag)
PY
    )
    fetch "https://github.com/$repo/releases/download/$tag/$asset" "$work/$asset"
    fetch "https://github.com/$repo/releases/download/$tag/$asset.sha256" "$work/$asset.sha256"
    expected=$(awk -v name="$asset" '$2 == name || $2 == "*" name {print $1}' "$work/$asset.sha256")
    [[ "$expected" =~ ^[a-fA-F0-9]{64}$ ]] || die 'Invalid checksum file'
    actual=$(sha256sum "$work/$asset" | awk '{print $1}')
    [[ "${expected,,}" == "$actual" ]] || die 'Checksum mismatch; installation unchanged'
    # Extract only regular, explicitly named files; never follow archive links.
    # migrate.py is an inert compatibility stub in newer releases.
    python3 - "$work/$asset" "$work" <<'PY'
import pathlib, sys, tarfile
names = ('elise', 'elisectl', 'install.sh', 'install-release.py', 'migrate.py', 'runtime.py',
         'elise@.service', 'LICENSE', 'SCRIPTS-LICENSE', 'THIRD-PARTY-NOTICES')
with tarfile.open(sys.argv[1], 'r:gz') as archive:
    for name in names:
        matches = [m for m in archive.getmembers() if m.name == 'elise/' + name]
        if len(matches) != 1 or not matches[0].isfile():
            sys.exit('Missing, duplicate, or invalid archive member: ' + name)
        path = pathlib.Path(sys.argv[2]) / name
        with archive.extractfile(matches[0]) as source, path.open('wb') as output:
            import shutil
            shutil.copyfileobj(source, output)
        path.chmod(0o700 if name in ('elise', 'elisectl', 'install.sh') else 0o600)
PY
    resolved_tag=$tag
}

usage() {
    cat <<'EOF'
Usage: bash install.sh [install|update] [vX.Y.Z]
       bash install.sh [install] [vX.Y.Z] --node-type=TYPE --panel-url=URL --api-key=KEY --node-id=ID [options]

Without node options, installs only the Elise program and management tools.
With node options, also creates, enables, and starts one node without prompts.
Required: --node-type (vless, vmess, anytls, hysteria, hysteria2), --panel-url,
          --node-id, and --api-key (or --api-key-file).
Optional: --panel-type (default v2board), --listen (default 0.0.0.0).
For certificate TLS, choose one:
  --cert-mode=file --cert-file=/absolute/fullchain.pem --key-file=/absolute/key.pem
  --cert-mode=http --domain=node.example.com --email=admin@example.com
  --cert-mode=self-signed --domain=node.example.com
Self-signed certificates are valid for 3650 days (about 10 years); clients must trust them.
HTTP mode uses Let's Encrypt HTTP-01; DNS must point here and TCP port 80 must be open.
Options accept --name=value or --name value. Existing nodes are never overwritten.
Node options require Elise v1.0.5 or newer. Pin a release with the positional version.
EOF
}

parse_install_args() {
    local action=install option
    case "${1:-install}" in
        install|update) action=${1:-install}; [[ $# -eq 0 ]] || shift ;;
    esac
    if [[ $# -gt 0 && "$1" != -* ]]; then
        release_version=$1; shift
        [[ "$release_version" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.-]+)?$ ]] || die 'Invalid Elise release version'
    fi
    while [[ $# -gt 0 ]]; do
        option=${1%%=*}
        case "$option" in
            --node-type|--node-id|--panel-type|--panel-url|--api-key|--api-key-file|--listen|--cert-mode|--cert-file|--key-file|--domain|--email) ;;
            *) die 'Unknown installer option; see bash install.sh --help' ;;
        esac
        node_args+=("$1")
        if [[ "$1" == *=* ]]; then
            [[ -n "${1#*=}" ]] || die "Missing value for $option"
            shift
        else
            [[ $# -ge 2 && "$2" != --* ]] || die "Missing value for $option"
            node_args+=("$2"); shift 2
        fi
    done
    [[ "$action" != update || ${#node_args[@]} -eq 0 ]] || die 'Use install to provision a node; update takes only a release version'
}

ensure_install_dependencies() {
    [[ $EUID -eq 0 ]] || die 'Run as root (sudo bash install.sh install)'
    [[ $(uname -s) == Linux && -d /run/systemd/system ]] || die 'Linux with systemd is required'
    case "$(uname -m)" in
        x86_64|amd64) arch=amd64 ;;
        aarch64|arm64) arch=arm64 ;;
        *) die 'Releases support Linux amd64 and arm64' ;;
    esac
    for command in curl tar sha256sum systemctl flock; do
        command -v "$command" >/dev/null || die "Install $command first"
    done
    if ! command -v python3 >/dev/null; then
        if command -v apt-get >/dev/null; then
            apt-get update -y
            DEBIAN_FRONTEND=noninteractive apt-get install -y python3
        elif command -v dnf >/dev/null; then
            dnf install -y python3
        elif command -v yum >/dev/null; then
            yum install -y python3
        else
            die 'Python 3.8 or newer is required'
        fi
    fi
    python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' || die 'Python 3.8 or newer is required'
}

main() {
    case "${1:-}" in -h|--help|help) usage; return 0 ;; esac
    if [[ ( "${1:-}" == install || "${1:-}" == update ) && ( "${2:-}" == --help || "${2:-}" == -h ) ]]; then
        usage; return 0
    fi
    local release_version="" arch
    local -a node_args=()
    parse_install_args "$@"
    ensure_install_dependencies
    download_release "$release_version" "$arch"
    if [[ ${#node_args[@]} -gt 0 ]]; then
        # Use the verified archive's manager and core to check the node before
        # replacing installed files or restarting any existing Elise instances.
        bash "$work/elisectl" __check-add "$work/elise" "${node_args[@]}" </dev/null
    fi
    python3 "$work/install-release.py" "$work" "$resolved_tag"
    if [[ ${#node_args[@]} -gt 0 ]]; then
        bash "$manager" add "${node_args[@]}" </dev/null
    fi
}

if [[ -z "${BASH_SOURCE[0]:-}" || "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
