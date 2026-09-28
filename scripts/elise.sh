#!/usr/bin/env bash
set -euo pipefail

# Elise remains a separate Rust process. The V2bX Go service must not manage
# the same panel node, or both processes will bind and report it.
repo="phungvanquy/Elise-Backend"
bin_dir="/usr/local/libexec/V2bX"
binary="${bin_dir}/elise"
config_dir="/etc/v2bx-elise"
v2bx_config="${V2BX_CONFIG_PATH:-/etc/V2bX/config.json}"
unit_file="/etc/systemd/system/V2bX-elise@.service"
work=""
trap '[[ -z "$work" ]] || rm -rf -- "$work"' EXIT

die() { echo "V2bX Elise: $*" >&2; exit 1; }
need_root() { [[ $EUID -eq 0 ]] || die "run as root"; }
need_systemd() { command -v systemctl >/dev/null && [[ -d /run/systemd/system ]] || die "systemd is required"; }
need_python() { command -v python3 >/dev/null || die "python3 is required"; }
fetch() {
    curl --fail --location --silent --show-error --proto '=https' --proto-redir '=https' \
        --retry 3 --retry-delay 2 --connect-timeout 15 --max-time 300 \
        --output "$2" "$1"
}
valid_instance() { [[ "${1:-}" =~ ^(vless|vmess)-[1-9][0-9]*$ ]]; }
instance_dir() { printf '%s/%s' "$config_dir" "$1"; }
instance_unit() { printf 'V2bX-elise@%s.service' "$1"; }

write_unit() {
    cat > "$unit_file" <<'EOF'
[Unit]
Description=V2bX Elise Rust node %i
After=network-online.target nss-lookup.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
UMask=0077
WorkingDirectory=/etc/v2bx-elise/%i
ExecStart=/usr/local/libexec/V2bX/elise run -c /etc/v2bx-elise/%i/elise.conf
Restart=on-failure
RestartSec=10
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
    chmod 0644 "$unit_file"
    systemctl daemon-reload
}

restore_release() {
    local previous_binary=$1 previous_unit=$2 previous_license=$3 instance
    if [[ -f "$previous_binary" ]]; then cp -p "$previous_binary" "$binary"; else rm -f -- "$binary"; fi
    if [[ -f "$previous_unit" ]]; then cp -p "$previous_unit" "$unit_file"; else rm -f -- "$unit_file"; fi
    if [[ -f "$previous_license" ]]; then cp -p "$previous_license" "$bin_dir/elise.LICENSE"; else rm -f -- "$bin_dir/elise.LICENSE"; fi
    systemctl daemon-reload || true
    for instance in "${active[@]}"; do systemctl restart "$(instance_unit "$instance")" || true; done
}

installed_instances() {
    local file name
    for file in "$config_dir"/*/elise.conf; do
        [[ -f "$file" ]] || continue
        name=${file%/elise.conf}
        name=${name##*/}
        valid_instance "$name" && printf '%s\n' "$name"
    done
}

install_binary() {
    need_root; need_systemd; need_python
    local arch tag asset archive checksum expected actual old_binary old_unit old_license port listen details
    case "$(uname -m)" in
        x86_64|amd64) arch=amd64 ;;
        aarch64|arm64) arch=arm64 ;;
        *) die "Elise releases support Linux amd64 and arm64; this host is $(uname -m)" ;;
    esac
    work=$(mktemp -d /tmp/v2bx-elise.XXXXXX)
    if [[ -n "${1:-}" ]]; then
        tag=${1#v}
        [[ "$tag" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.-]+)?$ ]] || die "invalid Elise version"
        tag="v$tag"
        fetch "https://api.github.com/repos/$repo/releases/tags/$tag" "$work/release.json"
    else
        fetch "https://api.github.com/repos/$repo/releases/latest" "$work/release.json"
        tag=$(python3 - "$work/release.json" <<'PY'
import json, re, sys
release = json.load(open(sys.argv[1]))
tag = release.get('tag_name', '')
if release.get('draft') or release.get('prerelease') or not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', tag):
    sys.exit('invalid latest Elise release')
print(tag)
PY
        )
    fi
    asset="elise-linux-${arch}.tar.gz"
    python3 - "$work/release.json" "$repo" "$tag" "$asset" <<'PY'
import json, sys
release = json.load(open(sys.argv[1]))
repo, tag, asset = sys.argv[2:]
expected = {f'https://github.com/{repo}/releases/download/{tag}/{name}' for name in (asset, asset + '.sha256')}
actual = {item.get('browser_download_url') for item in release.get('assets', []) if item.get('state') == 'uploaded'}
if release.get('tag_name') != tag or not expected <= actual:
    sys.exit('Elise release assets are missing or do not match the requested version')
PY
    archive="$work/$asset"
    checksum="$archive.sha256"
    fetch "https://github.com/$repo/releases/download/$tag/$asset" "$archive"
    fetch "https://github.com/$repo/releases/download/$tag/$asset.sha256" "$checksum"
    expected=$(awk -v name="$asset" '$2 == name || $2 == "*" name {print $1}' "$checksum")
    [[ "$expected" =~ ^[a-fA-F0-9]{64}$ ]] || die "invalid Elise checksum file"
    actual=$(sha256sum "$archive" | awk '{print $1}')
    [[ "${expected,,}" == "$actual" ]] || die "Elise archive checksum mismatch; installation unchanged"
    tar -xOzf "$archive" elise/elise > "$work/elise" || die "Elise binary missing from archive"
    tar -xOzf "$archive" elise/LICENSE > "$work/LICENSE" || die "Elise license missing from archive"
    chmod 0755 "$work/elise"
    [[ "$("$work/elise" --version)" == "elise ${tag#v}" ]] || die "Elise version or architecture mismatch"

    mkdir -p "$bin_dir" "$config_dir"
    chmod 0700 "$config_dir"
    old_binary="$work/old-elise"; old_unit="$work/old-unit"; old_license="$work/old-license"
    [[ ! -f "$binary" ]] || cp -p "$binary" "$old_binary"
    [[ ! -f "$unit_file" ]] || cp -p "$unit_file" "$old_unit"
    [[ ! -f "$bin_dir/elise.LICENSE" ]] || cp -p "$bin_dir/elise.LICENSE" "$old_license"
    local -a active=()
    local instance
    while IFS= read -r instance; do
        if systemctl is-active --quiet "$(instance_unit "$instance")"; then active+=("$instance"); fi
    done < <(installed_instances)
    if ! install -m 0755 "$work/elise" "$binary.new" ||
       ! mv -f "$binary.new" "$binary" ||
       ! install -m 0644 "$work/LICENSE" "$bin_dir/elise.LICENSE" ||
       ! write_unit; then
        restore_release "$old_binary" "$old_unit" "$old_license"
        die "Elise installation failed; previous release restored"
    fi
    for instance in "${active[@]}"; do
        details=$(panel_port_and_security "$(instance_dir "$instance")/elise.conf" no-bind) || details=""
        port=${details%%$'\n'*}
        listen=$(sed -n 's/^listen=//p' "$(instance_dir "$instance")/elise.conf" | head -n 1)
        if [[ ! "$port" =~ ^[0-9]+$ ]] ||
           ! systemctl restart "$(instance_unit "$instance")" ||
           ! systemctl is-active --quiet "$(instance_unit "$instance")" ||
           ! wait_node_port "$listen" "$port"; then
            restore_release "$old_binary" "$old_unit" "$old_license"
            die "Elise failed to restart; previous binary and service restored"
        fi
    done
    echo "Installed Elise $tag ($arch). Add a VLESS or VMess node with: V2bX elise add <type> <id>"
}

check_v2bx_assignment() {
    python3 - "$1" "$2" "$v2bx_config" <<'PY'
import json, pathlib, sys
kind, node_id = sys.argv[1], int(sys.argv[2])
path = pathlib.Path(sys.argv[3])
if not path.exists():
    sys.exit(0)
source = path.read_text()
clean = []
i = 0
quoted = False
while i < len(source):
    char = source[i]
    if quoted:
        clean.append(char)
        if char == '\\' and i + 1 < len(source):
            i += 1
            clean.append(source[i])
        elif char == '"':
            quoted = False
    elif char == '"':
        quoted = True
        clean.append(char)
    elif source.startswith('//', i):
        while i < len(source) and source[i] not in '\r\n':
            i += 1
        continue
    elif source.startswith('/*', i):
        end = source.find('*/', i + 2)
        if end < 0:
            sys.exit('unterminated comment in V2bX config')
        i = end + 2
        continue
    else:
        clean.append(char)
    i += 1
source = ''.join(clean)
clean = []
i = 0
quoted = False
while i < len(source):
    char = source[i]
    if quoted:
        clean.append(char)
        if char == '\\' and i + 1 < len(source):
            i += 1
            clean.append(source[i])
        elif char == '"':
            quoted = False
    elif char == '"':
        quoted = True
        clean.append(char)
    elif char == ',':
        j = i + 1
        while j < len(source) and source[j].isspace():
            j += 1
        if j >= len(source) or source[j] not in '}]':
            clean.append(char)
    else:
        clean.append(char)
    i += 1
try:
    data = json.loads(''.join(clean))
except (ValueError, OSError) as exc:
    sys.exit(f'cannot verify V2bX node assignments in {path}: {exc}')
for node in data.get('Nodes', []):
    if node.get('Include'):
        sys.exit('V2bX node includes must be reviewed before adding an Elise node')
    api = node.get('ApiConfig') or node
    if str(api.get('NodeType', '')).lower() == kind and api.get('NodeID') == node_id:
        sys.exit(f'{kind} node {node_id} is already managed by the V2bX Go service')
PY
}

panel_port_and_security() {
    python3 - "$1" "${2:-}" <<'PY'
import pathlib, socket, sys, urllib.parse, urllib.request, json
values = {}
for line in pathlib.Path(sys.argv[1]).read_text().splitlines():
    if '=' in line:
        key, value = line.split('=', 1)
        values[key.strip()] = value.strip()
kind = values['panel_node_type']
query = urllib.parse.urlencode({'node_type': kind, 'node_id': values['node_id'], 'token': values['panel_key']})
url = values['panel_url'].rstrip('/') + '/api/v1/server/UniProxy/config?' + query
try:
    request = urllib.request.Request(url, headers={'User-Agent': 'V2bX-Elise/1.0'})
    with urllib.request.urlopen(request, timeout=15) as response:
        payload = json.load(response)
except Exception as exc:
    sys.exit(f'cannot fetch panel node configuration: {exc}')
data = payload.get('data', payload)
reported = data.get('server_type') or data.get('protocol') or data.get('node_type')
if reported and reported.lower() not in (kind, 'v2ray' if kind == 'vmess' else kind):
    sys.exit(f'panel returned {reported}, expected {kind}')
port = data.get('server_port')
if not isinstance(port, int) or not (1 <= port <= 65535):
    sys.exit('panel did not return a valid server_port')
security = data.get('tls', 0)
if kind == 'vmess' and security not in (0, 1):
    sys.exit('VMess supports plain or TLS mode in this installer')
if kind == 'vless' and security not in (0, 1, 2):
    sys.exit('unsupported VLESS security mode')
if security == 2:
    tls = data.get('tls_settings') or data.get('tlsSettings') or {}
    if not (tls.get('private_key') and (tls.get('public_key') or data.get('public_key'))):
        sys.exit('REALITY requires matching private and public keys in the panel')
if sys.argv[2] != 'no-bind':
    address = values['listen']
    family = socket.AF_INET6 if ':' in address else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        try:
            sock.bind((address, port))
        except OSError as exc:
            sys.exit(f'cannot bind {address}:{port}: {exc}')
print(port)
print(security)
PY
}

wait_node_port() {
    python3 - "$1" "$2" <<'PY'
import socket, sys, time
address, port = sys.argv[1], int(sys.argv[2])
if address == '0.0.0.0': address = '127.0.0.1'
if address == '::': address = '::1'
for _ in range(30):
    try:
        with socket.create_connection((address, port), timeout=0.5):
            sys.exit(0)
    except OSError:
        time.sleep(0.3)
sys.exit('Elise inbound did not open its panel port')
PY
}

add_node() {
    need_root; need_systemd; need_python
    [[ -x "$binary" ]] || die "install the Elise binary first"
    local kind=${1:-} node_id=${2:-} instance target panel_url panel_key listen cert_file key_file security port
    [[ "$kind" == vless || "$kind" == vmess ]] || die "type must be vless or vmess"
    [[ "$node_id" =~ ^[1-9][0-9]*$ ]] || die "node ID must be a positive integer"
    python3 - "$node_id" <<'PY' || die "node ID exceeds Elise's u32 range"
import sys
sys.exit(0 if int(sys.argv[1]) <= 4294967295 else 1)
PY
    instance="$kind-$node_id"; target=$(instance_dir "$instance")
    [[ ! -e "$target" ]] || die "$instance already exists; edit its config or remove it first"
    check_v2bx_assignment "$kind" "$node_id" || die "remove this node from /etc/V2bX/config.json before adding it to Elise"
    read -rp 'Panel URL: ' panel_url
    python3 - "$panel_url" <<'PY' || die "invalid panel URL"
import sys, urllib.parse
url = urllib.parse.urlsplit(sys.argv[1])
sys.exit(0 if url.scheme in ('http', 'https') and url.netloc and not url.query and not url.fragment and not any(c.isspace() for c in sys.argv[1]) else 1)
PY
    read -rsp 'Panel API key: ' panel_key; echo
    [[ -n "$panel_key" && "$panel_key" != *$'\r'* ]] || die "invalid panel API key"
    read -rp 'Listen address [0.0.0.0]: ' listen
    listen=${listen:-0.0.0.0}
    [[ "$listen" =~ ^[0-9a-fA-F:.]+$ ]] || die "listen address must be an IP address"
    work=$(mktemp -d /tmp/v2bx-elise.XXXXXX)
    cat > "$work/elise.conf" <<EOF
type=xboard
panel_url=$panel_url
panel_key=$panel_key
panel_node_type=$kind
node_id=$node_id
nodes_dir=$target/nodes
listen=$listen
pprof_addr=off
auto_tls=false
check_interval=60
submit_interval=60
routes_file=$target/routes.toml
dns_file=$target/dns.yml
block_list_file=$target/blockList
white_list_file=$target/whiteList
EOF
    chmod 0600 "$work/elise.conf"
    mapfile -t details < <(panel_port_and_security "$work/elise.conf") || die "panel preflight failed"
    port=${details[0]:-}; security=${details[1]:-}
    [[ "$port" =~ ^[0-9]+$ && "$security" =~ ^[0-2]$ ]] || die "panel preflight failed"
    if [[ "$security" == 1 ]]; then
        read -rp 'TLS certificate file (full chain): ' cert_file
        read -rp 'TLS private key file: ' key_file
        [[ "$cert_file" == /* && "$key_file" == /* && -s "$cert_file" && -s "$key_file" ]] || die "TLS certificate and key must be nonempty absolute files"
        printf 'cert_file=%s\nkey_file=%s\n' "$cert_file" "$key_file" >> "$work/elise.conf"
    fi
    mkdir -p "$target/nodes"
    chmod 0700 "$config_dir" "$target" "$target/nodes"
    install -m 0600 "$work/elise.conf" "$target/elise.conf"
    local name
    for name in routes.toml dns.yml blockList whiteList; do
        : > "$target/$name"
        chmod 0600 "$target/$name"
    done
    if ! systemctl enable --now "$(instance_unit "$instance")" ||
       ! systemctl is-active --quiet "$(instance_unit "$instance")" ||
       ! wait_node_port "$listen" "$port"; then
        systemctl disable --now "$(instance_unit "$instance")" >/dev/null 2>&1 || true
        rm -rf -- "$target"
        die "Elise service failed; inspect journalctl -u $(instance_unit "$instance")"
    fi
    echo "Elise $instance started on $listen:$port"
    if [[ "$security" == 1 ]]; then
        echo "Configure your certificate renewal tool to run: V2bX elise restart $instance"
    fi
}

service_action() {
    need_root; need_systemd
    local action=$1 instance=${2:-}
    valid_instance "$instance" || die "use vless-<id> or vmess-<id>"
    [[ -f "$(instance_dir "$instance")/elise.conf" ]] || die "unknown Elise node $instance"
    case "$action" in
        log) journalctl -u "$(instance_unit "$instance")" -n 100 --no-pager ;;
        status) systemctl status "$(instance_unit "$instance")" ;;
        *) systemctl "$action" "$(instance_unit "$instance")" ;;
    esac
}

remove_node() {
    need_root; need_systemd
    local instance=${1:-}
    valid_instance "$instance" || die "use vless-<id> or vmess-<id>"
    [[ -d "$(instance_dir "$instance")" ]] || die "unknown Elise node $instance"
    if systemctl is-active --quiet "$(instance_unit "$instance")"; then
        systemctl stop "$(instance_unit "$instance")" || die "could not stop $instance"
    fi
    systemctl disable "$(instance_unit "$instance")" >/dev/null 2>&1 || true
    rm -rf -- "$(instance_dir "$instance")"
    echo "Removed Elise node $instance"
}

uninstall_all() {
    need_root; need_systemd
    local instance
    while IFS= read -r instance; do
        if systemctl is-active --quiet "$(instance_unit "$instance")"; then
            systemctl stop "$(instance_unit "$instance")" || die "could not stop $instance"
        fi
        systemctl disable "$(instance_unit "$instance")" >/dev/null 2>&1 || true
    done < <(installed_instances)
    rm -f -- "$unit_file" "$binary" "$bin_dir/elise.LICENSE"
    systemctl daemon-reload
    echo "Elise binary and services removed. Configuration remains in $config_dir."
}

usage() {
    cat <<'EOF'
Usage: V2bX elise install [version]
       V2bX elise add <vless|vmess> <node-id>
       V2bX elise list
       V2bX elise start|stop|restart|status|log <vless-id|vmess-id>
       V2bX elise remove <vless-id|vmess-id>
       V2bX elise uninstall
EOF
}

case "${1:-}" in
    install|update) shift; install_binary "${1:-}" ;;
    add) shift; add_node "${1:-}" "${2:-}" ;;
    list) need_root; installed_instances ;;
    start|stop|restart|status|log) action=$1; shift; service_action "$action" "${1:-}" ;;
    remove) shift; remove_node "${1:-}" ;;
    uninstall) uninstall_all ;;
    help|-h|--help|'') usage ;;
    *) usage; exit 2 ;;
esac
