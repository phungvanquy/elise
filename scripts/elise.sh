#!/usr/bin/env bash
set -euo pipefail

# SPDX-License-Identifier: MPL-2.0
bin_dir="/usr/local/bin"
binary="${bin_dir}/elise"
config_dir="/etc/elise/instances"
state_dir="/var/lib/elise"
support_dir="/usr/local/lib/elise"
license_dir="/usr/local/share/licenses/elise"
v2bx_config="${V2BX_CONFIG_PATH:-/etc/V2bX/config.json}"
unit_file="/etc/systemd/system/elise@.service"
work=""
trap '[[ -z "$work" ]] || rm -rf -- "$work"' EXIT

die() { echo "Elise: $*" >&2; exit 1; }
need_root() { [[ $EUID -eq 0 ]] || die "run as root"; }
need_systemd() { command -v systemctl >/dev/null && [[ -d /run/systemd/system ]] || die "systemd is required"; }
ensure_python() {
    command -v python3 >/dev/null 2>&1 && return 0
    echo "Elise: installing python3" >&2
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -y && DEBIAN_FRONTEND=noninteractive apt-get install -y python3 || die "could not install python3 with apt-get"
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y python3 || die "could not install python3 with dnf"
    elif command -v yum >/dev/null 2>&1; then
        yum install -y python3 || die "could not install python3 with yum"
    else
        die "python3 is required and no supported package manager was found"
    fi
    command -v python3 >/dev/null 2>&1 || die "python3 installation did not provide python3"
}
ensure_openssl() {
    command -v openssl >/dev/null 2>&1 && return 0
    echo "Elise: installing openssl" >&2
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -y && DEBIAN_FRONTEND=noninteractive apt-get install -y openssl || die "could not install openssl with apt-get"
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y openssl || die "could not install openssl with dnf"
    elif command -v yum >/dev/null 2>&1; then
        yum install -y openssl || die "could not install openssl with yum"
    else
        die "openssl is required and no supported package manager was found"
    fi
    command -v openssl >/dev/null 2>&1 || die "openssl installation did not provide openssl"
}
fetch() {
    curl --fail --location --silent --show-error --proto '=https' --proto-redir '=https' \
        --retry 3 --retry-delay 2 --connect-timeout 15 --max-time 300 \
        --output "$2" "$1"
}
normalize_kind() {
    case "${1,,}" in
        vless|vmess|anytls|hysteria|hysteria2) printf '%s\n' "${1,,}" ;;
        hysteria1|hy1) echo hysteria ;;
        hy2) echo hysteria2 ;;
        *) return 1 ;;
    esac
}
normalize_panel() {
    case "${1,,}" in
        xboard|v2board|v2board-uniproxy|xiaov2board|ppanel|sspanel) printf '%s\n' "${1,,}" ;;
        xiaov2b) echo xiaov2board ;;
        sspanel-uim) echo sspanel ;;
        *) return 1 ;;
    esac
}
valid_instance() { [[ "${1:-}" =~ ^(vless|vmess|anytls|hysteria|hysteria2)-[1-9][0-9]*$ ]]; }
instance_dir() { printf '%s/%s' "$config_dir" "$1"; }
instance_unit() { printf 'elise@%s.service' "$1"; }

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
    need_root; need_systemd
    [[ $# -le 1 ]] || die "install/update takes only an optional release version"
    [[ -f "$support_dir/install.sh" ]] || die "install using https://github.com/phungvanquy/elise#installation"
    bash "$support_dir/install.sh" install "$@"
}

health_check() {
    local instance=$1 config preflight listen port transport
    local -a details
    valid_instance "$instance" || die "invalid instance"
    config="$(instance_dir "$instance")/elise.conf"
    preflight=$(panel_port_and_security "$config" no-bind) || return 1
    mapfile -t details <<< "$preflight"
    port=${details[0]:-}; transport=${details[2]:-}
    listen=$(sed -n 's/^listen=//p' "$config" | head -n 1)
    [[ "$port" =~ ^[0-9]+$ && "$transport" =~ ^(tcp|udp)$ ]] || return 1
    systemctl is-active --quiet "$(instance_unit "$instance")" &&
        wait_node_port "$listen" "$port" "$transport" "$(startup_timeout "$config")" &&
        systemctl is-active --quiet "$(instance_unit "$instance")"
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
    node_kind = str(api.get('NodeType', '')).lower()
    node_kind = {'v2ray': 'vmess', 'hysteria1': 'hysteria', 'hy1': 'hysteria', 'hy2': 'hysteria2'}.get(node_kind, node_kind)
    if node_kind == kind and api.get('NodeID') == node_id:
        sys.exit(f'{kind} node {node_id} is already managed by the V2bX Go service')
PY
}

panel_port_and_security() {
    python3 - "$1" "${2:-}" "$binary" <<'PY'
import pathlib, socket, subprocess, sys, urllib.parse, urllib.request, json
values = {}
for line in pathlib.Path(sys.argv[1]).read_text().splitlines():
    if '=' in line:
        key, value = line.split('=', 1)
        values[key.strip()] = value.strip()
kind = values['panel_node_type']
panel_type = values.get('type', 'v2board')
def redact(message):
    secret = values['panel_key']
    for variant in (urllib.parse.quote_plus(secret), urllib.parse.quote(secret, safe=''), secret):
        message = message.replace(variant, '[redacted]')
    return message
if panel_type == 'xboard':
    # Keep XBoard installation compatible with earlier Elise binaries.
    query = urllib.parse.urlencode({'node_type': kind, 'node_id': values['node_id'], 'token': values['panel_key']})
    url = values['panel_url'].rstrip('/') + '/api/v1/server/UniProxy/config?' + query
    try:
        request = urllib.request.Request(url, headers={'User-Agent': 'V2bX-Elise/1.0'})
        with urllib.request.urlopen(request, timeout=15) as response:
            payload = json.load(response)
        data = payload.get('data', payload)
    except Exception as exc:
        sys.exit('cannot fetch panel node configuration: ' + redact(str(exc)))
else:
    # Use the same API adapters and protocol selection as the running core.
    try:
        result = subprocess.run([sys.argv[3], 'panel-info', '--config', sys.argv[1]],
                                capture_output=True, text=True, timeout=60)
        if result.returncode:
            if 'unrecognized subcommand' in result.stderr or 'requires type=xboard' in result.stderr:
                sys.exit('this panel requires a newer Elise binary; run elisectl update')
            sys.exit(f'cannot fetch {panel_type} node configuration: ' + redact(result.stderr.strip()))
        data = json.loads(result.stdout)
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        sys.exit(f'cannot inspect {panel_type} node configuration: ' + redact(str(exc)))
reported = data.get('server_type') or data.get('protocol') or data.get('node_type') or data.get('type')
def protocol(name):
    name = name.lower()
    name = {'v2ray': 'vmess', 'hysteria1': 'hysteria', 'hy1': 'hysteria', 'hy': 'hysteria', 'hy2': 'hysteria2'}.get(name, name)
    if name == 'hysteria' and data.get('version') == 2:
        return 'hysteria2'
    return name
if reported and (not isinstance(reported, str) or protocol(reported) != protocol(kind)):
    sys.exit(f'panel returned {reported}, expected {kind}')
port = data.get('server_port')
if not isinstance(port, int) or not (1 <= port <= 65535):
    sys.exit('panel did not return a valid server_port')
requires_tls = kind in ('anytls', 'hysteria', 'hysteria2')
security = data.get('tls')
if security is None:
    security = 1 if requires_tls else 0
if requires_tls and security != 1:
    sys.exit(f'{kind} requires TLS mode')
if kind == 'vmess' and security not in (0, 1):
    sys.exit('VMess supports plain or TLS mode in this installer')
if kind == 'vless' and security not in (0, 1, 2):
    sys.exit('unsupported VLESS security mode')
if security == 2:
    tls = data.get('tls_settings') or data.get('tlsSettings') or {}
    if not (data.get('reality_keys_present') or (tls.get('private_key') and (tls.get('public_key') or data.get('public_key')))):
        sys.exit('REALITY requires matching private and public keys in the panel')
transport = 'udp' if kind in ('hysteria', 'hysteria2') else 'tcp'
if sys.argv[2] != 'no-bind':
    address = values['listen']
    family = socket.AF_INET6 if ':' in address else socket.AF_INET
    socket_type = socket.SOCK_DGRAM if transport == 'udp' else socket.SOCK_STREAM
    with socket.socket(family, socket_type) as sock:
        try:
            sock.bind((address, port))
        except OSError as exc:
            sys.exit(f'cannot bind {address}:{port}: {exc}')
print(port)
print(security)
print(transport)
PY
}

startup_timeout() {
    local mode
    if [[ -f "$1" ]] && mode=$(sed -n 's/^cert_mode=//p' "$1") && [[ "$mode" == http || "$mode" == acme ]]; then
        echo 300
    else
        echo 15
    fi
}

wait_node_port() {
    python3 - "$1" "$2" "${3:-tcp}" "${4:-15}" <<'PY'
import pathlib, socket, sys, time
address, port = sys.argv[1], int(sys.argv[2])
transport = sys.argv[3]
if transport not in ('tcp', 'udp'):
    sys.exit('unsupported listener transport')
if transport == 'tcp':
    if address == '0.0.0.0': address = '127.0.0.1'
    if address == '::': address = '::1'
family = socket.AF_INET6 if ':' in address else socket.AF_INET
if transport == 'udp':
    # Read Linux's socket table so a probe cannot take the server's UDP port
    # while it starts. UDP connect succeeds even when no listener exists.
    packed = socket.inet_pton(family, address)
    encoded = ''.join(f'{int.from_bytes(packed[i:i+4], sys.byteorder):08X}' for i in range(0, len(packed), 4))
    udp_table = pathlib.Path('/proc/net/udp6' if family == socket.AF_INET6 else '/proc/net/udp')
deadline = time.monotonic() + float(sys.argv[4])
while time.monotonic() < deadline:
    try:
        if transport == 'udp':
            for line in udp_table.read_text().splitlines()[1:]:
                local, hex_port = line.split()[1].split(':')
                if local in (encoded, '0' * len(encoded)) and int(hex_port, 16) == port:
                    sys.exit(0)
        else:
            with socket.create_connection((address, port), timeout=0.5):
                sys.exit(0)
    except OSError as exc:
        if transport == 'udp':
            sys.exit(f'cannot check UDP listener: {exc}')
    time.sleep(0.3)
sys.exit('Elise inbound did not open its panel port')
PY
}

validate_tls_domain() {
    python3 - "$1" <<'PY'
import ipaddress, re, sys
domain = sys.argv[1]
try:
    ipaddress.ip_address(domain)
except ValueError:
    if len(domain) <= 253 and '.' in domain and all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label) for label in domain.split('.')):
        sys.exit(0)
sys.exit('enter a DNS hostname, such as node.example.com (no URL, IP, or wildcard)')
PY
}

http_tls_preflight() {
    python3 - "$1" "$2" "$3" <<'PY'
import socket, sys
domain, port, transport = sys.argv[1:]
if port == '80' and transport == 'tcp':
    sys.exit('automatic HTTP TLS needs TCP port 80 for renewal; change the panel node port or use existing files')
try:
    socket.getaddrinfo(domain, 80, type=socket.SOCK_STREAM)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(('0.0.0.0', 80))
    if socket.has_ipv6:
        try:
            with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as sock:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                sock.bind(('::', 80))
        except OSError as exc:
            import errno
            if exc.errno not in (errno.EAFNOSUPPORT, errno.EADDRNOTAVAIL):
                raise
except OSError as exc:
    sys.exit(f'HTTP TLS preflight failed: {exc}; point DNS at this server and free TCP port 80, or use existing files')
PY
}

configure_tls() {
    local target=$1 port=$2 transport=$3 mode
    if [[ "$non_interactive" == true ]]; then
        case "$cert_mode" in
            file) mode=1 ;;
            http) mode=2 ;;
            self-signed) mode=3 ;;
            *) die "this node requires TLS; supply --cert-mode=file with --cert-file and --key-file, --cert-mode=http with --domain and --email, or --cert-mode=self-signed with --domain" ;;
        esac
    else
        cat <<'EOF'
TLS certificate:
  1) Existing certificate and private key files (default)
  2) Automatic Let's Encrypt certificate (HTTP-01, with automatic renewal)
  3) Generate a self-signed certificate (clients must trust it explicitly)
EOF
        read -rp 'Certificate mode [1]: ' mode
        mode=${mode:-1}
    fi
    case "$mode" in
        1)
            if [[ "$non_interactive" == false ]]; then
                read -rp 'TLS certificate file (full chain): ' cert_file
                read -rp 'TLS private key file: ' key_file
            fi
            [[ "$cert_file" == /* && "$key_file" == /* && -s "$cert_file" && -s "$key_file" && "$cert_file$key_file" != *[[:cntrl:]]* ]] || die "TLS certificate and key must be nonempty absolute files"
            python3 - "$cert_file" "$key_file" <<'PY' || die "invalid TLS certificate or private key"
import ssl, sys
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(sys.argv[1], sys.argv[2], password='')
PY
            printf 'cert_mode=file\ncert_file=%s\nkey_file=%s\n' "$cert_file" "$key_file" >> "$work/elise.conf"
            ;;
        2|3)
            if [[ "$non_interactive" == false ]]; then
                read -rp 'TLS hostname (for example node.example.com): ' domain
            fi
            validate_tls_domain "$domain" || die "invalid TLS hostname"
            domain=${domain,,}
            printf 'cert_domain=%s\ncert_file=%s/cert/fullchain.pem\nkey_file=%s/cert/privkey.pem\n' "$domain" "$target" "$target" >> "$work/elise.conf"
            if [[ "$mode" == 2 ]]; then
                echo "Point the domain's A/AAAA records at this server and allow inbound TCP port 80. Keep port 80 available for renewal."
                echo "This mode registers an account under the Let's Encrypt subscriber agreement: https://letsencrypt.org/repository/"
                if [[ "$non_interactive" == false ]]; then
                    read -rp "Let's Encrypt account email: " email
                fi
                [[ "$email" =~ ^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$ && "$email" != *'#'* ]] || die "invalid account email"
                http_tls_preflight "$domain" "$port" "$transport" || die "automatic TLS preflight failed"
                printf 'cert_mode=http\ncert_key_length=ec-256\nacme_server=letsencrypt\nacme_email=%s\n' "$email" >> "$work/elise.conf"
                echo "Initial certificate issuance may take a few minutes."
            else
                ensure_openssl
                mkdir -m 0700 "$work/cert"
                (umask 077; openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 365 \
                    -subj "/CN=$domain" -addext "subjectAltName=DNS:$domain" \
                    -addext 'basicConstraints=critical,CA:FALSE' -addext 'keyUsage=critical,digitalSignature,keyEncipherment' \
                    -addext 'extendedKeyUsage=serverAuth' \
                    -keyout "$work/cert/privkey.pem" -out "$work/cert/fullchain.pem" 2>"$work/openssl.log") || die "could not generate self-signed certificate"
                printf 'cert_mode=file\n' >> "$work/elise.conf"
            fi
            ;;
        *) die "certificate mode must be 1, 2, or 3" ;;
    esac
    tls_choice=$mode
}

parse_add_args() {
    # These options belong to add_node's local scope, shared with configure_tls.
    local option value
    local -A seen=()
    if [[ $# -gt 0 && "$1" != -* ]]; then
        kind=$1; shift
        node_id=${1:-}; [[ $# -eq 0 ]] || shift
        seen[--node-type]=1; seen[--node-id]=1
        if [[ $# -gt 0 && "$1" != -* ]]; then
            panel_type=$1; shift
            seen[--panel-type]=1
        fi
    fi
    if [[ $# -gt 0 || "${add_check_only:-false}" == true ]]; then
        non_interactive=true
    fi
    while [[ $# -gt 0 ]]; do
        option=${1%%=*}
        case "$option" in
            --node-type|--node-id|--panel-type|--panel-url|--api-key|--api-key-file|--listen|--cert-mode|--cert-file|--key-file|--domain|--email) ;;
            *) die "unknown node option; see elisectl --help" ;;
        esac
        [[ ! ${seen[$option]+yes} ]] || die "duplicate option: $option"
        seen[$option]=1
        if [[ "$1" == *=* ]]; then
            value=${1#*=}; shift
        else
            [[ $# -ge 2 && "$2" != --* ]] || die "missing value for $option"
            value=$2; shift 2
        fi
        [[ -n "$value" && "$value" != *[[:cntrl:]]* ]] || die "empty value or control character in $option"
        case "$option" in
            --node-type) kind=$value ;;
            --node-id) node_id=$value ;;
            --panel-type) panel_type=$value ;;
            --panel-url) panel_url=$value ;;
            --api-key) panel_key=$value ;;
            --api-key-file) api_key_file=$value ;;
            --listen) listen=$value ;;
            --cert-mode) cert_mode=$value ;;
            --cert-file) cert_file=$value ;;
            --key-file) key_file=$value ;;
            --domain) domain=$value ;;
            --email) email=$value ;;
        esac
    done
    [[ -z "$api_key_file" || -z "$panel_key" ]] || die "use only one of --api-key and --api-key-file"
    if [[ -n "$api_key_file" ]]; then
        [[ -f "$api_key_file" && -r "$api_key_file" ]] || die "--api-key-file must be a readable regular file"
        panel_key=$(cat -- "$api_key_file")
    fi
    if [[ "$non_interactive" == true ]]; then
        [[ -n "$kind" && -n "$node_id" && -n "$panel_url" && -n "$panel_key" ]] || die "non-interactive add requires --node-type, --node-id, --panel-url, and --api-key (or --api-key-file)"
        case "$cert_mode" in
            '') [[ -z "$cert_file$key_file$domain$email" ]] || die "TLS options require --cert-mode" ;;
            file)
                [[ -n "$cert_file" && -n "$key_file" && -z "$domain$email" ]] || die "--cert-mode=file requires --cert-file and --key-file only"
                ;;
            http)
                [[ -n "$domain" && -n "$email" && -z "$cert_file$key_file" ]] || die "--cert-mode=http requires --domain and --email only"
                ;;
            self-signed)
                [[ -n "$domain" && -z "$cert_file$key_file$email" ]] || die "--cert-mode=self-signed requires --domain only"
                ;;
            *) die "--cert-mode must be file, http, or self-signed" ;;
        esac
    fi
}

add_node() {
    local kind="" node_id="" panel_type=v2board instance target panel_url="" panel_key="" listen=0.0.0.0 security port transport preflight tls_choice=""
    local non_interactive=false cert_mode="" cert_file="" key_file="" domain="" email="" api_key_file=""
    local -a details
    parse_add_args "$@"
    need_root; need_systemd
    [[ -x "$binary" ]] || die "install the Elise binary first"
    ensure_python
    kind=$(normalize_kind "$kind") || die "type must be vless, vmess, anytls, hysteria (hysteria1/hy1), or hysteria2 (hy2)"
    panel_type=$(normalize_panel "$panel_type") || die "panel must be xboard, v2board, v2board-uniproxy, xiaov2board, ppanel, or sspanel"
    [[ "$node_id" =~ ^[1-9][0-9]*$ ]] || die "node ID must be a positive integer"
    python3 - "$node_id" <<'PY' || die "node ID exceeds Elise's u32 range"
import sys
sys.exit(0 if int(sys.argv[1]) <= 4294967295 else 1)
PY
    instance="$kind-$node_id"; target=$(instance_dir "$instance")
    [[ ! -e "$target" && ! -L "$target" ]] || die "$instance already exists; edit its config or remove it first"
    [[ ! -f "/etc/v2bx-elise/$instance/elise.conf" ]] || die "legacy instance exists; use elisectl migrate --from-v2bx"
    check_v2bx_assignment "$kind" "$node_id" || die "remove this node from /etc/V2bX/config.json before adding it to Elise"
    if [[ "$non_interactive" == false ]]; then
        read -rp 'Panel URL: ' panel_url
    fi
    python3 - "$panel_url" <<'PY' || die "invalid panel URL"
import sys, urllib.parse
url = urllib.parse.urlsplit(sys.argv[1])
sys.exit(0 if url.scheme in ('http', 'https') and url.hostname and not url.username and not url.password and not url.query and not url.fragment and not any(c.isspace() for c in sys.argv[1]) else 1)
PY
    if [[ "$non_interactive" == false ]]; then
        read -rsp 'Panel API key: ' panel_key; echo
        read -rp 'Listen address [0.0.0.0]: ' listen
    fi
    [[ -n "$panel_key" && "$panel_key" != *[[:cntrl:]]* && "$panel_key" != [[:space:]]* && "$panel_key" != *[[:space:]] ]] || die "invalid panel API key"
    listen=${listen:-0.0.0.0}
    python3 - "$listen" <<'PY' || die "listen address must be an IP address"
import ipaddress, sys
try:
    ipaddress.ip_address(sys.argv[1])
except ValueError:
    sys.exit(1)
PY
    work=$(mktemp -d /tmp/elise-node.XXXXXX)
    cat > "$work/elise.conf" <<EOF
type=$panel_type
panel_url=$panel_url
panel_key=$panel_key
panel_node_type=$kind
node_id=$node_id
nodes_dir=$target/nodes
ip_user_cache_save_dir=$state_dir/$instance
listen=$listen
pprof_addr=off
auto_tls=false
routes_file=$target/routes.toml
dns_file=$target/dns.yml
block_list_file=$target/blockList
white_list_file=$target/whiteList
EOF
    chmod 0600 "$work/elise.conf"
    preflight=$(panel_port_and_security "$work/elise.conf") || die "panel preflight failed"
    mapfile -t details <<< "$preflight"
    port=${details[0]:-}; security=${details[1]:-}; transport=${details[2]:-}
    [[ "$port" =~ ^[0-9]+$ && "$security" =~ ^[0-2]$ && "$transport" =~ ^(tcp|udp)$ ]] || die "panel preflight failed"
    if [[ "$security" == 1 ]]; then
        configure_tls "$target" "$port" "$transport"
    elif [[ -n "$cert_mode" ]]; then
        die "the panel node does not use certificate TLS; remove the certificate options or change the node in the panel"
    fi
    if [[ "${add_check_only:-false}" == true ]]; then
        echo "Elise $instance preflight passed"
        return 0
    fi
    mkdir -p "$target/nodes"
    chmod 0700 "$config_dir" "$target" "$target/nodes"
    install -m 0600 "$work/elise.conf" "$target/elise.conf"
    if [[ -d "$work/cert" ]]; then
        mkdir -m 0700 "$target/cert"
        install -m 0600 "$work/cert/fullchain.pem" "$work/cert/privkey.pem" "$target/cert/"
    fi
    local name
    for name in routes.toml dns.yml blockList whiteList; do
        : > "$target/$name"
        chmod 0600 "$target/$name"
    done
    if ! systemctl enable --now "$(instance_unit "$instance")" ||
       ! systemctl is-active --quiet "$(instance_unit "$instance")" ||
       ! wait_node_port "$listen" "$port" "$transport" "$(startup_timeout "$target/elise.conf")"; then
        systemctl disable --now "$(instance_unit "$instance")" >/dev/null 2>&1 || true
        die "Elise service failed; configuration and certificates retained at $target. Inspect journalctl -u $(instance_unit "$instance"), fix the issue, then run: systemctl enable --now $(instance_unit "$instance")"
    fi
    echo "Elise $instance started on $listen:$port ($transport)"
    case "$tls_choice" in
        1) echo "Configure your certificate renewal tool to run: elisectl restart $instance" ;;
        2) echo "Elise renews this certificate automatically and reloads the listener after renewal." ;;
        3)
            echo "Self-signed certificate saved at $target/cert/fullchain.pem (valid for 365 days)."
            echo "Trust this certificate explicitly in your client and set the TLS server name to the configured hostname. Replace it before expiry."
            openssl x509 -in "$target/cert/fullchain.pem" -noout -fingerprint -sha256
            ;;
    esac
}

service_action() {
    need_root; need_systemd
    local action=$1 instance=${2:-}
    valid_instance "$instance" || die "use <vless|vmess|anytls|hysteria|hysteria2>-<id>"
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
    valid_instance "$instance" || die "use <vless|vmess|anytls|hysteria|hysteria2>-<id>"
    [[ -d "$(instance_dir "$instance")" ]] || die "unknown Elise node $instance"
    if systemctl is-active --quiet "$(instance_unit "$instance")"; then
        systemctl stop "$(instance_unit "$instance")" || die "could not stop $instance"
    fi
    systemctl disable "$(instance_unit "$instance")" >/dev/null 2>&1 || true
    # A migrated node has its own unit and effective drop-ins.
    local service_dir=${unit_file%/*}
    rm -f -- "$service_dir/$(instance_unit "$instance")"
    rm -rf -- "$service_dir/$(instance_unit "$instance").d"
    systemctl daemon-reload
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
    rm -f -- "$unit_file" "$binary"
    systemctl daemon-reload
    echo "Elise binary removed; instances stopped and disabled. Configuration, state, and service overrides retained. Reinstall with: elisectl install"
}

# Purge only the standalone installation's namespaces. Never chase configured
# certificate/log/state paths: migrated instances can reference V2bX-owned data.
purge_all() {
    [[ $# -eq 1 && "$1" == --yes ]] || die "purge permanently deletes Elise configuration, certificates, state and backups; run: elisectl purge --yes"
    need_root; need_systemd
    local listed unit rest file load_state instance service_dir=${unit_file%/*}
    local config_root=${config_dir%/instances}
    local -A units=()
    [[ "$config_root" != "$config_dir" && -n "$config_root" && "$config_root" != / ]] || die "invalid Elise configuration directory"

    # Include orphaned/failed services and migrated instance units, even after
    # uninstall removed the template or a configuration file was deleted.
    listed=$(systemctl list-units --all --plain --no-legend 'elise@*.service') || die "could not enumerate Elise services"
    while read -r unit rest; do
        [[ "$unit" == elise@?*.service ]] && units["$unit"]=1
    done <<< "$listed"
    listed=$(systemctl list-unit-files --no-legend 'elise@*.service') || die "could not enumerate Elise unit files"
    while read -r unit rest; do
        [[ "$unit" == elise@?*.service ]] && units["$unit"]=1
    done <<< "$listed"
    while IFS= read -r instance; do
        units["$(instance_unit "$instance")"]=1
    done < <(installed_instances)
    for file in "$service_dir"/elise@*.service "$service_dir"/elise@*.service.d; do
        [[ -e "$file" || -L "$file" ]] || continue
        unit=${file##*/}; unit=${unit%.d}
        [[ "$unit" == elise@?*.service ]] && units["$unit"]=1
    done

    # Stop every service before deleting anything. This includes activating or
    # reloading services, which an is-active-only check can miss.
    for unit in "${!units[@]}"; do
        load_state=$(systemctl show "$unit" --property=LoadState --value) || die "could not inspect $unit"
        [[ -n "$load_state" ]] || die "empty service state for $unit"
        if [[ "$load_state" != not-found ]]; then
            systemctl stop "$unit" || die "could not stop $unit; no files deleted"
        fi
    done
    for unit in "${!units[@]}"; do
        # Missing templates after uninstall can make disable return nonzero.
        systemctl disable "$unit" >/dev/null 2>&1 || true
        systemctl reset-failed "$unit" >/dev/null 2>&1 || true
    done
    # Remove only Elise unit names, including stale enablement links. rm does
    # not follow symlinks to external certificates, state, or drop-in targets.
    for file in "$service_dir"/elise@*.service "$service_dir"/elise@*.service.d \
                "$service_dir"/*.wants/elise@*.service "$service_dir"/*.requires/elise@*.service; do
        [[ -e "$file" || -L "$file" ]] || continue
        rm -rf --one-file-system -- "$file"
    done
    systemctl daemon-reload || die "could not reload systemd; data retained"
    rm -rf --one-file-system -- "$config_root" "$state_dir" "$support_dir" "$license_dir"
    rm -f -- "$binary" "$bin_dir/elisectl"
    echo "Elise purged: services, binaries, configuration, local certificates, state and backups removed."
    echo "External files, legacy V2bX data and the system journal were preserved."
}

usage() {
    cat <<'EOF'
Usage: elisectl install|update [Elise release version]
       elisectl add <vless|vmess|anytls|hysteria|hysteria2> <node-id> [panel]
       elisectl add --node-type=TYPE --node-id=ID --panel-url=URL --api-key=KEY [options]
       elisectl list
       elisectl start|stop|restart|status|log <protocol-id>
       elisectl remove <protocol-id>
       elisectl uninstall
       elisectl purge --yes
       elisectl migrate --from-v2bx [--dry-run]

Hysteria aliases: hysteria1/hy1 -> hysteria; hy2 -> hysteria2.
Panels: v2board (default, unified V2Node), v2board-uniproxy (protocol nodes), xboard, xiaov2board (xiaov2b), ppanel, sspanel (sspanel-uim).
Node options (using any option disables all prompts):
  --panel-type=NAME             Default: v2board
  --listen=IP                   Default: 0.0.0.0
  --api-key-file=PATH            Read the key from a file instead of --api-key
  --cert-mode=file              Requires --cert-file=PATH and --key-file=PATH
  --cert-mode=http              Requires --domain=HOST and --email=ADDRESS
  --cert-mode=self-signed       Requires --domain=HOST; clients must trust the certificate
TLS options are required only for certificate TLS, as configured in the panel.
HTTP mode uses Let's Encrypt HTTP-01; DNS must point here and TCP port 80 must be open.
Options accept --name=value or --name value. Existing instances are never overwritten.
remove deletes the selected instance configuration and certificates.
uninstall retains all configuration and state; install restores the binary.
purge --yes permanently removes standalone Elise configuration, local certificates,
state, backups, service overrides, binaries and manager; external/V2bX files remain.
EOF
}

main() {
    if [[ "${1:-}" == add && ( "${2:-}" == --help || "${2:-}" == -h ) ]]; then
        usage; return 0
    fi
    case "${1:-}" in
        add|__check-add|remove|uninstall|purge|start|stop|restart)
            need_root
            command -v flock >/dev/null || die "flock (util-linux) is required"
            exec 9>/run/lock/elise.lock
            flock -n 9 || die "another Elise management operation is running"
            ;;
    esac
    case "${1:-}" in
        install|update) shift; install_binary "$@" ;;
        add) shift; add_node "$@" ;;
        __check-add) shift; binary=$1; shift; local add_check_only=true; add_node "$@" ;;
        list) need_root; installed_instances ;;
        start|stop|restart|status|log) action=$1; shift; service_action "$action" "${1:-}" ;;
        remove) shift; remove_node "${1:-}" ;;
        uninstall) uninstall_all ;;
        purge) shift; purge_all "$@" ;;
        migrate) shift; need_root; need_systemd; ensure_python; exec python3 "$support_dir/migrate.py" "$@" ;;
        __health) shift; health_check "$1" ;;
        __preflight) shift; panel_port_and_security "$1" no-bind ;;
        help|-h|--help|'') usage ;;
        *) usage; return 2 ;;
    esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
