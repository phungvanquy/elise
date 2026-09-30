#!/usr/bin/env bash
set -euo pipefail

helper=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/elise.sh
python3 - "$helper" <<'PY'
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Thread
import json
import os
import socket
import subprocess
import sys
import tarfile
import urllib.parse

helper = sys.argv[1]

class Panel(BaseHTTPRequestHandler):
    def do_GET(self):
        assert self.headers.get('User-Agent') == 'V2bX-Elise/1.0'
        query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        assert query == {'node_type': [panel_kind], 'node_id': ['9'], 'token': ['key+value']}, query
        payload = json.dumps(panel_payload).encode()
        self.send_response(200)
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self):
        assert self.path == '/start'
        listener = socket.socket(socket.AF_INET, self.server.node_transport)
        listener.bind(('127.0.0.1', self.server.node_port))
        if self.server.node_transport == socket.SOCK_STREAM:
            listener.listen()
        self.server.node_listener = listener
        self.send_response(200)
        self.send_header('Content-Length', '0')
        self.end_headers()

    def log_message(self, *_):
        pass

with socket.socket() as sock:
    sock.bind(('127.0.0.1', 0))
    node_port = sock.getsockname()[1]

panel_kind = 'vmess'
panel_payload = {'server_port': node_port, 'tls': 0, 'network': 'tcp'}
server = HTTPServer(('127.0.0.1', 0), Panel)
server.node_listener = None
thread = Thread(target=server.serve_forever, daemon=True)
thread.start()
try:
    with TemporaryDirectory() as root:
        panel_config = Path(root) / 'elise.conf'
        panel_config.write_text(
            f'type=xboard\npanel_url=http://127.0.0.1:{server.server_port}\n'
            'panel_key=key+value\npanel_node_type=vmess\nnode_id=9\nlisten=127.0.0.1\n'
        )
        v2bx_config = Path(root) / 'config.json'
        v2bx_config.write_text('{"Nodes":[{"ApiConfig":{"NodeType":"vmess","NodeID":9},},],} // comment\n')
        env = os.environ.copy()
        env['V2BX_CONFIG_PATH'] = str(v2bx_config)
        command = (
            'helper=$1; panel=$2; set --; source "$helper" >/dev/null; '
            'if check_v2bx_assignment vmess 9 >/dev/null 2>&1; then exit 1; fi; '
            'check_v2bx_assignment vless 9; '
            'panel_port_and_security "$panel"'
        )
        result = subprocess.run(
            ['bash', '-c', command, 'bash', helper, str(panel_config)],
            env=env, capture_output=True, text=True, check=True,
        )
        assert result.stdout.strip() == f'{node_port}\n0\ntcp', result.stdout

        def run_helper(command, *args, **kwargs):
            return subprocess.run(
                ['bash', '-c', 'helper=$1; shift; args=("$@"); set --; source "$helper" >/dev/null; set -- "${args[@]}"; ' + command,
                 'bash', helper, *map(str, args)],
                env=env, capture_output=True, text=True, timeout=20, **kwargs,
            )

        def configure_panel(kind, payload):
            global panel_kind, panel_payload
            panel_kind, panel_payload = kind, payload
            panel_config.write_text(
                f'type=xboard\npanel_url=http://127.0.0.1:{server.server_port}\n'
                f'panel_key=key+value\npanel_node_type={kind}\nnode_id=9\nlisten=127.0.0.1\n'
            )

        for kind, payload, security, transport in [
            ('vless', {'tls': 1}, 1, 'tcp'),
            ('anytls', {'server_type': 'AnyTLS'}, 1, 'tcp'),
            ('hysteria', {'server_type': 'hysteria1', 'version': 1}, 1, 'udp'),
            ('hysteria', {'server_type': 'hysteria', 'version': 2}, 1, 'udp'),
            ('hysteria2', {'server_type': 'hysteria', 'version': 2}, 1, 'udp'),
            ('hysteria2', {'server_type': 'hy2', 'tls': 1}, 1, 'udp'),
        ]:
            configure_panel(kind, {'data': {'server_port': node_port, **payload}})
            result = run_helper('panel_port_and_security "$1"', panel_config, check=True)
            assert result.stdout.strip() == f'{node_port}\n{security}\n{transport}', result

        for kind, payload, error in [
            ('anytls', {'tls': 0}, 'requires TLS'),
            ('anytls', {'tls': 2}, 'requires TLS'),
            ('hysteria', {'tls': 0}, 'requires TLS'),
            ('hysteria2', {'tls': 2}, 'requires TLS'),
            ('hysteria2', {'server_type': 'hysteria', 'version': 1}, 'expected hysteria2'),
            ('anytls', {'type': 'vless'}, 'expected anytls'),
            ('vmess', {'tls': 2}, 'plain or TLS'),
            ('vless', {'tls': 2}, 'REALITY requires'),
        ]:
            configure_panel(kind, {'server_port': node_port, **payload})
            result = run_helper('panel_port_and_security "$1"', panel_config)
            assert result.returncode != 0 and error in result.stderr, result

        # Availability checks use the protocol's socket type, even when the
        # other transport already owns the same numeric port.
        for kind, socket_type, transport in [
            ('anytls', socket.SOCK_STREAM, 'tcp'),
            ('hysteria', socket.SOCK_DGRAM, 'udp'),
            ('hysteria2', socket.SOCK_DGRAM, 'udp'),
        ]:
            other_type = socket.SOCK_DGRAM if socket_type == socket.SOCK_STREAM else socket.SOCK_STREAM
            with socket.socket(socket.AF_INET, other_type) as other:
                other.bind(('127.0.0.1', 0))
                port = other.getsockname()[1]
                configure_panel(kind, {'server_port': port, 'tls': 1})
                run_helper('panel_port_and_security "$1"', panel_config, check=True)
                with socket.socket(socket.AF_INET, socket_type) as listener:
                    listener.bind(('127.0.0.1', port))
                    if socket_type == socket.SOCK_STREAM:
                        listener.listen()
                    result = run_helper('panel_port_and_security "$1"', panel_config)
                    assert result.returncode != 0 and 'cannot bind' in result.stderr, result
                    run_helper('panel_port_and_security "$1" no-bind', panel_config, check=True)
                    run_helper('wait_node_port 127.0.0.1 "$1" "$2"', port, transport, check=True)

        for address in ('0.0.0.0', '127.0.0.1', '::', '::1'):
            family = socket.AF_INET6 if ':' in address else socket.AF_INET
            with socket.socket(family, socket.SOCK_DGRAM) as listener:
                try:
                    listener.bind((address, 0))
                except OSError:
                    if family == socket.AF_INET6:
                        continue
                    raise
                port = listener.getsockname()[1]
                run_helper('wait_node_port "$1" "$2" udp', address, port, check=True)

        # A UDP connect cannot tell whether a server exists. An unbound port
        # must fail readiness instead of being accepted immediately.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        result = run_helper('wait_node_port 127.0.0.1 "$1" udp', port)
        assert result.returncode != 0 and 'did not open' in result.stderr, result

        for kind in ('vmess', 'anytls', 'hysteria', 'hysteria2'):
            v2bx_config.write_text(json.dumps({'Nodes': [{'NodeType': kind, 'NodeID': 9}]}))
            result = run_helper('check_v2bx_assignment "$1" 9', kind)
            assert result.returncode != 0 and 'already managed' in result.stderr, result
        for alias, kind in [('hysteria1', 'hysteria'), ('hy1', 'hysteria'), ('hy2', 'hysteria2')]:
            v2bx_config.write_text(json.dumps({'Nodes': [{'NodeType': alias, 'NodeID': 9}]}))
            assert run_helper('check_v2bx_assignment "$1" 9', kind).returncode != 0

        # Exercise node creation and management against a fake systemd that
        # opens real local sockets, without writing to system directories.
        v2bx_config.write_text('{"Nodes":[]}')
        cert = Path(root) / 'cert.pem'
        key = Path(root) / 'key.pem'
        cert.write_text('fixture certificate')
        key.write_text('fixture key')
        service_log = Path(root) / 'services.log'
        env.update({
            'ELISE_SERVICE_LOG': str(service_log),
            'ELISE_TEST_START_URL': f'http://127.0.0.1:{server.server_port}/start',
        })
        service_setup = r'''
config_dir=$1; shift
binary=/bin/true
need_root() { :; }
need_systemd() { :; }
systemctl() {
    printf '%s\n' "$*" >> "$ELISE_SERVICE_LOG"
    if [[ "$1" == enable ]]; then
        python3 -c 'import sys, urllib.request; urllib.request.urlopen(urllib.request.Request(sys.argv[1], method="POST")).close()' "$ELISE_TEST_START_URL"
    fi
}
'''
        config_root = Path(root) / 'instances'
        for requested, kind in [
            ('vmess', 'vmess'), ('vless', 'vless'), ('AnyTLS', 'anytls'),
            ('hysteria1', 'hysteria'), ('hy2', 'hysteria2'),
        ]:
            transport = 'udp' if kind.startswith('hysteria') else 'tcp'
            server.node_transport = socket.SOCK_DGRAM if transport == 'udp' else socket.SOCK_STREAM
            with socket.socket(socket.AF_INET, server.node_transport) as sock:
                sock.bind(('127.0.0.1', 0))
                server.node_port = sock.getsockname()[1]
            configure_panel(kind, {'server_port': server.node_port})
            instance = f'{kind}-9'
            result = run_helper(
                service_setup + 'add_node "$1" 9; installed_instances; service_action restart "$2"',
                config_root, requested, instance,
                input=f'http://127.0.0.1:{server.server_port}\nkey+value\n127.0.0.1\n{cert}\n{key}\n',
                check=True,
            )
            config = config_root / instance / 'elise.conf'
            assert f'panel_node_type={kind}\n' in config.read_text()
            if kind in ('anytls', 'hysteria', 'hysteria2'):
                assert f'cert_file={cert}\nkey_file={key}\n' in config.read_text()
                assert 'certificate renewal' in result.stdout
            assert f'({transport})' in result.stdout and instance in result.stdout
            assert config.stat().st_mode & 0o777 == 0o600
            assert f'restart V2bX-elise@{instance}.service' in service_log.read_text()
            run_helper(service_setup + 'remove_node "$1"', config_root, instance, check=True)
            assert not config.parent.exists()
            server.node_listener.close()
            server.node_listener = None
finally:
    if server.node_listener:
        server.node_listener.close()
    server.shutdown()

with TemporaryDirectory() as root:
    binary = Path(root) / 'elise'
    binary.write_text('#!/bin/sh\necho elise 1.0.1\n')
    binary.chmod(0o755)
    output = Path(root) / 'dist'
    package_script = Path(helper).parent / 'package-elise.sh'
    for arch in ('amd64', 'arm64'):
        subprocess.run(['bash', str(package_script), str(binary), arch, str(output)], check=True)
        archive = f'elise-linux-{arch}.tar.gz'
        subprocess.run(['sha256sum', '-c', archive + '.sha256'], cwd=output, check=True, capture_output=True)
        with tarfile.open(output / archive, 'r:gz') as packaged:
            assert {'elise/elise', 'elise/LICENSE', 'elise/README.md'} <= set(packaged.getnames())

with TemporaryDirectory() as root:
    fake_bin = Path(root) / 'bin'
    fake_bin.mkdir()
    (fake_bin / 'cat').symlink_to('/bin/cat')
    package_log = Path(root) / 'packages.log'
    apt_get = fake_bin / 'apt-get'
    apt_get.write_text(
        '#!/bin/sh\n'
        'printf "%s\\n" "$*" >> "$ELISE_PACKAGE_LOG"\n'
        'if [ "$1" = install ]; then\n'
        '  printf "#!/bin/sh\\nexit 0\\n" > "$ELISE_FAKE_BIN/python3"\n'
        '  /bin/chmod 755 "$ELISE_FAKE_BIN/python3"\n'
        'fi\n'
    )
    apt_get.chmod(0o755)
    env = os.environ.copy()
    env.update({
        'PATH': str(fake_bin),
        'ELISE_PACKAGE_LOG': str(package_log),
        'ELISE_FAKE_BIN': str(fake_bin),
    })
    command = 'helper=$1; set --; source "$helper" >/dev/null; ensure_python'
    for _ in range(2):
        subprocess.run(['/bin/bash', '-c', command, 'bash', helper], env=env, check=True, capture_output=True)
    assert package_log.read_text().splitlines() == ['update -y', 'install -y python3']
    assert (fake_bin / 'python3').is_file()
PY
