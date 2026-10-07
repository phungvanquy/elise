#!/usr/bin/env bash
set -euo pipefail

helper=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/elise.sh
python3 "${helper%/*}/test-purge.py"
python3 - "$helper" <<'PY'
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Thread
import json
import os
import socket
import ssl
import subprocess
import sys
import tarfile
import urllib.parse

helper = sys.argv[1]

class Panel(BaseHTTPRequestHandler):
    def do_GET(self):
        assert self.headers.get('User-Agent') == 'Elise/1.0'
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
        env = os.environ.copy()
        command = (
            'helper=$1; panel=$2; set --; source "$helper" >/dev/null; '
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

        def assert_self_signed_validity(cert_path):
            decoded = ssl._ssl._test_decode_cert(str(cert_path))
            lifetime = ssl.cert_time_to_seconds(decoded['notAfter']) - ssl.cert_time_to_seconds(decoded['notBefore'])
            assert lifetime == 3650 * 24 * 60 * 60, decoded
            assert ('DNS', 'node.example.com') in decoded['subjectAltName']

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
        result = run_helper('wait_node_port 127.0.0.1 "$1" udp 0.5', port)
        assert result.returncode != 0 and 'did not open' in result.stderr, result

        # Exercise node creation and management against a fake systemd that
        # opens real local sockets, without writing to system directories.
        cert = Path(root) / 'cert.pem'
        key = Path(root) / 'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-subj', '/CN=node.example.com', '-addext', 'subjectAltName=DNS:node.example.com',
                        '-out', str(cert), '-keyout', str(key)], check=True, capture_output=True)
        service_log = Path(root) / 'services.log'
        env.update({
            'ELISE_SERVICE_LOG': str(service_log),
            'ELISE_TEST_START_URL': f'http://127.0.0.1:{server.server_port}/start',
        })
        service_setup = r'''
config_dir=$1; shift
unit_file="$config_dir/systemd/elise@.service"
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
                service_setup + 'add_node "$1" 9 xboard; installed_instances; service_action restart "$2"',
                config_root, requested, instance,
                input=f'http://127.0.0.1:{server.server_port}\nkey+value\n127.0.0.1\n1\n{cert}\n{key}\n',
                check=True,
            )
            config = config_root / instance / 'elise.conf'
            assert f'panel_node_type={kind}\n' in config.read_text()
            if kind in ('anytls', 'hysteria', 'hysteria2'):
                assert f'cert_file={cert}\nkey_file={key}\n' in config.read_text()
                assert 'certificate renewal' in result.stdout
            assert f'({transport})' in result.stdout and instance in result.stdout
            assert config.stat().st_mode & 0o777 == 0o600
            assert f'restart elise@{instance}.service' in service_log.read_text()
            run_helper(service_setup + 'remove_node "$1"', config_root, instance, check=True)
            assert not config.parent.exists()
            server.node_listener.close()
            server.node_listener = None

        # Other platforms must use the Rust adapter rather than the XBoard URL.
        # The Rust integration tests exercise these adapters against real HTTP fixtures.
        panel_binary = Path(root) / 'panel-info-core'
        panel_binary.write_text('''#!/usr/bin/env python3
import json, os, pathlib, sys
assert sys.argv[1:3] == ['panel-info', '--config'], sys.argv
values = dict(line.split('=', 1) for line in pathlib.Path(sys.argv[3]).read_text().splitlines() if '=' in line)
assert values['type'] == os.environ['ELISE_TEST_PANEL']
assert values['panel_node_type'] == 'anytls'
assert values['panel_key'] == 'key+value'
print(os.environ['ELISE_TEST_NODE_INFO'])
''')
        panel_binary.chmod(0o755)
        native_setup = service_setup + 'binary=$2; '
        for requested, platform in [('', 'v2board'), ('v2board', 'v2board'), ('v2board-uniproxy', 'v2board-uniproxy'), ('xiaov2board', 'xiaov2board'),
                                    ('xiaov2b', 'xiaov2board'), ('ppanel', 'ppanel'),
                                    ('sspanel', 'sspanel'), ('sspanel-uim', 'sspanel')]:
            with socket.socket() as sock:
                sock.bind(('127.0.0.1', 0))
                server.node_port = sock.getsockname()[1]
            server.node_transport = socket.SOCK_STREAM
            env['ELISE_TEST_PANEL'] = platform
            env['ELISE_TEST_NODE_INFO'] = json.dumps({'server_type': 'anytls', 'server_port': server.node_port, 'tls': 1})
            result = run_helper(
                native_setup + 'if [[ -n "$1" ]]; then add_node anytls 9 "$1"; else add_node anytls 9; fi', config_root, requested, panel_binary,
                input=f'http://127.0.0.1:{server.server_port}\nkey+value\n127.0.0.1\n1\n{cert}\n{key}\n', check=True,
            )
            config = config_root / 'anytls-9/elise.conf'
            assert f'type={platform}\n' in config.read_text()
            assert 'panel_node_type=anytls\n' in config.read_text()
            run_helper(service_setup + 'remove_node anytls-9', config_root, check=True)
            server.node_listener.close()
            server.node_listener = None

        result = run_helper(service_setup + 'add_node anytls 9 unknown', config_root)
        assert result.returncode != 0 and 'panel must be' in result.stderr
        env['ELISE_TEST_NODE_INFO'] = json.dumps({'server_type': 'vmess', 'server_port': server.node_port, 'tls': 1})
        result = run_helper(native_setup + 'add_node anytls 9 "$1"', config_root, 'sspanel', panel_binary,
                            input=f'http://127.0.0.1:{server.server_port}\nkey+value\n127.0.0.1\n')
        assert result.returncode != 0 and 'expected anytls' in result.stderr
        assert not (config_root / 'anytls-9').exists()
        panel_binary.write_text("#!/bin/sh\necho 'error: unrecognized subcommand panel-info' >&2\nexit 2\n")
        result = run_helper(native_setup + 'add_node anytls 9 "$1"', config_root, 'sspanel', panel_binary,
                            input=f'http://127.0.0.1:{server.server_port}\nkey+value\n127.0.0.1\n')
        assert result.returncode != 0 and 'run elisectl update' in result.stderr

        for domain in ('*.example.com', 'https://node.example.com', '../bad', '127.0.0.1', 'node', '-bad.example.com', 'bad#.example.com'):
            assert run_helper('validate_tls_domain "$1"', domain).returncode != 0, domain
        run_helper('validate_tls_domain node.example.com', check=True)
        assert run_helper('http_tls_preflight node.example.com 80 tcp').returncode != 0
        # No requests to a public CA: fake systemd opens the inbound as above,
        # and the HTTP preflight is stubbed only in automatic-mode wizard tests.
        for kind in ('anytls', 'hysteria', 'hysteria2'):
            for mode in ('2', '3'):
                transport = 'udp' if kind.startswith('hysteria') else 'tcp'
                server.node_transport = socket.SOCK_DGRAM if transport == 'udp' else socket.SOCK_STREAM
                with socket.socket(socket.AF_INET, server.node_transport) as sock:
                    sock.bind(('127.0.0.1', 0))
                    server.node_port = sock.getsockname()[1]
                configure_panel(kind, {'server_port': server.node_port})
                instance = f'{kind}-9'
                result = run_helper(
                    service_setup + 'http_tls_preflight() { :; }; add_node "$1" 9 xboard',
                    config_root, kind,
                    input=f'http://127.0.0.1:{server.server_port}\nkey+value\n127.0.0.1\n{mode}\nnode.example.com\nadmin@example.com\n',
                    check=True,
                )
                config = config_root / instance / 'elise.conf'
                contents = config.read_text()
                cert_path = config.parent / 'cert/fullchain.pem'
                key_path = config.parent / 'cert/privkey.pem'
                assert f'cert_file={cert_path}\nkey_file={key_path}\n' in contents
                assert 'cert_domain=node.example.com\n' in contents and 'auto_tls=false\n' in contents
                if mode == '2':
                    assert 'cert_mode=http\n' in contents and 'acme_email=admin@example.com\n' in contents
                    assert 'renew' in result.stdout and not cert_path.exists()
                    assert run_helper('startup_timeout "$1"', config, check=True).stdout.strip() == '300'
                else:
                    assert 'cert_mode=file\n' in contents and 'Trust this certificate' in result.stdout
                    assert key_path.stat().st_mode & 0o777 == 0o600
                    ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(cert_path, key_path)
                    assert_self_signed_validity(cert_path)
                    assert 'valid for 3650 days' in result.stdout
                    before = cert_path.read_bytes()
                    run_helper(service_setup + 'service_action restart "$1"', config_root, instance, check=True)
                    assert cert_path.read_bytes() == before
                    assert run_helper('startup_timeout "$1"', config, check=True).stdout.strip() == '15'
                run_helper(service_setup + 'remove_node "$1"', config_root, instance, check=True)
                server.node_listener.close()
                server.node_listener = None

        configure_panel('anytls', {'server_port': server.node_port})
        # A failed first start retains the config/certificate for diagnosis and
        # retry; repeatedly deleting them can trigger unnecessary CA orders.
        result = run_helper(
            service_setup + 'systemctl() { return 1; }; add_node anytls 9 xboard', config_root,
            input=f'http://127.0.0.1:{server.server_port}\nkey+value\n127.0.0.1\n3\nnode.example.com\n',
        )
        assert result.returncode != 0 and 'retained' in result.stderr
        assert (config_root / 'anytls-9/cert/privkey.pem').exists()
        run_helper(service_setup + 'remove_node anytls-9', config_root, check=True)

        bad_key = Path(root) / 'bad-key.pem'
        bad_key.write_text('not a private key')
        result = run_helper(service_setup + 'add_node anytls 9 xboard', config_root,
                            input=f'http://127.0.0.1:{server.server_port}\nkey+value\n127.0.0.1\n1\n{cert}\n{bad_key}\n')
        assert result.returncode != 0 and 'invalid TLS certificate' in result.stderr
        assert not (config_root / 'anytls-9').exists()

        # Non-interactive provisioning uses the same preflight and service
        # checks, including when stdin is already exhausted by curl | bash.
        def node_options(kind='vmess'):
            return [f'--node-type={kind}', '--node-id', '9',
                    f'--panel-url=http://127.0.0.1:{server.server_port}',
                    '--api-key', 'key+value', '--panel-type=xboard', '--listen=127.0.0.1']

        key_file = Path(root) / 'panel-key'
        key_file.write_text('key+value\n')
        key_file.chmod(0o600)
        for requested, kind, payload, tls_args in [
            ('vmess', 'vmess', {'tls': 0}, []),
            ('vless', 'vless', {'tls': 2, 'tls_settings': {'private_key': 'private', 'public_key': 'public'}}, []),
            ('AnyTLS', 'anytls', {}, ['--cert-mode=file', '--cert-file', cert, '--key-file', key]),
            ('hy2', 'hysteria2', {}, ['--cert-mode=http', '--domain=node.example.com', '--email=admin@example.com']),
            ('hy1', 'hysteria', {}, ['--cert-mode=self-signed', '--domain=node.example.com']),
        ]:
            server.node_transport = socket.SOCK_DGRAM if kind.startswith('hysteria') else socket.SOCK_STREAM
            with socket.socket(socket.AF_INET, server.node_transport) as sock:
                sock.bind(('127.0.0.1', 0))
                server.node_port = sock.getsockname()[1]
            configure_panel(kind, {'server_port': server.node_port, **payload})
            options = node_options(requested) + tls_args
            if kind == 'vless':
                options[4:6] = ['--api-key-file', str(key_file)]
            setup = service_setup + 'http_tls_preflight() { :; }; '
            before_services = service_log.read_bytes()
            checked = run_helper(setup + 'add_check_only=true; add_node "$@"', config_root, *options, input='', check=True)
            assert 'preflight passed' in checked.stdout
            assert not (config_root / f'{kind}-9').exists()
            assert service_log.read_bytes() == before_services
            result = run_helper(setup + 'add_node "$@"', config_root, *options, input='', check=True)
            assert 'key+value' not in result.stdout + result.stderr
            config = config_root / f'{kind}-9/elise.conf'
            contents = config.read_text()
            assert f'panel_node_type={kind}\n' in contents and 'panel_key=key+value\n' in contents
            assert config.stat().st_mode & 0o777 == 0o600
            assert config.parent.stat().st_mode & 0o777 == 0o700
            if kind == 'hysteria2':
                assert 'cert_mode=http\n' in contents and 'acme_email=admin@example.com\n' in contents
            if kind == 'hysteria':
                assert (config.parent / 'cert/privkey.pem').stat().st_mode & 0o777 == 0o600
                assert_self_signed_validity(config.parent / 'cert/fullchain.pem')
                assert 'valid for 3650 days' in result.stdout
            before_services = service_log.read_bytes()
            again = run_helper(setup + 'add_node "$@"', config_root, *options, input='')
            assert again.returncode != 0 and 'already exists' in again.stderr
            assert config.read_text() == contents and service_log.read_bytes() == before_services
            run_helper(service_setup + 'remove_node "$1"', config_root, f'{kind}-9', check=True)
            server.node_listener.close()
            server.node_listener = None

        # Reject incomplete/ambiguous options without reading stdin, starting a
        # service, or leaving an instance directory. Never echo secret values.
        configure_panel('vmess', {'server_port': server.node_port, 'tls': 0})
        options = node_options()
        invalid_options = [
            (options[1:], 'requires --node-type'),
            (options + ['--node-id=10'], 'duplicate'),
            (options[:-1] + ['--listen=999.0.0.1'], 'IP address'),
            (options + ['--domain=node.example.com'], 'require --cert-mode'),
            (options + ['--cert-mode=unknown'], '--cert-mode must be'),
            (options + ['--cert-mode=file'], 'requires --cert-file'),
            (options + ['--cert-mode=http', '--domain=node.example.com'], 'requires --domain and --email'),
            (options + ['--cert-mode=self-signed'], 'requires --domain only'),
            (options + ['--api-key-file', key_file], 'only one of'),
            (options + ['--domain'], 'missing value'),
            (options + ['--unknown=do-not-print-this'], 'unknown node option'),
            (options[:4] + ['--api-key=secret\nnode_id=42'], 'control character'),
            (options[:4] + ['--api-key=secret\rnode_id=42'], 'control character'),
            (options[:4] + ['--api-key= secret '], 'invalid panel API key'),
            (options[:4] + ['--api-key-file=/no/such/key'], 'readable regular file'),
            (options[:4] + ['--api-key='], 'empty value'),
            (['--node-type=vmess', '--node-id=4294967296'] + options[3:], 'u32 range'),
            (['--node-type=vmess', '--node-id=0'] + options[3:], 'positive integer'),
            (options + ['--cert-mode=file', '--cert-file', cert, '--key-file', key], 'does not use certificate TLS'),
        ]
        before_services = service_log.read_bytes()
        for arguments, error in invalid_options:
            result = run_helper(service_setup + 'add_node "$@"', config_root, *arguments, input='')
            assert result.returncode != 0 and error in result.stderr, (arguments, result)
            assert not (config_root / 'vmess-9').exists()
            assert service_log.read_bytes() == before_services
            assert 'do-not-print-this' not in result.stdout + result.stderr
            assert 'secret' not in result.stdout + result.stderr

        configure_panel('anytls', {'server_port': server.node_port, 'tls': 1})
        result = run_helper(service_setup + 'add_node "$@"', config_root, *node_options('anytls'), input='')
        assert result.returncode != 0 and 'this node requires TLS' in result.stderr
        assert not (config_root / 'anytls-9').exists()
        result = run_helper(service_setup + 'add_node "$@"', config_root, *node_options('anytls'),
                            '--cert-mode=file', '--cert-file', cert, '--key-file', bad_key, input='')
        assert result.returncode != 0 and 'invalid TLS certificate' in result.stderr
        assert not (config_root / 'anytls-9').exists()

        # An API adapter's diagnostics can contain a credential-bearing URL.
        panel_binary.write_text("#!/bin/sh\necho 'failed token=key%2Bvalue raw=key+value' >&2\nexit 1\n")
        result = run_helper(native_setup + 'set -- "$1" "${@:3}"; add_node "$@"', config_root, '--panel-type=sspanel', panel_binary,
                            *[arg for arg in node_options('anytls') if arg != '--panel-type=xboard'], input='')
        assert result.returncode != 0 and '[redacted]' in result.stderr
        assert 'key+value' not in result.stderr and 'key%2Bvalue' not in result.stderr
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
