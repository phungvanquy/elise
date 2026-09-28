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
import urllib.parse

helper = sys.argv[1]

class Panel(BaseHTTPRequestHandler):
    def do_GET(self):
        assert self.headers.get('User-Agent') == 'V2bX-Elise/1.0'
        query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        assert query == {'node_type': ['vmess'], 'node_id': ['9'], 'token': ['key+value']}, query
        payload = json.dumps({'server_port': node_port, 'tls': 0, 'network': 'tcp'}).encode()
        self.send_response(200)
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_):
        pass

with socket.socket() as sock:
    sock.bind(('127.0.0.1', 0))
    node_port = sock.getsockname()[1]

server = HTTPServer(('127.0.0.1', 0), Panel)
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
        assert result.stdout.strip() == f'{node_port}\n0', result.stdout
finally:
    server.shutdown()
PY
