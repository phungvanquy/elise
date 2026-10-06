# Elise

Elise is a Rust node backend configured by default for
[phungvanquy/v2board-new](https://github.com/phungvanquy/v2board-new), with optional
support for XBoard, XiaoV2Board, PPanel, and SSPanel. This repository owns its source, releases, installation tools, and
service management. Each installer-managed panel node runs in its own systemd
service. V2bX is not required to build, install, or run Elise.

## Installation

Supported release targets: **Linux amd64 and arm64 with systemd**. Run the
installer as root. Bash, curl, CA certificates, tar, sha256sum, flock
(util-linux), and Python 3.8+ are required. The installer can provision Python
with apt-get, dnf, or yum. Self-signed certificates also need OpenSSL; the wizard
can install it with those package managers. Alpine/OpenRC is not supported by
these installation tools.

Install the [latest stable release](https://github.com/phungvanquy/elise/releases/latest)
(current release: **v1.0.7**). Omit the version argument to always install the
latest stable release:

```bash
curl -fsSL https://raw.githubusercontent.com/phungvanquy/elise/refs/heads/main/install.sh -o /tmp/elise-install.sh &&
sudo bash /tmp/elise-install.sh install
```

For a reproducible version, pin both the bootstrap script and release:

```bash
curl -fsSL https://raw.githubusercontent.com/phungvanquy/elise/refs/tags/v1.0.7/install.sh -o /tmp/elise-install.sh &&
sudo bash /tmp/elise-install.sh install v1.0.7
```

The installer verifies the release archive's SHA-256 checksum and installs the
binary, manager, service template, and migration tools from that same archive.
It checks that the Rust binary version matches the requested release tag.
Without node options, installation creates no nodes. Legacy V2bX-managed
services are not started by installation.

### Install and start a node in one command

Install the latest stable release and start a VLESS node configured with REALITY
or no TLS in the panel:

```bash
curl -fsSL \
  https://raw.githubusercontent.com/phungvanquy/elise/refs/heads/main/install.sh | \
  sudo bash -s -- install \
    --panel-url='https://panel.example.com' \
    --api-key='REPLACE_WITH_PANEL_KEY' \
    --node-id=123 \
    --node-type=vless
```

The arguments after `bash -s --` go to the installer. Change `--node-type` to
match the panel node: `vless`, `vmess`, `anytls`, `hysteria`, or `hysteria2`.
The type is required because a panel can reuse a node ID across protocols.
The panel defaults to `v2board` for the panel's unified **V2Node** section.
For nodes in the separate **VLESS, VMess, AnyTLS, or Hysteria** sections, add
`--panel-type=v2board-uniproxy`. Both modes support the same wizard protocols.
Node IDs belong to their selected section; Elise does not probe another section
if the node is missing. Other adapters are `xboard`, `xiaov2board`, `ppanel`, and
`sspanel`. The listen address defaults to
`0.0.0.0`; override it with `--listen=::` or another IP address.

If the panel node uses **certificate TLS**, append one of these sets of options
to that command. AnyTLS and Hysteria 1/2 always require certificate TLS:

```bash
# Existing certificate and matching private key
--cert-mode=file --cert-file=/etc/ssl/elise/fullchain.pem --key-file=/etc/ssl/elise/privkey.pem

# Automatic Let's Encrypt certificate and renewal
--cert-mode=http --domain=node.example.com --email=admin@example.com

# Self-signed certificate; configure clients to trust it explicitly
--cert-mode=self-signed --domain=node.example.com
```

HTTP mode requires DNS to point at this server and inbound TCP port 80 to
remain available. It registers an account under the
[Let's Encrypt subscriber agreement](https://letsencrypt.org/repository/).
REALITY uses the keys in the panel and does not take certificate options.

Node options disable all prompts; both `--name=value` and `--name value` work.
The installer checks the panel, free listener port, and certificate settings
before replacing Elise files or restarting existing services. It then installs
the release, enables the new node at boot, starts it, and checks its listener.
An existing instance is never overwritten. If the first start fails, the new
configuration and certificates remain for diagnosis; the command returns a
failure and prints recovery instructions. The program installation remains.

For automation, replace `--api-key=...` with
`--api-key-file=/root/.config/elise/panel.key` to read a key from a file readable
by root. Store only the key in that file and set its permissions to `0600`.
This keeps the literal key out of command history and process arguments.

After Elise is installed, add further nodes without reinstalling the program:

```bash
sudo elisectl add --panel-url='https://panel.example.com' --api-key-file=/root/.config/elise/panel.key --node-id=124 --node-type=hysteria2 --cert-mode=http --domain=hy2.example.com --email=admin@example.com
```

## Add and manage nodes

The `elise` command is the Rust executable. Use `elisectl` for installation and
node service management:

```bash
sudo elisectl add vless 123 v2board
sudo elisectl add vmess 456 v2board-uniproxy
sudo elisectl add anytls 789 ppanel
sudo elisectl add hysteria 101 sspanel
sudo elisectl add hysteria2 102 xiaov2board
sudo elisectl list
sudo elisectl status hysteria2-102
sudo elisectl log hysteria2-102
sudo elisectl restart hysteria2-102
elise --version
```

The wizard asks for the panel URL, API key, listen address, and certificate
settings. It checks the panel protocol, security mode, and listener port before
starting the service. Panel selection defaults to `v2board` (unified V2Node); `xiaov2b` and
`sspanel-uim` are aliases. Protocol aliases are `hysteria1`/`hy1` and `hy2`.
The panel must expose the requested protocol using its supported Elise adapter.
REALITY keys must be configured in the panel. REALITY destinations accept a hostname
or IP with an optional port; the default is `tls_settings.server_port` or 443.
For example, `visualstudio.microsoft.com` uses port 443. Invalid destinations
are rejected while loading the node configuration.

The managed wizard supports VLESS, VMess, AnyTLS, and Hysteria 1/2. Additional
native core protocols can be configured manually; their presence in the source
does not imply wizard support. A panel node must have only one backend owner.
If V2bX also runs on the server, remove that node from its configuration before
adding it to Elise. Elise checks the default V2bX config when it exists.

| Item | Location |
| --- | --- |
| Core executable | `/usr/local/bin/elise` |
| Manager | `/usr/local/bin/elisectl` |
| Installation and migration tools | `/usr/local/lib/elise/` |
| Instance configuration | `/etc/elise/instances/<protocol-id>/elise.conf` |
| State for newly added nodes | `/var/lib/elise/<protocol-id>/` |
| Service | `elise@<protocol-id>.service` |
| Installation/migration backups | `/var/lib/elise/backups/` |

Migrated nodes retain their original traffic-state location explicitly. Keep
legacy configuration directories after migration; see the migration guide.

## V2Board API compatibility

| Panel node section | `type` / `--panel-type` | Config endpoint | Reporting node type |
| --- | --- | --- | --- |
| Unified V2Node (default) | `v2board` | `/api/v2/server/config` | `v2node` |
| Separate protocol nodes | `v2board-uniproxy` | `/api/v1/server/UniProxy/config` | Configured protocol |

Both modes fetch users and alive counts and submit traffic and online IPs through
`/api/v1/server/UniProxy/{user,alivelist,push,alive}` with the panel token and node
ID. No `/report` or `/status` calls are sent. Empty traffic reports keep idle
nodes online in the panel. Config and user ETags avoid downloading unchanged data.
Panel push/pull intervals and V2Node reporting thresholds apply unless explicitly
overridden locally. Intervals have a 10-second minimum; panel thresholds use decimal
KB, while local `submit_*_min_traffic` settings use KiB.

For manual configs, set `type=v2board-uniproxy` and `panel_node_type` to the node's
protocol; this mode requires a single node ID. The core also accepts `shadowsocks`,
`trojan`, and `tuic` here. Unified V2Node configs can discover the protocol from the
panel and retain support for multiple IDs. Existing explicit panel selections
remain in effect; update `type` in an existing config to select one of these modes.

## Certificates

| Wizard mode | Required input | Renewal |
| --- | --- | --- |
| Existing files | Absolute paths to a PEM chain and matching unencrypted key | External tool; restart the instance from its deploy hook |
| Automatic HTTP-01 | Domain and account email | Elise renews and reloads the listener |
| Persistent self-signed | TLS hostname | Replace before its 365-day expiry; explicitly trust it in clients |

HTTP-01 requires DNS to point at this server and public inbound TCP port 80 to
remain available. Proxy TCP listeners must use another port. The wizard checks
local DNS and port availability; it cannot verify external firewall/NAT rules.
DNS-01 is not built into the wizard; externally issued certificates work with
existing-file mode. AnyTLS and both Hysteria versions require TLS certificates;
Hysteria listeners use UDP. Startup can take up to five minutes during issuance.

External renewal hooks should run `elisectl restart <instance>`. Automatic
renewal checks run every 12 hours and renew within 30 days of expiry; reloading
can interrupt sessions. See [protocol notes](docs/protocol-notes.md) for native
TLS settings, Hysteria, online IP limits, and XHTTP interoperability.

## Logs and debugging

Use `elisectl log <instance>` to follow a node's systemd journal. The default
`log_level=info` records startup, configuration changes, and failures. Routine
connections, successful user polls, and handshake details use `debug`. To investigate
an issue, temporarily set `log_level=debug` in the instance's `elise.conf` and restart
it; return to `info` afterwards. `RUST_LOG` overrides this setting when present.
Runtime logs redact panel tokens, ClickHouse passwords, and URL credentials/queries.
VMess credentials and VLESS/REALITY private-key configurations are never logged.

Optional `log_file` and `audit_log_file` use these limits independently:

```ini
log_max_size_mb=10
log_max_files=5
log_retention_days=7
```

Files rotate at the size limit or on a UTC day change. The active file plus numbered
backups occupy at most **50 MiB per sink** with these defaults. Expired backups are
removed on startup and rotation. Files use mode `0600` on Unix. A value of zero
is clamped to one; `log_max_files` is capped at 100. Existing numbered backups beyond
the limits are pruned. Older daily-named files from previous releases are not managed
by this rotation policy. Runtime file output duplicates the console output.

The systemd service limits bursts to 200 messages per 30 seconds. Journal disk size
and retention remain controlled by the host's journald configuration; the file
settings above do not limit the journal. An updated unit takes effect after reinstalling
or updating Elise and restarting the instance.

Audit logs are optional and include user IDs, client IPs, destinations, and traffic
counts. Their JSON records are bounded in size and omit URL queries. File and
ClickHouse queues hold at most 256 records each; overload drops records with warning
summaries instead of delaying proxy traffic. Graceful shutdown attempts to drain them.
ClickHouse checks HTTP status, uses a three-second request timeout, and retries failed
batches up to three attempts. These are best-effort diagnostic logs: failures can lose
records, and a retry after a lost acknowledgement can duplicate records. ClickHouse
server-side retention/TTL must be configured on its table separately.

## Update, migration, and removal

```bash
sudo elisectl update          # latest stable Elise release
sudo elisectl update v1.0.7   # explicit Elise version
```

Updates restart only currently running standalone instances, preserve stopped
instances and boot enable states, and attempt to restore previous files and
services if startup checks fail. Configurations, certificates, and traffic state
are not reset. Connections on restarted instances will be interrupted.

For existing `v2bx elise` installations, first install standalone Elise, then:

```bash
sudo elisectl migrate --from-v2bx --dry-run
sudo elisectl migrate --from-v2bx
```

Read [migration and recovery](docs/migration.md) before migrating. Supported
service settings and certificates are retained. Custom runtime overrides may
require manual adaptation, detected before stopping legacy services.

`elisectl uninstall` stops and disables instances and removes the core and
shared service template. Configuration, state, service overrides, and the manager
remain available for recovery; `elisectl install` reinstalls the core.
`elisectl remove <instance>` deletes its configuration and certificates after
stopping it. External certificates and retained state are not deleted.

## Build and test

```bash
git clone git@github.com:phungvanquy/elise.git
cd elise
cargo build --locked --release
cargo fmt --check
cargo clippy --locked --all-targets --all-features
cargo test --locked --all
bash scripts/test-elise.sh
python3 scripts/test-deploy.py
```

Rust is pinned by `rust-toolchain.toml`. Go is needed only for interoperability
tests, with its version and dependencies pinned in `tests/interop/hysteria2`:

```bash
cargo test --locked --test hysteria2_v2bx -- --ignored --nocapture
cargo test --locked --manifest-path vendor/quinn-proto/Cargo.toml
```

CI builds musl release archives for amd64 and arm64 with `cross`. The tagged
release workflow runs checks before publishing both archives and checksums.
See [source provenance](docs/provenance.md) for the history extraction and local
TLS/QUIC patches. Source builds do not depend on a V2bX checkout.

## Licenses

The Rust core retains [PolyForm Noncommercial 1.0.0](LICENSE). Installation and
management scripts retain [MPL-2.0](scripts/LICENSE). Vendored dependencies and
Restls retain their license notices; release archives include them in
`THIRD-PARTY-NOTICES`. The repository move does not relicense existing code.
