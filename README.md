# Elise

Elise is a Rust node backend configured by default for
[phungvanquy/v2board-new](https://github.com/phungvanquy/v2board-new), with optional
support for XBoard, XiaoV2Board, PPanel, and SSPanel. This repository owns its source, releases, installation tools, and
service management. Each installer-managed panel node runs in its own systemd
service. V2bX is not required to build, install, or run Elise.

To remove an existing installation, see [Completely uninstall Elise](#completely-uninstall-elise).

## Installation

For a first installation, [choose your panel type](#choose-your-panel-type),
[install Elise](#install-elise), then [add a node](#add-and-manage-nodes).
If Elise is already installed, go straight to adding a node.

### Before you begin

- Use a **Linux amd64 or arm64 server with systemd**. Alpine/OpenRC is not
  supported by these installation tools.
- Run installation and management commands as root. The examples use `sudo`;
  omit it if you are already logged in as root.
- Have Bash, curl, CA certificates, tar, sha256sum, flock (util-linux), and
  Python 3.8+ available. The installer can install missing Python with apt-get,
  dnf, or yum. Self-signed certificates also need OpenSSL; the wizard can
  install it with those package managers.
- Create the node in your panel first. Have its **panel URL, backend API key,
  node ID, protocol, and security mode** ready. Elise reads the listening port
  and protocol settings from the panel; it does not create the panel entry.
- Allow the node's listening port through your firewall: TCP for VLESS, VMess,
  and AnyTLS; UDP for Hysteria 1/2. Automatic certificates also need TCP port 80.

A panel node must have only one backend owner. If V2bX already manages this
node, remove its assignment before adding it to Elise. To move an existing
`v2bx elise` installation, use the [migration guide](docs/migration.md).

### Choose your panel type

For [phungvanquy/v2board-new](https://github.com/phungvanquy/v2board-new), choose
the value that matches **where you created the node in the panel**:

| Panel or node section | `--panel-type` value |
| --- | --- |
| V2Board: unified **V2Node** section | `v2board` (default) |
| V2Board: separate **VLESS, VMess, AnyTLS, or Hysteria** sections | `v2board-uniproxy` |
| XBoard | `xboard` |
| XiaoV2Board | `xiaov2board` |
| PPanel | `ppanel` |
| SSPanel | `sspanel` |

`--node-type` is the node's protocol: `vless`, `vmess`, `anytls`, `hysteria`
(Hysteria 1), or `hysteria2`. For example, a VLESS node in the separate VLESS
section needs **both** `--node-type=vless` and `--panel-type=v2board-uniproxy`.
A VLESS node in V2Node uses `--node-type=vless --panel-type=v2board`.

Node IDs can overlap between sections. Use the ID from the selected section;
Elise does not search other sections if it cannot find the node.

### Install Elise

Install the [latest stable release](https://github.com/phungvanquy/elise/releases/latest):

```bash
curl -fsSL https://raw.githubusercontent.com/phungvanquy/elise/refs/heads/main/install.sh -o /tmp/elise-install.sh &&
sudo bash /tmp/elise-install.sh install
```

This installs the program and `elisectl` manager **without creating a node**.
Next, [add your first node](#add-and-manage-nodes). The `elise` command is the
core executable; `elisectl` configures nodes and manages their services.

To install a specific version, pin both the bootstrap script and release.
For example, to install v1.0.8:

```bash
curl -fsSL https://raw.githubusercontent.com/phungvanquy/elise/refs/tags/v1.0.8/install.sh -o /tmp/elise-install.sh &&
sudo bash /tmp/elise-install.sh install v1.0.8
```

The installer verifies the release archive's SHA-256 checksum and installs the
binary, manager, service template, and migration tools from that same archive.
It checks that the Rust binary version matches the requested release tag.
Legacy V2bX-managed services are not started by installation.

### Install and start a node in one command

As an alternative to installing and then running `elisectl add`, you can do
both together. This example uses node **123 in the separate VLESS section**,
configured with **REALITY or no TLS** in the panel. Replace the example URL,
key, and node ID with your panel's values:

```bash
curl -fsSL \
  https://raw.githubusercontent.com/phungvanquy/elise/refs/heads/main/install.sh | \
  sudo bash -s -- install \
    --panel-url='https://panel.example.com' \
    --api-key='REPLACE_WITH_PANEL_KEY' \
    --node-id=123 \
    --node-type=vless \
    --panel-type=v2board-uniproxy
```

For a V2Node entry, change the last option to `--panel-type=v2board`.
For certificate TLS, include the [certificate options](#certificates) as well.
The arguments after `bash -s --` go to the installer and use the same node
options as `elisectl add`.

Node options disable all prompts; both `--name=value` and `--name value` work.
The installer checks the panel, free listener port, and certificate settings
before replacing Elise files or restarting existing services. It then installs
the release, enables the new node at boot, starts it, and checks its listener.
An existing instance is never overwritten. If the first start fails, the new
configuration and certificates remain for diagnosis; the command returns a
failure and prints recovery instructions. The program installation remains.

## Add and manage nodes

### Add a node with command-line options

Use this after installing Elise, for your first node or any additional node.
This example adds node **123 from the separate VLESS section**, configured
with **REALITY or no TLS**. Replace the URL, key, and ID before running it:

```bash
sudo elisectl add \
  --panel-url='https://panel.example.com' \
  --api-key='REPLACE_WITH_PANEL_KEY' \
  --node-id=123 \
  --node-type=vless \
  --panel-type=v2board-uniproxy
```

For a VLESS node in the unified **V2Node** section, use this instead:

```bash
sudo elisectl add \
  --panel-url='https://panel.example.com' \
  --api-key='REPLACE_WITH_PANEL_KEY' \
  --node-id=123 \
  --node-type=vless \
  --panel-type=v2board
```

Use the panel's base URL, without an API endpoint or query string. The API key
is the panel's backend API key. `--node-type` and `--panel-type` must match
the [protocol and panel section](#choose-your-panel-type).

**Using any named option disables all prompts.** Supply all four required
values: panel URL, API key, node ID, and node type. For a node using certificate
TLS, also supply [certificate options](#certificates). Both `--name=value`
and `--name value` work. The listen address defaults to `0.0.0.0` (all IPv4
interfaces); add `--listen=::` or another IP address to change it.

For automation, replace `--api-key=...` with
`--api-key-file=/root/.config/elise/panel.key`. Create that file first, store
only the key in it, and set its permissions to `0600`. The file must be readable
by root. This keeps the literal key out of command history and process arguments.

### Use the interactive wizard

If you prefer prompts for the URL, key, listen address, and certificates, use
positional arguments: `elisectl add <protocol> <node-id> [panel-type]`.
For node 123 in the separate VLESS section:

```bash
sudo elisectl add vless 123 v2board-uniproxy
```

For V2Node, use `sudo elisectl add vless 123 v2board`. Omitting the panel type
also selects `v2board`. Choose either the wizard or the command-line options
above for the same node; existing instances are never overwritten.

The wizard supports VLESS, VMess, AnyTLS, and Hysteria 1/2. Protocol aliases
are `hysteria1`/`hy1` and `hy2`; panel aliases are `xiaov2b` and `sspanel-uim`.
The panel must expose the requested protocol using its supported Elise adapter.
Additional native core protocols can be configured manually; their presence
in the source does not imply wizard support.

### Check that the node started

Adding a node checks the panel, security mode, and free listener port, then
starts its service and enables it at boot. An instance is named
`<protocol>-<node-id>`, so the VLESS examples above create **`vless-123`**:

```bash
sudo elisectl list
sudo elisectl status vless-123
sudo elisectl log vless-123
elise --version
```

Look for `active (running)` in the status and `Node ready with panel users` in
the logs. Then check the node in your panel and connect with a configured
client; local startup checks do not verify external firewall rules or a client
session. `elisectl log` shows the latest 100 journal lines. To follow new logs:

```bash
sudo journalctl -u elise@vless-123.service -f
```

Use `sudo elisectl restart vless-123` after editing its configuration.
Replace `vless-123` with your instance name in all management commands.
See [installation troubleshooting](#installation-troubleshooting) if startup fails.

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
Malformed user/alive responses retain the last valid state. Traffic and online-IP
reports are acknowledged only when the panel returns `data=true`; unsuccessful
traffic batches remain pending for retry. The panel API has no idempotency key, so
an accepted report whose response is lost can be counted again on retry. Node failure
recovery uses cached config and users even when the panel is unavailable; failure to
restore the listener exits the runner so systemd can restart it. Slow API calls do
not accumulate bursts of catch-up polls. Routine heartbeats wait for listener readiness;
shutdown still attempts to flush pending traffic.

Panel push/pull intervals and V2Node reporting thresholds apply unless explicitly
overridden locally. Intervals have a 10-second minimum; panel thresholds use decimal
KB, while local `submit_*_min_traffic` settings use KiB.

For manual configs, set `type=v2board-uniproxy` and `panel_node_type` to the node's
protocol; this mode requires a single node ID. The core also accepts `shadowsocks`,
`trojan`, and `tuic` here. Unified V2Node configs can discover the protocol from the
panel and retain support for multiple IDs. Existing explicit panel selections
remain in effect; update `type` in an existing config to select one of these modes.

## Certificates

Match the security mode configured in the panel:

| Node security | Options to add to `elisectl add` or the installer |
| --- | --- |
| VLESS with REALITY | No certificate options; configure matching REALITY keys in the panel |
| VLESS or VMess without TLS | No certificate options |
| VLESS or VMess with certificate TLS | Choose one certificate mode below |
| AnyTLS, Hysteria 1, or Hysteria 2 | Always choose one certificate mode below |

REALITY destinations accept a hostname or IP with an optional port; the default
is `tls_settings.server_port` or 443. For example, `visualstudio.microsoft.com`
uses port 443. Invalid destinations are rejected when loading the configuration.

For example, add a VLESS node from the separate VLESS section with automatic
Let's Encrypt TLS. Set the node to certificate TLS in the panel first, point
`node.example.com` at this server, and replace all example values:

```bash
sudo elisectl add \
  --panel-url='https://panel.example.com' \
  --api-key='REPLACE_WITH_PANEL_KEY' \
  --node-id=123 \
  --node-type=vless \
  --panel-type=v2board-uniproxy \
  --cert-mode=http \
  --domain=node.example.com \
  --email=admin@example.com
```

For a separate Hysteria 2 node, use `--node-type=hysteria2` and that node's ID.
For a V2Node entry, use `--panel-type=v2board`.

Choose **one** of these option sets. With existing files or a self-signed
certificate, replace the example's `--cert-mode`, `--domain`, and `--email`
lines with the matching set:

| Certificate mode | Command-line options | Renewal |
| --- | --- | --- |
| Existing files | `--cert-mode=file --cert-file=/etc/ssl/elise/fullchain.pem --key-file=/etc/ssl/elise/privkey.pem` | External tool; restart the instance from its deploy hook |
| Automatic Let's Encrypt | `--cert-mode=http --domain=node.example.com --email=admin@example.com` | Elise renews and reloads the listener |
| Self-signed certificate | `--cert-mode=self-signed --domain=node.example.com` | Replace before its 365-day expiry; explicitly trust it in clients |

The interactive wizard asks for the same information. Existing-file mode
requires absolute paths to a PEM certificate chain and matching unencrypted
private key.

HTTP-01 requires DNS to point at this server and public inbound TCP port 80 to
remain available. Proxy TCP listeners must use another port. The wizard checks
local DNS and port availability; it cannot verify external firewall/NAT rules.
HTTP mode registers an account under the
[Let's Encrypt subscriber agreement](https://letsencrypt.org/repository/).
DNS-01 is not built into the wizard; externally issued certificates work with
existing-file mode. Hysteria listeners use UDP. Startup can take up to five
minutes during issuance.

External renewal hooks should run `elisectl restart <instance>`. Automatic
renewal checks run every 12 hours and renew within 30 days of expiry; reloading
can interrupt sessions. See [protocol notes](docs/protocol-notes.md) for native
TLS settings, Hysteria, online IP limits, and XHTTP interoperability.

## Installation troubleshooting

| Message or symptom | What to check |
| --- | --- |
| `elisectl: command not found` | Run the [installer](#install-elise) first. The manager is installed at `/usr/local/bin/elisectl`; ensure `/usr/local/bin` is in your PATH. |
| `unknown node option` or an unsupported panel type | Check `elisectl add --help`. If your installed version lacks these options, run `sudo elisectl update`. |
| Cannot fetch panel configuration, or node not found | Check the base URL, backend API key, and node ID. For V2Board, confirm whether the entry is in V2Node (`v2board`) or a separate protocol section (`v2board-uniproxy`). |
| `panel returned …, expected …` | Set `--node-type` to the protocol configured for that node and confirm the selected panel section. |
| `this node requires TLS` | Supply a complete [certificate option set](#certificates), or use the interactive wizard. Named options disable prompts. |
| `cannot bind …` / port already in use | Check the panel's listening port and stop or reconfigure the service already using it. |
| HTTP certificate preflight or issuance fails | Point the domain's A/AAAA records at this server, allow public inbound TCP port 80, and keep port 80 free for certificate issuance and renewal. |
| `already exists` | Inspect the existing instance with `sudo elisectl status vless-123`; edit its config and restart it instead of adding it again. Substitute your actual instance name. |
| Service runs but clients cannot connect | Check the node's TCP/UDP port in the firewall, client settings, panel users, and node logs. |

If the first start fails, Elise retains the new configuration and certificates
and prints their location. For `vless-123`, inspect the logs with
`sudo elisectl log vless-123`, fix the configuration at
`/etc/elise/instances/vless-123/elise.conf`, then retry:

```bash
sudo systemctl enable --now elise@vless-123.service
```

Use your actual instance name. There is no need to reinstall Elise or add the
same node again.

## Logs and debugging

Use `sudo elisectl log <instance>` to view the latest 100 lines of a node's
systemd journal, or `sudo journalctl -u elise@<instance>.service -f` to follow
new entries. The default `log_level=info` records startup, configuration changes,
and failures. Routine
connections, successful user polls, and handshake details use `debug`. To investigate
an issue, temporarily set `log_level=debug` in the instance's `elise.conf` and restart
it; return to `info` afterwards. `RUST_LOG` overrides this setting when present.
Every protocol fetches its initial panel user list before opening its listener.
Failed initial user requests retry every 10 seconds and can be interrupted by shutdown.
A successful empty list is valid and starts the listener with no authorized users.
`Panel users loaded` and `Node ready with panel users` show the initial counts at info
level. Later polling uses the configured/panel pull interval; failed refreshes retain
the last valid users, while a successful empty response revokes access. Listener and
certificate reloads reuse the last valid list. User-count changes and recovery are
logged at info; unchanged counts use debug. Repeated user-fetch failures are summarized
at failure counts 1, 2, 4, 8, and so on, keeping persistent outages quiet.

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
sudo elisectl update v1.0.8   # explicit Elise version
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

### Completely uninstall Elise

To permanently remove **all standalone Elise instances and their retained data**,
run this **online uninstall command** on your server (no repository clone needed):

```bash
curl -fsSL https://raw.githubusercontent.com/phungvanquy/elise/refs/heads/main/uninstall.sh | sudo bash -s -- --yes
```

If you are already logged in as root, omit `sudo`. `--yes` confirms permanent
deletion of Elise's data.

Alternatively, download the script first, then run it:

```bash
curl -fsSL https://raw.githubusercontent.com/phungvanquy/elise/refs/heads/main/uninstall.sh -o /tmp/elise-uninstall.sh &&
sudo bash /tmp/elise-uninstall.sh --yes
```

From a checkout of this repository, run `sudo bash uninstall.sh --yes`.
Use `bash uninstall.sh --help` to see what it removes.

The script downloads the current purge tool over HTTPS. It requires Linux with
systemd, root, Bash, curl, CA certificates, and flock (util-linux). It works with
older installations, including v1.0.8, and after the manager has been removed.
No binary rebuild, upgrade, or new release is needed.

If your installed manager already supports `purge`, you can also remove Elise
directly without downloading anything:

```bash
sudo elisectl purge --yes
```

Purge stops all discovered `elise@` instance services, including orphaned and migrated
units, before deleting files. It removes `/etc/elise`, `/var/lib/elise` (including
backups and pending traffic), `/usr/local/lib/elise`, `/usr/local/share/licenses/elise`,
both `elise` and `elisectl` binaries, and Elise's systemd template, instance units,
drop-ins and enablement links. If a service cannot be stopped, no files are deleted.
`--yes` is required; this cannot be undone. The command also works after `uninstall`.

External certificate/log/state paths, original V2bX directories, and the host's system
journal are preserved. Symlinks inside Elise's directories are removed without deleting
their external targets.

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
