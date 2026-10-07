# Source provenance

Extracted from `phungvanquy/v2bx-new` commit
`0d359200a0e6fd66df9d76201e2985d1a1ca0e87` (V2bX v0.6.8, Elise 1.0.3).

`git-filter-repo` v2.47.0 selected `rust/elise/`, `scripts/elise.sh`,
`scripts/package-elise.sh`, `scripts/test-elise.sh`, and
`.github/workflows/elise.yml`, mapping `rust/elise/` to the root. A fresh clone
was used without importing V2bX tags. The [commit map](v2bx-commit-map.txt) records
original and extracted IDs; zero destinations denote pruned commits. V2bX
history was not rewritten. Scripts retain MPL-2.0 in `scripts/LICENSE`.

V2bX originally imported the Rust source from
[`phungvanquy/Elise-Backend`](https://github.com/phungvanquy/Elise-Backend)
commit `b152c13beaa87192951900e5f77ea9d055928f83` (v1.0.1). This extraction
preserves the history present in V2bX from that import onward, not earlier
Elise-Backend history. Original author and commit metadata are retained.

Patched `vendor/quinn-proto` and `vendor/rustls` are carried over unchanged.
Their patches support existing Hysteria/QUIC and TLS interoperability behavior;
replacing them with crates.io copies requires separate protocol regression
testing. Cargo.lock remains committed.

The Hysteria interoperability fixture now has its own module in
`tests/interop/hysteria2`, pinning Hysteria core/extras v2.12.2 and the same
apernet/quic-go revision used at extraction. Optional Tunnio testing still needs
an explicit `TUNNIO_CORE_DIR`. XBoard and V2Board UniProxy requests now use the
standalone `Elise/1.0` user agent.

Automatic migration support has been removed. Release archives retain an inert
`migrate.py` entry because already released Elise installers require that filename
before they can install an update. Installing the stub also replaces any old
migration implementation; running it exits with an explanation and changes no
files or services. Existing instance configurations, custom service units, and
external traffic-state paths are preserved during updates.
