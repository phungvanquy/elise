# Elise Rust core

This directory contains the Elise Rust backend used by the V2bX VLESS, VMess, AnyTLS, and Hysteria 1/2 installer. It builds as a separate executable and runs as a separate systemd service for each panel node.

The source was imported from [`phungvanquy/Elise-Backend`](https://github.com/phungvanquy/Elise-Backend) at commit `b152c13beaa87192951900e5f77ea9d055928f83` (`v1.0.1`). The Rust source retains its [PolyForm Noncommercial 1.0.0 license](LICENSE); the V2bX Go source retains its repository license.

From the V2bX repository root:

```bash
cargo test --locked --all --manifest-path rust/elise/Cargo.toml
cargo build --locked --release --manifest-path rust/elise/Cargo.toml
```

The V2bX release workflow packages Linux amd64 and arm64 builds alongside the Go archives. The installer downloads the Elise asset from the same V2bX release.

Use `V2bX elise add <vless|vmess|anytls|hysteria|hysteria2> <node-id>` to configure a node. `hysteria1` and `hy1` map to the panel type `hysteria`; `hy2` maps to `hysteria2`. AnyTLS and Hysteria require local TLS certificate and key files. Hysteria uses UDP listeners, including startup checks. Panels returning `version=2` for a `hysteria` node select the Hysteria 2 inbound automatically.
