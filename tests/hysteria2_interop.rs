#![cfg(feature = "quic-protocols")]

use elise::panel::types::{NodeInfo, User};
use elise::protocol::hysteria::Hysteria2Inbound;
use elise::protocol::{Inbound, InboundContext};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
#[ignore = "requires Go and the pinned interoperability fixture dependencies"]
async fn hysteria2_tcp_udp_and_bandwidth_negotiation() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();
    let _ = rustls::crypto::ring::default_provider().install_default();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/interop/hysteria2");
    let directory = std::env::temp_dir().join(format!("elise-hy2-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&directory).unwrap();
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(directory.clone());
    let source = directory.join("client.go");
    let executable = directory.join("client");
    std::fs::write(&source, include_str!("interop/hysteria2/client.go")).unwrap();
    let output = tokio::process::Command::new("go")
        .args(["build", "-mod=readonly", "-o"])
        .arg(&executable)
        .arg(&source)
        .current_dir(root)
        .kill_on_drop(true)
        .output()
        .await
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_path = directory.join("cert.pem");
    let key_path = directory.join("key.pem");
    std::fs::write(&cert_path, cert.cert.pem()).unwrap();
    std::fs::write(&key_path, cert.key_pair.serialize_pem()).unwrap();
    let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_address = tcp.local_addr().unwrap();
    let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_address = udp.local_addr().unwrap();
    let mut echoes = tokio::task::JoinSet::new();
    echoes.spawn(async move {
        let mut streams = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                _ = streams.join_next(), if !streams.is_empty() => {},
                accepted = tcp.accept() => {
                    let (mut stream, _) = accepted.unwrap();
                    streams.spawn(async move {
                        let mut buf = vec![0; 32768];
                        while let Ok(n) = stream.read(&mut buf).await {
                            if n == 0 || stream.write_all(&buf[..n]).await.is_err() { break; }
                        }
                    });
                }
            }
        }
    });
    echoes.spawn(async move {
        let mut buf = vec![0; 65536];
        loop {
            let (n, from) = udp.recv_from(&mut buf).await.unwrap();
            tracing::trace!(n, "UDP echo received");
            udp.send_to(&buf[..n], from).await.unwrap();
        }
    });

    for (name, obfs, up, down, ignore, rx, tx, expected, fast_open) in [
        ("auto", "none", 8, 16, false, 0, 0, 0, false),
        (
            "brutal", "none", 8, 16, false, 2_000_000, 8_000_000, 2_000_000, false,
        ),
        (
            "salamander",
            "salamander",
            8,
            16,
            false,
            2_000_000,
            8_000_000,
            2_000_000,
            true,
        ),
        (
            "unlimited",
            "none",
            0,
            0,
            false,
            2_000_000,
            8_000_000,
            8_000_000,
            false,
        ),
        (
            "ignore", "none", 8, 16, true, 2_000_000, 8_000_000, 0, false,
        ),
    ] {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = socket.local_addr().unwrap();
        drop(socket);
        let (ready, mut readiness) = tokio::sync::watch::channel(false);
        let ctx = context(address.port(), ready);
        ctx.audit.reload_block_list("domain:blocked.test");
        let devices = ctx.device_limiter.clone();
        let inbound = Hysteria2Inbound::new();
        inbound.update_users(vec![User {
            id: 7,
            password: Some("fixture".into()),
            ..Default::default()
        }]);
        let info = NodeInfo {
            node_type: "hysteria2".into(),
            server_port: address.port(),
            up_mbps: Some(up),
            down_mbps: Some(down),
            ignore_client_bandwidth: ignore,
            obfs: Some(obfs.into()),
            obfs_password: Some("fixture-obfs".into()),
            tls_settings: Some(serde_json::json!({"cert_file": cert_path, "key_file": key_path})),
            ..Default::default()
        };
        let (shutdown, shutdown_rx) = tokio::sync::broadcast::channel(1);
        let server = tokio::spawn(async move { inbound.start(ctx, info, shutdown_rx).await });
        tokio::time::timeout(Duration::from_secs(3), readiness.wait_for(|ready| *ready))
            .await
            .unwrap()
            .unwrap();
        let output = tokio::time::timeout(
            Duration::from_secs(30),
            tokio::process::Command::new(&executable)
                .arg(address.to_string())
                .arg(&cert_path)
                .arg(tcp_address.to_string())
                .arg(udp_address.to_string())
                .arg(obfs)
                .arg(rx.to_string())
                .arg(tx.to_string())
                .arg(expected.to_string())
                .arg(fast_open.to_string())
                .arg(
                    if ignore || rx == 0 {
                        0
                    } else if up == 0 {
                        rx as u64
                    } else {
                        (rx as u64).min(u64::from(up) * 125_000)
                    }
                    .to_string(),
                )
                .kill_on_drop(true)
                .output(),
        )
        .await
        .expect("Hysteria client timed out")
        .unwrap();
        shutdown.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(3), server)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(
            output.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(devices.get_online_devices(7).is_empty());
        eprintln!("{name}: {}", String::from_utf8_lossy(&output.stdout).trim());
    }
}

fn context(port: u16, ready: tokio::sync::watch::Sender<bool>) -> InboundContext {
    let geo = Arc::new(elise::geo::GeoEngine::default());
    let dialer = Arc::new(elise::proxy::router::OutboundDialer::new(
        Arc::new(elise::dns::DNSResolver::default()),
        None,
        None,
        false,
    ));
    InboundContext {
        ready: Some(ready),
        node_id: 1,
        listen_addr: "127.0.0.1".into(),
        port,
        router: Arc::new(elise::proxy::router::Router::new(
            Default::default(),
            dialer,
            geo.clone(),
        )),
        rate_limiter: Arc::new(elise::limiter::RateLimiter::new()),
        conn_limiter: Arc::new(elise::limiter::ConnectionLimiter::new()),
        device_limiter: Arc::new(elise::limiter::DeviceLimiter::new(60, 32, 128, None)),
        audit: Arc::new(elise::security::AuditController::new("", "", geo)),
        defense: Arc::new(elise::security::AttackDefenseManager::default()),
        tls_manager: Arc::new(elise::security::TLSManager::new(false, "localhost".into())),
        audit_logger: Arc::new(elise::observability::AuditLogger::new(None::<&str>)),
        clickhouse_logger: Arc::new(elise::observability::ClickHouseLogger::new(
            false,
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            None,
        )),
        on_traffic: Arc::new(|_, _, _| {}),
        global_config: Arc::new(elise::config::GlobalConfig::default()),
        ip_user_cache: Arc::new(elise::limiter::IpUserCache::new(1, false, "")),
    }
}
