use elise::panel::{NodeInfo, User};
use elise::protocol::anytls::{
    make_frame, AnytlsInbound, CMD_FIN, CMD_PSH, CMD_SETTINGS, CMD_SYN, CMD_SYNACK,
};
use elise::protocol::{Inbound, InboundContext};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, watch};

const PASSWORD: &str = "anytls-password-fixture";

fn context(port: u16) -> InboundContext {
    let geo = Arc::new(elise::geo::GeoEngine::default());
    let dialer = Arc::new(elise::proxy::router::OutboundDialer::new(
        Arc::new(elise::dns::DNSResolver::default()),
        None,
        None,
        false,
    ));
    let config = elise::config::GlobalConfig {
        domain_sniff: false,
        auto_tls: false,
        ..Default::default()
    };
    InboundContext {
        ready: None,
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
        global_config: Arc::new(config),
        ip_user_cache: Arc::new(elise::limiter::IpUserCache::new(1, false, "")),
    }
}

struct RunningInbound {
    address: SocketAddr,
    ctx: InboundContext,
    shutdown: broadcast::Sender<()>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl RunningInbound {
    async fn start(info: NodeInfo) -> Self {
        Self::start_with_proxy(info, elise::conn::ProxyProtocolMode::Off).await
    }

    async fn start_with_proxy(info: NodeInfo, proxy: elise::conn::ProxyProtocolMode) -> Self {
        let reserved = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = reserved.local_addr().unwrap();
        let mut ctx = context(address.port());
        Arc::make_mut(&mut ctx.global_config).proxy_protocol_mode = proxy;
        Arc::make_mut(&mut ctx.global_config).proxy_protocol =
            proxy != elise::conn::ProxyProtocolMode::Off;
        let (ready, mut readiness) = watch::channel(false);
        ctx.ready = Some(ready);
        let inbound = AnytlsInbound::new();
        inbound.update_users(vec![User {
            id: 7,
            uuid: "uuid-is-not-the-password".into(),
            password: Some(PASSWORD.into()),
            ..Default::default()
        }]);
        let (shutdown, rx) = broadcast::channel(1);
        drop(reserved);
        let server_ctx = ctx.clone();
        let task = tokio::spawn(async move { inbound.start(server_ctx, info, rx).await });
        tokio::time::timeout(Duration::from_secs(3), readiness.wait_for(|ready| *ready))
            .await
            .unwrap()
            .unwrap();
        Self {
            address,
            ctx,
            shutdown,
            task,
        }
    }

    async fn stop(self) {
        self.shutdown.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(6), self.task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(self.ctx.conn_limiter.get_total_active(), 0);
        assert!(self.ctx.device_limiter.get_online_devices(7).is_empty());
    }
}

fn tls_node(mode: Option<u8>) -> (NodeInfo, Arc<rustls::ClientConfig>) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.cert.der().clone()).unwrap();
    let mut client = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client.alpn_protocols = vec![b"h2".to_vec()];
    (
        NodeInfo {
            node_type: "anytls".into(),
            tls: mode,
            tls_settings: Some(json!({"server_name":"localhost","alpn":["h2"]})),
            cert_config: Some(
                json!({"certificate":cert.cert.pem(),"key":cert.key_pair.serialize_pem()}),
            ),
            ..Default::default()
        },
        Arc::new(client),
    )
}

fn reality_node(dest: SocketAddr) -> (NodeInfo, String) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let keys = elise::security::generate_reality_keypair();
    (
        NodeInfo {
            node_type: "anytls".into(),
            tls: Some(2),
            network: Some("tcp".into()),
            tls_settings: Some(json!({"dest":dest.to_string(),"server_name":"localhost",
            "private_key":keys.private_key,"public_key":keys.public_key,"short_id":"01020304"})),
            // REALITY must not try to load certificate TLS, even if old file paths remain.
            cert_config: Some(
                json!({"cert_file":"/nonexistent/anytls.crt","key_file":"/nonexistent/anytls.key"}),
            ),
            ..Default::default()
        },
        keys.public_key,
    )
}

async fn authenticate<S: AsyncWrite + Unpin>(stream: &mut S, password: &str) {
    stream
        .write_all(&Sha256::digest(password.as_bytes()))
        .await
        .unwrap();
    stream.write_all(&5u16.to_be_bytes()).await.unwrap();
    stream.write_all(b"pad!!").await.unwrap();
}

async fn multiplexed_roundtrip<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S, port: u16) {
    authenticate(stream, PASSWORD).await;
    stream
        .write_all(&make_frame(CMD_SETTINGS, 0, b"v=2\n"))
        .await
        .unwrap();
    for (id, payload) in [
        (1, b"first-stream".as_slice()),
        (2, b"second-stream".as_slice()),
    ] {
        stream
            .write_all(&make_frame(CMD_SYN, id, &[]))
            .await
            .unwrap();
        let mut request = vec![1, 127, 0, 0, 1];
        request.extend_from_slice(&port.to_be_bytes());
        request.extend_from_slice(payload);
        stream
            .write_all(&make_frame(CMD_PSH, id, &request))
            .await
            .unwrap();
    }
    let mut received = [Vec::new(), Vec::new()];
    let mut acknowledged = [false; 2];
    tokio::time::timeout(Duration::from_secs(5), async {
        while received[0].len() < b"first-stream".len()
            || received[1].len() < b"second-stream".len()
        {
            let mut header = [0; 7];
            stream.read_exact(&mut header).await.unwrap();
            let id = u32::from_be_bytes(header[1..5].try_into().unwrap());
            let mut payload =
                vec![0; u16::from_be_bytes(header[5..7].try_into().unwrap()) as usize];
            stream.read_exact(&mut payload).await.unwrap();
            if matches!(header[0], CMD_PSH | CMD_SYNACK) {
                assert!(matches!(id, 1 | 2));
                if header[0] == CMD_PSH {
                    received[(id - 1) as usize].extend_from_slice(&payload);
                } else {
                    assert!(payload.is_empty(), "stream failed: {payload:?}");
                    acknowledged[(id - 1) as usize] = true;
                }
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(received[0], b"first-stream");
    assert_eq!(received[1], b"second-stream");
    assert_eq!(acknowledged, [true, true]);
    for id in [1, 2] {
        stream
            .write_all(&make_frame(CMD_FIN, id, &[]))
            .await
            .unwrap();
    }
}

async fn echo_target() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        for _ in 0..2 {
            let (stream, _) = listener.accept().await.unwrap();
            connections.spawn(async move {
                let (mut reader, mut writer) = stream.into_split();
                tokio::io::copy(&mut reader, &mut writer).await.unwrap();
            });
        }
        while let Some(result) = connections.join_next().await {
            result.unwrap();
        }
    });
    (address, task)
}

#[tokio::test]
async fn anytls_certificate_tls_and_omitted_mode_keep_authentication_and_multiplexing() {
    for mode in [None, Some(1)] {
        let (info, client) = tls_node(mode);
        let server = RunningInbound::start(info).await;
        let connector = tokio_rustls::TlsConnector::from(client);
        let mut rejected = connector
            .connect(
                "localhost".try_into().unwrap(),
                TcpStream::connect(server.address).await.unwrap(),
            )
            .await
            .unwrap();
        authenticate(&mut rejected, "wrong-password").await;
        let closed = tokio::time::timeout(Duration::from_secs(3), rejected.read(&mut [0]))
            .await
            .unwrap();
        assert!(matches!(closed, Ok(0) | Err(_)));
        assert_eq!(server.ctx.conn_limiter.get_total_active(), 0);
        let mut stream = connector
            .connect(
                "localhost".try_into().unwrap(),
                TcpStream::connect(server.address).await.unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(stream.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
        let (target, echo) = echo_target().await;
        multiplexed_roundtrip(&mut stream, target.port()).await;
        drop(stream);
        server.stop().await;
        tokio::time::timeout(Duration::from_secs(3), echo)
            .await
            .unwrap()
            .unwrap();
    }
}

#[tokio::test]
async fn anytls_rejects_plaintext_unknown_modes_and_invalid_reality_before_readiness() {
    for mode in [0, 3, 255] {
        let inbound = AnytlsInbound::new();
        let (ready, readiness) = watch::channel(false);
        let mut ctx = context(0);
        ctx.ready = Some(ready);
        let (_shutdown, rx) = broadcast::channel(1);
        let err = inbound
            .start(
                ctx,
                NodeInfo {
                    node_type: "anytls".into(),
                    tls: Some(mode),
                    ..Default::default()
                },
                rx,
            )
            .await
            .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
        assert!(!*readiness.borrow());
    }
    for settings in [
        json!({"server_name":"localhost"}),
        json!({"server_name":"localhost","private_key":"invalid"}),
        json!({"server_name":"localhost","private_key":base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, [7;32]),"short_id":"not-hex"}),
    ] {
        let inbound = AnytlsInbound::new();
        let (ready, readiness) = watch::channel(false);
        let mut ctx = context(0);
        ctx.ready = Some(ready);
        let (_shutdown, rx) = broadcast::channel(1);
        let err = inbound
            .start(
                ctx,
                NodeInfo {
                    node_type: "anytls".into(),
                    tls: Some(2),
                    tls_settings: Some(settings),
                    ..Default::default()
                },
                rx,
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("REALITY"), "{err}");
        assert!(!*readiness.borrow());
    }
}

#[tokio::test]
async fn anytls_reality_probes_reach_fallback_without_consuming_user_limits() {
    let fallback = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (info, _) = reality_node(fallback.local_addr().unwrap());
    let server = RunningInbound::start(info).await;
    // A connect-only readiness probe must not connect to the fallback.
    drop(TcpStream::connect(server.address).await.unwrap());
    assert!(
        tokio::time::timeout(Duration::from_millis(100), fallback.accept())
            .await
            .is_err()
    );
    let mut probe = TcpStream::connect(server.address).await.unwrap();
    probe.write_all(b"probe-without-tls").await.unwrap();
    let (mut forwarded, _) = tokio::time::timeout(Duration::from_secs(3), fallback.accept())
        .await
        .unwrap()
        .unwrap();
    let mut payload = [0; 17];
    forwarded.read_exact(&mut payload).await.unwrap();
    assert_eq!(&payload, b"probe-without-tls");
    forwarded.write_all(b"decoy-response").await.unwrap();
    let mut response = [0; 14];
    probe.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"decoy-response");
    assert_eq!(server.ctx.conn_limiter.get_total_active(), 0);
    assert!(server.ctx.device_limiter.get_online_devices(7).is_empty());
    drop(probe);
    drop(forwarded);
    server.stop().await;
}

#[tokio::test]
#[ignore = "requires Go and the pinned tests/interop/anytls dependencies"]
async fn anytls_reality_go_client_roundtrips() {
    let directory = std::env::temp_dir().join(format!("elise-anytls-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&directory).unwrap();
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(directory.clone());
    let executable = directory.join("client");
    let output = tokio::process::Command::new("go")
        .args(["build", "-mod=readonly", "-o"])
        .arg(&executable)
        .arg(".")
        .current_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/interop/anytls"))
        .output()
        .await
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    for (alpn, proxy) in [
        (None, "off"),
        (Some("h2"), "off"),
        (Some("h2"), "v1"),
        (Some("h2"), "v2"),
    ] {
        let fallback = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (mut info, public) = reality_node(fallback.local_addr().unwrap());
        if let Some(alpn) = alpn {
            info.tls_settings.as_mut().unwrap()["alpn"] = json!([alpn]);
        }
        let server = RunningInbound::start_with_proxy(
            info,
            if proxy == "off" {
                elise::conn::ProxyProtocolMode::Off
            } else {
                elise::conn::ProxyProtocolMode::Auto
            },
        )
        .await;
        let (target, echo) = echo_target().await;
        let output = tokio::time::timeout(
            Duration::from_secs(15),
            tokio::process::Command::new(&executable)
                .args([
                    server.address.to_string(),
                    public.clone(),
                    "01020304".into(),
                    PASSWORD.into(),
                    target.to_string(),
                    alpn.unwrap_or("").into(),
                    proxy.into(),
                ])
                .kill_on_drop(true)
                .output(),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(
            output.status.success(),
            "{alpn:?}/{proxy}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(100), fallback.accept())
                .await
                .is_err(),
            "authenticated client reached fallback"
        );
        if alpn.is_none() {
            // REALITY authentication does not replace the AnyTLS password.
            let rejected = tokio::time::timeout(
                Duration::from_secs(15),
                tokio::process::Command::new(&executable)
                    .args([
                        server.address.to_string(),
                        public.clone(),
                        "01020304".into(),
                        "wrong-password".into(),
                        target.to_string(),
                        String::new(),
                        "off".into(),
                    ])
                    .kill_on_drop(true)
                    .output(),
            )
            .await
            .unwrap()
            .unwrap();
            assert!(!rejected.status.success());
            assert!(
                String::from_utf8_lossy(&rejected.stdout).contains("REALITY certificate verified")
            );
            assert!(
                tokio::time::timeout(Duration::from_millis(100), fallback.accept())
                    .await
                    .is_err()
            );

            // A wrong short ID or public key must take the REALITY fallback
            // path and must never reach the AnyTLS target.
            for (public, short_id) in [
                (public, "ffffffff"),
                (
                    elise::security::generate_reality_keypair().public_key,
                    "01020304",
                ),
            ] {
                let rejection = async {
                    let (mut decoy, _) = fallback.accept().await.unwrap();
                    let mut header = [0; 5];
                    decoy.read_exact(&mut header).await.unwrap();
                    assert_eq!(header[0], 0x16);
                    decoy
                        .write_all(b"HTTP/1.0 400 Bad Request\r\n\r\n")
                        .await
                        .unwrap();
                };
                let mut command = tokio::process::Command::new(&executable);
                command
                    .args([
                        server.address.to_string(),
                        public,
                        short_id.into(),
                        PASSWORD.into(),
                        target.to_string(),
                        String::new(),
                        "off".into(),
                    ])
                    .kill_on_drop(true);
                let client = command.output();
                let ((), rejected) = tokio::time::timeout(Duration::from_secs(15), async {
                    tokio::join!(rejection, client)
                })
                .await
                .unwrap();
                let rejected = rejected.unwrap();
                assert!(!rejected.status.success());
                assert!(!String::from_utf8_lossy(&rejected.stdout)
                    .contains("REALITY certificate verified"));
            }
        }
        server.stop().await;
        tokio::time::timeout(Duration::from_secs(3), echo)
            .await
            .unwrap()
            .unwrap();
    }
}
