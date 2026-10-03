use elise::protocol::vless::{parse_vless_request_header, write_vless_response_header};
use elise::transport::serve_transport;
use elise::transport::types::{TransportConfig, XHttpTransportConfig};
use rcgen::generate_simple_self_signed;
use rustls::pki_types::PrivatePkcs8KeyDer;
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::process::Command;
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;

const UUID: &str = "6a9ecf20-44b2-4fc2-a3a0-4dcda7b2c3eb";

#[tokio::test]
#[ignore = "requires TUNNIO_CORE_DIR pointing to Tunnio/core and its Go dependencies"]
async fn tunnio_vless_tls_xhttp_roundtrips() {
    let core = std::env::var("TUNNIO_CORE_DIR").expect("set TUNNIO_CORE_DIR");
    let directory = std::env::temp_dir().join(format!("elise-xhttp-{}", uuid::Uuid::new_v4()));
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
    std::fs::write(&source, include_str!("testdata/xhttp_tunnio.go")).unwrap();
    let output = Command::new("go")
        .args(["build", "-mod=readonly", "-o"])
        .arg(&executable)
        .arg(&source)
        .current_dir(core)
        .output()
        .await
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()).into(),
        )
        .unwrap();
    tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(tls));
    let mut tasks = JoinSet::new();
    for (name, mode, extra) in [
        (
            "packet-header",
            "packet-up",
            json!({
                "uplinkHTTPMethod":"GET", "uplinkDataPlacement":"header", "uplinkDataKey":"X-Data",
                "scMaxEachPostBytes":"2048", "uplinkChunkSize":"2048", "xPaddingBytes":"100-1000", "xPaddingObfsMode":true
            }),
        ),
        (
            "packet-body",
            "packet-up",
            json!({"scMaxEachPostBytes":2048}),
        ),
        ("stream-one", "stream-one", json!({})),
        ("stream-up", "stream-up", json!({})),
    ] {
        let config = TransportConfig::XHttp(XHttpTransportConfig {
            mode: mode.into(),
            host: Some("localhost".into()),
            path: "/api/v1/sync".into(),
            extra: Some(extra),
            ..Default::default()
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let acceptor = acceptor.clone();
        tasks.spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (stream, _) = accepted.unwrap();
                        let (acceptor, config) = (acceptor.clone(), config.clone());
                        connections.spawn(async move {
                            let stream = acceptor.accept(stream).await.unwrap();
                            let _ = serve_transport(Box::new(stream), &config, None, |mut stream| async move {
                                let request = parse_vless_request_header(&mut stream).await.unwrap();
                                assert_eq!(request.uuid_bytes, *uuid::Uuid::parse_str(UUID).unwrap().as_bytes());
                                assert_eq!(request.command, 1);
                                write_vless_response_header(&mut stream).await.unwrap();
                                let (mut reader, mut writer) = tokio::io::split(stream);
                                let _ = tokio::io::copy(&mut reader, &mut writer).await;
                            }).await;
                        });
                    }
                    result = connections.join_next(), if !connections.is_empty() => {
                        result.unwrap().unwrap();
                    }
                }
            }
        });
        for alpn in ["h2", "http/1.1"] {
            let output = tokio::time::timeout(
                Duration::from_secs(30),
                Command::new(&executable)
                    .args([address.to_string(), name.to_string(), alpn.to_string()])
                    .kill_on_drop(true)
                    .output(),
            )
            .await
            .expect("client timed out")
            .unwrap();
            assert!(
                output.status.success(),
                "{name}/{alpn}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            println!(
                "{name}/{alpn}: {}",
                String::from_utf8_lossy(&output.stdout).trim()
            );
        }
    }
}
