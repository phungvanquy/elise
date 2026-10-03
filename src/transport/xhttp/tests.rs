use super::*;
use serde_json::json;
use tokio::net::TcpListener;
use tokio::task::{JoinHandle, JoinSet};

fn config(extra: serde_json::Value) -> XHttpTransportConfig {
    XHttpTransportConfig {
        mode: "packet-up".into(),
        path: "/api/v1/sync".into(),
        extra: Some(extra),
        ..Default::default()
    }
}

fn header_config() -> XHttpTransportConfig {
    config(json!({
        "uplinkHTTPMethod": "GET", "uplinkDataPlacement": "header", "uplinkDataKey": "X-Data",
        "scMaxEachPostBytes": "2048", "uplinkChunkSize": "2048", "xPaddingBytes": "100-1000",
        "xPaddingObfsMode": true
    }))
}

struct TestServer {
    url: String,
    task: JoinHandle<()>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn server(config: XHttpTransportConfig) -> TestServer {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/api/v1/sync/", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let mut tasks = JoinSet::new();
        loop {
            tokio::select! {
                conn = listener.accept() => {
                    let (conn, _) = conn.unwrap();
                    let config = config.clone();
                    tasks.spawn(async move {
                        let _ = serve_xhttp(Box::new(conn), &config, |stream| async move {
                            let (mut reader, mut writer) = tokio::io::split(stream);
                            let _ = tokio::io::copy(&mut reader, &mut writer).await;
                        }).await;
                    });
                }
                _ = tasks.join_next(), if !tasks.is_empty() => {}
            }
        }
    });
    TestServer { url, task }
}

fn client(h2: bool) -> reqwest::Client {
    let builder = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5));
    (if h2 {
        builder.http2_prior_knowledge()
    } else {
        builder.http1_only()
    })
    .build()
    .unwrap()
}

fn padded(request: reqwest::RequestBuilder, obfs: bool) -> reqwest::RequestBuilder {
    request.header(
        if obfs { "X-Padding" } else { "Referer" },
        format!("https://example.com/?x_padding={}", "X".repeat(100)),
    )
}

async fn read_bytes(response: &mut reqwest::Response, count: usize) -> Vec<u8> {
    let mut data = Vec::new();
    while data.len() < count {
        data.extend(response.chunk().await.unwrap().expect("download closed"));
    }
    data
}

async fn packet_roundtrip(h2: bool, headers: bool) {
    let cfg = if headers {
        header_config()
    } else {
        config(json!({"scMaxEachPostBytes": 2048}))
    };
    let server = server(cfg).await;
    let down = client(h2);
    let up = client(h2);
    // The initial upload and download deliberately use different TCP connections.
    let send = |seq: usize, data: &[u8]| {
        let request = if headers {
            let encoded = URL_SAFE_NO_PAD.encode(data);
            let mut request = up.get(format!("{}session/{seq}", server.url));
            for (i, chunk) in encoded.as_bytes().chunks(1024).enumerate() {
                request =
                    request.header(format!("X-Data-{i}"), std::str::from_utf8(chunk).unwrap());
            }
            request
        } else {
            up.post(format!("{}session/{seq}", server.url))
                .body(data.to_vec())
        };
        padded(request, headers).send()
    };
    assert_eq!(
        send(1, &vec![b'b'; 2048]).await.unwrap().status(),
        StatusCode::OK
    );
    let mut response = padded(down.get(format!("{}session", server.url)), headers)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.version(),
        if h2 {
            http::Version::HTTP_2
        } else {
            http::Version::HTTP_11
        }
    );
    assert_eq!(
        send(0, &vec![b'a'; 2048]).await.unwrap().status(),
        StatusCode::OK
    );
    assert_eq!(send(2, b"tail").await.unwrap().status(), StatusCode::OK);
    let expected = [vec![b'a'; 2048], vec![b'b'; 2048], b"tail".to_vec()].concat();
    assert_eq!(read_bytes(&mut response, expected.len()).await, expected);
    assert_eq!(
        send(2, b"duplicate").await.unwrap().status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        send(3, &vec![0; 2049]).await.unwrap().status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
}

#[tokio::test]
async fn packet_up_h2_header_get_with_default_padding_and_ordered_sessions() {
    packet_roundtrip(true, true).await;
}

#[tokio::test]
async fn packet_up_http1_header_get_with_default_padding_and_ordered_sessions() {
    packet_roundtrip(false, true).await;
}

#[tokio::test]
async fn packet_up_h2_post_body() {
    packet_roundtrip(true, false).await;
}

#[tokio::test]
async fn packet_up_http1_post_body() {
    packet_roundtrip(false, false).await;
}

#[tokio::test]
async fn cookie_uploads_and_padding_are_decoded() {
    let server = server(config(json!({"uplinkHTTPMethod":"GET", "uplinkDataPlacement":"cookie", "xPaddingObfsMode":true, "xPaddingPlacement":"cookie"}))).await;
    let client = client(true);
    let padding = format!("x_padding={}", "X".repeat(100));
    let mut down = client
        .get(format!("{}cookie", server.url))
        .header("cookie", &padding)
        .send()
        .await
        .unwrap();
    assert_eq!(down.status(), StatusCode::OK);
    let ack = client
        .get(format!("{}cookie/0", server.url))
        .header(
            "cookie",
            format!(
                "{padding}; x_data_0={}",
                URL_SAFE_NO_PAD.encode(b"cookie payload")
            ),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(ack.status(), StatusCode::OK);
    assert_eq!(read_bytes(&mut down, 14).await, b"cookie payload");
}

#[tokio::test]
async fn invalid_padding_payload_and_route_do_not_poison_connection() {
    let server = server(header_config()).await;
    let client = client(true);
    assert_eq!(
        client
            .get(format!("{}bad/0", server.url))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        padded(
            client
                .get(format!("{}bad/0", server.url))
                .header("X-Data-0", "invalid!"),
            true
        )
        .send()
        .await
        .unwrap()
        .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        padded(client.get(format!("{}bad/not-a-number", server.url)), true)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        padded(
            client.get(server.url.replace("/sync/", "/sync-wrong/s/0")),
            true
        )
        .send()
        .await
        .unwrap()
        .status(),
        StatusCode::NOT_FOUND
    );
    let mut down = padded(client.get(format!("{}good", server.url)), true)
        .send()
        .await
        .unwrap();
    assert_eq!(down.status(), StatusCode::OK);
    assert_eq!(
        padded(
            client
                .get(format!("{}good/0", server.url))
                .header("X-Data-0", "b2s"),
            true
        )
        .send()
        .await
        .unwrap()
        .status(),
        StatusCode::OK
    );
    assert_eq!(read_bytes(&mut down, 2).await, b"ok");
}

#[tokio::test]
async fn session_state_is_isolated_per_inbound() {
    let config_a = header_config();
    let config_b = header_config();
    let session = config_a.sessions.get("same-id").unwrap();
    session.push(0, Bytes::from_static(b"private"), 30).unwrap();
    let other = config_b.sessions.get("same-id").unwrap();
    let mut reader = other.reader().unwrap();
    let mut buf = [0; 7];
    assert!(
        tokio::time::timeout(Duration::from_millis(20), reader.read_exact(&mut buf))
            .await
            .is_err()
    );
    let clone = config_a.clone();
    let mut reader = clone.sessions.get("same-id").unwrap().reader().unwrap();
    reader.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"private");
}

#[tokio::test]
async fn session_buffer_limits_and_close_release_pending_uploads() {
    let sessions = Arc::new(Sessions::default());
    let session = sessions.get("bounded").unwrap();
    session.push(1, Bytes::from_static(b"future"), 1).unwrap();
    assert_eq!(
        session.push(2, Bytes::from_static(b"overflow"), 1),
        Err(StatusCode::TOO_MANY_REQUESTS)
    );
    let mut reader = session.reader().unwrap();
    assert!(session.reader().is_err());
    drop(sessions.guard("bounded".into(), session.clone()));
    assert_eq!(reader.read(&mut [0; 8]).await.unwrap(), 0);
    assert_eq!(session.push(0, Bytes::new(), 1), Err(StatusCode::CONFLICT));
    assert!(!Arc::ptr_eq(&session, &sessions.get("bounded").unwrap()));
}

#[tokio::test(start_paused = true)]
async fn orphan_uploads_expire_but_connected_sessions_remain() {
    let sessions = Arc::new(Sessions::default());
    let orphan = sessions.get("orphan").unwrap();
    let connected = sessions.get("connected").unwrap();
    let _reader = connected.reader().unwrap();
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(31)).await;
    tokio::task::yield_now().await;
    assert!(!Arc::ptr_eq(&orphan, &sessions.get("orphan").unwrap()));
    assert!(orphan.reader().is_err());
    assert!(Arc::ptr_eq(&connected, &sessions.get("connected").unwrap()));
}

#[tokio::test]
async fn dropping_download_closes_its_session() {
    for h2 in [false, true] {
        let cfg = header_config();
        let session = cfg.sessions.get("cancel").unwrap();
        let mut closed = session.closed.subscribe();
        let server = server(cfg).await;
        let client = client(h2);
        let response = padded(client.get(format!("{}cancel", server.url)), true)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        drop(response);
        tokio::time::timeout(Duration::from_secs(2), closed.changed())
            .await
            .unwrap()
            .unwrap();
        assert!(*closed.borrow());
    }
}

#[test]
fn padding_defaults_and_number_ranges_match_xray() {
    let options = Options::parse(&header_config()).unwrap();
    assert_eq!(options.max_post, 2048);
    assert_eq!(options.padding_placement, options::Placement::QueryInHeader);
    let valid = Request::builder()
        .uri("/api/v1/sync/s/0")
        .header(
            "X-Padding",
            format!("https://example.com/?x_padding={}", "X".repeat(100)),
        )
        .body(())
        .unwrap();
    assert_eq!(options.validate(&valid), Ok(()));
    for value in [
        json!(2048),
        json!("2048"),
        json!("1024-2048"),
        json!("2048-1024"),
    ] {
        assert_eq!(
            Options::parse(&config(json!({"scMaxEachPostBytes":value})))
                .unwrap()
                .max_post,
            2048
        );
    }
    for extra in [
        json!({"scMaxEachPostBytes":0}),
        json!({"scMaxEachPostBytes":"-1"}),
        json!({"xPaddingBytes":"0-100"}),
        json!({"uplinkDataPlacement":"invalid"}),
        json!({"xPaddingMethod":"unknown"}),
        json!({"xPaddingObfsMode":"true"}),
        json!(false),
    ] {
        assert!(validate_config(&config(extra)).is_err());
    }
}

#[test]
fn configured_host_and_padding_locations_are_checked() {
    for placement in ["header", "query", "cookie", "queryInHeader"] {
        let mut cfg = config(json!({"xPaddingObfsMode":true,"xPaddingPlacement":placement}));
        cfg.host = Some("example.com".into());
        let options = Options::parse(&cfg).unwrap();
        let padding = "X".repeat(100);
        let mut req = Request::builder()
            .uri("/api/v1/sync/s")
            .header("Host", "EXAMPLE.com:443");
        match placement {
            "header" => req = req.header("X-Padding", &padding),
            "query" => req = req.uri(format!("/api/v1/sync/s?x_padding={padding}")),
            "cookie" => req = req.header("Cookie", format!("x_padding={padding}")),
            _ => {
                req = req.header(
                    "X-Padding",
                    format!("https://example.com/?x_padding={padding}"),
                )
            }
        }
        let mut req = req.body(()).unwrap();
        assert_eq!(options.validate(&req), Ok(()));
        req.headers_mut().remove("host");
        assert_eq!(options.validate(&req), Err(StatusCode::NOT_FOUND));
    }
}

#[tokio::test]
async fn streaming_modes_keep_upload_and_download_connected() {
    for h2 in [false, true] {
        for mode in ["stream-one", "stream-up"] {
            let mut cfg = config(json!({}));
            cfg.mode = mode.into();
            let server = server(cfg).await;
            let client = client(h2);
            if mode == "stream-one" {
                let response = padded(client.post(&server.url).body("streamed"), false)
                    .send()
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::OK);
                assert_eq!(response.bytes().await.unwrap(), b"streamed"[..]);
            } else {
                let mut down = padded(client.get(format!("{}stream", server.url)), false)
                    .send()
                    .await
                    .unwrap();
                assert_eq!(down.status(), StatusCode::OK);
                let upload = padded(
                    client
                        .post(format!("{}stream", server.url))
                        .body("streamed"),
                    false,
                )
                .send()
                .await
                .unwrap();
                assert_eq!(upload.status(), StatusCode::OK);
                assert_eq!(read_bytes(&mut down, 8).await, b"streamed");
            }
        }
    }
}
