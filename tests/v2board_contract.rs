//! Wire contract from phungvanquy/v2board-new at 850fff5ced1edd966ced081ec9f1e4efefc683c0.
use elise::panel::{
    create_panel_client_with_node_type, NodeStatusReport, OnlineDeviceItem, TrafficItem,
};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn invalid_configs_do_not_poison_etags_or_cross_node_caches() {
    for panel in ["v2board", "v2board-uniproxy"] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = create_panel_client_with_node_type(
            panel,
            &format!("http://{}", listener.local_addr().unwrap()),
            "fixture",
            Some("vless"),
        );
        let server = tokio::spawn(async move {
            for (node, status, etag, body, conditional) in [
                (
                    1,
                    "200 OK",
                    "same",
                    r#"{"protocol":"vless","server_port":12345}"#,
                    false,
                ),
                (
                    2,
                    "200 OK",
                    "same",
                    r#"{"protocol":"vless","server_port":23456}"#,
                    false,
                ),
                (
                    1,
                    "200 OK",
                    "bad",
                    r#"{"status":"fail","message":"token is error"}"#,
                    true,
                ),
                (1, "304 Not Modified", "", "", true),
                (2, "200 OK", "bad", "{", true),
                (2, "304 Not Modified", "", "", true),
                (3, "304 Not Modified", "", "", false),
            ] {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut header = Vec::new();
                while !header.ends_with(b"\r\n\r\n") {
                    header.push(socket.read_u8().await.unwrap());
                }
                let header = String::from_utf8(header).unwrap().to_lowercase();
                assert!(header.contains(&format!("node_id={node}&")));
                assert_eq!(header.contains("if-none-match:"), conditional);
                if conditional {
                    assert!(header.contains(if panel == "v2board" {
                        "if-none-match: same\r\n"
                    } else {
                        "if-none-match: \"same\"\r\n"
                    }));
                }
                let etag = if etag.is_empty() {
                    String::new()
                } else {
                    format!("ETag: \"{etag}\"\r\n")
                };
                socket.write_all(format!("HTTP/1.1 {status}\r\n{etag}Content-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
            }
        });
        assert_eq!(client.get_node_info(1).await.unwrap().server_port, 12345);
        assert_eq!(client.get_node_info(2).await.unwrap().server_port, 23456);
        assert!(client.get_node_info(1).await.is_err());
        assert_eq!(client.get_node_info(1).await.unwrap().server_port, 12345);
        assert!(client.get_node_info(2).await.is_err());
        assert_eq!(client.get_node_info(2).await.unwrap().server_port, 23456);
        assert!(client.get_node_info(3).await.is_err());
        server.await.unwrap();
    }
}

#[tokio::test]
async fn both_node_sections_use_only_supported_apis() {
    for panel in ["v2board", "v2board-uniproxy"] {
        for protocol in [
            "vless",
            "vmess",
            "anytls",
            "hysteria",
            "hysteria2",
            "trojan",
            "tuic",
            "shadowsocks",
        ] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let client = create_panel_client_with_node_type(
                panel,
                &format!("http://{}", listener.local_addr().unwrap()),
                "key+&=#?",
                Some(protocol),
            );
            let server = tokio::spawn(async move {
                let config_path = if panel == "v2board" {
                    "/api/v2/server/config"
                } else {
                    "/api/v1/server/UniProxy/config"
                };
                let mut config = json!({"server_port":12345,"network":"tcp","tls":1,
                    "version":if protocol == "hysteria2" {2} else {1},
                    "base_config":{"push_interval":30,"pull_interval":45,
                        "node_report_min_traffic":2,"device_online_min_traffic":3},
                    "padding_scheme":"stop=8", "obfs-password":"secret"});
                if panel == "v2board" {
                    config["protocol"] = json!(protocol);
                }
                for (method, path, status, etag, body, expected_body) in [
                    (
                        "GET",
                        config_path,
                        "200 OK",
                        "\"config\"",
                        config.to_string(),
                        Value::Null,
                    ),
                    (
                        "GET",
                        config_path,
                        "304 Not Modified",
                        "",
                        String::new(),
                        Value::Null,
                    ),
                    (
                        "GET",
                        "/api/v1/server/UniProxy/user",
                        "200 OK",
                        "\"users\"",
                        json!({"users":[{"id":7,"uuid":"user","speed_limit":8,"device_limit":2}]})
                            .to_string(),
                        Value::Null,
                    ),
                    (
                        "GET",
                        "/api/v1/server/UniProxy/user",
                        "304 Not Modified",
                        "",
                        String::new(),
                        Value::Null,
                    ),
                    (
                        "GET",
                        "/api/v1/server/UniProxy/alivelist",
                        "200 OK",
                        "",
                        json!({"alive":{"7":2}}).to_string(),
                        Value::Null,
                    ),
                    (
                        "POST",
                        "/api/v1/server/UniProxy/push",
                        "200 OK",
                        "",
                        "{\"data\":true}".into(),
                        json!({"7":[10,20]}),
                    ),
                    (
                        "POST",
                        "/api/v1/server/UniProxy/push",
                        "200 OK",
                        "",
                        "{\"data\":true}".into(),
                        json!({}),
                    ),
                    (
                        "POST",
                        "/api/v1/server/UniProxy/alive",
                        "200 OK",
                        "",
                        "{\"data\":true}".into(),
                        json!({"7":["192.0.2.1","2001:db8::1"]}),
                    ),
                    (
                        "POST",
                        "/api/v1/server/UniProxy/alive",
                        "200 OK",
                        "",
                        "{\"data\":true}".into(),
                        json!({"7":[]}),
                    ),
                ] {
                    let (mut socket, _) =
                        tokio::time::timeout(Duration::from_secs(5), listener.accept())
                            .await
                            .unwrap()
                            .unwrap();
                    let mut header = Vec::new();
                    while !header.ends_with(b"\r\n\r\n") {
                        header.push(socket.read_u8().await.unwrap());
                    }
                    let header = String::from_utf8(header).unwrap();
                    let mut request_line = header.lines().next().unwrap().split_whitespace();
                    assert_eq!(request_line.next(), Some(method));
                    let url = reqwest::Url::parse(&format!(
                        "http://localhost{}",
                        request_line.next().unwrap()
                    ))
                    .unwrap();
                    assert_eq!(url.path(), path);
                    let query: HashMap<_, _> = url.query_pairs().into_owned().collect();
                    assert_eq!(query.len(), 3);
                    assert_eq!(
                        query["node_type"],
                        if panel == "v2board" {
                            "v2node"
                        } else {
                            protocol
                        }
                    );
                    assert_eq!(query["node_id"], "9");
                    assert_eq!(query["token"], "key+&=#?");
                    let headers: HashMap<_, _> = header
                        .lines()
                        .skip(1)
                        .filter_map(|line| line.split_once(':'))
                        .map(|(k, v)| (k.to_lowercase(), v.trim().to_string()))
                        .collect();
                    if status.starts_with("304") {
                        assert_eq!(
                            headers["if-none-match"],
                            if path == config_path {
                                if panel == "v2board" {
                                    "config"
                                } else {
                                    "\"config\""
                                }
                            } else {
                                "\"users\""
                            }
                        );
                    } else {
                        assert!(!headers.contains_key("if-none-match"));
                    }
                    if method == "POST" {
                        let mut bytes = vec![0; headers["content-length"].parse().unwrap()];
                        socket.read_exact(&mut bytes).await.unwrap();
                        assert_eq!(
                            serde_json::from_slice::<Value>(&bytes).unwrap(),
                            expected_body
                        );
                    }
                    let etag = if etag.is_empty() {
                        String::new()
                    } else {
                        format!("ETag: {etag}\r\n")
                    };
                    socket.write_all(format!("HTTP/1.1 {status}\r\n{etag}Content-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
                }
                // report_node_status and empty online lists must not emit requests.
                assert!(
                    tokio::time::timeout(Duration::from_millis(50), listener.accept())
                        .await
                        .is_err()
                );
            });
            for _ in 0..2 {
                let info = client.get_node_info(9).await.unwrap();
                assert_eq!(info.node_type, protocol);
                assert_eq!(info.server_port, 12345);
                assert_eq!(info.base_config.unwrap().pull_interval, Some(45));
                assert_eq!(info.obfs_password.as_deref(), Some("secret"));
            }
            for _ in 0..2 {
                let users = client.get_users(9).await.unwrap();
                assert_eq!(users[0].speed_limit, 1_000_000);
                assert_eq!(users[0].device_limit, 2);
            }
            assert_eq!(client.get_user_alivelist(9).await.unwrap()[&7], 2);
            assert!(client.traffic_heartbeat());
            client
                .report_traffic(
                    9,
                    vec![TrafficItem {
                        user_id: 7,
                        u: 10,
                        d: 20,
                    }],
                )
                .await
                .unwrap();
            client.report_traffic(9, vec![]).await.unwrap();
            client
                .report_online_devices(
                    9,
                    vec![OnlineDeviceItem {
                        user_id: 7,
                        ips: vec!["192.0.2.1".into(), "2001:db8::1".into()],
                    }],
                )
                .await
                .unwrap();
            client
                .report_online_devices(
                    9,
                    vec![OnlineDeviceItem {
                        user_id: 7,
                        ips: vec![],
                    }],
                )
                .await
                .unwrap();
            client.report_online_devices(9, vec![]).await.unwrap();
            client
                .report_node_status(9, &NodeStatusReport::default())
                .await
                .unwrap();
            server.await.unwrap();
        }
    }
}
