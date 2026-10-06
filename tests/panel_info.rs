use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Command, Output};

fn inspect(panel: &str, requested: &str, payload: Value, status: &str) -> Output {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let platform = panel.to_string();
    let requested_type = requested.to_string();
    let status = status.to_string();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            stream.read_exact(&mut byte).unwrap();
            request.push(byte[0]);
        }
        let request = String::from_utf8(request).unwrap();
        let target = request.split_whitespace().nth(1).unwrap();
        let url = reqwest::Url::parse(&format!("http://localhost{target}")).unwrap();
        let query: HashMap<_, _> = url.query_pairs().into_owned().collect();
        let (path, key) = match platform.as_str() {
            "xboard" | "v2board-uniproxy" => {
                assert_eq!(query.get("node_type"), Some(&requested_type));
                ("/api/v1/server/UniProxy/config", "token")
            }
            "v2board" => {
                assert_eq!(query.get("node_type").map(String::as_str), Some("v2node"));
                ("/api/v2/server/config", "token")
            }
            "xiaov2board" | "xiaov2b" => ("/api/v2/server/config", "token"),
            "ppanel" => ("/v2/server/70", "secret_key"),
            "sspanel" | "sspanel-uim" => ("/mod_mu/nodes/70/info", "key"),
            _ => panic!("unknown fixture panel"),
        };
        assert_eq!(url.path(), path);
        assert_eq!(query.get(key).map(String::as_str), Some("fixture+&=#?"));
        if !matches!(platform.as_str(), "ppanel" | "sspanel" | "sspanel-uim") {
            assert_eq!(query.get("node_id").map(String::as_str), Some("70"));
        }
        let body = json!({"data": payload}).to_string();
        write!(
            stream,
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
    });
    let directory = std::env::temp_dir().join(format!("elise-panel-info-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&directory).unwrap();
    let config = directory.join("elise.conf");
    std::fs::write(&config, format!(
        "type={panel}\npanel_node_type={requested}\nnode_id=70\npanel_url=http://{address}\npanel_key=fixture+&=#?\n"
    )).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_elise"))
        .args(["panel-info", "--config"])
        .arg(config)
        .output()
        .unwrap();
    server.join().unwrap();
    std::fs::remove_dir_all(directory).unwrap();
    output
}

fn node(panel: &str, kind: &str, version: u32) -> Value {
    if panel == "ppanel" {
        let other = if kind == "vmess" { "vless" } else { "vmess" };
        json!({"protocols": [
            {"enable": false, "type": kind, "version": version, "port": 9999, "security": "tls"},
            {"enable": true, "type": other, "port": 8888, "security": "tls"},
            {"enable": true, "type": kind, "version": version, "port": 12345, "security": "tls"}
        ]})
    } else {
        json!({"type": kind, "protocol": kind, "server_type": kind, "version": version,
        "server_port": 12345, "tls": 1, "tls_settings": {
            "private_key": "private-fixture", "public_key": "public-fixture"
        }})
    }
}

#[test]
fn installer_can_inspect_each_panel_and_select_the_requested_protocol() {
    for panel in [
        "xboard",
        "v2board",
        "v2board-uniproxy",
        "xiaov2board",
        "ppanel",
        "sspanel",
        "xiaov2b",
        "sspanel-uim",
    ] {
        for kind in ["vless", "vmess", "anytls", "hysteria", "hysteria2"] {
            let output = inspect(
                panel,
                kind,
                node(panel, kind, if kind == "hysteria2" { 2 } else { 1 }),
                "200 OK",
            );
            assert!(
                output.status.success(),
                "{panel}/{kind}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let info: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(info["server_type"], kind, "{panel}/{kind}");
            assert_eq!(info["server_port"], 12345, "{panel}/{kind}");
            assert_eq!(info["tls"], 1, "{panel}/{kind}");
            let text = String::from_utf8(output.stdout).unwrap();
            assert!(
                !text.contains("fixture"),
                "panel-info leaked credentials or keys"
            );
        }
    }
}

#[test]
fn mismatched_and_disabled_panel_protocols_are_rejected() {
    for panel in ["xboard", "v2board", "xiaov2board", "ppanel", "sspanel"] {
        let payload = if panel == "ppanel" {
            json!({"protocols": [{"type": "anytls", "enable": false, "port": 12345}]})
        } else {
            node(panel, "vmess", 1)
        };
        let output = inspect(panel, "anytls", payload, "200 OK");
        assert!(
            !output.status.success(),
            "{panel} accepted a mismatched or disabled node"
        );
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn hysteria_version_two_selects_hysteria_two_on_each_panel() {
    for panel in ["xboard", "v2board", "xiaov2board", "ppanel", "sspanel"] {
        let output = inspect(panel, "hysteria", node(panel, "hysteria", 2), "200 OK");
        assert!(
            output.status.success(),
            "{panel}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let info: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(info["server_type"], "hysteria2", "{panel}");
    }
}

#[test]
fn sspanel_does_not_accept_a_failed_config_response() {
    let output = inspect(
        "sspanel",
        "anytls",
        node("sspanel", "anytls", 1),
        "403 Forbidden",
    );
    assert!(!output.status.success());
}

#[test]
fn v2board_rejects_http_200_business_failures_and_invalid_ports() {
    for payload in [
        json!({"status":"fail","message":"token is error"}),
        json!({"protocol":"vless"}),
        json!({"protocol":"vless","server_port":65536}),
    ] {
        assert!(!inspect("v2board", "vless", payload, "200 OK")
            .status
            .success());
    }
}

#[test]
fn uniproxy_hysteria_two_rejects_version_one_without_a_type_field() {
    let output = inspect(
        "v2board-uniproxy",
        "hysteria2",
        json!({"server_port":12345,"version":1}),
        "200 OK",
    );
    assert!(!output.status.success());
}
