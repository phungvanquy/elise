use crate::panel::types::{NodeInfo, NodeStatusReport, OnlineDeviceItem, TrafficItem, User};
use parking_lot::RwLock;
use reqwest::header::IF_NONE_MATCH;
use reqwest::Client;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;

pub(super) fn resolve_node_type(name: &str, version: Option<u32>) -> String {
    let name = name.to_ascii_lowercase();
    match name.as_str() {
        "v2ray" => "vmess".into(),
        "hysteria" | "hysteria1" | "hy" | "hy1" => {
            if version == Some(2) {
                "hysteria2".into()
            } else {
                "hysteria".into()
            }
        }
        "hy2" => "hysteria2".into(),
        _ => name,
    }
}

pub struct XboardClient {
    client: Client,
    base_url: String,
    token: String,
    node_type: Option<String>,
    v2board_uniproxy: bool,
    cached_nodes: RwLock<HashMap<u32, Arc<tokio::sync::Mutex<(Option<String>, Option<NodeInfo>)>>>>,
    cached_users: RwLock<HashMap<u32, Arc<tokio::sync::Mutex<(Option<String>, Vec<User>)>>>>,
}

impl XboardClient {
    pub fn new(base_url: String, token: String) -> Self {
        Self::new_with_node_type(base_url, token, None)
    }

    pub fn new_with_node_type(base_url: String, token: String, node_type: Option<String>) -> Self {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .user_agent("V2bX-Elise/1.0")
            .build()
            .unwrap_or_default();

        Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            token,
            node_type,
            v2board_uniproxy: false,
            cached_nodes: RwLock::new(HashMap::new()),
            cached_users: RwLock::new(HashMap::new()),
        }
    }

    /// The protocol-specific API of phungvanquy/v2board-new has no status endpoint.
    pub fn new_v2board_uniproxy(
        base_url: String,
        token: String,
        node_type: Option<String>,
    ) -> Self {
        let mut client = Self::new_with_node_type(base_url, token, node_type);
        client.v2board_uniproxy = true;
        client
    }

    pub(super) fn is_v2board_uniproxy(&self) -> bool {
        self.v2board_uniproxy
    }

    fn endpoint(&self, path: &str, node_id: u32) -> std::io::Result<String> {
        if self.v2board_uniproxy && self.node_type.is_none() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "v2board-uniproxy requires panel_node_type to select the protocol node table",
            ));
        }
        let mut url = reqwest::Url::parse(&format!("{}{}", self.base_url, path))
            .map_err(std::io::Error::other)?;
        {
            let mut query = url.query_pairs_mut();
            if let Some(node_type) = self.node_type.as_deref() {
                query.append_pair("node_type", node_type);
            }
            query.append_pair("node_id", &node_id.to_string());
            query.append_pair("token", &self.token);
        }
        Ok(url.to_string())
    }

    pub async fn get_node_info(
        &self,
        node_id: u32,
    ) -> Result<NodeInfo, Box<dyn std::error::Error + Send + Sync>> {
        let url = self.endpoint("/api/v1/server/UniProxy/config", node_id)?;
        let cache = self
            .cached_nodes
            .write()
            .entry(node_id)
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new((None, None))))
            .clone();
        let mut cache = cache.lock().await;
        let mut request = self.client.get(&url);
        if let Some(etag) = cache.0.as_ref() {
            request = request.header(IF_NONE_MATCH, etag);
        }
        let resp = request.send().await?;
        if resp.status() == reqwest::StatusCode::NOT_MODIFIED {
            if cache.0.is_some() {
                if let Some(info) = &cache.1 {
                    return Ok(info.clone());
                }
            }
            return Err("UniProxy returned 304 without a cached configuration".into());
        }
        let new_etag = resp
            .headers()
            .get("ETag")
            .and_then(|h| h.to_str().ok())
            .map(str::to_owned);

        if !resp.status().is_success() {
            return Err(format!("Xboard API returned status {}", resp.status()).into());
        }

        let val: Value = resp.json().await?;
        let data = val.get("data").unwrap_or(&val);
        let server_port = data
            .get("server_port")
            .and_then(Value::as_u64)
            .and_then(|p| u16::try_from(p).ok())
            .filter(|p| *p != 0)
            .ok_or("UniProxy configuration has no valid server_port")?;

        let version = data
            .get("version")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32);

        if self.v2board_uniproxy
            && self
                .node_type
                .as_deref()
                .is_some_and(|t| resolve_node_type(t, None) == "hysteria2")
            && version.is_some_and(|v| v != 2)
        {
            return Err("Panel Hysteria version does not match configured hysteria2".into());
        }

        let reported_type = data
            .get("server_type")
            .or_else(|| data.get("protocol"))
            .or_else(|| data.get("node_type"))
            .or_else(|| data.get("type"))
            .and_then(|v| v.as_str());
        if let (Some(expected), Some(reported)) = (self.node_type.as_deref(), reported_type) {
            if resolve_node_type(expected, version) != resolve_node_type(reported, version) {
                return Err(format!(
                    "Panel node type {reported} does not match configured {expected}"
                )
                .into());
            }
        }
        let node_type = self
            .node_type
            .as_deref()
            .unwrap_or(reported_type.unwrap_or("vless"));
        let node_type = resolve_node_type(node_type, version);

        let mut info = NodeInfo {
            base_config: data
                .get("base_config")
                .filter(|v| !v.is_null())
                .cloned()
                .map(serde_json::from_value)
                .transpose()?,
            id: node_id,
            node_type,
            server_port,
            host: data.get("host").and_then(|v| v.as_str()).map(String::from),
            path: data.get("path").and_then(|v| v.as_str()).map(|p| {
                if p.is_empty() || p.starts_with('/') {
                    p.to_string()
                } else {
                    format!("/{p}")
                }
            }),
            server_name: data
                .get("server_name")
                .and_then(|v| v.as_str())
                .map(String::from),
            tls: data.get("tls").and_then(|v| v.as_u64()).map(|v| v as u8),
            network: data
                .get("network")
                .or_else(|| data.get("transport"))
                .and_then(|v| v.as_str())
                .map(String::from),
            cipher: data
                .get("cipher")
                .and_then(|v| v.as_str())
                .map(String::from),
            plugin: data
                .get("plugin")
                .and_then(|v| v.as_str())
                .map(String::from),
            plugin_opts: data.get("plugin_opts").cloned(),
            ignore_client_bandwidth: super::types::ignore_client_bandwidth(data),
            up_mbps: data
                .get("up_mbps")
                .and_then(|v| v.as_u64())
                .map(|v| v as u32),
            down_mbps: data
                .get("down_mbps")
                .and_then(|v| v.as_u64())
                .map(|v| v as u32),
            server_key: data
                .get("server_key")
                .and_then(|v| v.as_str())
                .map(String::from),
            short_ids: None,
            public_key: data
                .get("public_key")
                .and_then(|v| v.as_str())
                .map(String::from),
            routes: data.get("routes").and_then(|v| v.as_array()).cloned(),
            custom_outbounds: data
                .get("custom_outbounds")
                .and_then(|v| v.as_array())
                .cloned(),
            custom_routes: data
                .get("custom_routes")
                .and_then(|v| v.as_array())
                .cloned(),
            cert_config: data.get("cert_config").cloned(),
            network_settings: data
                .get("networkSettings")
                .or_else(|| data.get("network_settings"))
                .or_else(|| data.get("transportSettings"))
                .or_else(|| data.get("transport_settings"))
                .or_else(|| data.get("wsSettings"))
                .or_else(|| data.get("tcpSettings"))
                .or_else(|| data.get("grpcSettings"))
                .or_else(|| data.get("httpSettings"))
                .or_else(|| data.get("xhttpSettings"))
                .or_else(|| data.get("splithttpSettings"))
                .or_else(|| data.get("httpupgradeSettings"))
                .cloned(),
            obfs: data.get("obfs").and_then(|v| v.as_str()).map(String::from),
            obfs_password: data
                .get("obfs-password")
                .or_else(|| data.get("obfs_password"))
                .or_else(|| data.get("obfsPassword"))
                .and_then(|v| v.as_str())
                .map(String::from),
            tls_settings: data
                .get("tls_settings")
                .or_else(|| data.get("tlsSettings"))
                .cloned(),
            multiplex: data.get("multiplex").cloned(),
            utls: data.get("utls").cloned(),
            listen_ip: data
                .get("listen_ip")
                .and_then(|v| v.as_str())
                .map(String::from),
            rate: data.get("rate").and_then(|v| v.as_f64()),
            flow: data.get("flow").and_then(|v| v.as_str()).map(String::from),
            encryption: data
                .get("encryption")
                .and_then(|v| v.as_str())
                .map(String::from),
            decryption: data
                .get("decryption")
                .and_then(|v| v.as_str())
                .map(String::from),
            encryption_settings: data
                .get("encryption_settings")
                .or_else(|| data.get("encryptionSettings"))
                .cloned(),
            padding_scheme: data
                .get("padding_scheme")
                .or_else(|| data.get("paddingScheme"))
                .cloned(),
            version: data
                .get("version")
                .and_then(|v| v.as_u64())
                .map(|v| v as u32),
            congestion_control: data
                .get("congestion_control")
                .or_else(|| data.get("congestion-controller"))
                .and_then(|v| v.as_str())
                .map(String::from),
            alpn: data.get("alpn").cloned(),
            udp_relay_mode: data
                .get("udp_relay_mode")
                .or_else(|| data.get("udp-relay-mode"))
                .and_then(|v| v.as_str())
                .map(String::from),
            auth_timeout: data
                .get("auth_timeout")
                .and_then(|v| v.as_str())
                .map(String::from),
            heartbeat: data
                .get("heartbeat")
                .and_then(|v| v.as_str())
                .map(String::from),
            zero_rtt_handshake: data.get("zero_rtt_handshake").and_then(|v| v.as_bool()),
            ports: data
                .get("ports")
                .or_else(|| data.get("server_ports"))
                .and_then(|v| v.as_str())
                .map(String::from),
            hop_interval: data
                .get("hop_interval")
                .or_else(|| data.get("hopInterval"))
                .and_then(|v| v.as_u64())
                .map(|v| v as u32),
            traffic_pattern: data
                .get("traffic_pattern")
                .or_else(|| data.get("trafficPattern"))
                .and_then(|v| v.as_str())
                .map(String::from),
            transport: data
                .get("transport")
                .or_else(|| data.get("network"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_ascii_uppercase()),
            ..Default::default()
        };

        if let Some(sids) = data.get("short_ids").and_then(|v| v.as_array()) {
            let ids: Vec<String> = sids
                .iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect();
            info.short_ids = Some(ids);
        }

        *cache = (new_etag, Some(info.clone()));
        Ok(info)
    }

    pub async fn get_users(
        &self,
        node_id: u32,
    ) -> Result<Vec<User>, Box<dyn std::error::Error + Send + Sync>> {
        let url = self.endpoint("/api/v1/server/UniProxy/user", node_id)?;

        let cache = self
            .cached_users
            .write()
            .entry(node_id)
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new((None, Vec::new()))))
            .clone();
        let mut cache = cache.lock().await;
        let mut req = self.client.get(&url);
        if let Some(etag) = cache.0.as_ref() {
            req = req.header(IF_NONE_MATCH, etag);
        }

        let resp = req.send().await?;

        if resp.status() == reqwest::StatusCode::NOT_MODIFIED {
            if cache.0.is_none() {
                return Err("Xboard returned 304 without a cached ETag".into());
            }
            return Ok(cache.1.clone());
        }

        if !resp.status().is_success() {
            return Err(format!("Xboard API user sync returned status {}", resp.status()).into());
        }

        let new_etag = resp
            .headers()
            .get("ETag")
            .and_then(|h| h.to_str().ok())
            .map(str::to_owned);

        let val: Value = resp.json().await?;
        let user_list = val
            .get("users")
            .or_else(|| val.get("data"))
            .and_then(|v| v.as_array());
        if user_list.is_none() {
            return Err("Xboard user response has no users array".into());
        }

        let mut users = Vec::new();
        if let Some(arr) = user_list {
            for item in arr {
                let id = item.get("id").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                let uuid = item
                    .get("uuid")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();
                let speed_limit = crate::panel::types::speed_limit_bps(item.get("speed_limit"))?;
                let device_limit = item
                    .get("device_limit")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as u32;

                users.push(User {
                    id,
                    uuid,
                    speed_limit,
                    device_limit,
                    password: item
                        .get("password")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    method: item
                        .get("method")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    port: item.get("port").and_then(|v| v.as_u64()).map(|v| v as u16),
                    flow: item.get("flow").and_then(|v| v.as_str()).map(String::from),
                });
            }
        }

        *cache = (new_etag, users.clone());
        Ok(users)
    }

    pub async fn report_traffic(
        &self,
        node_id: u32,
        traffic: Vec<TrafficItem>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if traffic.is_empty() && !self.v2board_uniproxy {
            return Ok(());
        }

        let url = self.endpoint("/api/v1/server/UniProxy/push", node_id)?;

        let mut payload: HashMap<String, [u64; 2]> = HashMap::with_capacity(traffic.len());
        for item in traffic {
            payload.insert(item.user_id.to_string(), [item.u, item.d]);
        }

        let resp = self.client.post(&url).json(&payload).send().await?;

        if !resp.status().is_success() {
            return Err(format!(
                "Xboard API traffic report returned status {}",
                resp.status()
            )
            .into());
        }
        Ok(())
    }

    pub async fn report_online_devices(
        &self,
        node_id: u32,
        devices: Vec<OnlineDeviceItem>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if devices.is_empty() {
            return Ok(());
        }

        let url = self.endpoint("/api/v1/server/UniProxy/alive", node_id)?;

        let mut payload: HashMap<String, Vec<String>> = HashMap::with_capacity(devices.len());
        for item in devices {
            payload.insert(item.user_id.to_string(), item.ips);
        }

        self.client
            .post(&url)
            .json(&payload)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    pub async fn get_user_alivelist(
        &self,
        node_id: u32,
    ) -> Result<HashMap<u32, u32>, Box<dyn std::error::Error + Send + Sync>> {
        let url = self.endpoint("/api/v1/server/UniProxy/alivelist", node_id)?;
        let resp = self.client.get(&url).send().await?;

        if !resp.status().is_success() {
            return Err(format!("Xboard API alive list returned status {}", resp.status()).into());
        }

        let val: Value = resp.json().await?;

        let mut res = HashMap::new();
        let map_obj = val
            .get("alive")
            .or_else(|| val.get("data").and_then(|v| v.get("alive").or(Some(v))))
            .or(Some(&val))
            .and_then(|v| v.as_object());
        if let Some(map) = map_obj {
            for (k, v) in map {
                if let (Ok(uid), Some(cnt)) = (k.parse::<u32>(), v.as_u64()) {
                    res.insert(uid, cnt as u32);
                }
            }
        }
        Ok(res)
    }

    pub async fn report_node_status(
        &self,
        node_id: u32,
        status: &NodeStatusReport,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if self.v2board_uniproxy {
            return Ok(());
        }
        let v2_url = self.endpoint("/api/v2/server/report", node_id)?;

        let v2_payload = serde_json::json!({
            "status": {
                "cpu": status.cpu,
                "mem": {
                    "total": status.mem_total,
                    "used": status.mem_used,
                },
                "swap": {
                    "total": status.swap_total,
                    "used": status.swap_used,
                },
                "disk": {
                    "total": status.disk_total,
                    "used": status.disk_used,
                },
                "kernel_status": status.kernel_status,
            },
            "metrics": {
                "uptime": status.uptime,
                "goroutines": status.tasks_count,
                "active_connections": status.active_connections,
                "total_connections": status.total_connections,
                "total_users": status.total_users,
                "active_users": status.active_users,
                "inbound_speed": status.in_speed,
                "outbound_speed": status.out_speed,
                "kernel_status": status.kernel_status,
            }
        });

        match self.client.post(&v2_url).json(&v2_payload).send().await {
            Ok(resp) if resp.status().is_success() => return Ok(()),
            Ok(resp) if resp.status() == reqwest::StatusCode::NOT_FOUND => {}
            Err(e) => {
                tracing::debug!("Xboard V2 server report request failed: {:?}", e);
            }
            Ok(resp) => {
                tracing::debug!("Xboard V2 server report returned status: {}", resp.status());
            }
        }

        let v1_url = self.endpoint("/api/v1/server/UniProxy/status", node_id)?;
        let v1_payload = serde_json::json!({
            "cpu": status.cpu,
            "mem": {
                "total": status.mem_total,
                "used": status.mem_used,
            },
            "swap": {
                "total": status.swap_total,
                "used": status.swap_used,
            },
            "disk": {
                "total": status.disk_total,
                "used": status.disk_used,
            }
        });

        let _ = self.client.post(&v1_url).json(&v1_payload).send().await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn v2bx_anytls_and_hysteria_resolve_panel_types_and_versions() {
        for (configured, reported, version, expected) in [
            ("anytls", "AnyTLS", None, Some("anytls")),
            ("hysteria", "hysteria1", Some(1), Some("hysteria")),
            ("hysteria", "hy1", None, Some("hysteria")),
            ("hysteria", "hysteria", Some(2), Some("hysteria2")),
            ("hysteria2", "hysteria", Some(2), Some("hysteria2")),
            ("hysteria2", "hy2", Some(2), Some("hysteria2")),
            ("hysteria2", "hysteria", Some(1), None),
            ("anytls", "vless", None, None),
        ] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let client = XboardClient::new_with_node_type(
                format!("http://{}", listener.local_addr().unwrap()),
                "key+value".into(),
                Some(configured.into()),
            );
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    request.push(stream.read_u8().await.unwrap());
                }
                let request = String::from_utf8(request).unwrap();
                let target = request.split_whitespace().nth(1).unwrap();
                let url = reqwest::Url::parse(&format!("http://localhost{target}")).unwrap();
                assert_eq!(url.path(), "/api/v1/server/UniProxy/config");
                let query: HashMap<_, _> = url.query_pairs().into_owned().collect();
                assert_eq!(query.get("node_type").map(String::as_str), Some(configured));
                assert_eq!(query.get("node_id").map(String::as_str), Some("9"));
                let body = serde_json::json!({"data": {
                    "server_type": reported, "version": version, "server_port": 12345,
                    "tls": 1, "up_mbps": 100, "down_mbps": 200, "ignore_client_bandwidth": true,
                    "obfs": "salamander", "obfs_password": "fixture",
                    "padding_scheme": "stop=8"
                }})
                .to_string();
                stream
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
            });
            let result = client.get_node_info(9).await;
            if let Some(expected) = expected {
                let info = result.unwrap();
                assert_eq!(info.node_type, expected);
                assert_eq!(info.version, version);
                assert_eq!(info.tls, Some(1));
                assert_eq!(info.up_mbps, Some(100));
                assert_eq!(info.down_mbps, Some(200));
                assert!(info.ignore_client_bandwidth);
                assert_eq!(info.obfs_password.as_deref(), Some("fixture"));
                assert_eq!(info.padding_scheme, Some(serde_json::json!("stop=8")));
                assert!(crate::proxy::registry::create_inbound(&info.node_type).is_ok());
            } else {
                assert!(result.unwrap_err().to_string().contains("does not match"));
            }
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn v2bx_vmess_uses_typed_uniproxy_requests_and_alive_map() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = XboardClient::new_with_node_type(
            format!("http://{}", listener.local_addr().unwrap()),
            "key+value".into(),
            Some("vmess".into()),
        );
        let server = tokio::spawn(async move {
            for (path, body) in [
                ("config", r#"{"server_port":12345,"network":"tcp"}"#),
                ("user", r#"{"users":[{"id":7,"uuid":"test-user"}]}"#),
                ("alivelist", r#"{"alive":{"7":2}}"#),
                ("push", "{}"),
            ] {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    request.push(stream.read_u8().await.unwrap());
                }
                let request = String::from_utf8(request).unwrap();
                assert!(request
                    .to_ascii_lowercase()
                    .contains("user-agent: v2bx-elise/1.0\r\n"));
                let target = request.split_whitespace().nth(1).unwrap();
                let url = reqwest::Url::parse(&format!("http://localhost{target}")).unwrap();
                assert!(url.path().ends_with(path));
                let query: HashMap<_, _> = url.query_pairs().into_owned().collect();
                assert_eq!(query.get("node_type").map(String::as_str), Some("vmess"));
                assert_eq!(query.get("node_id").map(String::as_str), Some("9"));
                assert_eq!(query.get("token").map(String::as_str), Some("key+value"));
                stream
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
            }
        });
        assert_eq!(client.get_node_info(9).await.unwrap().node_type, "vmess");
        assert_eq!(client.get_users(9).await.unwrap()[0].id, 7);
        assert_eq!(
            client.get_user_alivelist(9).await.unwrap().get(&7),
            Some(&2)
        );
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
        server.await.unwrap();
    }

    #[tokio::test]
    async fn node_caches_and_etags_are_isolated_and_commit_after_parse() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = XboardClient::new(
            format!("http://{}", listener.local_addr().unwrap()),
            "fixture".into(),
        );
        let server = tokio::spawn(async move {
            let mut hits = HashMap::new();
            for _ in 0..8 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut bytes = Vec::new();
                while !bytes.ends_with(b"\r\n\r\n") {
                    bytes.push(stream.read_u8().await.unwrap());
                }
                let request = String::from_utf8(bytes).unwrap().to_lowercase();
                let node = if request.contains("node_id=1&") { 1 } else { 2 };
                let hit = hits.entry(node).or_insert(0);
                *hit += 1;
                let (status, etag, body) = if *hit == 1 {
                    assert!(!request.contains("if-none-match:"));
                    (
                        "200 OK",
                        "ETag: same\r\n",
                        format!("{{\"users\":[{{\"id\":{node},\"uuid\":\"user-{node}\"}}]}}"),
                    )
                } else if node == 1 && *hit == 3 {
                    assert!(request.contains("if-none-match: same"));
                    ("200 OK", "ETag: invalid-new\r\n", "{".into())
                } else if node == 1 && *hit == 5 {
                    assert!(request.contains("if-none-match: same"));
                    ("200 OK", "", "{\"users\":[]}".into())
                } else if node == 1 && *hit == 6 {
                    assert!(!request.contains("if-none-match:"));
                    ("304 Not Modified", "", "".into())
                } else {
                    assert!(request.contains("if-none-match: same"));
                    ("304 Not Modified", "", "".into())
                };
                stream.write_all(format!("HTTP/1.1 {status}\r\n{etag}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await.unwrap();
            }
        });
        let (a, b) = tokio::join!(client.get_users(1), client.get_users(2));
        assert_eq!(a.unwrap()[0].id, 1);
        assert_eq!(b.unwrap()[0].id, 2);
        let (a, b) = tokio::join!(client.get_users(1), client.get_users(2));
        assert_eq!(a.unwrap()[0].id, 1);
        assert_eq!(b.unwrap()[0].id, 2);
        assert!(client.get_users(1).await.is_err());
        assert_eq!(client.get_users(1).await.unwrap()[0].id, 1);
        assert!(client.get_users(1).await.unwrap().is_empty());
        assert!(client.get_users(1).await.is_err());
        server.await.unwrap();
    }
}
