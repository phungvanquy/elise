use crate::config::node::NodeConfig;
use crate::config::routes::RoutesConfig;
use crate::config::GlobalConfig;
use crate::dns::RuleBasedDNSManager;
use crate::limiter::{ConnectionLimiter, DeviceLimiter, IpUserCache, RateLimiter};
use crate::observability::{AuditLogger, ClickHouseLogger};
use crate::proxy::node::NodeRunner;
use crate::proxy::router::{OutboundDialer, Router};
use crate::security::{AttackDefenseManager, AuditController, TLSManager};
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::broadcast;
use tokio::task::JoinSet;
use tracing::info;

pub struct MasterServer {
    global_config: Arc<GlobalConfig>,
    shutdown_tx: broadcast::Sender<()>,
}

impl MasterServer {
    pub fn new(global_config: GlobalConfig) -> Self {
        let (shutdown_tx, _) = broadcast::channel(16);
        Self {
            global_config: Arc::new(global_config),
            shutdown_tx,
        }
    }

    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!(
            "Elise MasterServer initializing with {} configured node(s)",
            self.global_config.node_ids.len()
        );
        if self.global_config.node_ids.is_empty() {
            return Err("No nodes are configured".into());
        }

        let panel_client = crate::panel::create_panel_client_with_node_type(
            &self.global_config.panel_type,
            &self.global_config.api_host,
            &self.global_config.api_key,
            self.global_config.panel_node_type.as_deref(),
        );

        let dns_manager = Arc::new(RuleBasedDNSManager::new(
            &self.global_config.dns_strategy,
            self.global_config.dns_cache_time,
            self.global_config.default_dns.as_deref(),
            self.global_config.dns_file.clone(),
        ));
        let dns_resolver = dns_manager.resolver();

        let out_v4: Option<IpAddr> = self
            .global_config
            .out_ip_ipv4
            .as_deref()
            .and_then(|s| s.parse().ok());
        let out_v6: Option<IpAddr> = self
            .global_config
            .out_ip_ipv6
            .as_deref()
            .and_then(|s| s.parse().ok());

        let dialer = Arc::new(OutboundDialer::new(
            dns_resolver.clone(),
            out_v4,
            out_v6,
            self.global_config.auto_out_ip,
        ));

        let geo_engine = Arc::new(crate::geo::GeoEngine::new(
            self.global_config.geoip_file.clone(),
            self.global_config.geosite_file.clone(),
        ));

        let routes_config = RoutesConfig::load_from_file(&self.global_config.routes_file);
        let router = Arc::new(Router::new(routes_config, dialer, geo_engine.clone()));

        let rate_limiter = Arc::new(RateLimiter::new());
        let conn_limiter = Arc::new(ConnectionLimiter::new());
        let device_limiter = Arc::new(DeviceLimiter::new_with_redis(
            self.global_config.device_limit_window,
            self.global_config.device_limit_prefix_ipv4,
            self.global_config.device_limit_prefix_ipv6,
            self.global_config.get_redis_url(),
            self.global_config.conn_limit_expiry,
            self.global_config.redis_timeout_ms,
        ));
        let ip_user_cache = Arc::new(IpUserCache::new(
            self.global_config.ip_user_cache_time,
            self.global_config.ip_user_cache_save_enable,
            &self.global_config.ip_user_cache_save_dir,
        ));

        let audit = Arc::new(AuditController::new_with_options(
            &self.global_config.block_list,
            &self.global_config.white_list,
            geo_engine,
            self.global_config.forbidden_ports.clone(),
            self.global_config.ban_private_ip,
            self.global_config.forbidden_bit_torrent,
        ));

        router.dialer().set_audit(audit.clone());

        let defense = Arc::new(AttackDefenseManager::default());

        let tls_manager = Arc::new(TLSManager::new(
            self.global_config.auto_tls,
            self.global_config.fake_sni.clone(),
        ));

        let audit_logger = Arc::new(AuditLogger::new(
            self.global_config.audit_log_file.as_deref(),
        ));
        let clickhouse_logger = Arc::new(ClickHouseLogger::new(
            self.global_config.clickhouse_enabled,
            self.global_config.clickhouse_addr.clone(),
            self.global_config.clickhouse_db.clone(),
            self.global_config.clickhouse_table.clone(),
            self.global_config.clickhouse_user.clone(),
            self.global_config.clickhouse_password.clone(),
        ));

        let nodes_dir = self
            .global_config
            .nodes_dir
            .clone()
            .unwrap_or_else(find_nodes_dir);
        let mut node_handles = JoinSet::new();

        for (idx, &node_id) in self.global_config.node_ids.iter().enumerate() {
            let mut node_cfg = NodeConfig::load_for_node(&nodes_dir, node_id);
            node_cfg.inherit_from_global(&self.global_config);
            if node_cfg.listen_addr.is_none() {
                node_cfg.listen_addr = Some(self.global_config.get_listen_ip_for_node(idx, None));
            }
            let runner = Arc::new(NodeRunner::new(
                node_id,
                panel_client.clone(),
                self.global_config.clone(),
                node_cfg,
                router.clone(),
                rate_limiter.clone(),
                conn_limiter.clone(),
                device_limiter.clone(),
                audit.clone(),
                defense.clone(),
                tls_manager.clone(),
                audit_logger.clone(),
                clickhouse_logger.clone(),
                ip_user_cache.clone(),
            ));

            let shutdown_sub = self.shutdown_tx.subscribe();
            node_handles.spawn(async move {
                runner.run(shutdown_sub).await;
                node_id
            });
        }

        info!(
            "All {} node runner(s) started successfully",
            node_handles.len()
        );

        let pprof_handle = crate::observability::PprofServer::start(
            &self.global_config.pprof_addr,
            self.shutdown_tx.subscribe(),
        );

        let mut shutdown = self.shutdown_tx.subscribe();
        #[cfg(unix)]
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        let failure = tokio::select! {
            biased;
            _ = shutdown.recv() => None,
            _ = tokio::signal::ctrl_c() => { info!("SIGINT received, shutting down Elise MasterServer..."); None },
            _ = async {
                #[cfg(unix)]
                terminate.recv().await;
                #[cfg(not(unix))]
                std::future::pending::<()>().await;
            } => { info!("SIGTERM received, shutting down Elise MasterServer..."); None },
            result = node_handles.join_next() => Some(match result {
                Some(Ok(node_id)) => format!("Node {node_id} stopped unexpectedly"),
                Some(Err(e)) => format!("Node task failed: {e}"),
                None => "All node runners stopped unexpectedly".to_string(),
            }),
        };

        let _ = self.shutdown_tx.send(());
        while let Some(result) = node_handles.join_next().await {
            if let Err(e) = result {
                tracing::error!(error = %e, "Node task failed during shutdown");
            }
        }

        if let Some(h) = pprof_handle {
            let _ = h.await;
        }

        ip_user_cache.save_to_disk();

        if let Some(message) = failure {
            return Err(message.into());
        }
        info!("Elise MasterServer terminated cleanly.");
        Ok(())
    }

    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(());
    }
}

fn find_nodes_dir() -> std::path::PathBuf {
    let standard = std::path::PathBuf::from("/etc/elise/nodes");
    if standard.exists() || standard.parent().map(|p| p.exists()).unwrap_or(false) {
        return standard;
    }
    let local = std::path::PathBuf::from("./nodes");
    if local.exists() {
        return local;
    }
    standard
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn master_exits_when_its_node_cannot_start() {
        for case in ["panel_error", "bind_error"] {
            let occupied = if case == "bind_error" {
                Some(tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap())
            } else {
                None
            };
            let panel = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let panel_addr = panel.local_addr().unwrap();
            let port = occupied
                .as_ref()
                .map(|listener| listener.local_addr().unwrap().port())
                .unwrap_or(12345);
            let panel_task = tokio::spawn(async move {
                let (mut stream, _) = panel.accept().await.unwrap();
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    request.push(stream.read_u8().await.unwrap());
                }
                let (status, body) = if case == "panel_error" {
                    ("403 Forbidden", "{}".to_string())
                } else {
                    (
                        "200 OK",
                        format!(
                            r#"{{"server_type":"vless","server_port":{port},"network":"tcp","tls":0}}"#
                        ),
                    )
                };
                stream
                    .write_all(
                        format!(
                            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
            });

            let dir =
                std::env::temp_dir().join(format!("elise-master-test-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(&dir).unwrap();
            let config = GlobalConfig {
                api_host: format!("http://{panel_addr}"),
                api_key: "fixture".into(),
                panel_node_type: Some("vless".into()),
                node_ids: vec![7],
                listen_addr: "127.0.0.1".into(),
                nodes_dir: Some(dir.join("nodes")),
                ip_user_cache_save_dir: dir.clone(),
                pprof_addr: "off".into(),
                auto_tls: false,
                ..GlobalConfig::default()
            };

            let result = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                MasterServer::new(config).run(),
            )
            .await
            .expect("master must exit when its only node fails");
            assert!(result.is_err(), "{case}: master exited successfully");
            panel_task.await.unwrap();
            drop(occupied);
            std::fs::remove_dir_all(dir).unwrap();
        }
    }
}
