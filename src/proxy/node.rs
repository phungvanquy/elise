use crate::config::node::NodeConfig;
use crate::config::routes::RoutesConfig;
use crate::config::GlobalConfig;
use crate::limiter::{ConnectionLimiter, DeviceLimiter, IpUserCache, RateLimiter};
use crate::observability::{AuditLogger, ClickHouseLogger};
use crate::panel::types::{NodeInfo, OnlineDeviceItem, TrafficItem, User};
use crate::panel::PanelClient;
use crate::protocol::{Inbound, InboundContext, TrafficCallback};
use crate::proxy::registry::create_inbound;
use crate::proxy::router::Router;
use crate::security::{AttackDefenseManager, AuditController, TLSManager};
use crate::stats::SystemCollector;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;
use tracing::{error, info, warn};

pub struct NodeRunner {
    pub node_id: u32,
    panel_client: Arc<dyn PanelClient>,
    global_config: Arc<GlobalConfig>,
    node_config: Arc<parking_lot::RwLock<NodeConfig>>,
    router: Arc<Router>,
    node_info: Mutex<Option<NodeInfo>>,
    rate_limiter: Arc<RateLimiter>,
    conn_limiter: Arc<ConnectionLimiter>,
    device_limiter: Arc<DeviceLimiter>,
    audit: Arc<AuditController>,
    defense: Arc<AttackDefenseManager>,
    tls_manager: Arc<TLSManager>,
    audit_logger: Arc<AuditLogger>,
    clickhouse_logger: Arc<ClickHouseLogger>,
    pub ip_user_cache: Arc<IpUserCache>,
    traffic_buffer: Arc<Mutex<HashMap<u32, (u64, u64)>>>,
    report_lock: tokio::sync::Mutex<()>,
    reported_online: Mutex<HashMap<u32, Vec<String>>>,
    traffic_path: std::path::PathBuf,
    traffic_file_lock: Mutex<Option<Arc<std::fs::File>>>,
    traffic_io_lock: Arc<Mutex<()>>,
    sys_collector: Arc<SystemCollector>,
    synced_user_count: Arc<AtomicU32>,
    user_sync_state: Mutex<(bool, u32)>,
    readiness: tokio::sync::watch::Sender<bool>,
}

struct ActiveInbound {
    inbound: Arc<dyn Inbound>,
    stop: broadcast::Sender<()>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl ActiveInbound {
    async fn stop(&mut self) {
        let _ = self.stop.send(());
        if self.task.is_finished() {
            return;
        }
        if tokio::time::timeout(Duration::from_secs(32), &mut self.task)
            .await
            .is_err()
        {
            self.task.abort();
            let _ = (&mut self.task).await;
        }
    }
}

impl Drop for ActiveInbound {
    fn drop(&mut self) {
        let _ = self.stop.send(());
        self.task.abort();
    }
}

impl NodeRunner {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        node_id: u32,
        panel_client: Arc<dyn PanelClient>,
        global_config: Arc<GlobalConfig>,
        node_config: NodeConfig,
        router: Arc<Router>,
        rate_limiter: Arc<RateLimiter>,
        conn_limiter: Arc<ConnectionLimiter>,
        device_limiter: Arc<DeviceLimiter>,
        audit: Arc<AuditController>,
        defense: Arc<AttackDefenseManager>,
        tls_manager: Arc<TLSManager>,
        audit_logger: Arc<AuditLogger>,
        clickhouse_logger: Arc<ClickHouseLogger>,
        ip_user_cache: Arc<IpUserCache>,
    ) -> Self {
        if global_config.user_speed_limit > 0 || global_config.node_speed_limit > 0 {
            warn!("Local user_speed_limit/node_speed_limit ignored; only panel user plan limits apply");
        }
        use sha2::Digest;
        let panel = format!(
            "{}:{}",
            global_config.panel_type.to_lowercase(),
            global_config.api_host.trim_end_matches('/')
        );
        let identity = format!("{:x}", sha2::Sha256::digest(panel.as_bytes()));
        let traffic_path = global_config
            .ip_user_cache_save_dir
            .join("traffic")
            .join(format!("{identity}-{node_id}.json"));
        Self {
            node_id,
            panel_client,
            global_config,
            node_config: Arc::new(parking_lot::RwLock::new(node_config)),
            router: Arc::new(router.fork()),
            node_info: Mutex::new(None),
            rate_limiter,
            conn_limiter,
            device_limiter,
            audit,
            defense,
            tls_manager,
            audit_logger,
            clickhouse_logger,
            ip_user_cache,
            traffic_buffer: Arc::new(Mutex::new(HashMap::new())),
            report_lock: tokio::sync::Mutex::new(()),
            reported_online: Mutex::new(HashMap::new()),
            traffic_path,
            traffic_file_lock: Mutex::new(None),
            traffic_io_lock: Arc::new(Mutex::new(())),
            sys_collector: Arc::new(SystemCollector::new()),
            synced_user_count: Arc::new(AtomicU32::new(0)),
            user_sync_state: Mutex::new((false, 0)),
            readiness: tokio::sync::watch::channel(false).0,
        }
    }

    fn restore_pending(&self) -> std::io::Result<()> {
        let parent = self.traffic_path.parent().unwrap();
        std::fs::create_dir_all(parent)?;
        let lock = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(self.traffic_path.with_extension("lock"))?;
        lock.try_lock().map_err(std::io::Error::other)?;
        let pending = match std::fs::read(&self.traffic_path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(std::io::Error::other)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => HashMap::new(),
            Err(e) => return Err(e),
        };
        *self.traffic_buffer.lock() = pending;
        *self.traffic_file_lock.lock() = Some(Arc::new(lock));
        Ok(())
    }

    async fn save_pending(&self) -> std::io::Result<()> {
        let Some(file_lock) = self.traffic_file_lock.lock().clone() else {
            return Ok(());
        };
        let path = self.traffic_path.clone();
        let buffer = self.traffic_buffer.clone();
        let io_lock = self.traffic_io_lock.clone();
        tokio::task::spawn_blocking(move || {
            use std::io::Write;
            let _file_lock = file_lock;

            let _guard = io_lock.lock();
            let pending = buffer.lock().clone();
            let bytes = serde_json::to_vec(&pending).map_err(std::io::Error::other)?;
            let temporary = path.with_extension("tmp");
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&temporary)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            drop(file);
            std::fs::rename(&temporary, &path)?;
            #[cfg(unix)]
            std::fs::File::open(path.parent().unwrap())?.sync_all()?;
            Ok::<_, std::io::Error>(())
        })
        .await
        .map_err(std::io::Error::other)?
    }

    pub async fn run(self: Arc<Self>, mut shutdown_rx: broadcast::Receiver<()>) {
        info!("Starting NodeRunner for Node ID {}", self.node_id);
        if let Err(e) = self.restore_pending() {
            error!(node_id = self.node_id, error = %e, "Cannot open pending traffic store; node not started");
            return;
        }

        let mut node_info = match self.panel_client.get_node_info(self.node_id).await {
            Ok(info) => info,
            Err(e) => {
                error!(
                    "Node {}: Failed to fetch node info from panel: {:?}",
                    self.node_id, e
                );
                return;
            }
        };

        let nodes_dir = self.global_config.nodes_dir.clone().unwrap_or_else(|| {
            if std::path::Path::new("/etc/elise/nodes").exists()
                || std::path::Path::new("/etc/elise").exists()
            {
                std::path::PathBuf::from("/etc/elise/nodes")
            } else {
                std::path::PathBuf::from("./nodes")
            }
        });

        if self.node_config.read().cert_mode.as_deref() == Some("http")
            || self.node_config.read().cert_mode.as_deref() == Some("acme")
        {
            let mut cfg_clone = self.node_config.read().clone();
            let certificate = tokio::select! {
                biased;
                _ = shutdown_rx.recv() => return,
                result = crate::security::ensure_acme_certificate(&mut cfg_clone, &node_info) => result,
            };
            match certificate {
                Ok(acme_cfg) => {
                    *self.node_config.write() = cfg_clone;
                    info!(
                        node_id = self.node_id,
                        domain = %acme_cfg.domain,
                        cert_file = %acme_cfg.cert_file.display(),
                        key_file = %acme_cfg.key_file.display(),
                        "ACME TLS certificate is ready for node"
                    );
                }
                Err(e) => {
                    error!(
                        node_id = self.node_id,
                        error = %e,
                        "Failed to obtain a usable ACME certificate; node not started"
                    );
                    return;
                }
            }
        }

        if let Err(e) = self
            .node_config
            .read()
            .prepare_node_info(&nodes_dir, &mut node_info)
        {
            error!(node_id = self.node_id, error = %e, "Invalid node security configuration");
            return;
        }

        if let Err(e) = self
            .node_config
            .read()
            .save_node_conf(&nodes_dir, &node_info)
        {
            warn!(
                "Node {}: Failed to save node config to {}: {}",
                self.node_id,
                nodes_dir.display(),
                e
            );
        } else {
            info!(
                "Node {}: Node config updated at {}/node_{}.conf",
                self.node_id,
                nodes_dir.display(),
                self.node_id
            );
        }

        self.apply_node_routes(&node_info);

        let (certificate_updates, certificate_rx) = tokio::sync::watch::channel(());
        let inbound_task = {
            let runner = self.clone();
            let shutdown_sub = shutdown_rx.resubscribe();
            let node_info_clone = node_info.clone();
            tokio::spawn(async move {
                runner
                    .run_inbound(node_info_clone, shutdown_sub, certificate_rx)
                    .await;
            })
        };

        let acme_task = {
            let runner = self.clone();
            let mut shutdown_sub = shutdown_rx.resubscribe();
            let node_info_snapshot = node_info.clone();
            tokio::spawn(async move {
                if runner.node_config.read().cert_mode.as_deref() != Some("http")
                    && runner.node_config.read().cert_mode.as_deref() != Some("acme")
                {
                    return;
                }
                let mut ticker = tokio::time::interval(Duration::from_secs(12 * 3600));
                ticker.tick().await;
                loop {
                    tokio::select! {
                        _ = shutdown_sub.recv() => break,
                        _ = ticker.tick() => {
                            let mut cfg_clone = runner.node_config.read().clone();
                            let previous = cfg_clone.cert_file.as_ref().and_then(|path| std::fs::read(path).ok());
                            match crate::security::ensure_acme_certificate(&mut cfg_clone, &node_info_snapshot).await {
                                Ok(acme_cfg) => {
                                    *runner.node_config.write() = cfg_clone;
                                    if std::fs::read(&acme_cfg.cert_file).ok() != previous {
                                        let _ = certificate_updates.send(());
                                    }
                                    info!(
                                        node_id = runner.node_id,
                                        domain = %acme_cfg.domain,
                                        "ACME certificate background check completed successfully"
                                    );
                                }
                                Err(e) => {
                                    warn!(
                                        node_id = runner.node_id,
                                        error = %e,
                                        "ACME certificate background check encountered error"
                                    );
                                }
                            }
                        }
                    }
                }
            })
        };

        let report_task = {
            let runner = self.clone();
            let shutdown_sub = shutdown_rx.resubscribe();
            tokio::spawn(async move { runner.run_reports(shutdown_sub).await })
        };

        let rules_sync_task = {
            let runner = self.clone();
            let mut shutdown_sub = shutdown_rx.resubscribe();
            tokio::spawn(async move {
                let client = reqwest::Client::builder()
                    .timeout(Duration::from_secs(10))
                    .build()
                    .unwrap_or_default();
                let mut ticker = tokio::time::interval(Duration::from_secs(60));
                loop {
                    tokio::select! {
                        _ = shutdown_sub.recv() => break,
                        _ = ticker.tick() => {
                            if let Some(url) = &runner.global_config.routes_url {
                                match client.get(url).send().await {
                                    Ok(resp) if resp.status().is_success() => {
                                        if let Ok(text) = resp.text().await {
                                            let cfg = RoutesConfig::parse_content(&text);
                                            runner.reload_routes(cfg);
                                            tracing::debug!("Reloaded remote routes from {}", url);
                                        }
                                    }
                                    _ => {
                                        warn!(
                                            "Failed to fetch routes_url from {}, falling back to local routes file",
                                            url
                                        );
                                        let cfg = RoutesConfig::load_from_file(
                                            &runner.global_config.routes_file,
                                        );
                                        runner.reload_routes(cfg);
                                    }
                                }
                            }
                            if let Some(url) = &runner.global_config.block_list_url {
                                if let Ok(resp) = client.get(url).send().await {
                                    if resp.status().is_success() {
                                        if let Ok(text) = resp.text().await {
                                            runner.audit.reload_block_list(&text);
                                            tracing::debug!("Reloaded remote block_list from {}", url);
                                        }
                                    }
                                }
                            }
                            if let Some(url) = &runner.global_config.white_list_url {
                                if let Ok(resp) = client.get(url).send().await {
                                    if resp.status().is_success() {
                                        if let Ok(text) = resp.text().await {
                                            runner.audit.reload_white_list(&text);
                                            tracing::debug!("Reloaded remote white_list from {}", url);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            })
        };

        let local_watch_task = {
            let runner = self.clone();
            let mut shutdown_sub = shutdown_rx.resubscribe();
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(Duration::from_secs(10));
                let mut last_routes_mtime = None;
                let mut last_block_mtime = None;
                let mut last_white_mtime = None;

                loop {
                    tokio::select! {
                        _ = shutdown_sub.recv() => break,
                        _ = ticker.tick() => {

                            if runner.global_config.routes_url.is_none() {
                                if let Ok(meta) = std::fs::metadata(&runner.global_config.routes_file) {
                                    if let Ok(mtime) = meta.modified() {
                                        if let Some(prev) = last_routes_mtime {
                                            if mtime > prev {
                                                let cfg = RoutesConfig::load_from_file(&runner.global_config.routes_file);
                                                runner.reload_routes(cfg);
                                                info!("Hot-reloaded local routes from {:?}", runner.global_config.routes_file);
                                            }
                                        }
                                        last_routes_mtime = Some(mtime);
                                    }
                                }
                            }

                            if runner.global_config.block_list_url.is_none() {
                                if let Ok(meta) = std::fs::metadata(&runner.global_config.block_list) {
                                    if let Ok(mtime) = meta.modified() {
                                        if let Some(prev) = last_block_mtime {
                                            if mtime > prev {
                                                if let Ok(content) = std::fs::read_to_string(&runner.global_config.block_list) {
                                                    runner.audit.reload_block_list(&content);
                                                    info!("Hot-reloaded local block_list from {:?}", runner.global_config.block_list);
                                                }
                                            }
                                        }
                                        last_block_mtime = Some(mtime);
                                    }
                                }
                            }

                            if runner.global_config.white_list_url.is_none() {
                                if let Ok(meta) = std::fs::metadata(&runner.global_config.white_list) {
                                    if let Ok(mtime) = meta.modified() {
                                        if let Some(prev) = last_white_mtime {
                                            if mtime > prev {
                                                if let Ok(content) = std::fs::read_to_string(&runner.global_config.white_list) {
                                                    runner.audit.reload_white_list(&content);
                                                    info!("Hot-reloaded local white_list from {:?}", runner.global_config.white_list);
                                                }
                                            }
                                        }
                                        last_white_mtime = Some(mtime);
                                    }
                                }
                            }
                        }
                    }
                }
            })
        };

        let mut inbound_task = inbound_task;
        let inbound_finished = tokio::select! {
            biased;
            _ = shutdown_rx.recv() => false,
            result = &mut inbound_task => {
                error!(node_id = self.node_id, ?result, "Inbound stopped unexpectedly");
                true
            }
        };
        info!("NodeRunner {} shutting down", self.node_id);

        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        for mut task in [report_task, rules_sync_task, local_watch_task, acme_task] {
            if inbound_finished || tokio::time::timeout_at(deadline, &mut task).await.is_err() {
                task.abort();
                let _ = task.await;
            }
        }
        if !inbound_finished
            && tokio::time::timeout(Duration::from_secs(35), &mut inbound_task)
                .await
                .is_err()
        {
            warn!("Node {}: Inbound drain timed out", self.node_id);
            inbound_task.abort();
            let _ = inbound_task.await;
        }

        let flushed = tokio::time::timeout(Duration::from_secs(35), async {
            for attempt in 0..3 {
                self.report_data(true).await;
                if self.traffic_buffer.lock().is_empty() {
                    break;
                }
                tokio::time::sleep(Duration::from_secs(1 << attempt)).await;
            }
        })
        .await;
        if flushed.is_err() || !self.traffic_buffer.lock().is_empty() {
            error!(
                "Node {}: Shutdown ended with unacknowledged pending traffic",
                self.node_id
            );
        }
        if let Err(e) = self.save_pending().await {
            error!(node_id = self.node_id, error = %e, "Final pending traffic snapshot failed");
        }
    }

    fn inbound_context(&self, node_info: &NodeInfo) -> std::io::Result<InboundContext> {
        let cfg = self.node_config.read();
        let port = u16::try_from(i64::from(node_info.server_port) + i64::from(cfg.port_offset))
            .ok()
            .filter(|port| *port > 0)
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid node port")
            })?;
        let listen_addr = cfg
            .listen_addr
            .clone()
            .or_else(|| node_info.listen_ip.clone())
            .unwrap_or_else(|| self.global_config.listen_addr.clone());

        let buf = self.traffic_buffer.clone();
        let sys_collector = self.sys_collector.clone();
        let on_traffic: TrafficCallback = Arc::new(move |user_id, up, down| {
            let mut map = buf.lock();
            let entry = map.entry(user_id).or_insert((0, 0));
            entry.0 += up;
            entry.1 += down;
            sys_collector.add_traffic(up, down);
        });

        let mut node_effective_global = (*self.global_config).clone();
        if let Some(pattern) = cfg.custom_settings.get("mieru_traffic_pattern") {
            if !pattern.trim().is_empty() {
                node_effective_global
                    .raw_properties
                    .insert("mieru_traffic_pattern".into(), pattern.clone());
            }
        }
        if let Some(pp) = cfg.proxy_protocol {
            node_effective_global.proxy_protocol = pp;
            if pp
                && node_effective_global.proxy_protocol_mode == crate::conn::ProxyProtocolMode::Off
            {
                node_effective_global.proxy_protocol_mode = crate::conn::ProxyProtocolMode::Auto;
            }
        }
        if let Some(upp) = cfg.udp_proxy_protocol {
            node_effective_global.udp_proxy_protocol = upp;
        }
        if let Some(mptcp) = cfg.mptcp {
            node_effective_global.mptcp = mptcp;
        }
        if let Some(force_close) = cfg.force_close_ssl {
            if force_close {
                node_effective_global.auto_tls = false;
            }
        }
        drop(cfg);

        Ok(InboundContext {
            ready: None,
            node_id: self.node_id,
            listen_addr,
            port,
            router: self.router.clone(),
            rate_limiter: self.rate_limiter.clone(),
            conn_limiter: self.conn_limiter.clone(),
            device_limiter: self.device_limiter.clone(),
            audit: self.audit.clone(),
            defense: self.defense.clone(),
            tls_manager: self.tls_manager.clone(),
            audit_logger: self.audit_logger.clone(),
            clickhouse_logger: self.clickhouse_logger.clone(),
            on_traffic,
            global_config: Arc::new(node_effective_global),
            ip_user_cache: self.ip_user_cache.clone(),
        })
    }

    fn set_ready(&self, ready: bool) {
        self.readiness.send_if_modified(|value| {
            if *value == ready {
                false
            } else {
                *value = ready;
                true
            }
        });
    }

    async fn run_reports(&self, mut shutdown: broadcast::Receiver<()>) {
        let mut readiness = self.readiness.subscribe();
        let mut interval = self.panel_interval(true);
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            let readiness_changed = tokio::select! {
                biased;
                _ = shutdown.recv() => break,
                result = readiness.changed() => {
                    if result.is_err() { break; }
                    true
                }
                _ = ticker.tick() => false,
            };
            if *readiness.borrow_and_update() {
                tokio::select! {
                    biased;
                    _ = shutdown.recv() => break,
                    _ = self.report_data(false) => {}
                }
            }
            self.prune_memory_leaks();
            let next = self.panel_interval(true);
            if next != interval {
                interval = next;
                ticker = tokio::time::interval_at(tokio::time::Instant::now() + next, next);
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            } else if readiness_changed {
                ticker.reset();
            }
        }
    }

    fn panel_interval(&self, push: bool) -> Duration {
        let node = self.node_config.read();
        let info = self.node_info.lock();
        let base = info.as_ref().and_then(|i| i.base_config.as_ref());
        let (local, default, keys, panel) = if push {
            (
                node.submit_interval,
                self.global_config.node_report_interval,
                ["submit_interval", "node_report_interval"],
                base.and_then(|b| b.push_interval),
            )
        } else {
            (
                node.check_interval,
                self.global_config.node_sync_interval,
                ["check_interval", "node_sync_interval"],
                base.and_then(|b| b.pull_interval),
            )
        };
        let explicit = keys
            .iter()
            .any(|k| self.global_config.raw_properties.contains_key(*k));
        Duration::from_secs(
            local
                .or(if explicit { Some(default) } else { panel })
                .unwrap_or(default)
                .max(10),
        )
    }

    fn report_threshold(&self, online: bool) -> u64 {
        let info = self.node_info.lock();
        let base = info.as_ref().and_then(|i| i.base_config.as_ref());
        let (key, local, panel) = if online {
            (
                "submit_alive_ip_min_traffic",
                self.global_config.submit_alive_ip_min_traffic,
                base.and_then(|b| b.device_online_min_traffic),
            )
        } else {
            (
                "submit_traffic_min_traffic",
                self.global_config.submit_traffic_min_traffic,
                base.and_then(|b| b.node_report_min_traffic),
            )
        };
        if self.global_config.raw_properties.contains_key(key) {
            local.saturating_mul(1024)
        } else {
            // V2Node's panel thresholds use decimal KB; Elise's local settings use KiB.
            panel
                .map(|n| n.saturating_mul(1000))
                .unwrap_or_else(|| local.saturating_mul(1024))
        }
    }

    fn apply_node_routes(&self, node_info: &NodeInfo) {
        *self.node_info.lock() = Some(node_info.clone());
        self.reload_routes(RoutesConfig::load_from_file(
            &self.global_config.routes_file,
        ));
    }

    fn reload_routes(&self, mut cfg: RoutesConfig) {
        if let Some(info) = self.node_info.lock().as_ref() {
            let mut routes = info.routes.clone().unwrap_or_default();
            routes.extend(info.custom_routes.clone().unwrap_or_default());
            cfg.import_panel_routes(&routes, info.custom_outbounds.as_deref().unwrap_or(&[]));
        }
        self.router.reload(cfg);
    }

    async fn run_inbound(
        self: Arc<Self>,
        info: NodeInfo,
        mut shutdown: broadcast::Receiver<()>,
        certificate_updates: tokio::sync::watch::Receiver<()>,
    ) {
        let Some(users) = self.initial_users(&mut shutdown).await else {
            return;
        };
        tokio::select! {
            biased;
            _ = shutdown.recv() => return,
            _ = self.sync_alive() => {}
        }
        let launched = tokio::select! {
            biased;
            _ = shutdown.recv() => return,
            result = self.launch_inbound(&info, &users) => result,
        };
        let active = match launched {
            Ok(active) => active,
            Err(e) => {
                error!(node_id = self.node_id, error = %e, "Inbound startup failed");
                return;
            }
        };
        self.set_ready(true);
        info!(
            node_id = self.node_id,
            user_count = users.len(),
            "Node ready with panel users"
        );
        self.run_active_inbound(info, users, active, shutdown, certificate_updates)
            .await;
    }

    async fn run_active_inbound(
        self: Arc<Self>,
        mut info: NodeInfo,
        mut users: Vec<User>,
        mut active: ActiveInbound,
        mut shutdown: broadcast::Receiver<()>,
        mut certificate_updates: tokio::sync::watch::Receiver<()>,
    ) {
        let mut retired = tokio::task::JoinSet::new();
        let mut interval = self.panel_interval(false);
        let mut ticker = tokio::time::interval_at(tokio::time::Instant::now() + interval, interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut watch_certificates = true;
        loop {
            let (certificate_changed, listener_exited) = tokio::select! {
                biased;
                _ = shutdown.recv() => break,
                result = &mut active.task => {
                    self.set_ready(false);
                    warn!(node_id = self.node_id, ?result, "Listener stopped; restoring cached configuration and users");
                    (false, true)
                },
                result = retired.join_next(), if !retired.is_empty() => {
                    if let Some(Err(e)) = result { warn!(error = %e, "Retired inbound task failed"); }
                    continue;
                }
                result = certificate_updates.changed(), if watch_certificates => {
                    if result.is_err() {
                        watch_certificates = false;
                        continue;
                    }
                    (true, false)
                }
                _ = ticker.tick() => (false, false),
            };
            let mut listener_unavailable = listener_exited;
            let update = async {
                // Renewal must reach the listener even during a panel outage.
                let mut next = if certificate_changed || listener_exited {
                    info.clone()
                } else {
                    if let Some(synced) = self.sync_users(&active.inbound).await {
                        users = synced;
                    }
                    match self.panel_client.get_node_info(self.node_id).await {
                        Ok(next) => next,
                        Err(e) => {
                            warn!(node_id = self.node_id, error = %e, "Node sync failed; keeping active configuration");
                            return;
                        }
                    }
                };
                let nodes_dir = self.global_config.nodes_dir.clone().unwrap_or_else(|| {
                    if std::path::Path::new("/etc/elise").exists() {
                        std::path::PathBuf::from("/etc/elise/nodes")
                    } else {
                        std::path::PathBuf::from("./nodes")
                    }
                });
                if let Err(e) = self
                    .node_config
                    .read()
                    .prepare_node_info(&nodes_dir, &mut next)
                {
                    warn!(node_id = self.node_id, error = %e, "Invalid node security update; keeping active configuration");
                    return;
                }
                let mut previous_listener = info.clone();
                previous_listener.base_config = next.base_config.clone();
                if !certificate_changed
                    && !listener_exited
                    && serde_json::to_value(&next).ok()
                        == serde_json::to_value(&previous_listener).ok()
                    && !active.task.is_finished()
                {
                    *self.node_info.lock() = Some(next.clone());
                    info = next;
                    return;
                }
                let next_ctx = match self.inbound_context(&next) {
                    Ok(ctx) => ctx,
                    Err(e) => {
                        warn!(error = %e, "Invalid node update; keeping active configuration");
                        return;
                    }
                };
                let old_ctx = self
                    .inbound_context(&info)
                    .expect("Previously validated context");
                let same_address =
                    next_ctx.port == old_ctx.port && next_ctx.listen_addr == old_ctx.listen_addr;
                if same_address {
                    self.set_ready(false);
                    active.stop().await;
                }
                let candidate = if same_address {
                    self.launch_replacement(&next, &users).await
                } else {
                    self.launch_inbound(&next, &users).await
                };
                match candidate {
                    Ok(candidate) => {
                        self.set_ready(true);
                        listener_unavailable = false;
                        let mut old = std::mem::replace(&mut active, candidate);
                        retired.spawn(async move {
                            old.stop().await;
                        });
                        self.apply_node_routes(&next);
                        info = next;
                        if let Err(e) = self.node_config.read().save_node_conf(&nodes_dir, &info) {
                            warn!(node_id = self.node_id, error = %e, "Failed to update node AUTO settings");
                        }
                        info!(
                            node_id = self.node_id,
                            port = info.server_port,
                            certificate_changed,
                            listener_exited,
                            "Node configuration reloaded"
                        );
                    }
                    Err(e) => {
                        warn!(node_id = self.node_id, error = %e, "Node update failed; keeping previous configuration");
                        if same_address {
                            match self.launch_replacement(&info, &users).await {
                                Ok(previous) => {
                                    self.set_ready(true);
                                    active = previous;
                                    listener_unavailable = false;
                                }
                                Err(e) => {
                                    listener_unavailable = true;
                                    error!(node_id = self.node_id, error = %e, "Failed to restore previous listener")
                                }
                            }
                        }
                    }
                }
            };
            tokio::select! { biased; _ = shutdown.recv() => break, _ = update => {} }
            if listener_unavailable {
                break; // Let the master/systemd restart a node that cannot recover.
            }
            let next = self.panel_interval(false);
            if next != interval {
                interval = next;
                ticker = tokio::time::interval_at(tokio::time::Instant::now() + next, next);
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            }
        }
        self.set_ready(false);
        active.stop().await;
        while retired.join_next().await.is_some() {}
    }

    async fn launch_inbound(
        &self,
        info: &NodeInfo,
        users: &[User],
    ) -> std::io::Result<ActiveInbound> {
        let mut ctx = self.inbound_context(info)?;
        let protocol = if (info.node_type.eq_ignore_ascii_case("hysteria")
            || info.node_type.eq_ignore_ascii_case("hy"))
            && info.version == Some(2)
        {
            "hysteria2"
        } else {
            &info.node_type
        };
        let inbound = create_inbound(protocol)?;
        inbound.update_users(users.to_vec());
        let (ready, mut ready_rx) = tokio::sync::watch::channel(false);
        ctx.ready = Some(ready);
        let (stop, rx) = broadcast::channel(1);
        let server = inbound.clone();
        let info = info.clone();
        let task = tokio::spawn(async move { server.start(ctx, info, rx).await });
        let mut active = ActiveInbound {
            inbound,
            stop,
            task,
        };
        tokio::select! {
            biased;
            result = &mut active.task => {
                return Err(match result {
                    Ok(Err(e)) => e,
                    other => std::io::Error::other(format!("Inbound stopped before ready: {other:?}")),
                });
            }
            result = ready_rx.changed() => {
                if result.is_err() || !*ready_rx.borrow() { return Err(std::io::Error::other("Inbound did not become ready")); }
            }
            _ = tokio::time::sleep(Duration::from_secs(30)) => {
                return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "Inbound startup timed out"));
            }
        }
        Ok(active)
    }

    async fn launch_replacement(
        &self,
        info: &NodeInfo,
        users: &[User],
    ) -> std::io::Result<ActiveInbound> {
        // QUIC's driver can retain the UDP socket while closed connections
        // drain, even after the inbound task exits. Wait for it to release the
        // port before considering a same-address reload a failure.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            match self.launch_inbound(info, users).await {
                Err(e)
                    if e.kind() == std::io::ErrorKind::AddrInUse
                        && tokio::time::Instant::now() < deadline =>
                {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                result => return result,
            }
        }
    }

    async fn initial_users(&self, shutdown: &mut broadcast::Receiver<()>) -> Option<Vec<User>> {
        loop {
            tokio::select! {
                biased;
                _ = shutdown.recv() => return None,
                users = self.fetch_users() => {
                    if users.is_some() { return users; }
                }
            }
            tokio::select! {
                biased;
                _ = shutdown.recv() => return None,
                _ = tokio::time::sleep(Duration::from_secs(10)) => {}
            }
        }
    }

    async fn fetch_users(&self) -> Option<Vec<User>> {
        match self.panel_client.get_users(self.node_id).await {
            Ok(users) => {
                let mut state = self.user_sync_state.lock();
                let previous = self
                    .synced_user_count
                    .swap(users.len() as u32, Ordering::Relaxed);
                if !state.0 || state.1 > 0 || previous != users.len() as u32 {
                    info!(
                        node_id = self.node_id,
                        user_count = users.len(),
                        recovered = state.1 > 0,
                        "Panel users loaded"
                    );
                } else {
                    tracing::debug!(
                        node_id = self.node_id,
                        user_count = users.len(),
                        "Panel users unchanged in count"
                    );
                }
                *state = (true, 0);
                drop(state);
                for u in &users {
                    self.rate_limiter.set_user_limit(u.id, u.speed_limit);

                    let effective_dev_limit =
                        match (u.device_limit, self.global_config.user_conn_limit) {
                            (0, g) => g,
                            (p, 0) => p,
                            (p, g) => p.min(g),
                        };
                    self.device_limiter
                        .set_user_limit(u.id, effective_dev_limit);

                    if self.global_config.user_tcp_limit > 0 {
                        self.conn_limiter
                            .set_user_limit(u.id, self.global_config.user_tcp_limit);
                    }
                }
                Some(users)
            }
            Err(e) => {
                let mut state = self.user_sync_state.lock();
                state.1 = state.1.saturating_add(1);
                if state.1.is_power_of_two() {
                    let action = if state.0 {
                        "retaining previous users"
                    } else {
                        "waiting before opening listener"
                    };
                    warn!(node_id = self.node_id, failures = state.1, action, error = %e,
                        "User fetch failed; will retry");
                }
                None
            }
        }
    }

    async fn sync_users(&self, inbound: &Arc<dyn Inbound>) -> Option<Vec<User>> {
        let users = self.fetch_users().await;
        if let Some(users) = &users {
            inbound.update_users(users.clone());
        }
        self.sync_alive().await;
        users
    }

    async fn sync_alive(&self) {
        match self.panel_client.get_user_alivelist(self.node_id).await {
            Ok(alive_map) => {
                self.device_limiter.update_global_alive(alive_map);
            }
            Err(e)
                if e.downcast_ref::<std::io::Error>()
                    .is_some_and(|io| io.kind() == std::io::ErrorKind::Unsupported) => {}
            Err(e) => warn!(node_id = self.node_id, error = %e, "Alive list sync failed"),
        }
    }

    async fn report_data(&self, force: bool) {
        let _report_guard = self.report_lock.lock().await;

        let min_traffic_bytes = self.report_threshold(false);
        let min_alive_bytes = self.report_threshold(true);

        let (items, active_users): (Vec<TrafficItem>, HashMap<u32, u64>) = {
            let buf = self.traffic_buffer.lock();
            let mut res = Vec::new();
            let mut active = HashMap::new();
            for (&user_id, &(u, d)) in buf.iter() {
                let total = u + d;
                active.insert(user_id, total);
                if (force || total >= min_traffic_bytes) && total > 0 {
                    res.push(TrafficItem { user_id, u, d });
                }
            }
            (res, active)
        };

        if !items.is_empty() || self.panel_client.traffic_heartbeat() {
            if let Err(e) = self.save_pending().await {
                error!(node_id = self.node_id, error = %e, "Traffic batch not persisted; report deferred");
                return;
            }
            match self
                .panel_client
                .report_traffic(self.node_id, items.clone())
                .await
            {
                Ok(()) => {
                    let mut buf = self.traffic_buffer.lock();
                    for item in items {
                        if let Some(pending) = buf.get_mut(&item.user_id) {
                            pending.0 -= item.u;
                            pending.1 -= item.d;
                            if *pending == (0, 0) {
                                buf.remove(&item.user_id);
                            }
                        }
                    }
                }
                Err(e) => warn!(
                    "Node {}: Traffic report failed, pending traffic retained: {:?}",
                    self.node_id, e
                ),
            }
        }

        if let Err(e) = self.save_pending().await {
            error!(node_id = self.node_id, error = %e, "Failed to persist traffic acknowledgement");
        }

        let online_map = self.device_limiter.get_all_online_devices();
        let mut report: HashMap<u32, Vec<String>> = online_map
            .iter()
            .filter(|(user_id, _)| {
                min_alive_bytes == 0
                    || active_users.get(user_id).copied().unwrap_or(0) >= min_alive_bytes
            })
            .map(|(&user_id, ips)| (user_id, ips.clone()))
            .collect();
        // A missing user leaves the panel's previous IPs alive until its TTL.
        // Explicitly clear users whose last session closed, retrying on failure.
        for &user_id in self.reported_online.lock().keys() {
            if !online_map.contains_key(&user_id) {
                report.insert(user_id, Vec::new());
            }
        }
        if !report.is_empty() {
            let items = report
                .iter()
                .map(|(&user_id, ips)| OnlineDeviceItem {
                    user_id,
                    ips: ips.clone(),
                })
                .collect();
            match self
                .panel_client
                .report_online_devices(self.node_id, items)
                .await
            {
                Ok(()) => {
                    self.device_limiter.record_panel_report(&report);
                    let mut previous = self.reported_online.lock();
                    for (user_id, ips) in report {
                        if ips.is_empty() {
                            previous.remove(&user_id);
                        } else {
                            previous.insert(user_id, ips);
                        }
                    }
                }
                Err(e) => {
                    warn!(node_id = self.node_id, error = %e, "Online IP report failed; will retry")
                }
            }
        }

        let total_users = self.synced_user_count.load(Ordering::Relaxed);
        let active_user_count = active_users.len() as u32;
        let active_conns = self
            .conn_limiter
            .get_total_active()
            .max(self.device_limiter.get_all_online_devices().len() as u32);

        let mut report = self.sys_collector.collect(total_users, active_user_count);
        if active_conns > 0 && report.active_connections == 0 {
            report.active_connections = active_conns;
            report.total_connections = report.total_connections.max(active_conns as u64);
        }
        if let Err(e) = self
            .panel_client
            .report_node_status(self.node_id, &report)
            .await
        {
            tracing::debug!("Node {}: Status report failed: {:?}", self.node_id, e);
        }
    }

    fn prune_memory_leaks(&self) {
        self.device_limiter.prune_expired();
        self.conn_limiter.prune_idle();
        self.rate_limiter.prune_idle();
        self.defense.prune_expired();
        self.ip_user_cache.prune();
        self.ip_user_cache.save_to_disk();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    fn runner(url: String) -> NodeRunner {
        let geo = Arc::new(crate::geo::GeoEngine::default());
        let dialer = Arc::new(crate::proxy::router::OutboundDialer::new(
            Arc::new(crate::dns::DNSResolver::default()),
            None,
            None,
            false,
        ));
        let mut config = crate::config::GlobalConfig::default();
        config.domain_sniff = false;
        NodeRunner::new(
            1,
            Arc::new(crate::panel::SSPanelClient::new(url, "fixture".into())),
            Arc::new(config),
            NodeConfig {
                node_id: 1,
                ..Default::default()
            },
            Arc::new(Router::new(Default::default(), dialer, geo.clone())),
            Arc::new(RateLimiter::new()),
            Arc::new(ConnectionLimiter::new()),
            Arc::new(DeviceLimiter::new(60, 32, 128, None)),
            Arc::new(AuditController::new("", "", geo)),
            Arc::new(AttackDefenseManager::default()),
            Arc::new(TLSManager::new(false, "localhost".into())),
            Arc::new(AuditLogger::new(None::<&str>)),
            Arc::new(ClickHouseLogger::new(
                false,
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                None,
            )),
            Arc::new(IpUserCache::new(1, false, "")),
        )
    }

    struct UserPanel {
        replies: Mutex<std::collections::VecDeque<Option<Vec<User>>>>,
        calls: AtomicU32,
        reports: AtomicU32,
    }

    impl UserPanel {
        fn new(replies: Vec<Option<Vec<User>>>) -> Arc<Self> {
            Arc::new(Self {
                replies: Mutex::new(replies.into()),
                calls: AtomicU32::new(0),
                reports: AtomicU32::new(0),
            })
        }
    }

    #[async_trait::async_trait]
    impl PanelClient for UserPanel {
        fn traffic_heartbeat(&self) -> bool {
            true
        }
        async fn get_node_info(
            &self,
            _: u32,
        ) -> Result<NodeInfo, Box<dyn std::error::Error + Send + Sync>> {
            Err("panel unavailable".into())
        }
        async fn get_users(
            &self,
            _: u32,
        ) -> Result<Vec<User>, Box<dyn std::error::Error + Send + Sync>> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            self.replies
                .lock()
                .pop_front()
                .flatten()
                .ok_or_else(|| "panel unavailable".into())
        }
        async fn report_traffic(
            &self,
            _: u32,
            _: Vec<TrafficItem>,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            self.reports.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
        async fn report_online_devices(
            &self,
            _: u32,
            _: Vec<OnlineDeviceItem>,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Ok(())
        }
    }

    #[tokio::test(start_paused = true)]
    async fn heartbeat_waits_for_readiness_and_resumes_without_duplicate_tick() {
        let panel = UserPanel::new(vec![]);
        let mut runner = runner("http://unused".into());
        runner.panel_client = panel.clone();
        let runner = Arc::new(runner);
        let (shutdown, rx) = broadcast::channel(1);
        let worker = runner.clone();
        let task = tokio::spawn(async move { worker.run_reports(rx).await });
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(120)).await;
        tokio::task::yield_now().await;
        assert_eq!(panel.reports.load(Ordering::Relaxed), 0);
        runner.set_ready(true);
        tokio::task::yield_now().await;
        assert_eq!(panel.reports.load(Ordering::Relaxed), 1);
        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(panel.reports.load(Ordering::Relaxed), 1);
        runner.set_ready(false);
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(120)).await;
        tokio::task::yield_now().await;
        assert_eq!(panel.reports.load(Ordering::Relaxed), 1);
        runner.set_ready(true);
        tokio::task::yield_now().await;
        assert_eq!(panel.reports.load(Ordering::Relaxed), 2);
        shutdown.send(()).unwrap();
        task.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn initial_users_retry_and_empty_success_and_shutdown() {
        let panel = UserPanel::new(vec![None, Some(vec![])]);
        let mut runner = runner("http://unused".into());
        runner.panel_client = panel.clone();
        let (shutdown, mut rx) = broadcast::channel(1);
        let start = tokio::time::Instant::now();
        assert!(runner.initial_users(&mut rx).await.unwrap().is_empty());
        assert_eq!(panel.calls.load(Ordering::Relaxed), 2);
        assert_eq!(start.elapsed(), Duration::from_secs(10));
        // A shutdown during the retry delay must not wait for the next poll.
        let wait = runner.initial_users(&mut rx);
        tokio::pin!(wait);
        tokio::select! {
            _ = &mut wait => panic!("outage should retry"),
            _ = tokio::time::sleep(Duration::from_secs(1)) => {}
        }
        shutdown.send(()).unwrap();
        assert!(wait.await.is_none());
        assert_eq!(panel.calls.load(Ordering::Relaxed), 3);
    }

    async fn socks_auth(port: u16) -> u8 {
        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        stream.write_all(b"\x05\x01\x02").await.unwrap();
        let mut response = [0; 2];
        stream.read_exact(&mut response).await.unwrap();
        if response[1] == 255 {
            return 255;
        }
        stream.write_all(b"\x01\x04test\x04pass").await.unwrap();
        stream.read_exact(&mut response).await.unwrap();
        response[1]
    }

    #[tokio::test]
    async fn startup_authenticates_before_poll_and_reload_retains_users() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let user = User {
                id: 42,
                uuid: "test".into(),
                password: Some("pass".into()),
                ..Default::default()
            };
            let panel = UserPanel::new(vec![Some(vec![user]), None, Some(vec![])]);
            let mut runner = runner("http://unused".into());
            runner.panel_client = panel.clone();
            let dir = std::env::temp_dir().join(format!("elise-users-{}", uuid::Uuid::new_v4()));
            Arc::get_mut(&mut runner.global_config).unwrap().nodes_dir = Some(dir.clone());
            let port = std::net::TcpListener::bind("127.0.0.1:0")
                .unwrap()
                .local_addr()
                .unwrap()
                .port();
            let info = NodeInfo {
                node_type: "socks".into(),
                server_port: port,
                listen_ip: Some("127.0.0.1".into()),
                ..Default::default()
            };
            let runner = Arc::new(runner);
            let (shutdown, rx) = broadcast::channel(1);
            let (updates, certificate_rx) = tokio::sync::watch::channel(());
            let task = tokio::spawn(runner.clone().run_inbound(info, rx, certificate_rx));
            loop {
                if tokio::net::TcpStream::connect(("127.0.0.1", port))
                    .await
                    .is_ok()
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            assert_eq!(socks_auth(port).await, 0);
            assert_eq!(
                panel.calls.load(Ordering::Relaxed),
                1,
                "no duplicate startup fetch"
            );
            // Force a listener replacement while the panel is unavailable.
            updates.send(()).unwrap();
            while !dir.join("node_1.conf").exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            assert_eq!(socks_auth(port).await, 0);
            assert_eq!(
                panel.calls.load(Ordering::Relaxed),
                1,
                "certificate reload must reuse users"
            );
            shutdown.send(()).unwrap();
            task.await.unwrap();
            let _ = std::fs::remove_dir_all(dir);
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn stopped_listener_recovers_cached_users_during_panel_outage() {
        tokio::time::timeout(Duration::from_secs(8), async {
            let mut runner = runner("http://unused".into());
            let panel = UserPanel::new(vec![]);
            runner.panel_client = panel.clone();
            let dir = std::env::temp_dir().join(format!("elise-recover-{}", uuid::Uuid::new_v4()));
            Arc::get_mut(&mut runner.global_config).unwrap().nodes_dir = Some(dir.clone());
            let port = std::net::TcpListener::bind("127.0.0.1:0")
                .unwrap()
                .local_addr()
                .unwrap()
                .port();
            let info = NodeInfo {
                node_type: "socks".into(),
                server_port: port,
                listen_ip: Some("127.0.0.1".into()),
                ..Default::default()
            };
            let users = vec![User {
                id: 42,
                uuid: "test".into(),
                password: Some("pass".into()),
                ..Default::default()
            }];
            let active = runner.launch_inbound(&info, &users).await.unwrap();
            assert_eq!(socks_auth(port).await, 0);
            active.task.abort();
            while !active.task.is_finished() {
                tokio::task::yield_now().await;
            }
            let (shutdown, rx) = broadcast::channel(1);
            let (_updates, certificate_rx) = tokio::sync::watch::channel(());
            let task = tokio::spawn(Arc::new(runner).run_active_inbound(
                info,
                users,
                active,
                rx,
                certificate_rx,
            ));
            while !dir.join("node_1.conf").exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            assert_eq!(socks_auth(port).await, 0);
            assert_eq!(panel.calls.load(Ordering::Relaxed), 0);
            shutdown.send(()).unwrap();
            task.await.unwrap();
            std::fs::remove_dir_all(dir).unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn failed_user_sync_keeps_access_and_empty_success_revokes_it() {
        let user = User {
            id: 42,
            uuid: "test".into(),
            password: Some("pass".into()),
            ..Default::default()
        };
        let panel = UserPanel::new(vec![Some(vec![user]), None, Some(vec![])]);
        let mut runner = runner("http://unused".into());
        runner.panel_client = panel;
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let info = NodeInfo {
            node_type: "socks".into(),
            server_port: port,
            listen_ip: Some("127.0.0.1".into()),
            ..Default::default()
        };
        let mut active = runner.launch_inbound(&info, &[]).await.unwrap();
        assert_eq!(runner.sync_users(&active.inbound).await.unwrap().len(), 1);
        assert_eq!(socks_auth(port).await, 0);
        assert!(runner.sync_users(&active.inbound).await.is_none());
        assert_eq!(socks_auth(port).await, 0);
        assert_eq!(runner.synced_user_count.load(Ordering::Relaxed), 1);
        assert!(runner.sync_users(&active.inbound).await.unwrap().is_empty());
        assert_eq!(socks_auth(port).await, 255);
        assert_eq!(runner.synced_user_count.load(Ordering::Relaxed), 0);
        active.stop().await;
    }

    #[test]
    fn panel_reporting_settings_allow_explicit_local_overrides() {
        let mut runner = runner("http://localhost".into());
        *runner.node_info.lock() = Some(NodeInfo {
            base_config: Some(crate::panel::types::PanelBaseConfig {
                push_interval: Some(30),
                pull_interval: Some(45),
                node_report_min_traffic: Some(2),
                device_online_min_traffic: Some(3),
            }),
            ..Default::default()
        });
        assert_eq!(runner.panel_interval(true), Duration::from_secs(30));
        assert_eq!(runner.panel_interval(false), Duration::from_secs(45));
        assert_eq!(runner.report_threshold(false), 2000);
        assert_eq!(runner.report_threshold(true), 3000);
        let global = Arc::make_mut(&mut runner.global_config);
        global.node_report_interval = 80;
        global
            .raw_properties
            .insert("submit_interval".into(), "80".into());
        global.submit_traffic_min_traffic = 4;
        global
            .raw_properties
            .insert("submit_traffic_min_traffic".into(), "4".into());
        assert_eq!(runner.panel_interval(true), Duration::from_secs(80));
        assert_eq!(runner.report_threshold(false), 4096);
        runner.node_config.write().submit_interval = Some(5);
        assert_eq!(runner.panel_interval(true), Duration::from_secs(10));
    }

    #[tokio::test]
    async fn empty_alive_list_clears_counts_but_panel_errors_preserve_them() {
        let panel = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let panel_addr = panel.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for (path, status, body) in [
                (
                    "user",
                    "200 OK",
                    r#"{"users":[{"id":7,"uuid":"fb11878d-1492-4a7b-b98d-cf916067833e","device_limit":1}]}"#,
                ),
                ("alivelist", "200 OK", r#"{"alive":{"7":1}}"#),
                (
                    "user",
                    "200 OK",
                    r#"{"users":[{"id":7,"uuid":"fb11878d-1492-4a7b-b98d-cf916067833e","device_limit":1}]}"#,
                ),
                ("alivelist", "500 Internal Server Error", "{}"),
                (
                    "user",
                    "200 OK",
                    r#"{"users":[{"id":7,"uuid":"fb11878d-1492-4a7b-b98d-cf916067833e","device_limit":1}]}"#,
                ),
                ("alivelist", "200 OK", r#"{"alive":{}}"#),
            ] {
                let (mut stream, _) = panel.accept().await.unwrap();
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    request.push(stream.read_u8().await.unwrap());
                }
                let request = String::from_utf8(request).unwrap();
                assert!(request.split_whitespace().nth(1).unwrap().contains(path));
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
            }
        });

        let mut runner = runner(format!("http://{panel_addr}"));
        runner.panel_client = Arc::new(crate::panel::XboardClient::new_with_node_type(
            format!("http://{panel_addr}"),
            "fixture".into(),
            Some("vless".into()),
        ));
        let inbound: Arc<dyn Inbound> = Arc::new(crate::protocol::vless::VlessInbound::new());
        let client_ip = "198.51.100.7".parse().unwrap();

        runner.sync_users(&inbound).await;
        assert!(!runner.device_limiter.check_and_record(7, client_ip));
        runner.sync_users(&inbound).await;
        assert!(!runner.device_limiter.check_and_record(7, client_ip));
        runner.sync_users(&inbound).await;
        assert!(runner.device_limiter.check_and_record(7, client_ip));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn socks_requires_panel_users_and_limits_handshake_not_session() {
        tokio::time::timeout(Duration::from_secs(22), async {
            let runner = runner("http://127.0.0.1:1".into());
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            drop(listener);
            let info = NodeInfo {
                node_type: "socks".into(),
                server_port: port,
                listen_ip: Some("127.0.0.1".into()),
                ..Default::default()
            };
            let mut active = runner.launch_inbound(&info, &[]).await.unwrap();
            let mut response = [0u8; 2];
            let mut unauth = tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .unwrap();
            unauth.write_all(b"\x05\x01\x00").await.unwrap();
            unauth.read_exact(&mut response).await.unwrap();
            assert_eq!(response, [5, 255]);
            drop(unauth);
            active.inbound.update_users(vec![User {
                id: 42,
                uuid: "test".into(),
                password: Some("pass".into()),
                ..Default::default()
            }]);
            let mut bad = tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .unwrap();
            bad.write_all(b"\x05\x01\x02").await.unwrap();
            bad.read_exact(&mut response).await.unwrap();
            bad.write_all(b"\x01\x04test\x05wrong").await.unwrap();
            bad.read_exact(&mut response).await.unwrap();
            assert_eq!(response, [1, 1]);
            drop(bad);
            let mut silent = tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .unwrap();
            let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let target_port = echo.local_addr().unwrap().port();
            let target = tokio::spawn(async move {
                let (mut stream, _) = echo.accept().await.unwrap();
                let mut received = Vec::new();
                stream.read_to_end(&mut received).await.unwrap();
                assert_eq!(received, b"after-handshake-timeout");
                stream.write_all(b"half-close-response").await.unwrap();
            });
            let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .unwrap();
            stream.write_all(b"\x05\x01\x02").await.unwrap();
            stream.read_exact(&mut response).await.unwrap();
            stream.write_all(b"\x01\x04test\x04pass").await.unwrap();
            stream.read_exact(&mut response).await.unwrap();
            assert_eq!(response, [1, 0]);
            let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
            request.extend_from_slice(&target_port.to_be_bytes());
            stream.write_all(&request).await.unwrap();
            let mut response = [0; 10];
            stream.read_exact(&mut response).await.unwrap();
            assert_eq!(response[1], 0);
            tokio::time::sleep(Duration::from_secs(16)).await;
            assert_eq!(silent.read(&mut [0u8; 1]).await.unwrap(), 0);
            stream.write_all(b"after-handshake-timeout").await.unwrap();
            stream.shutdown().await.unwrap();
            let mut response = Vec::new();
            stream.read_to_end(&mut response).await.unwrap();
            assert_eq!(response, b"half-close-response");
            target.await.unwrap();
            active.inbound.update_users(vec![]);
            let mut removed = tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .unwrap();
            removed.write_all(b"\x05\x02\x00\x02").await.unwrap();
            let mut response = [0u8; 2];
            removed.read_exact(&mut response).await.unwrap();
            assert_eq!(response, [5, 255]);
            drop(removed);
            active.stop().await;
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn socks_udp_control_close_and_idle_release_relay_socket() {
        let mut runner = runner("http://127.0.0.1:1".into());
        Arc::make_mut(&mut runner.global_config).udp_timeout = 1;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let info = NodeInfo {
            node_type: "socks".into(),
            server_port: port,
            listen_ip: Some("127.0.0.1".into()),
            ..Default::default()
        };
        let user = User {
            id: 42,
            uuid: "test".into(),
            password: Some("pass".into()),
            ..Default::default()
        };
        let mut active = runner.launch_inbound(&info, &[user]).await.unwrap();
        let echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target_port = echo.local_addr().unwrap().port();
        let target = tokio::spawn(async move {
            let mut buf = [0u8; 128];
            for _ in 0..4 {
                let (n, peer) = echo.recv_from(&mut buf).await.unwrap();
                assert_eq!(&buf[..n], b"udp-payload");
                echo.send_to(&buf[..n], peer).await.unwrap();
            }
        });
        for exit in ["close", "idle"] {
            let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .unwrap();
            stream.write_all(b"\x05\x01\x02").await.unwrap();
            let mut response = [0u8; 2];
            stream.read_exact(&mut response).await.unwrap();
            assert_eq!(response, [5, 2]);
            stream.write_all(b"\x01\x04test\x04pass").await.unwrap();
            stream.read_exact(&mut response).await.unwrap();
            assert_eq!(response, [1, 0]);
            stream
                .write_all(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
                .await
                .unwrap();
            let mut response = [0u8; 10];
            stream.read_exact(&mut response).await.unwrap();
            assert_eq!(&response[..4], &[5, 0, 0, 1]);
            let relay_port = u16::from_be_bytes([response[8], response[9]]);
            let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let malformed = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let mut packet = vec![0, 0, 1, 1, 127, 0, 0, 1];
            packet.extend_from_slice(&target_port.to_be_bytes());
            packet.extend_from_slice(b"udp-payload");
            malformed
                .send_to(&packet, ("127.0.0.1", relay_port))
                .await
                .unwrap();
            packet[2] = 0;
            for _ in 0..2 {
                client
                    .send_to(&packet, ("127.0.0.1", relay_port))
                    .await
                    .unwrap();
                let mut response = [0u8; 128];
                let (n, _) =
                    tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut response))
                        .await
                        .unwrap()
                        .unwrap();
                assert_eq!(&response[..n], &packet);
            }
            if exit == "idle" {
                let mut byte = [0u8; 1];
                assert_eq!(
                    tokio::time::timeout(Duration::from_secs(3), stream.read(&mut byte))
                        .await
                        .unwrap()
                        .unwrap(),
                    0
                );
            }
            drop(stream);
            tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    if let Ok(socket) = tokio::net::UdpSocket::bind(("0.0.0.0", relay_port)).await {
                        drop(socket);
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("UDP relay leaked after control closed");
        }
        tokio::time::timeout(Duration::from_secs(2), target)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(runner.traffic_buffer.lock().get(&42), Some(&(44, 44)));
        active.stop().await;
    }

    #[tokio::test]
    async fn certificate_renewal_reloads_tls_and_quic_without_panel_access() {
        async fn peer_certificate(
            protocol: &str,
            port: u16,
            roots: rustls::RootCertStore,
        ) -> Option<Vec<u8>> {
            let mut tls = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            if protocol == "anytls" {
                let stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
                    .await
                    .ok()?;
                let connector = tokio_rustls::TlsConnector::from(Arc::new(tls));
                let stream = connector
                    .connect("node.example.com".try_into().unwrap(), stream)
                    .await
                    .ok()?;
                Some(stream.get_ref().1.peer_certificates()?[0].to_vec())
            } else {
                tls.alpn_protocols = vec![if protocol == "hysteria" {
                    b"hysteria".to_vec()
                } else {
                    b"h3".to_vec()
                }];
                let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap();
                let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
                endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
                let connection = endpoint
                    .connect(([127, 0, 0, 1], port).into(), "node.example.com")
                    .ok()?
                    .await
                    .ok()?;
                let identity = connection
                    .peer_identity()?
                    .downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
                    .ok()?;
                let cert = identity[0].to_vec();
                connection.close(0u32.into(), b"test complete");
                Some(cert)
            }
        }
        let _ = rustls::crypto::ring::default_provider().install_default();
        for protocol in ["anytls", "hysteria", "hysteria2"] {
            let dir = std::env::temp_dir().join(format!("elise-renew-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(&dir).unwrap();
            let cert_path = dir.join("fullchain.pem");
            let key_path = dir.join("privkey.pem");
            let first =
                rcgen::generate_simple_self_signed(vec!["node.example.com".into()]).unwrap();
            let second =
                rcgen::generate_simple_self_signed(vec!["node.example.com".into()]).unwrap();
            std::fs::write(&cert_path, first.cert.pem()).unwrap();
            std::fs::write(&key_path, first.key_pair.serialize_pem()).unwrap();
            let mut roots = rustls::RootCertStore::empty();
            roots.add(first.cert.der().clone()).unwrap();
            roots.add(second.cert.der().clone()).unwrap();
            let port = if protocol == "anytls" {
                std::net::TcpListener::bind("127.0.0.1:0")
                    .unwrap()
                    .local_addr()
                    .unwrap()
                    .port()
            } else {
                std::net::UdpSocket::bind("127.0.0.1:0")
                    .unwrap()
                    .local_addr()
                    .unwrap()
                    .port()
            };
            let mut runner = runner("http://127.0.0.1:1".into());
            runner.panel_client = UserPanel::new(vec![Some(vec![])]);
            Arc::get_mut(&mut runner.global_config).unwrap().nodes_dir = Some(dir.join("nodes"));
            *runner.node_config.write() = NodeConfig {
                cert_file: Some(cert_path.clone()),
                key_file: Some(key_path.clone()),
                cert_domain: Some("node.example.com".into()),
                ..Default::default()
            };
            let mut info = NodeInfo {
                node_type: protocol.into(),
                server_port: port,
                listen_ip: Some("127.0.0.1".into()),
                tls: Some(1),
                ..Default::default()
            };
            runner
                .node_config
                .read()
                .prepare_node_info(&dir.join("nodes"), &mut info)
                .unwrap();
            let (shutdown, rx) = broadcast::channel(1);
            let (updates, certificate_rx) = tokio::sync::watch::channel(());
            let task = tokio::spawn(Arc::new(runner).run_inbound(info, rx, certificate_rx));
            for expected in [first.cert.der(), second.cert.der()] {
                if expected == second.cert.der() {
                    std::fs::write(&cert_path, second.cert.pem()).unwrap();
                    std::fs::write(&key_path, second.key_pair.serialize_pem()).unwrap();
                    updates.send(()).unwrap();
                }
                tokio::time::timeout(Duration::from_secs(8), async {
                    loop {
                        if let Ok(Some(cert)) = tokio::time::timeout(
                            Duration::from_millis(500),
                            peer_certificate(protocol, port, roots.clone()),
                        )
                        .await
                        {
                            if cert == expected.as_ref() {
                                break;
                            }
                        }
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                })
                .await
                .unwrap_or_else(|_| {
                    panic!(
                        "{protocol} did not serve the expected certificate (renewed={})",
                        expected == second.cert.der()
                    )
                });
            }
            shutdown.send(()).unwrap();
            tokio::time::timeout(Duration::from_secs(3), task)
                .await
                .unwrap()
                .unwrap();
            std::fs::remove_dir_all(dir).unwrap();
        }
    }

    #[tokio::test]
    async fn tls_inbounds_respect_panel_certificate_policy() {
        let runner = runner("http://127.0.0.1:1".into());
        for protocol in ["vless", "vmess", "trojan", "http", "anytls", "naive"] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            drop(listener);
            let mut info = NodeInfo {
                node_type: protocol.into(),
                server_port: port,
                tls: Some(1),
                listen_ip: Some("127.0.0.1".into()),
                tls_settings: Some(
                    serde_json::json!({"server_name":"localhost","allow_insecure":false}),
                ),
                ..Default::default()
            };
            let error = runner
                .launch_inbound(&info, &[])
                .await
                .err()
                .expect("missing certificate must fail");
            assert!(
                error.to_string().contains("TLS has no certificate"),
                "{protocol}: {error}"
            );
            info.tls_settings.as_mut().unwrap()["allow_insecure"] = serde_json::json!(true);
            let mut active = runner
                .launch_inbound(&info, &[])
                .await
                .unwrap_or_else(|e| panic!("{protocol}: {e}"));
            active.stop().await;
            info.tls_settings.as_mut().unwrap()["cert_file"] =
                serde_json::json!("/elise-missing-certificate.pem");
            info.tls_settings.as_mut().unwrap()["key_file"] =
                serde_json::json!("/elise-missing-private-key.pem");
            assert!(
                runner.launch_inbound(&info, &[]).await.is_err(),
                "{protocol} must not fall back from a broken certificate"
            );
        }
    }

    #[tokio::test]
    async fn mieru_pattern_overrides_reach_inbound() {
        use base64::prelude::*;
        use prost::Message;

        let pattern = BASE64_STANDARD.encode(
            crate::protocol::mieru::proto::TrafficPattern {
                seed: Some(42),
                ..Default::default()
            }
            .encode_to_vec(),
        );
        let mut runner = runner("http://127.0.0.1:1".into());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut info = NodeInfo {
            node_type: "mieru".into(),
            server_port: listener.local_addr().unwrap().port(),
            listen_ip: Some("127.0.0.1".into()),
            traffic_pattern: Some(pattern.clone()),
            ..Default::default()
        };
        drop(listener);
        let mut active = runner.launch_inbound(&info, &[]).await.unwrap();
        active.stop().await;

        info.traffic_pattern = Some("invalid".into());
        assert!(runner.launch_inbound(&info, &[]).await.is_err());
        runner.global_config = Arc::new(crate::config::GlobalConfig::parse(&format!(
            "mieru_traffic_pattern = {pattern}"
        )));
        let mut active = runner.launch_inbound(&info, &[]).await.unwrap();
        active.stop().await;

        runner
            .node_config
            .write()
            .parse_content("[USER]\nmieru_traffic_pattern = invalid");
        assert!(runner.launch_inbound(&info, &[]).await.is_err());
        runner
            .node_config
            .write()
            .parse_content(&format!("[USER]\nmieru_traffic_pattern = {pattern}"));
        runner.global_config = Arc::new(crate::config::GlobalConfig::parse(
            "mieru_traffic_pattern = invalid",
        ));
        let mut active = runner.launch_inbound(&info, &[]).await.unwrap();
        active.stop().await;

        runner
            .node_config
            .write()
            .parse_content("[USER]\nmieru_traffic_pattern = ");
        runner.global_config = Arc::new(crate::config::GlobalConfig::parse(
            "mieru_traffic_pattern = ",
        ));
        assert!(runner.launch_inbound(&info, &[]).await.is_err());
        info.traffic_pattern = Some(pattern);
        let mut active = runner.launch_inbound(&info, &[]).await.unwrap();
        active.stop().await;
    }

    #[tokio::test]
    async fn anytls_and_hysteria_bind_configured_ipv4_and_ipv6_addresses() {
        let runner = runner("http://127.0.0.1:1".into());
        for address in ["127.0.0.1", "::1"] {
            if address == "::1" && std::net::UdpSocket::bind((address, 0)).is_err() {
                continue;
            }
            for protocol in ["anytls", "hysteria", "hysteria2"] {
                let port = if protocol == "anytls" {
                    std::net::TcpListener::bind((address, 0))
                        .unwrap()
                        .local_addr()
                        .unwrap()
                        .port()
                } else {
                    std::net::UdpSocket::bind((address, 0))
                        .unwrap()
                        .local_addr()
                        .unwrap()
                        .port()
                };
                let info = NodeInfo {
                    node_type: protocol.into(),
                    server_port: port,
                    listen_ip: Some(address.into()),
                    tls: Some(1),
                    tls_settings: Some(serde_json::json!({"allow_insecure":true})),
                    ..Default::default()
                };
                let mut active = runner
                    .launch_inbound(&info, &[])
                    .await
                    .unwrap_or_else(|e| panic!("{protocol} on {address}: {e}"));
                if protocol == "anytls" {
                    assert!(std::net::TcpListener::bind((address, port)).is_err());
                    if address == "127.0.0.1" {
                        assert!(std::net::TcpListener::bind(("127.0.0.2", port)).is_ok());
                    }
                } else {
                    assert!(std::net::UdpSocket::bind((address, port)).is_err());
                    if address == "127.0.0.1" {
                        assert!(std::net::UdpSocket::bind(("127.0.0.2", port)).is_ok());
                    }
                }
                active.stop().await;
            }
        }
    }

    #[tokio::test]
    async fn inbound_readiness_reports_bind_and_config_failures() {
        let runner = runner("http://127.0.0.1:1".into());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut info = NodeInfo {
            node_type: "trojan".into(),
            server_port: port,
            listen_ip: Some("127.0.0.1".into()),
            tls_settings: Some(serde_json::json!({"allow_insecure":true})),
            ..Default::default()
        };
        let ctx = runner.inbound_context(&info).unwrap();
        assert!(Arc::ptr_eq(
            &ctx.rate_limiter,
            &runner.inbound_context(&info).unwrap().rate_limiter
        ));
        assert!(runner.launch_inbound(&info, &[]).await.is_err());
        drop(listener);
        let mut active = runner.launch_inbound(&info, &[]).await.unwrap();
        active.stop().await;
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
            .await
            .unwrap();
        drop(listener);
        info.node_type = "unknown-protocol".into();
        assert_eq!(
            runner
                .launch_inbound(&info, &[])
                .await
                .err()
                .unwrap()
                .kind(),
            std::io::ErrorKind::Unsupported
        );
        info.server_port = 0;
        assert!(runner.inbound_context(&info).is_err());
    }

    #[tokio::test]
    async fn offline_ip_reports_are_explicit_and_retried_after_failure() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut runner = runner(format!("http://{}", listener.local_addr().unwrap()));
            let directory = std::env::temp_dir().join(format!("elise-online-{}", uuid::Uuid::new_v4()));
            runner.traffic_path = directory.join("traffic.json");
            runner.restore_pending().unwrap();
            let mut config = (*runner.global_config).clone();
            config.submit_alive_ip_min_traffic = 0;
            runner.global_config = Arc::new(config);
            let server = tokio::spawn(async move {
                for step in 0..3 {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    let mut header = Vec::new();
                    while !header.ends_with(b"\r\n\r\n") { header.push(stream.read_u8().await.unwrap()); }
                    let header = String::from_utf8(header).unwrap().to_lowercase();
                    assert!(header.contains("/mod_mu/users/aliveip?"));
                    let length = header.lines().find_map(|line| line.strip_prefix("content-length:")).unwrap().trim().parse().unwrap();
                    let mut body = vec![0; length];
                    stream.read_exact(&mut body).await.unwrap();
                    let devices: Vec<OnlineDeviceItem> = serde_json::from_slice(&body).unwrap();
                    assert_eq!(devices.len(), 1);
                    assert_eq!(devices[0].user_id, 7);
                    assert_eq!(devices[0].ips, if step == 0 { vec!["192.0.2.7".to_owned()] } else { vec![] });
                    let status = if step == 1 { "500 Internal Server Error" } else { "200 OK" };
                    stream.write_all(format!("HTTP/1.1 {status}\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}").as_bytes()).await.unwrap();
                }
            });
            let guard = runner.device_limiter.try_acquire_async(7, "192.0.2.7".parse().unwrap()).await.unwrap();
            runner.report_data(false).await;
            assert!(runner.reported_online.lock().contains_key(&7));
            drop(guard);
            runner.report_data(false).await;
            assert!(runner.reported_online.lock().contains_key(&7));
            runner.report_data(false).await;
            assert!(runner.reported_online.lock().is_empty());
            server.await.unwrap();
            std::fs::remove_dir_all(directory).unwrap();
        }).await.unwrap();
    }

    #[tokio::test]
    async fn traffic_retries_failures_and_serializes_ack_with_new_traffic() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let runner = Arc::new(runner(format!("http://{}", listener.local_addr().unwrap())));
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let mut started = Some(started_tx);
            let mut release = Some(release_rx);
            let mut requests = Vec::new();
            for step in 0..4 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut header = Vec::new();
                while !header.ends_with(b"\r\n\r\n") {
                    header.push(stream.read_u8().await.unwrap());
                }
                let header = String::from_utf8(header).unwrap().to_lowercase();
                let len: usize = header
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length:"))
                    .unwrap()
                    .trim()
                    .parse()
                    .unwrap();
                let mut body = vec![0; len];
                stream.read_exact(&mut body).await.unwrap();
                let items: Vec<TrafficItem> = serde_json::from_slice(&body).unwrap();
                requests.push((items[0].u, items[0].d));
                if step == 1 {
                    tokio::time::sleep(Duration::from_secs(16)).await;
                    continue;
                }
                if step == 2 {
                    started.take().unwrap().send(()).unwrap();
                    release.take().unwrap().await.unwrap();
                }
                let status = if step == 0 {
                    "500 Internal Server Error"
                } else {
                    "200 OK"
                };
                stream.write_all(format!("HTTP/1.1 {status}\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}").as_bytes()).await.unwrap();
            }
            requests
        });
        runner.traffic_buffer.lock().insert(42, (100, 500));
        runner.report_data(false).await;
        assert_eq!(runner.traffic_buffer.lock()[&42], (100, 500));
        runner.report_data(false).await;
        assert_eq!(runner.traffic_buffer.lock()[&42], (100, 500));
        let r = runner.clone();
        let first = tokio::spawn(async move { r.report_data(false).await });
        started_rx.await.unwrap();
        *runner.traffic_buffer.lock().get_mut(&42).unwrap() = (130, 570);
        let r = runner.clone();
        let concurrent = tokio::spawn(async move { r.report_data(false).await });
        release_tx.send(()).unwrap();
        first.await.unwrap();
        concurrent.await.unwrap();
        assert!(runner.traffic_buffer.lock().is_empty());
        assert_eq!(
            server.await.unwrap(),
            vec![(100, 500), (100, 500), (100, 500), (30, 70)]
        );
    }
    #[tokio::test]
    async fn pending_traffic_survives_restart_and_rejects_conflicting_or_corrupt_state() {
        let dir = std::env::temp_dir().join(format!("elise-traffic-{}", uuid::Uuid::new_v4()));
        let path = dir.join("pending.json");
        let mut first = runner("http://127.0.0.1:1".into());
        first.traffic_path = path.clone();
        first.restore_pending().unwrap();
        first.traffic_buffer.lock().insert(42, (100, 500));
        first.save_pending().await.unwrap();
        let mut second = runner("http://127.0.0.1:1".into());
        second.traffic_path = path.clone();
        assert!(second.restore_pending().is_err());
        drop(first);
        second.restore_pending().unwrap();
        assert_eq!(second.traffic_buffer.lock()[&42], (100, 500));
        second.traffic_buffer.lock().insert(42, (130, 570));
        std::fs::create_dir(path.with_extension("tmp")).unwrap();
        assert!(second.save_pending().await.is_err());
        let stored: HashMap<u32, (u64, u64)> =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(stored[&42], (100, 500));
        std::fs::remove_dir(path.with_extension("tmp")).unwrap();
        second.save_pending().await.unwrap();
        drop(second);
        let mut restored = runner("http://127.0.0.1:1".into());
        restored.traffic_path = path.clone();
        restored.restore_pending().unwrap();
        assert_eq!(restored.traffic_buffer.lock()[&42], (130, 570));
        restored.traffic_buffer.lock().clear();
        restored.save_pending().await.unwrap();
        drop(restored);
        std::fs::write(&path, b"{bad-json").unwrap();
        let mut corrupt = runner("http://127.0.0.1:1".into());
        corrupt.traffic_path = path.clone();
        assert!(corrupt.restore_pending().is_err());
        assert!(corrupt.traffic_file_lock.lock().is_none());
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_file(path.with_extension("lock")).unwrap();
        std::fs::remove_dir(dir).unwrap();
    }
}
