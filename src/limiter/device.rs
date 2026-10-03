use parking_lot::Mutex;
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[cfg(feature = "distributed")]
use redis::aio::ConnectionManager;

// UniProxy retains submitted IPs for 120s and caches totals for another 60s.
const PANEL_REPORT_GRACE: Duration = Duration::from_secs(180);

const REDIS_DEVICE_LIMIT_LUA: &str = r#"
local cutoff = tonumber(ARGV[2]) - tonumber(ARGV[3])
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', cutoff)
local score = redis.call('ZSCORE', KEYS[1], ARGV[1])
if score then
    redis.call('ZADD', KEYS[1], ARGV[2], ARGV[1])
    redis.call('EXPIRE', KEYS[1], ARGV[3])
    return 1
end
local limit = tonumber(ARGV[4])
if limit and limit > 0 then
    local count = redis.call('ZCARD', KEYS[1])
    if count >= limit then
        return 0
    end
end
redis.call('ZADD', KEYS[1], ARGV[2], ARGV[1])
redis.call('EXPIRE', KEYS[1], ARGV[3])
return 1
"#;

struct Device {
    last_seen: Instant,
    connections: usize,
}

impl Device {
    fn online(&self, now: Instant, window: Duration) -> bool {
        self.connections > 0 || now.duration_since(self.last_seen) < window
    }
}

/// Keeps a normalized IP occupied until the last authenticated session closes.
pub struct DeviceGuard {
    limiter: DeviceLimiter,
    user_id: u32,
    device_key: String,
}

impl Drop for DeviceGuard {
    fn drop(&mut self) {
        let mut users = self.limiter.user_devices.lock();
        if let Some(devices) = users.get_mut(&self.user_id) {
            if let Some(device) = devices.get_mut(&self.device_key) {
                device.connections -= 1;
                if device.connections == 0 {
                    devices.remove(&self.device_key);
                }
            }
            if devices.is_empty() {
                users.remove(&self.user_id);
            }
        }
    }
}

struct PanelReport {
    at: Instant,
    counts: HashMap<u32, usize>,
}

#[derive(Clone)]
pub struct DeviceLimiter {
    window_duration: Duration,
    prefix_v4: u8,
    prefix_v6: u8,
    user_devices: Arc<Mutex<HashMap<u32, HashMap<String, Device>>>>,
    user_limits: Arc<Mutex<HashMap<u32, u32>>>,
    global_alive: Arc<Mutex<HashMap<u32, u32>>>,
    // UniProxy alive counts include our own reports and may be cached for 60s.
    // Keep acknowledged contributions through the IP TTL and cached totals.
    reported_local: Arc<Mutex<VecDeque<PanelReport>>>,
    redis_url: Option<String>,
    conn_limit_expiry: u64,
    redis_timeout: Duration,
    #[cfg(feature = "distributed")]
    redis_manager: Arc<tokio::sync::RwLock<Option<ConnectionManager>>>,
}

impl DeviceLimiter {
    pub fn new(window_secs: u64, prefix_v4: u8, prefix_v6: u8, redis_url: Option<String>) -> Self {
        Self::new_with_redis(
            window_secs,
            prefix_v4,
            prefix_v6,
            redis_url,
            window_secs,
            300,
        )
    }

    pub fn new_with_redis(
        window_secs: u64,
        prefix_v4: u8,
        prefix_v6: u8,
        redis_url: Option<String>,
        conn_limit_expiry: u64,
        redis_timeout_ms: u64,
    ) -> Self {
        Self {
            window_duration: Duration::from_secs(window_secs.max(1)),
            prefix_v4: prefix_v4.min(32),
            prefix_v6: prefix_v6.min(128),
            user_devices: Arc::new(Mutex::new(HashMap::new())),
            user_limits: Arc::new(Mutex::new(HashMap::new())),
            global_alive: Arc::new(Mutex::new(HashMap::new())),
            reported_local: Arc::new(Mutex::new(VecDeque::new())),
            redis_url,
            conn_limit_expiry: conn_limit_expiry.max(1),
            redis_timeout: Duration::from_millis(redis_timeout_ms.max(50)),
            #[cfg(feature = "distributed")]
            redis_manager: Arc::new(tokio::sync::RwLock::new(None)),
        }
    }

    pub fn update_global_alive(&self, map: HashMap<u32, u32>) {
        *self.global_alive.lock() = map;
    }

    pub fn record_panel_report(&self, devices: &HashMap<u32, Vec<String>>) {
        let now = Instant::now();
        let mut reports = self.reported_local.lock();
        reports.retain(|report| now.duration_since(report.at) < PANEL_REPORT_GRACE);
        reports.push_back(PanelReport {
            at: now,
            counts: devices.iter().map(|(&uid, ips)| (uid, ips.len())).collect(),
        });
    }

    fn remote_devices(&self, user_id: u32, now: Instant) -> u32 {
        let total = self.global_alive.lock().get(&user_id).copied().unwrap_or(0);
        let mut reports = self.reported_local.lock();
        reports.retain(|report| now.duration_since(report.at) < PANEL_REPORT_GRACE);
        let own = reports
            .iter()
            .filter_map(|report| report.counts.get(&user_id))
            .copied()
            .max()
            .unwrap_or(0);
        total.saturating_sub(own as u32)
    }

    pub fn redis_url(&self) -> Option<&str> {
        self.redis_url.as_deref()
    }

    pub fn set_user_limit(&self, user_id: u32, limit: u32) {
        let mut map = self.user_limits.lock();
        if limit > 0 {
            map.insert(user_id, limit);
        } else {
            map.remove(&user_id);
        }
    }

    pub fn get_online_devices(&self, user_id: u32) -> Vec<String> {
        let now = Instant::now();
        let mut map = self.user_devices.lock();
        if let Some(devices) = map.get_mut(&user_id) {
            devices.retain(|_, device| device.online(now, self.window_duration));
            let res: Vec<String> = devices.keys().cloned().collect();
            if devices.is_empty() {
                map.remove(&user_id);
            }
            res
        } else {
            Vec::new()
        }
    }

    pub async fn get_online_devices_async(&self, user_id: u32) -> Vec<String> {
        #[cfg(feature = "distributed")]
        if let Some(url) = &self.redis_url {
            if let Ok(ips) = self.get_redis_online_devices(user_id, url).await {
                return ips;
            }
        }
        self.get_online_devices(user_id)
    }

    #[cfg(feature = "distributed")]
    async fn get_redis_online_devices(
        &self,
        user_id: u32,
        url: &str,
    ) -> redis::RedisResult<Vec<String>> {
        let mgr = {
            let manager_guard = self.redis_manager.read().await;
            manager_guard.clone()
        };

        let mut mgr = match mgr {
            Some(m) => m,
            None => {
                let mut write_guard = self.redis_manager.write().await;
                if write_guard.is_none() {
                    let client = redis::Client::open(url)?;
                    let m = client.get_connection_manager().await?;
                    *write_guard = Some(m);
                }
                write_guard.clone().unwrap()
            }
        };

        let key = format!("elise:user_ips:{}", user_id);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let cutoff = now.saturating_sub(self.conn_limit_expiry);

        let ips: Vec<String> = redis::cmd("ZRANGEBYSCORE")
            .arg(key)
            .arg(cutoff)
            .arg("+inf")
            .query_async(&mut mgr)
            .await?;

        Ok(ips)
    }

    pub fn get_all_online_devices(&self) -> HashMap<u32, Vec<String>> {
        let now = Instant::now();
        let mut map = self.user_devices.lock();
        let mut result = HashMap::new();

        map.retain(|&user_id, devices| {
            devices.retain(|_, device| device.online(now, self.window_duration));
            if devices.is_empty() {
                false
            } else {
                result.insert(user_id, devices.keys().cloned().collect());
                true
            }
        });

        result
    }

    pub fn check_and_record(&self, user_id: u32, ip: IpAddr) -> bool {
        self.record_local(user_id, ip, false, true)
    }

    fn record_local(&self, user_id: u32, ip: IpAddr, acquire: bool, enforce: bool) -> bool {
        let limit = self.user_limits.lock().get(&user_id).copied();
        let device_key = self.normalize_ip(ip);

        let now = Instant::now();
        let mut map = self.user_devices.lock();
        let devices = map.entry(user_id).or_default();

        devices.retain(|_, device| device.online(now, self.window_duration));

        if let Some(max_dev) = limit.filter(|_| enforce || acquire) {
            if !devices.contains_key(&device_key) {
                let remote_devs = if enforce {
                    self.remote_devices(user_id, now)
                } else {
                    0
                };
                if (devices.len() as u32).saturating_add(remote_devs) >= max_dev {
                    return false;
                }
            }
        }

        let device = devices.entry(device_key).or_insert(Device {
            last_seen: now,
            connections: 0,
        });
        device.last_seen = now;
        if acquire {
            device.connections += 1;
        }
        true
    }

    pub async fn try_acquire_async(&self, user_id: u32, ip: IpAddr) -> Option<DeviceGuard> {
        #[allow(unused_mut)] // Remains immutable when Redis support is disabled.
        let mut enforce_local = true;
        #[cfg(feature = "distributed")]
        if let Some(url) = &self.redis_url {
            match tokio::time::timeout(self.redis_timeout, self.check_redis(user_id, ip, url)).await
            {
                Ok(Ok(false)) => return None,
                Ok(Ok(true)) => enforce_local = false,
                _ => tracing::warn!(
                    user_id,
                    "Redis device check unavailable; using local IP limit"
                ),
            }
        }
        if !self.record_local(user_id, ip, true, enforce_local) {
            return None;
        }
        Some(DeviceGuard {
            limiter: self.clone(),
            user_id,
            device_key: self.normalize_ip(ip),
        })
    }

    pub async fn check_and_record_async(&self, user_id: u32, ip: IpAddr) -> bool {
        #[cfg(feature = "distributed")]
        if let Some(url) = &self.redis_url {
            let res =
                tokio::time::timeout(self.redis_timeout, self.check_redis(user_id, ip, url)).await;
            match res {
                Ok(Ok(allowed)) => {
                    if allowed {
                        self.record_local(user_id, ip, false, false);
                    }
                    return allowed;
                }
                Ok(Err(e)) => {
                    tracing::warn!(
                        user_id,
                        "Redis device limit check error, falling back to local: {}",
                        e
                    );
                }
                Err(_) => {
                    tracing::warn!(
                        user_id,
                        "Redis device limit check timed out after {}ms, falling back to local",
                        self.redis_timeout.as_millis()
                    );
                }
            }
        }
        self.check_and_record(user_id, ip)
    }

    #[cfg(feature = "distributed")]
    async fn check_redis(&self, user_id: u32, ip: IpAddr, url: &str) -> redis::RedisResult<bool> {
        let mgr = {
            let manager_guard = self.redis_manager.read().await;
            manager_guard.clone()
        };

        let mut mgr = match mgr {
            Some(m) => m,
            None => {
                let mut write_guard = self.redis_manager.write().await;
                if write_guard.is_none() {
                    let client = redis::Client::open(url)?;
                    let m = client.get_connection_manager().await?;
                    *write_guard = Some(m);
                }
                write_guard.clone().unwrap()
            }
        };

        let key = format!("elise:user_ips:{}", user_id);
        let device_key = self.normalize_ip(ip);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let limit = self.user_limits.lock().get(&user_id).copied().unwrap_or(0);

        let script = redis::Script::new(REDIS_DEVICE_LIMIT_LUA);
        let res: redis::RedisResult<i32> = script
            .key(key)
            .arg(device_key)
            .arg(now)
            .arg(self.conn_limit_expiry)
            .arg(limit)
            .invoke_async(&mut mgr)
            .await;

        match res {
            Ok(result) => Ok(result == 1),
            Err(e) => {
                if e.is_io_error() || e.is_connection_dropped() || e.is_connection_refusal() {
                    *self.redis_manager.write().await = None;
                }
                Err(e)
            }
        }
    }

    pub fn prune_expired(&self) {
        let now = Instant::now();
        let mut map = self.user_devices.lock();
        map.retain(|_, devices| {
            devices.retain(|_, device| device.online(now, self.window_duration));
            !devices.is_empty()
        });
    }

    pub fn normalize_ip(&self, ip: IpAddr) -> String {
        match ip.to_canonical() {
            IpAddr::V4(v4) => {
                if self.prefix_v4 >= 32 {
                    v4.to_string()
                } else if self.prefix_v4 == 0 {
                    "0.0.0.0/0".to_string()
                } else {
                    let mask = !((1u64 << (32 - self.prefix_v4)) - 1) as u32;
                    let masked = u32::from(v4) & mask;
                    format!("{}/{}", Ipv4Addr::from(masked), self.prefix_v4)
                }
            }
            IpAddr::V6(v6) => {
                if self.prefix_v6 >= 128 {
                    v6.to_string()
                } else if self.prefix_v6 == 0 {
                    "::/0".to_string()
                } else {
                    let mask = !((1u128 << (128 - self.prefix_v6)) - 1);
                    let masked = u128::from(v6) & mask;
                    format!("{}/{}", Ipv6Addr::from(masked), self.prefix_v6)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_normalization() {
        let limiter = DeviceLimiter::new(60, 24, 64, None);
        let ip: IpAddr = "192.168.1.123".parse().unwrap();
        assert_eq!(limiter.normalize_ip(ip), "192.168.1.0/24");

        let limiter16 = DeviceLimiter::new(60, 16, 64, None);
        assert_eq!(limiter16.normalize_ip(ip), "192.168.0.0/16");
    }

    #[test]
    fn mapped_ipv4_uses_ipv4_device_identity() {
        let limiter = DeviceLimiter::new(60, 32, 64, None);
        let mapped = "::ffff:192.0.2.17".parse().unwrap();
        assert_eq!(limiter.normalize_ip(mapped), "192.0.2.17");
        assert_eq!(
            DeviceLimiter::new(60, 24, 64, None).normalize_ip(mapped),
            "192.0.2.0/24"
        );
        assert_eq!(
            limiter.normalize_ip("2001:db8:1:2::17".parse().unwrap()),
            "2001:db8:1:2::/64"
        );

        limiter.set_user_limit(12, 1);
        assert!(limiter.check_and_record(12, mapped));
        assert!(limiter.check_and_record(12, "192.0.2.17".parse().unwrap()));
        assert!(!limiter.check_and_record(12, "::ffff:192.0.2.18".parse().unwrap()));
        assert_eq!(limiter.get_online_devices(12), vec!["192.0.2.17"]);
    }

    #[test]
    fn test_device_limiter_pruning() {
        let limiter = DeviceLimiter::new(1, 32, 128, None);
        let ip: IpAddr = "1.1.1.1".parse().unwrap();
        assert!(limiter.check_and_record(100, ip));
        assert_eq!(limiter.get_online_devices(100).len(), 1);

        std::thread::sleep(Duration::from_millis(1100));
        limiter.prune_expired();
        assert_eq!(limiter.get_online_devices(100).len(), 0);
    }
    #[tokio::test]
    async fn last_disconnect_releases_slot_and_active_sessions_never_expire() {
        let limiter = DeviceLimiter::new(300, 32, 64, None);
        limiter.set_user_limit(7, 1);
        let first = "192.0.2.1".parse().unwrap();
        let next = "192.0.2.2".parse().unwrap();
        let a = limiter.try_acquire_async(7, first).await.unwrap();
        let b = limiter.try_acquire_async(7, first).await.unwrap();
        limiter
            .user_devices
            .lock()
            .get_mut(&7)
            .unwrap()
            .get_mut("192.0.2.1")
            .unwrap()
            .last_seen = Instant::now() - Duration::from_secs(600);
        limiter.prune_expired();
        assert_eq!(limiter.get_online_devices(7), vec!["192.0.2.1"]);
        assert!(limiter.try_acquire_async(7, next).await.is_none());
        drop(a);
        assert!(limiter.try_acquire_async(7, next).await.is_none());
        drop(b);
        assert!(limiter.get_all_online_devices().is_empty());
        let _next = limiter.try_acquire_async(7, next).await.unwrap();
    }

    #[tokio::test]
    async fn shared_ipv6_prefix_and_mapped_ipv4_release_after_last_session() {
        let limiter = DeviceLimiter::new(300, 32, 64, None);
        limiter.set_user_limit(1, 1);
        for (first, same, other) in [
            ("2001:db8::1", "2001:db8::2", "2001:db8:1::1"),
            ("192.0.2.1", "::ffff:192.0.2.1", "192.0.2.2"),
        ] {
            let a = limiter
                .try_acquire_async(1, first.parse().unwrap())
                .await
                .unwrap();
            let b = limiter
                .try_acquire_async(1, same.parse().unwrap())
                .await
                .unwrap();
            drop(a);
            assert!(limiter
                .try_acquire_async(1, other.parse().unwrap())
                .await
                .is_none());
            drop(b);
            assert!(limiter
                .try_acquire_async(1, other.parse().unwrap())
                .await
                .is_some());
        }
    }

    #[tokio::test]
    async fn cancellation_releases_device_even_without_a_tcp_limit() {
        let limiter = DeviceLimiter::new(300, 32, 64, None);
        limiter.set_user_limit(1, 1);
        let device = limiter
            .try_acquire_async(1, "192.0.2.1".parse().unwrap())
            .await
            .unwrap();
        let guard = crate::limiter::ConnectionLimiter::new()
            .try_acquire(1)
            .unwrap()
            .with_device(device);
        let task = tokio::spawn(async move {
            let _guard = guard;
            std::future::pending::<()>().await;
        });
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(limiter
            .try_acquire_async(1, "192.0.2.2".parse().unwrap())
            .await
            .is_some());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_connect_disconnect_and_prune_respects_limit() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let limiter = DeviceLimiter::new(300, 32, 64, None);
        limiter.set_user_limit(1, 1);
        let active = Arc::new(AtomicUsize::new(0));
        let mut tasks = tokio::task::JoinSet::new();
        for index in 1..=16 {
            let limiter = limiter.clone();
            let active = active.clone();
            tasks.spawn(async move {
                let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, index));
                for _ in 0..200 {
                    if let Some(guard) = limiter.try_acquire_async(1, ip).await {
                        assert_eq!(active.fetch_add(1, Ordering::SeqCst), 0);
                        tokio::task::yield_now().await;
                        assert_eq!(active.fetch_sub(1, Ordering::SeqCst), 1);
                        drop(guard);
                    }
                    limiter.prune_expired();
                    tokio::task::yield_now().await;
                }
            });
        }
        while let Some(result) = tasks.join_next().await {
            result.unwrap();
        }
        assert!(limiter.get_all_online_devices().is_empty());
    }

    #[tokio::test]
    async fn echoed_panel_reports_do_not_double_count_or_block_a_replacement() {
        let limiter = DeviceLimiter::new(300, 32, 64, None);
        limiter.set_user_limit(1, 2);
        let first = limiter
            .try_acquire_async(1, "192.0.2.1".parse().unwrap())
            .await
            .unwrap();
        limiter.record_panel_report(&limiter.get_all_online_devices());
        limiter.update_global_alive(HashMap::from([(1, 1)]));
        let second = limiter
            .try_acquire_async(1, "192.0.2.2".parse().unwrap())
            .await
            .unwrap();
        limiter.record_panel_report(&limiter.get_all_online_devices());
        limiter.update_global_alive(HashMap::from([(1, 2)]));
        assert!(limiter
            .try_acquire_async(1, "192.0.2.3".parse().unwrap())
            .await
            .is_none());
        drop(first);
        drop(second);
        limiter.record_panel_report(&HashMap::from([(1, Vec::new())]));
        let _replacement = limiter
            .try_acquire_async(1, "192.0.2.3".parse().unwrap())
            .await
            .unwrap();
        // Another node's contribution must still consume a slot.
        limiter.update_global_alive(HashMap::from([(1, 3)]));
        assert!(limiter
            .try_acquire_async(1, "192.0.2.4".parse().unwrap())
            .await
            .is_none());
        for report in limiter.reported_local.lock().iter_mut() {
            report.at = Instant::now() - PANEL_REPORT_GRACE - Duration::from_secs(1);
        }
        assert_eq!(limiter.remote_devices(1, Instant::now()), 3);
    }

    #[cfg(feature = "distributed")]
    #[tokio::test]
    async fn redis_outage_falls_back_to_releasable_local_slots() {
        let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("redis://{}", socket.local_addr().unwrap());
        let limiter = DeviceLimiter::new_with_redis(300, 32, 64, Some(url), 60, 50);
        limiter.set_user_limit(1, 1);
        let guard = limiter
            .try_acquire_async(1, "192.0.2.1".parse().unwrap())
            .await
            .unwrap();
        assert!(limiter
            .try_acquire_async(1, "192.0.2.2".parse().unwrap())
            .await
            .is_none());
        drop(guard);
        assert!(limiter
            .try_acquire_async(1, "192.0.2.2".parse().unwrap())
            .await
            .is_some());
    }
}
