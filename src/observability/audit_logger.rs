use super::queue::{LogQueue, Message};
use super::rolling::{LogLimits, RollingFile};
use chrono::Utc;
use serde::Serialize;
use std::io::Write;
use std::path::Path;

#[derive(Debug, Clone, Serialize)]
pub struct AuditRecord {
    #[serde(rename = "time")]
    pub timestamp: String,
    pub node_id: u32,
    pub user_id: u32,
    pub protocol: String,
    pub network: String,
    pub client_ip: String,
    pub target_host: String,
    #[serde(default)]
    pub target_ip: String,
    pub target_port: u16,
    #[serde(default)]
    pub target: String,
    #[serde(default)]
    pub original_target: String,
    #[serde(default)]
    pub path: String,
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub duration_ms: i64,
    pub outbound: String,
    pub status: String,
    #[serde(default)]
    pub source: String,
}

impl AuditRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        node_id: u32,
        user_id: u32,
        protocol: &str,
        network: &str,
        client_ip: &str,
        target_host: &str,
        target_port: u16,
        upload_bytes: u64,
        download_bytes: u64,
        duration_ms: i64,
        outbound: &str,
        status: &str,
    ) -> Self {
        let target = format!("{}:{}", target_host, target_port);
        Self {
            timestamp: Utc::now().to_rfc3339(),
            node_id,
            user_id,
            protocol: protocol.to_string(),
            network: network.to_string(),
            client_ip: client_ip.to_string(),
            target_host: target_host.to_string(),
            target_ip: target_host.to_string(),
            target_port,
            target: target.clone(),
            original_target: target,
            path: String::new(),
            upload_bytes,
            download_bytes,
            duration_ms,
            outbound: outbound.to_string(),
            status: status.to_string(),
            source: "client".to_string(),
        }
    }
}

impl Default for AuditRecord {
    fn default() -> Self {
        Self {
            timestamp: Utc::now().to_rfc3339(),
            node_id: 0,
            user_id: 0,
            protocol: String::new(),
            network: "tcp".to_string(),
            client_ip: String::new(),
            target_host: String::new(),
            target_ip: String::new(),
            target_port: 0,
            target: String::new(),
            original_target: String::new(),
            path: String::new(),
            upload_bytes: 0,
            download_bytes: 0,
            duration_ms: 0,
            outbound: "direct".to_string(),
            status: "connected".to_string(),
            source: "local".to_string(),
        }
    }
}

impl AuditRecord {
    pub(crate) fn sanitize(&mut self) {
        if self.timestamp.is_empty() {
            self.timestamp = Utc::now().to_rfc3339();
        }
        if self.target.is_empty() {
            self.target = format!("{}:{}", self.target_host, self.target_port);
        }
        if self.original_target.is_empty() {
            self.original_target = self.target.clone();
        }
        if self.target_ip.is_empty() {
            self.target_ip = self.target_host.clone();
        }
        if self.source.is_empty() {
            self.source = "client".into();
        }
        // URL paths may contain access tokens; retain the path but no query/fragment.
        self.path = self
            .path
            .split(['?', '#'])
            .next()
            .unwrap_or_default()
            .to_string();
        for value in [
            &mut self.timestamp,
            &mut self.protocol,
            &mut self.network,
            &mut self.client_ip,
            &mut self.target_host,
            &mut self.target_ip,
            &mut self.target,
            &mut self.original_target,
            &mut self.path,
            &mut self.outbound,
            &mut self.status,
            &mut self.source,
        ] {
            *value = super::logger::redact(value);
            super::logger::truncate(value, 1024);
        }
    }
}

#[derive(Clone)]
pub struct AuditLogger {
    queue: Option<LogQueue>,
}

impl AuditLogger {
    pub fn new<P: AsRef<Path>>(file_path: Option<P>) -> Self {
        Self::with_limits(file_path, LogLimits::default()).unwrap_or_else(|error| {
            tracing::error!(%error, "Cannot initialize audit log");
            Self { queue: None }
        })
    }

    pub fn with_limits<P: AsRef<Path>>(
        file_path: Option<P>,
        limits: LogLimits,
    ) -> std::io::Result<Self> {
        let Some(path) = file_path else {
            return Ok(Self { queue: None });
        };
        let mut file = RollingFile::new(path.as_ref(), limits)?;
        let (queue, mut rx) = LogQueue::new("audit file");
        // File I/O never blocks Tokio's networking threads.
        tokio::task::spawn_blocking(move || {
            let mut failures = 0u64;
            while let Some(message) = rx.blocking_recv() {
                match message {
                    Message::Record(record) => {
                        let result = serde_json::to_vec(&record)
                            .map_err(std::io::Error::other)
                            .and_then(|mut bytes| {
                                bytes.push(b'\n');
                                file.write_all(&bytes)
                            });
                        if let Err(error) = result {
                            failures += 1;
                            if failures.is_power_of_two() {
                                tracing::warn!(%error, failures, "Audit file write failed; record dropped");
                            }
                        } else if failures > 0 {
                            tracing::info!(dropped = failures, "Audit file writes recovered");
                            failures = 0;
                        }
                    }
                    Message::Shutdown(done) => {
                        if let Err(error) = file.flush() {
                            tracing::warn!(%error, "Audit log flush failed");
                        }
                        let _ = done.send(());
                        break;
                    }
                }
            }
        });
        Ok(Self { queue: Some(queue) })
    }
    pub fn record(&self, record: AuditRecord) {
        if let Some(queue) = &self.queue {
            queue.record(record);
        }
    }
    pub async fn shutdown(&self) {
        if let Some(queue) = &self.queue {
            queue.shutdown().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn shutdown_drains_and_rotates_audit_records() {
        let dir = std::env::temp_dir().join(format!("elise-audit-{}", uuid::Uuid::new_v4()));
        let path = dir.join("access.log");
        let logger = AuditLogger::with_limits(
            Some(&path),
            LogLimits {
                max_bytes: 800,
                max_files: 3,
                ..Default::default()
            },
        )
        .unwrap();
        for id in 0..10 {
            logger.record(AuditRecord {
                user_id: id,
                path: "/path?token=secret".into(),
                ..Default::default()
            });
        }
        logger.shutdown().await;
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains("secret"));
        let last: serde_json::Value = serde_json::from_str(text.lines().last().unwrap()).unwrap();
        assert_eq!(last["user_id"], 9);
        assert!(std::fs::read_dir(&dir).unwrap().count() <= 3);
        for file in std::fs::read_dir(&dir).unwrap() {
            assert!(file.unwrap().metadata().unwrap().len() <= 800);
        }
        std::fs::remove_dir_all(dir).unwrap();
    }
}
