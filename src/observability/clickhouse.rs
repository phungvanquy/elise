use super::queue::{LogQueue, Message};
use crate::observability::AuditRecord;
use std::time::Duration;

#[derive(Clone)]
pub struct ClickHouseLogger {
    queue: Option<LogQueue>,
}

impl ClickHouseLogger {
    pub fn new(
        enabled: bool,
        addr: String,
        db: String,
        table: String,
        user: String,
        password: Option<String>,
    ) -> Self {
        if !enabled {
            return Self { queue: None };
        }
        let Ok(mut url) = reqwest::Url::parse(&addr) else {
            tracing::error!("Invalid ClickHouse URL; access log sink disabled");
            return Self { queue: None };
        };
        url.query_pairs_mut()
            .append_pair("database", &db)
            .append_pair("query", &format!("INSERT INTO {table} FORMAT JSONEachRow"));
        let client = match reqwest::Client::builder()
            .timeout(Duration::from_secs(3))
            .build()
        {
            Ok(client) => client,
            Err(error) => {
                tracing::error!(error = %error.without_url(), "Cannot initialize ClickHouse client");
                return Self { queue: None };
            }
        };
        let (queue, mut rx) = LogQueue::new("ClickHouse");
        tokio::spawn(async move {
            let mut batch = Vec::new();
            let mut interval = tokio::time::interval(Duration::from_secs(5));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut attempts = 0;
            let mut failures = 0u64;
            let mut lost_batches = 0u64;
            let mut lost_records = 0u64;
            loop {
                let mut shutdown = None;
                tokio::select! {
                    message = rx.recv(), if attempts == 0 && batch.len() < 500 => {
                        match message {
                            Some(Message::Record(record)) => {
                                batch.push(*record);
                                if batch.len() < 500 { continue; }
                            }
                            Some(Message::Shutdown(done)) => shutdown = Some(done),
                            None => {
                                if !batch.is_empty() {
                                    if let Err(error) = Self::flush(&client, &url, &user, password.as_deref(), &mut batch).await {
                                        tracing::warn!(%error, dropped = batch.len(), "ClickHouse final batch failed");
                                    }
                                }
                                break;
                            }
                        }
                    }
                    _ = interval.tick() => {}
                }
                if !batch.is_empty() {
                    match Self::flush(&client, &url, &user, password.as_deref(), &mut batch).await {
                        Ok(()) => {
                            attempts = 0;
                            if failures > 0 {
                                tracing::info!(
                                    failed_attempts = failures,
                                    "ClickHouse logging recovered"
                                );
                                failures = 0;
                            }
                        }
                        Err(error) => {
                            attempts += 1;
                            failures += 1;
                            if failures.is_power_of_two() {
                                tracing::warn!(%error, failed_attempts = failures, "ClickHouse write failed; bounded retries enabled");
                            }
                            if attempts >= 3 || shutdown.is_some() {
                                lost_batches += 1;
                                lost_records += batch.len() as u64;
                                if lost_batches.is_power_of_two() {
                                    tracing::warn!(
                                        lost_batches,
                                        lost_records,
                                        "ClickHouse retry limit reached; records dropped"
                                    );
                                }
                                batch.clear();
                                attempts = 0;
                            }
                        }
                    }
                }
                if let Some(done) = shutdown {
                    let _ = done.send(());
                    break;
                }
            }
        });
        Self { queue: Some(queue) }
    }

    async fn flush(
        client: &reqwest::Client,
        url: &reqwest::Url,
        user: &str,
        password: Option<&str>,
        batch: &mut Vec<AuditRecord>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut body = Vec::new();
        for record in batch.iter() {
            serde_json::to_writer(&mut body, record)?;
            body.push(b'\n');
        }
        let mut request = client.post(url.clone()).body(body);
        if !user.is_empty() {
            request = request.header("X-ClickHouse-User", user);
        }
        if let Some(password) = password {
            request = request.header("X-ClickHouse-Key", password);
        }
        request
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(reqwest::Error::without_url)?;
        batch.clear();
        Ok(())
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    #[tokio::test]
    async fn failed_http_response_keeps_batch_for_retry() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/?token=secret", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        let server = tokio::spawn(async move {
            for status in ["500 Internal Server Error", "200 OK"] {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut header = Vec::new();
                while !header.ends_with(b"\r\n\r\n") {
                    header.push(socket.read_u8().await.unwrap());
                }
                let header = String::from_utf8(header).unwrap().to_lowercase();
                let count = header
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length: "))
                    .unwrap()
                    .parse()
                    .unwrap();
                let mut body = vec![0; count];
                socket.read_exact(&mut body).await.unwrap();
                assert!(String::from_utf8(body).unwrap().contains("\"user_id\":7"));
                socket
                    .write_all(
                        format!(
                            "HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
            }
        });
        let client = reqwest::Client::new();
        let mut batch = vec![AuditRecord {
            user_id: 7,
            ..Default::default()
        }];
        let error = ClickHouseLogger::flush(&client, &url, "", None, &mut batch)
            .await
            .unwrap_err();
        assert!(!error.to_string().contains("secret"));
        assert_eq!(batch.len(), 1);
        ClickHouseLogger::flush(&client, &url, "", None, &mut batch)
            .await
            .unwrap();
        assert!(batch.is_empty());
        server.await.unwrap();
    }
}
