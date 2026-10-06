use super::AuditRecord;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

pub(super) enum Message {
    Record(Box<AuditRecord>),
    Shutdown(oneshot::Sender<()>),
}

#[derive(Clone)]
pub(super) struct LogQueue {
    tx: mpsc::Sender<Message>,
    dropped: Arc<AtomicU64>,
    name: &'static str,
}
impl LogQueue {
    pub fn new(name: &'static str) -> (Self, mpsc::Receiver<Message>) {
        let (tx, rx) = mpsc::channel(256);
        (
            Self {
                tx,
                dropped: Arc::new(AtomicU64::new(0)),
                name,
            },
            rx,
        )
    }
    pub fn record(&self, mut record: AuditRecord) {
        record.sanitize();
        if self.tx.try_send(Message::Record(Box::new(record))).is_err() {
            let dropped = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
            // Logarithmic reporting cannot itself flood logs during an outage.
            if dropped.is_power_of_two() {
                tracing::warn!(
                    sink = self.name,
                    dropped,
                    "Access log queue unavailable; records dropped"
                );
            }
        }
    }
    pub async fn shutdown(&self) {
        let (tx, rx) = oneshot::channel();
        let drain = async {
            if self.tx.send(Message::Shutdown(tx)).await.is_ok() {
                let _ = rx.await;
            }
        };
        if tokio::time::timeout(Duration::from_secs(20), drain)
            .await
            .is_err()
        {
            tracing::warn!(
                sink = self.name,
                "Access log shutdown timed out; queued records may be lost"
            );
        }
        let dropped = self.dropped.load(Ordering::Relaxed);
        if dropped > 0 {
            tracing::warn!(sink = self.name, dropped, "Access log drop total");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn overflow_is_bounded_and_counted() {
        let (queue, mut rx) = LogQueue::new("test");
        for _ in 0..300 {
            queue.record(AuditRecord::default());
        }
        assert_eq!(queue.dropped.load(Ordering::Relaxed), 44);
        let mut count = 0;
        while rx.try_recv().is_ok() {
            count += 1;
        }
        assert_eq!(count, 256);
    }
}
