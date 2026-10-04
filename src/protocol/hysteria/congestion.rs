//! Hysteria 2 bandwidth negotiation: BBR for an unknown rate, Brutal otherwise.
//!
//! Brutal uses a fixed, explicitly paced rate and a two-BDP in-flight window.
//! As in Hysteria's Go core, loss compensation samples five seconds and is
//! limited to 25%. Quinn reports lost bytes in batches, so samples here are
//! byte-weighted rather than packet-weighted.

use quinn::congestion::{BbrConfig, Controller, ControllerFactory, ControllerMetrics};
use quinn_proto::RttEstimator;
use std::any::Any;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub(super) struct Hy2CongestionFactory {
    // Each connection gets its own factory. Sharing this with its replacement
    // paths preserves negotiation across QUIC migration and MTU black holes.
    pub send_rate: Arc<AtomicU64>,
}

impl ControllerFactory for Hy2CongestionFactory {
    fn build(self: Arc<Self>, now: Instant, mtu: u16) -> Box<dyn Controller> {
        Box::new(Hy2Controller {
            bbr: Arc::new(BbrConfig::default()).build(now, mtu),
            send_rate: self.send_rate.clone(),
            mtu,
            rtt: Duration::from_millis(333),
            epoch: now,
            samples: [Sample::default(); 5],
            ack_rate: 1.0,
        })
    }
}

#[derive(Clone, Copy, Default)]
struct Sample {
    second: u64,
    acked: u64,
    lost: u64,
}

struct Hy2Controller {
    bbr: Box<dyn Controller>,
    send_rate: Arc<AtomicU64>,
    mtu: u16,
    rtt: Duration,
    epoch: Instant,
    samples: [Sample; 5],
    ack_rate: f64,
}

impl Hy2Controller {
    fn rate(&self) -> u64 {
        self.send_rate.load(Ordering::Acquire)
    }

    fn record(&mut self, now: Instant, acked: u64, lost: u64) {
        let second = now.saturating_duration_since(self.epoch).as_secs();
        let sample = &mut self.samples[second as usize % self.samples.len()];
        if sample.second != second {
            *sample = Sample {
                second,
                ..Sample::default()
            };
        }
        sample.acked = sample.acked.saturating_add(acked);
        sample.lost = sample.lost.saturating_add(lost);
        let (acked, lost) = self
            .samples
            .iter()
            .filter(|sample| second.saturating_sub(sample.second) < 5)
            .fold((0u64, 0u64), |(acked, lost), sample| {
                (
                    acked.saturating_add(sample.acked),
                    lost.saturating_add(sample.lost),
                )
            });
        let total = acked.saturating_add(lost);
        self.ack_rate = if total < 50 * u64::from(self.mtu) {
            1.0
        } else {
            (acked as f64 / total as f64).max(0.8)
        };
    }
}

impl Controller for Hy2Controller {
    fn on_sent(&mut self, now: Instant, bytes: u64, last_packet_number: u64) {
        if self.rate() == 0 {
            self.bbr.on_sent(now, bytes, last_packet_number);
        }
    }

    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        app_limited: bool,
        rtt: &RttEstimator,
    ) {
        self.rtt = rtt.get();
        if self.rate() == 0 {
            self.bbr.on_ack(now, sent, bytes, app_limited, rtt);
        } else {
            self.record(now, bytes, 0);
        }
    }

    fn on_end_acks(
        &mut self,
        now: Instant,
        in_flight: u64,
        app_limited: bool,
        largest_packet_num_acked: Option<u64>,
    ) {
        if self.rate() == 0 {
            self.bbr
                .on_end_acks(now, in_flight, app_limited, largest_packet_num_acked);
        }
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        sent: Instant,
        persistent: bool,
        lost_bytes: u64,
    ) {
        if self.rate() == 0 {
            self.bbr
                .on_congestion_event(now, sent, persistent, lost_bytes);
        } else {
            self.record(now, 0, lost_bytes);
        }
    }

    fn on_mtu_update(&mut self, mtu: u16) {
        self.mtu = mtu;
        self.bbr.on_mtu_update(mtu);
    }

    fn window(&self) -> u64 {
        let rate = self.rate();
        if rate == 0 {
            self.bbr.window()
        } else {
            // Quinn reserves room for a whole packet batch before sending.
            // On short-RTT paths, a one/two-packet window can stall waiting for
            // delayed ACKs. Keep ten packets available; pacing still caps TX.
            ((rate as f64 / self.ack_rate * self.rtt.as_secs_f64() * 2.0) as u64)
                .max(10 * u64::from(self.mtu))
        }
    }

    fn pacing_rate(&self) -> Option<u64> {
        let rate = self.rate();
        if rate > 0 {
            Some((rate as f64 / self.ack_rate) as u64)
        } else {
            // Quinn's BBR exposes its calculated rate in bits/s via metrics.
            // Honor it instead of inferring a rate from its in-flight window.
            self.bbr
                .metrics()
                .pacing_rate
                .map(|bits| bits / 8)
                .filter(|rate| *rate > 0)
        }
    }

    fn metrics(&self) -> ControllerMetrics {
        if self.rate() > 0 {
            let rate = self.pacing_rate().unwrap();
            let mut metrics = ControllerMetrics::default();
            metrics.congestion_window = self.window();
            metrics.pacing_rate = Some(rate.saturating_mul(8));
            metrics
        } else {
            self.bbr.metrics()
        }
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(Self {
            bbr: self.bbr.clone_box(),
            send_rate: self.send_rate.clone(),
            mtu: self.mtu,
            rtt: self.rtt,
            epoch: self.epoch,
            samples: self.samples,
            ack_rate: self.ack_rate,
        })
    }

    fn initial_window(&self) -> u64 {
        self.bbr.initial_window()
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negotiated_rate_is_shared_with_paths_but_not_other_connections() {
        let now = Instant::now();
        let rate = Arc::new(AtomicU64::new(0));
        let factory = Arc::new(Hy2CongestionFactory {
            send_rate: rate.clone(),
        });
        let controller = factory.clone().build(now, 1200);
        let migrated = controller.clone_box();
        let other = Arc::new(Hy2CongestionFactory {
            send_rate: Arc::default(),
        })
        .build(now, 1200);
        assert!(controller.pacing_rate().is_none());
        rate.store(1_000_000, Ordering::Release);
        for path in [controller, migrated, factory.build(now, 1200)] {
            assert_eq!(path.pacing_rate(), Some(1_000_000));
            assert_eq!(path.window(), 666_000);
        }
        assert!(other.pacing_rate().is_none());
    }

    #[test]
    fn brutal_loss_compensation_is_bounded_and_expires() {
        let now = Instant::now();
        let mut controller = Arc::new(Hy2CongestionFactory {
            send_rate: Arc::new(AtomicU64::new(1_000_000)),
        })
        .build(now, 1200)
        .into_any()
        .downcast::<Hy2Controller>()
        .unwrap();
        controller.record(now, 100 * 1200, 100 * 1200);
        assert_eq!(controller.pacing_rate(), Some(1_250_000));
        controller.record(now + Duration::from_secs(5), 1200, 0);
        assert_eq!(controller.pacing_rate(), Some(1_000_000));
        controller.rtt = Duration::from_micros(10);
        assert_eq!(controller.window(), 12000);
    }
}
