pub use super::obfs::HysteriaObfuscator;
use quinn::{AsyncUdpSocket, Runtime, UdpPoller, VarInt};
use std::collections::VecDeque;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub struct QuicStream {
    pub read: quinn::RecvStream,
    pub write: quinn::SendStream,
}

impl QuicStream {
    pub fn new(read: quinn::RecvStream, write: quinn::SendStream) -> Self {
        Self { read, write }
    }
}

impl AsyncRead for QuicStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.read).poll_read(cx, buf)
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.write), cx, bytes)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.write), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.write), cx)
    }
}

#[derive(Debug)]
struct ObfsSocket {
    sender: Arc<dyn AsyncUdpSocket>,
    obfs: Arc<HysteriaObfuscator>,
    received: parking_lot::Mutex<VecDeque<(Vec<u8>, quinn::udp::RecvMeta)>>,
}

impl AsyncUdpSocket for ObfsSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.sender.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit<'_>) -> io::Result<()> {
        match &*self.obfs {
            HysteriaObfuscator::None => self.sender.try_send(transmit),
            _ => {
                for buf in self.obfs.obfuscate(transmit.contents) {
                    let obfs_transmit = quinn::udp::Transmit {
                        destination: transmit.destination,
                        ecn: transmit.ecn,
                        contents: &buf,
                        segment_size: None,
                        src_ip: transmit.src_ip,
                    };
                    self.sender.try_send(&obfs_transmit)?;
                }
                Ok(())
            }
        }
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if matches!(&*self.obfs, HysteriaObfuscator::None) {
            return self.sender.poll_recv(cx, bufs, meta);
        }
        let mut received = self.received.lock();
        if received.is_empty() {
            let count = match self.sender.poll_recv(cx, bufs, meta) {
                Poll::Ready(Ok(count)) => count,
                other => return other,
            };
            // The wrapped socket enables UDP GRO. Each coalesced datagram has
            // its own salt; decrypting the entire buffer corrupts every packet
            // after the first. Keep at most one receive batch pending, and split
            // before deobfuscation (Gecko can also complete a larger packet).
            for i in 0..count {
                let info = meta[i];
                for raw in bufs[i][..info.len].chunks(info.stride.max(1)) {
                    let mut packet = Vec::new();
                    if self.obfs.deobfuscate(raw, info.addr, &mut packet) && !packet.is_empty() {
                        let len = packet.len();
                        received.push_back((
                            packet,
                            quinn::udp::RecvMeta {
                                len,
                                stride: len,
                                ..info
                            },
                        ));
                    }
                }
            }
        }
        let mut count = 0;
        while count < bufs.len().min(meta.len()) {
            let Some((packet, info)) = received.pop_front() else {
                break;
            };
            if packet.len() <= bufs[count].len() {
                bufs[count][..packet.len()].copy_from_slice(&packet);
                meta[count] = info;
                count += 1;
            }
        }
        if count == 0 {
            cx.waker().wake_by_ref();
            Poll::Pending
        } else {
            Poll::Ready(Ok(count))
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.sender.local_addr()
    }

    fn may_fragment(&self) -> bool {
        match &*self.obfs {
            HysteriaObfuscator::None => self.sender.may_fragment(),
            _ => false,
        }
    }

    fn max_transmit_segments(&self) -> usize {
        match &*self.obfs {
            HysteriaObfuscator::None => self.sender.max_transmit_segments(),
            _ => 1,
        }
    }

    fn max_receive_segments(&self) -> usize {
        // Reserve enough space for GRO even when GSO is disabled for obfs.
        self.sender.max_receive_segments()
    }
}

pub fn create_hysteria_endpoint(
    socket: std::net::UdpSocket,
    tls_config: rustls::ServerConfig,
    alpn: &[&[u8]],
    obfs: HysteriaObfuscator,
    enable_datagrams: bool,
) -> io::Result<quinn::Endpoint> {
    let server = hysteria_server_config(tls_config, alpn, enable_datagrams)?;
    create_hysteria_endpoint_with_config(socket, server, obfs)
}

pub(super) fn hysteria_server_config(
    tls_config: rustls::ServerConfig,
    alpn: &[&[u8]],
    enable_datagrams: bool,
) -> io::Result<quinn::ServerConfig> {
    let mut tls = tls_config;
    tls.alpn_protocols = alpn.iter().map(|s| s.to_vec()).collect();
    tls.max_early_data_size = 0;

    let crypto =
        quinn::crypto::rustls::QuicServerConfig::try_from(tls).map_err(io::Error::other)?;
    let mut server = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    server.transport_config(Arc::new(hysteria_transport_config(enable_datagrams)));
    Ok(server)
}

pub(super) fn hysteria_transport_config(enable_datagrams: bool) -> quinn::TransportConfig {
    let mut transport = quinn::TransportConfig::default();
    transport
        .max_concurrent_bidi_streams(VarInt::from_u32(10000))
        .max_concurrent_uni_streams(VarInt::from_u32(10000))
        .max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()))
        .keep_alive_interval(Some(Duration::from_secs(10)))
        .stream_receive_window(VarInt::from_u32(8 * 1024 * 1024))
        .receive_window(VarInt::from_u32(20 * 1024 * 1024))
        .send_window(20 * 1024 * 1024);

    if enable_datagrams {
        transport.datagram_receive_buffer_size(Some(1024 * 1024));
        transport.datagram_send_buffer_size(1024 * 1024);
        transport.max_datagram_frame_size(Some(VarInt::from_u32(1200)));
    } else {
        transport.datagram_receive_buffer_size(None);
    }

    transport
}

pub(super) fn create_hysteria_endpoint_with_config(
    socket: std::net::UdpSocket,
    server: quinn::ServerConfig,
    obfs: HysteriaObfuscator,
) -> io::Result<quinn::Endpoint> {
    // Like quic-go, request larger kernel queues for bursty QUIC traffic. OS
    // limits may clamp these; a tuning failure must not prevent startup.
    let socket_ref = socket2::SockRef::from(&socket);
    for result in [
        socket_ref.set_recv_buffer_size(7 * 1024 * 1024),
        socket_ref.set_send_buffer_size(7 * 1024 * 1024),
    ] {
        if let Err(error) = result {
            tracing::debug!(%error, "Could not enlarge Hysteria UDP socket buffer");
        }
    }
    let runtime = Arc::new(quinn::TokioRuntime);

    let endpoint = if matches!(&obfs, HysteriaObfuscator::None) {
        quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(server),
            socket,
            runtime,
        )?
    } else {
        let sender = runtime.wrap_udp_socket(socket)?;
        quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            Some(server),
            Arc::new(ObfsSocket {
                sender,
                obfs: Arc::new(obfs),
                received: parking_lot::Mutex::default(),
            }),
            runtime,
        )?
    };

    Ok(endpoint)
}

pub fn build_hysteria_tls_config(
    node_info: &crate::panel::types::NodeInfo,
    default_sni: &str,
    alpn: &[&[u8]],
) -> io::Result<rustls::ServerConfig> {
    let mut certs: Vec<rustls::pki_types::CertificateDer<'static>> = Vec::new();
    let mut key_opt: Option<rustls::pki_types::PrivateKeyDer<'static>> = None;

    if let Some((c, k)) =
        crate::security::tls::resolve_node_certificate(node_info, Some(default_sni))
    {
        certs = c;
        key_opt = Some(k);
    }

    if certs.is_empty() || key_opt.is_none() {
        let allow_insecure = node_info
            .tls_settings
            .as_ref()
            .and_then(|ts| ts.get("allow_insecure"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let sni = node_info
            .server_name
            .as_deref()
            .or_else(|| node_info.host.as_deref())
            .unwrap_or(default_sni);

        if !allow_insecure {
            tracing::warn!(
                node_id = node_info.id,
                sni = %sni,
                "No valid TLS certificate found for Hysteria node and allow_insecure is false. \
                 Generating a self-signed certificate, but clients verifying certificates will fail with Alert 42 (bad_certificate)."
            );
        } else {
            tracing::info!(
                node_id = node_info.id,
                sni = %sni,
                "No certificates found for Hysteria node; generating self-signed certificate (allow_insecure=true)"
            );
        }

        let mut params = rcgen::CertificateParams::new(vec![
            sni.to_string(),
            "localhost".to_string(),
            "127.0.0.1".to_string(),
            "hysteria.local".to_string(),
        ])
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        params.not_before = rcgen::date_time_ymd(2024, 1, 1);
        params.not_after = rcgen::date_time_ymd(2034, 1, 1);

        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        let cert = params
            .self_signed(&key_pair)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        certs = vec![rustls::pki_types::CertificateDer::from(cert.der().to_vec())];
        key_opt = Some(rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(key_pair.serialize_der()),
        ));
    }

    let key = key_opt.unwrap();
    let mut cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

    cfg.alpn_protocols = alpn.iter().map(|s| s.to_vec()).collect();
    cfg.max_early_data_size = 0;

    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::super::obfs::SalamanderObfs;
    use super::*;

    #[derive(Debug)]
    struct CoalescedSocket {
        batch: parking_lot::Mutex<Option<(Vec<u8>, quinn::udp::RecvMeta)>>,
    }

    impl AsyncUdpSocket for CoalescedSocket {
        fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
            unreachable!()
        }
        fn try_send(&self, _: &quinn::udp::Transmit<'_>) -> io::Result<()> {
            unreachable!()
        }
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok("127.0.0.1:443".parse().unwrap())
        }
        fn max_receive_segments(&self) -> usize {
            64
        }
        fn poll_recv(
            &self,
            _: &mut Context<'_>,
            bufs: &mut [IoSliceMut<'_>],
            meta: &mut [quinn::udp::RecvMeta],
        ) -> Poll<io::Result<usize>> {
            let Some((batch, info)) = self.batch.lock().take() else {
                return Poll::Pending;
            };
            bufs[0][..batch.len()].copy_from_slice(&batch);
            meta[0] = info;
            Poll::Ready(Ok(1))
        }
    }

    #[test]
    fn salamander_splits_gro_packets_and_drains_pending_before_reading_again() {
        let obfs = HysteriaObfuscator::Salamander(SalamanderObfs::new("fixture"));
        let packets = [vec![1; 64], vec![2; 64], vec![3; 17]];
        let batch: Vec<u8> = packets
            .iter()
            .flat_map(|packet| obfs.obfuscate(packet).concat())
            .collect();
        let remote = "127.0.0.1:1234".parse().unwrap();
        let info = quinn::udp::RecvMeta {
            addr: remote,
            len: batch.len(),
            stride: 72,
            ecn: None,
            dst_ip: Some("127.0.0.1".parse().unwrap()),
        };
        let socket = ObfsSocket {
            sender: Arc::new(CoalescedSocket {
                batch: parking_lot::Mutex::new(Some((batch, info))),
            }),
            obfs: Arc::new(obfs),
            received: parking_lot::Mutex::default(),
        };
        assert_eq!(socket.max_receive_segments(), 64);
        let mut buffer = [0; 4096];
        let mut meta = [quinn::udp::RecvMeta::default()];
        let mut cx = Context::from_waker(futures_util::task::noop_waker_ref());
        for packet in packets {
            assert!(matches!(
                socket.poll_recv(&mut cx, &mut [IoSliceMut::new(&mut buffer)], &mut meta),
                Poll::Ready(Ok(1))
            ));
            assert_eq!(meta[0].addr, remote);
            assert_eq!(meta[0].dst_ip, info.dst_ip);
            assert_eq!(meta[0].stride, packet.len());
            assert_eq!(&buffer[..meta[0].len], packet);
        }
        assert!(socket.received.lock().is_empty());
    }
}
