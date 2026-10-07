use super::congestion::Hy2CongestionFactory;
use super::obfs::{GeckoObfs, HysteriaObfuscator, SalamanderObfs};
use super::qpack::{
    encode_h3_control_stream, encode_h3_response, parse_qpack_headers, quic_varint_len,
    read_quic_varint_async, write_quic_varint, H3_FRAME_DATA, H3_FRAME_HEADERS, H3_FRAME_SETTINGS,
    HYSTERIA_AUTH_HEADER, HYSTERIA_CC_RX_HEADER, HYSTERIA_PADDING_HEADER, HYSTERIA_UDP_HEADER,
};
use super::transport::{
    build_hysteria_tls_config, create_hysteria_endpoint_with_config, hysteria_server_config,
    hysteria_transport_config, QuicStream,
};
use crate::conn::MonitoredStream;
use crate::observability::AuditRecord;
use crate::panel::types::{NodeInfo, User};
use crate::protocol::{Inbound, InboundContext};
use crate::proxy::router::MatchContext;
use async_trait::async_trait;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::io::{self, Cursor};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::sync::{broadcast, mpsc, Notify};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

pub const HYSTERIA2_TCP_FRAME_TYPE: u64 = 0x401;

#[derive(Default)]
struct Hy2AuthState {
    done: Notify,
    ok: AtomicBool,
    user: Mutex<Option<User>>,
    authenticate: tokio::sync::Mutex<()>,
    send_rate: Arc<AtomicU64>,
    // Hold the authenticated user's device until all child streams stop.
    device_guard: Mutex<Option<crate::limiter::device::DeviceGuard>>,
}

#[derive(Clone, Copy)]
struct Hy2Bandwidth {
    max_tx: u64,
    max_rx: u64,
    ignore_client: bool,
}

impl Hy2Bandwidth {
    fn from_node(node: &NodeInfo) -> Self {
        Self {
            // Panel directions are from the server: up is TX, down is RX.
            max_tx: u64::from(node.up_mbps.unwrap_or(0)) * 125_000,
            max_rx: u64::from(node.down_mbps.unwrap_or(0)) * 125_000,
            ignore_client: node.ignore_client_bandwidth,
        }
    }

    fn negotiated_tx(self, client_rx: Option<&str>) -> u64 {
        if self.ignore_client {
            return 0;
        }
        let rx = client_rx
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0);
        if self.max_tx > 0 {
            rx.min(self.max_tx)
        } else {
            rx
        }
    }

    fn response_rx(self) -> String {
        if self.ignore_client {
            "auto".into()
        } else {
            self.max_rx.to_string()
        }
    }
}

struct Hy2ReassemblyEntry {
    fragments: Vec<Option<Vec<u8>>>,
    received_count: usize,
    total_count: usize,
    deadline: Instant,
    dest: String,
    total_bytes: usize,
}

pub struct Hy2Defragmenter {
    entries: Mutex<HashMap<(u32, u16), Hy2ReassemblyEntry>>,
    total_memory: Mutex<usize>,
}

const MAX_DEFRAG_ENTRIES: usize = 512;
const MAX_DEFRAG_MEMORY: usize = 16 * 1024 * 1024;

impl Default for Hy2Defragmenter {
    fn default() -> Self {
        Self::new()
    }
}

impl Hy2Defragmenter {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            total_memory: Mutex::new(0),
        }
    }

    pub fn push_fragment(
        &self,
        session_id: u32,
        packet_id: u16,
        frag_id: u8,
        frag_total: u8,
        dest: String,
        data: Vec<u8>,
    ) -> Option<(String, Vec<u8>)> {
        // Packet ID and Fragment ID are irrelevant for unfragmented messages.
        if frag_total == 1 {
            return Some((dest, data));
        }
        if frag_total == 0 || frag_id >= frag_total {
            debug!(
                "Hysteria v2 invalid fragment params: total={}, id={}",
                frag_total, frag_id
            );
            return None;
        }

        let now = Instant::now();
        let mut entries = self.entries.lock();
        let mut total_mem = self.total_memory.lock();

        if !entries.is_empty() {
            entries.retain(|_, v| {
                if v.deadline <= now {
                    *total_mem = total_mem.saturating_sub(v.total_bytes);
                    false
                } else {
                    true
                }
            });
        }

        let chunk_len = data.len();
        let key = (session_id, packet_id);

        if let Some(entry) = entries.get_mut(&key) {
            if entry.total_count != frag_total as usize || entry.dest != dest {
                debug!(
                    "Hysteria v2 fragment mismatch for key={:?}: dropping poisoned entry",
                    key
                );
                *total_mem = total_mem.saturating_sub(entry.total_bytes);
                entries.remove(&key);
                return None;
            }

            if entry.fragments[frag_id as usize].is_none() {
                if *total_mem + chunk_len > MAX_DEFRAG_MEMORY {
                    debug!("Hysteria v2 MAX_DEFRAG_MEMORY exceeded");
                    return None;
                }
                entry.total_bytes += chunk_len;
                *total_mem += chunk_len;
                entry.fragments[frag_id as usize] = Some(data);
                entry.received_count += 1;
            }

            if entry.received_count == entry.total_count {
                let mut assembled = Vec::with_capacity(entry.total_bytes);
                for f in entry.fragments.iter().flatten() {
                    assembled.extend_from_slice(f);
                }
                let d = entry.dest.clone();
                *total_mem = total_mem.saturating_sub(entry.total_bytes);
                entries.remove(&key);
                return Some((d, assembled));
            }
            return None;
        }

        if entries.len() >= MAX_DEFRAG_ENTRIES || *total_mem + chunk_len > MAX_DEFRAG_MEMORY {
            debug!("Hysteria v2 defrag capacity exceeded");
            return None;
        }

        let mut fragments = vec![None; frag_total as usize];
        fragments[frag_id as usize] = Some(data);
        *total_mem += chunk_len;

        entries.insert(
            key,
            Hy2ReassemblyEntry {
                fragments,
                received_count: 1,
                total_count: frag_total as usize,
                deadline: now + Duration::from_secs(8),
                dest,
                total_bytes: chunk_len,
            },
        );

        None
    }
}

pub struct Hysteria2Inbound {
    users: Arc<parking_lot::RwLock<HashMap<String, User>>>,
}

impl Default for Hysteria2Inbound {
    fn default() -> Self {
        Self {
            users: Arc::new(parking_lot::RwLock::new(HashMap::new())),
        }
    }
}

impl Hysteria2Inbound {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl Inbound for Hysteria2Inbound {
    fn protocol_type(&self) -> &'static str {
        "hysteria2"
    }

    fn update_users(&self, users: Vec<User>) {
        let mut map = HashMap::new();
        for u in users {
            if let Some(ref pass) = u.password {
                if !pass.is_empty() {
                    map.insert(pass.clone(), u.clone());
                }
            }
            if !u.uuid.is_empty() {
                map.insert(u.uuid.clone(), u);
            }
        }
        *self.users.write() = map;
    }

    async fn start(
        &self,
        ctx: InboundContext,
        node_info: NodeInfo,
        mut shutdown_rx: broadcast::Receiver<()>,
    ) -> io::Result<()> {
        let port = if node_info.server_port > 0 {
            node_info.server_port
        } else {
            ctx.port
        };

        let bind_addr = SocketAddr::new(
            ctx.listen_addr
                .parse()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?,
            port,
        );

        let std_socket = std::net::UdpSocket::bind(bind_addr)?;
        std_socket.set_nonblocking(true)?;

        let (obfs_type, pw, min_pkt, max_pkt) = if let Some(ref val) = node_info.network_settings {
            let t = val
                .get("obfs_type")
                .or_else(|| val.get("obfsType"))
                .and_then(|v| v.as_str())
                .or_else(|| node_info.obfs.as_deref())
                .unwrap_or("none");
            let p = val
                .get("obfs_password")
                .or_else(|| val.get("obfsPassword"))
                .or_else(|| val.get("obfs"))
                .and_then(|v| v.as_str())
                .or_else(|| node_info.obfs_password.as_deref());

            let min_p = val
                .get("min_packet_size")
                .or_else(|| val.get("minPacketSize"))
                .and_then(|v| v.as_u64())
                .map(|v| v as usize)
                .unwrap_or(512);
            let max_p = val
                .get("max_packet_size")
                .or_else(|| val.get("maxPacketSize"))
                .and_then(|v| v.as_u64())
                .map(|v| v as usize)
                .unwrap_or(1200);

            (t, p, min_p, max_p)
        } else {
            let t = node_info.obfs.as_deref().unwrap_or("none");
            let p = node_info.obfs_password.as_deref();
            (t, p, 512, 1200)
        };

        let obfs = match (obfs_type.to_ascii_lowercase().as_str(), pw) {
            ("gecko", Some(p)) if !p.is_empty() => {
                HysteriaObfuscator::Gecko(GeckoObfs::new(p, min_pkt, max_pkt)?)
            }
            ("salamander", Some(p)) if !p.is_empty() => {
                HysteriaObfuscator::Salamander(SalamanderObfs::new(p))
            }
            _ => HysteriaObfuscator::None,
        };

        let alpn = [b"h3".as_slice()];
        let tls_config = build_hysteria_tls_config(&node_info, "hysteria2.local", &alpn)?;

        let server_config = hysteria_server_config(tls_config, &alpn, true)?;
        let endpoint =
            create_hysteria_endpoint_with_config(std_socket, server_config.clone(), obfs)?;
        info!("Hysteria v2 inbound listening on QUIC {}", bind_addr);

        let users = self.users.clone();
        let cancel_token = CancellationToken::new();
        let mut connections = tokio::task::JoinSet::new();

        ctx.mark_ready();
        loop {
            tokio::select! {
                result = connections.join_next(), if !connections.is_empty() => {
                    if let Some(Err(e)) = result { tracing::warn!(error = %e, "Hysteria2 connection task failed"); }
                }
                _ = shutdown_rx.recv() => {
                    info!("Hysteria v2 inbound on port {} shutting down", port);
                    cancel_token.cancel();
                    endpoint.close(0u32.into(), b"server shutdown");
                    break;
                }
                incoming = endpoint.accept() => {
                    let Some(incoming) = incoming else { break; };
                    let users = users.clone();
                    let ctx = ctx.clone();
                    let node_info = node_info.clone();
                    let cancel = cancel_token.clone();
                    let server_config = server_config.clone();

                    connections.spawn(async move {
                        if let Err(e) = handle_hy2_connection(incoming, users, ctx, node_info, server_config, cancel).await {
                            debug!("Hysteria v2 connection finished: {:?}", e);
                        }
                    });
                }
            }
        }

        cancel_token.cancel();
        endpoint.close(0u32.into(), b"server shutdown");
        crate::protocol::common::inbound::drain_connections(&mut connections).await;
        Ok(())
    }
}

async fn handle_hy2_connection(
    incoming: quinn::Incoming,
    users: Arc<parking_lot::RwLock<HashMap<String, User>>>,
    ctx: InboundContext,
    node_info: NodeInfo,
    mut server_config: quinn::ServerConfig,
    global_cancel: CancellationToken,
) -> io::Result<()> {
    let auth = Arc::new(Hy2AuthState::default());
    let mut transport = hysteria_transport_config(true);
    // Some Go clients omit this parameter in Chrome-style handshakes.
    // Hysteria negotiates UDP at /auth and fixes its frame limit at 1200 bytes.
    transport.assume_peer_max_datagram_frame_size(Some(1200u32.into()));
    transport.congestion_controller_factory(Arc::new(Hy2CongestionFactory {
        send_rate: auth.send_rate.clone(),
    }));
    server_config.transport_config(Arc::new(transport));
    let connecting = incoming
        .accept_with(Arc::new(server_config))
        .map_err(io::Error::other)?;
    let conn = tokio::select! {
        _ = global_cancel.cancelled() => return Ok(()),
        result = connecting => result.map_err(io::Error::other)?,
    };
    let remote_addr = conn.remote_address();
    let client_ip = remote_addr.ip();

    if ctx.defense.is_banned(client_ip) {
        conn.close(1u32.into(), b"banned");
        return Ok(());
    }

    let bandwidth = Hy2Bandwidth::from_node(&node_info);

    let conn_cancel = global_cancel.child_token();
    let _cancel = conn_cancel.clone().drop_guard();
    let mut tasks = tokio::task::JoinSet::new();

    if let Ok(mut uni) = conn.open_uni().await {
        let _ = uni.write_all(&encode_h3_control_stream()).await;
        let _ = uni.flush().await;
        let ctrl_cancel = conn_cancel.clone();
        let ctrl_global = global_cancel.clone();
        tasks.spawn(async move {
            tokio::select! {
                _ = ctrl_cancel.cancelled() => {},
                _ = ctrl_global.cancelled() => {},
            }
            let _ = uni.finish();
        });
    }

    let uni_conn = conn.clone();
    let uni_cancel = conn_cancel.clone();
    let uni_global_cancel = global_cancel.clone();
    tasks.spawn(async move {
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                result = tasks.join_next(), if !tasks.is_empty() => {
                    if let Some(Err(e)) = result { tracing::warn!(error = %e, "Hysteria2 stream task failed"); }
                }
                _ = uni_cancel.cancelled() => break,
                _ = uni_global_cancel.cancelled() => break,
                res = uni_conn.accept_uni() => {
                    let Ok(mut stream) = res else { break; };
                    tasks.spawn(async move {
                        let mut buf = [0u8; 1024];
                        while let Ok(Some(_)) = stream.read(&mut buf).await {}
                    });
                }
            }
        }
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    });

    let udp_sessions: Arc<Mutex<HashMap<u32, mpsc::Sender<(String, Vec<u8>)>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let defragmenter = Arc::new(Hy2Defragmenter::new());

    let dg_conn = conn.clone();
    let dg_sessions = udp_sessions.clone();
    let dg_defrag = defragmenter.clone();
    let dg_cancel = conn_cancel.clone();
    let dg_ctx = ctx.clone();
    let dg_auth = auth.clone();
    let dg_remote = remote_addr;
    let dg_global_cancel = global_cancel.clone();

    tasks.spawn(async move {
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                result = tasks.join_next(), if !tasks.is_empty() => {
                    if let Some(Err(e)) = result { tracing::warn!(error = %e, "Hysteria2 UDP task failed"); }
                }
                _ = dg_cancel.cancelled() => break,
                _ = dg_global_cancel.cancelled() => break,
                dg_res = dg_conn.read_datagram() => {
                    let Ok(raw) = dg_res else { break; };
                    if raw.len() < 8 { continue; }

                    if !dg_auth.ok.load(Ordering::Acquire) {
                        continue;
                    }
                    let user = match dg_auth.user.lock().clone() {
                        Some(u) => u,
                        None => continue,
                    };

                    let session_id = u32::from_be_bytes(raw[0..4].try_into().unwrap());
                    let packet_id = u16::from_be_bytes(raw[4..6].try_into().unwrap());
                    let frag_id = raw[6];
                    let frag_total = raw[7];
                    tracing::trace!(session_id, packet_id, frag_id, frag_total, bytes = raw.len(), "Hysteria2 UDP fragment received");

                    let mut cursor = Cursor::new(&raw[8..]);
                    let dest_len = match read_quic_varint_sync(&mut cursor) {
                        Ok(l) => l as usize,
                        Err(_) => continue,
                    };

                    let dest_start = 8 + (cursor.position() as usize);
                    if raw.len() < dest_start + dest_len { continue; }

                    let dest_bytes = &raw[dest_start..dest_start + dest_len];
                    let dest = String::from_utf8_lossy(dest_bytes).to_string();
                    let payload = raw[dest_start + dest_len..].to_vec();

                    if let Some((dst, full_packet)) =
                        dg_defrag.push_fragment(session_id, packet_id, frag_id, frag_total, dest, payload)
                    {
                        let mut sessions_lock = dg_sessions.lock();
                        if let Some(tx) = sessions_lock.get(&session_id) {
                            let _ = tx.try_send((dst, full_packet));
                        } else {
                            if sessions_lock.len() >= 2048 {
                                sessions_lock.retain(|_, tx| !tx.is_closed());
                                if sessions_lock.len() >= 2048 {
                                    continue;
                                }
                            }

                            let (tx, rx) = mpsc::channel::<(String, Vec<u8>)>(256);
                            let _ = tx.try_send((dst.clone(), full_packet));
                            sessions_lock.insert(session_id, tx);
                            drop(sessions_lock);

                            let s_ctx = dg_ctx.clone();
                            let s_conn = dg_conn.clone();
                            let s_sessions = dg_sessions.clone();
                            let s_cancel = dg_cancel.child_token();

                            tasks.spawn(async move {
                                handle_hy2_udp_session(
                                    session_id,
                                    rx,
                                    s_conn,
                                    s_ctx,
                                    user,
                                    dg_remote,
                                    s_cancel,
                                ).await;
                                s_sessions.lock().remove(&session_id);
                            });
                        }
                    }
                }
            }
        }
        dg_cancel.cancel();
        crate::protocol::common::inbound::drain_connections(&mut tasks).await;
    });

    let result = loop {
        tokio::select! {
            result = tasks.join_next(), if !tasks.is_empty() => {
                if let Some(Err(e)) = result { tracing::warn!(error = %e, "Hysteria2 session task failed"); }
            }
            _ = conn_cancel.cancelled() => break Ok(()),
            _ = global_cancel.cancelled() => break Ok(()),
            bi_res = conn.accept_bi() => {
                let Ok((send, recv)) = bi_res else { break Ok(()); };

                // Each stream must parse independently: a partial varint or
                // HEADERS frame must not hold up /auth on another stream.
                let conn = conn.clone();
                let users = users.clone();
                let ctx = ctx.clone();
                let auth = auth.clone();
                let stream_cancel = conn_cancel.clone();
                tasks.spawn(async move {
                    tokio::select! {
                        _ = stream_cancel.cancelled() => {},
                        _ = handle_hy2_stream(conn, send, recv, users, ctx, auth, bandwidth) => {},
                    }
                });
            }
        }
    };
    conn_cancel.cancel();
    conn.close(0u32.into(), b"session closed");
    crate::protocol::common::inbound::drain_connections(&mut tasks).await;
    drop(auth);
    result
}

async fn handle_hy2_stream(
    conn: quinn::Connection,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    users: Arc<parking_lot::RwLock<HashMap<String, User>>>,
    ctx: InboundContext,
    auth: Arc<Hy2AuthState>,
    bandwidth: Hy2Bandwidth,
) {
    let remote_addr = conn.remote_address();
    let client_ip = remote_addr.ip();

    let first_varint = match tokio::time::timeout(
        Duration::from_secs(10),
        read_quic_varint_async(&mut recv),
    )
    .await
    {
        Ok(Ok(v)) => v,
        _ => return,
    };

    if first_varint == HYSTERIA2_TCP_FRAME_TYPE {
        let notified = auth.done.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if !auth.ok.load(Ordering::Acquire) {
            let wait_res = tokio::time::timeout(Duration::from_secs(10), notified).await;
            if wait_res.is_err() || !auth.ok.load(Ordering::Acquire) {
                let _ = send.finish();
                return;
            }
        }

        let user = match auth.user.lock().clone() {
            Some(u) => u,
            None => {
                let _ = send.finish();
                return;
            }
        };

        let (host, port) =
            match tokio::time::timeout(Duration::from_secs(10), read_hy2_tcp_target(&mut recv))
                .await
            {
                Ok(Ok(target)) => target,
                _ => return,
            };
        let _ = handle_hy2_tcp_stream(recv, send, ctx, user, remote_addr, host, port).await;
    } else {
        let frame_type = first_varint;
        let payload = match tokio::time::timeout(Duration::from_secs(10), async {
            let frame_len = read_quic_varint_async(&mut recv).await?;
            if frame_len > 65536 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "HTTP/3 frame too large",
                ));
            }
            let mut payload = vec![0u8; frame_len as usize];
            recv.read_exact(&mut payload)
                .await
                .map_err(io::Error::other)?;
            Ok(payload)
        })
        .await
        {
            Ok(Ok(payload)) => payload,
            _ => return,
        };

        if frame_type == H3_FRAME_SETTINGS {
            return;
        } else if frame_type == H3_FRAME_HEADERS {
            let parsed_req = parse_qpack_headers(&payload);
            let req = match parsed_req {
                Ok(r) => r,
                Err(_) => {
                    send_masquerade_404(&mut send).await;
                    return;
                }
            };

            let method = req.method.to_uppercase();
            let path = &req.path;

            if method != "POST" || path != "/auth" || req.host() != "hysteria" {
                debug!(
                    "Hysteria v2 invalid HTTP/3 request: method={}, path={}, host={}",
                    method,
                    path,
                    req.host()
                );
                send_masquerade_404(&mut send).await;
                return;
            }

            // Auth belongs to the connection. Serialize retries so that another
            // /auth stream cannot replace its user, device guard, or send rate.
            let _auth_lock = auth.authenticate.lock().await;
            if !auth.ok.load(Ordering::Acquire) {
                let auth_str = req.get_header(HYSTERIA_AUTH_HEADER).unwrap_or("");
                let matched_user = if auth_str.is_empty() {
                    None
                } else {
                    users.read().get(auth_str).cloned()
                };

                let user = match matched_user {
                    Some(u) => {
                        ctx.defense.record_success(client_ip);
                        u
                    }
                    None => {
                        ctx.defense.record_failure(client_ip);
                        send_masquerade_404(&mut send).await;
                        return;
                    }
                };

                let Some(guard) = ctx
                    .device_limiter
                    .try_acquire_async(user.id, client_ip)
                    .await
                else {
                    conn.close(1u32.into(), b"device limit exceeded");
                    return;
                };
                *auth.device_guard.lock() = Some(guard);

                *auth.user.lock() = Some(user);
                auth.send_rate.store(
                    bandwidth.negotiated_tx(req.get_header(HYSTERIA_CC_RX_HEADER)),
                    Ordering::Release,
                );
                auth.ok.store(true, Ordering::Release);
                auth.done.notify_waiters();
            }

            let rx_resp = bandwidth.response_rx();

            let padding = "A".repeat(32);
            let resp_headers = [
                (HYSTERIA_UDP_HEADER, "true"),
                (HYSTERIA_CC_RX_HEADER, rx_resp.as_str()),
                (HYSTERIA_PADDING_HEADER, padding.as_str()),
            ];
            let resp_frame = encode_h3_response(233, &resp_headers);
            let _ = send.write_all(&resp_frame).await;
            let _ = send.finish();
        }
    }
}

async fn read_hy2_tcp_target<R: tokio::io::AsyncRead + Unpin>(
    recv: &mut R,
) -> io::Result<(String, u16)> {
    use tokio::io::AsyncReadExt;
    let addr_len = read_quic_varint_async(recv).await?;
    if addr_len > 2048 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "TCP address too long",
        ));
    }
    let mut addr = vec![0u8; addr_len as usize];
    recv.read_exact(&mut addr).await?;
    let pad_len = read_quic_varint_async(recv).await?;
    if pad_len > 4096 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "TCP padding too long",
        ));
    }
    let mut padding = vec![0u8; pad_len as usize];
    recv.read_exact(&mut padding).await?;
    Ok(parse_host_port(&String::from_utf8_lossy(&addr)))
}

async fn send_masquerade_404(send: &mut quinn::SendStream) {
    let headers = [
        ("content-type", "text/html; charset=utf-8"),
        ("server", "nginx"),
    ];
    let resp_frame = encode_h3_response(404, &headers);
    let _ = send.write_all(&resp_frame).await;

    let html_body = b"<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><h1>404 Not Found</h1><p>The requested URL was not found on this server.</p><hr><p>nginx</p></body></html>";
    let mut data_frame = Vec::new();
    let _ = write_quic_varint(&mut data_frame, H3_FRAME_DATA);
    let _ = write_quic_varint(&mut data_frame, html_body.len() as u64);
    data_frame.extend_from_slice(html_body);
    let _ = send.write_all(&data_frame).await;
    let _ = send.finish();
}

async fn handle_hy2_tcp_stream(
    recv: quinn::RecvStream,
    send: quinn::SendStream,
    ctx: InboundContext,
    user: User,
    remote_addr: SocketAddr,
    target_host: String,
    target_port: u16,
) -> io::Result<()> {
    let _guard = ctx.conn_limiter.try_acquire(user.id).ok_or_else(|| {
        io::Error::new(io::ErrorKind::PermissionDenied, "Connection limit reached")
    })?;
    let client_ip = remote_addr.ip();
    let target_ip: Option<IpAddr> = target_host.parse().ok();

    let mut stream = QuicStream::new(recv, send);
    let early_response = ctx.global_config.domain_sniff && target_ip.is_some();
    if early_response {
        // Non-fast-open clients wait for TCPResponse before sending the bytes
        // needed by the sniffer, so accept the stream before sniffing.
        stream.write_all(&[0, 0, 0]).await?;
    }
    let (sniffed, stream) =
        crate::conn::sniff_async_stream(stream, target_ip, ctx.global_config.domain_sniff).await;
    let match_host = sniffed.as_deref().unwrap_or(&target_host);
    let dial_host = if ctx.global_config.sniff_redirect {
        match_host
    } else {
        &target_host
    };

    let mut stream = stream;
    if ctx.audit.should_block(match_host, target_ip, target_port) {
        if !early_response {
            let mut resp = Vec::new();
            resp.push(0x01);
            let msg = b"blocked by audit rule";
            let _ = write_quic_varint(&mut resp, msg.len() as u64);
            resp.extend_from_slice(msg);
            let _ = write_quic_varint(&mut resp, 0);
            let _ = stream.write_all(&resp).await;
        }
        let _ = stream.shutdown().await;
        return Ok(());
    }

    let mctx = MatchContext {
        node_id: ctx.node_id,
        network: "tcp",
        target_host: match_host,
        target_ip,
        target_port,
        inbound_local_ip: None,
    };
    let outbound = ctx.router.match_outbound(&mctx);

    let mut out_stream = match ctx
        .router
        .dialer()
        .dial(&outbound, dial_host, target_port, None)
        .await
    {
        Ok(s) => s,
        Err(e) => {
            debug!(
                "Hysteria v2 outbound TCP dial failed for {}:{}: {:?}",
                dial_host, target_port, e
            );
            if !early_response {
                let mut resp = Vec::new();
                resp.push(0x01);
                let msg = b"connection failed";
                let _ = write_quic_varint(&mut resp, msg.len() as u64);
                resp.extend_from_slice(msg);
                let _ = write_quic_varint(&mut resp, 0);
                let _ = stream.write_all(&resp).await;
            }
            let _ = stream.shutdown().await;
            return Ok(());
        }
    };

    if !early_response {
        stream.write_all(&[0, 0, 0]).await?;
    }

    let mut client_conn = MonitoredStream::new(stream, user.id, remote_addr);
    let _traffic = client_conn.traffic_guard(ctx.on_traffic.clone());
    let start_time = Instant::now();

    let _ = crate::conn::copy_bidirectional_throttled(
        &mut client_conn,
        &mut out_stream,
        user.id,
        Some(&ctx.rate_limiter),
        ctx.global_config.tcp_timeout,
    )
    .await;

    let duration = start_time.elapsed();
    let (up, down) = client_conn.stats();

    ctx.audit_logger.record(AuditRecord::new(
        ctx.node_id,
        user.id,
        "hysteria2",
        "tcp",
        &client_ip.to_string(),
        &target_host,
        target_port,
        up,
        down,
        duration.as_millis() as i64,
        &outbound.tag,
        "connected",
    ));

    Ok(())
}

async fn handle_hy2_udp_session(
    session_id: u32,
    mut packet_rx: mpsc::Receiver<(String, Vec<u8>)>,
    conn: quinn::Connection,
    ctx: InboundContext,
    user: User,
    remote_addr: SocketAddr,
    session_cancel: CancellationToken,
) {
    let _cancel = session_cancel.clone().drop_guard();
    let mut tasks = tokio::task::JoinSet::new();
    let mut sessions: HashMap<(String, u16), mpsc::Sender<Vec<u8>>> = HashMap::new();
    let (responses, mut response_rx) = mpsc::channel::<(
        Vec<u8>,
        shadowsocks::relay::socks5::Address,
        tokio::sync::oneshot::Sender<()>,
    )>(256);
    let idle_timeout = Duration::from_secs(if ctx.global_config.udp_timeout == 0 {
        u32::MAX as u64
    } else {
        ctx.global_config.udp_timeout
    });
    let idle = tokio::time::sleep(idle_timeout);
    tokio::pin!(idle);
    let mut packet_id = 0u16;
    loop {
        tokio::select! {
            _ = session_cancel.cancelled() => break,
            _ = &mut idle => break,
            result = tasks.join_next(), if !tasks.is_empty() => {
                if let Some(Err(e)) = result { tracing::warn!(error = %e, "Hysteria2 UDP outbound task failed"); }
            }
            response = response_rx.recv() => {
                let Some((data, address, ack)) = response else { break; };
                let destination = address.to_string();
                let dest_bytes = destination.as_bytes();
                let header_len = 8 + quic_varint_len(dest_bytes.len() as u64) + dest_bytes.len();
                let max_chunk = conn.max_datagram_size().unwrap_or(1200).saturating_sub(header_len);
                if max_chunk == 0 { continue; }
                let count = data.len().max(1).div_ceil(max_chunk);
                if count > u8::MAX as usize { continue; }
                packet_id = packet_id.wrapping_add(1);
                let mut sent_all = true;
                for i in 0..count {
                    let start = i * max_chunk;
                    let chunk = &data[start..(start + max_chunk).min(data.len())];
                    let mut packet = Vec::with_capacity(header_len + chunk.len());
                    packet.extend_from_slice(&session_id.to_be_bytes());
                    packet.extend_from_slice(&packet_id.to_be_bytes());
                    packet.push(i as u8);
                    packet.push(count as u8);
                    let _ = write_quic_varint(&mut packet, dest_bytes.len() as u64);
                    packet.extend_from_slice(dest_bytes);
                    packet.extend_from_slice(chunk);
                    if let Err(error) = conn.send_datagram(packet.into()) {
                        debug!(%error, session_id, "Hysteria2 UDP response could not be queued");
                        sent_all = false;
                        break;
                    }
                }
                if sent_all {
                    let _ = ack.send(());
                    idle.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
                }
            }
            packet = packet_rx.recv() => {
                let Some((destination, data)) = packet else { break; };
                let key = parse_host_port(&destination);
                if key.1 == 0 { continue; }
                if sessions.get(&key).is_none_or(|tx| tx.is_closed()) {
                    let session = match crate::conn::udp::UdpSession::connect(
                        ctx.clone(), user.id, remote_addr, key.0.clone(), key.1, None, "hysteria2",
                    ).await {
                        Ok(session) => session,
                        Err(e) => { debug!(error = %e, "Hysteria2 UDP rejected"); continue; }
                    };
                    let (tx, requests) = mpsc::channel(256);
                    sessions.insert(key.clone(), tx);
                    let responses = responses.clone();
                    let cancel = session_cancel.clone();
                    tasks.spawn(async move { let _ = session.relay(requests, responses, cancel).await; });
                }
                if let Some(tx) = sessions.get(&key) {
                    tokio::select! {
                        _ = session_cancel.cancelled() => break,
                        _ = &mut idle => break,
                        _ = tx.send(data) => {},
                    }
                }
                idle.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
            }
        }
    }
    session_cancel.cancel();
    while tasks.join_next().await.is_some() {}
}

pub fn parse_host_port(addr: &str) -> (String, u16) {
    if let Some(idx) = addr.rfind(':') {
        let host = addr[..idx]
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_string();
        let port = addr[idx + 1..].parse::<u16>().unwrap_or(0);
        (host, port)
    } else {
        (addr.to_string(), 0)
    }
}

pub fn read_quic_varint_sync<R: io::Read>(reader: &mut R) -> io::Result<u64> {
    let mut first = [0u8; 1];
    reader.read_exact(&mut first)?;
    let b = first[0];
    let prefix = b >> 6;
    let len = 1usize << prefix;
    let mut val = (b & 0x3f) as u64;

    for _ in 1..len {
        let mut next = [0u8; 1];
        reader.read_exact(&mut next)?;
        val = (val << 8) | (next[0] as u64);
    }
    Ok(val)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bandwidth_negotiation_converts_mbps_and_preserves_unlimited_rates() {
        let mut node = NodeInfo {
            up_mbps: Some(80),
            down_mbps: Some(16),
            ..Default::default()
        };
        let bandwidth = Hy2Bandwidth::from_node(&node);
        assert_eq!(bandwidth.response_rx(), "2000000");
        for (rx, expected) in [
            (None, 0),
            (Some("0"), 0),
            (Some("invalid"), 0),
            (Some("-1"), 0),
            (Some("18446744073709551616"), 0),
            (Some("5000000"), 5_000_000),
            (Some("20000000"), 10_000_000),
        ] {
            assert_eq!(bandwidth.negotiated_tx(rx), expected);
        }
        node.up_mbps = None;
        node.down_mbps = None;
        let bandwidth = Hy2Bandwidth::from_node(&node);
        assert_eq!(bandwidth.response_rx(), "0");
        assert_eq!(bandwidth.negotiated_tx(Some("20000000")), 20_000_000);
        node.ignore_client_bandwidth = true;
        let bandwidth = Hy2Bandwidth::from_node(&node);
        assert_eq!(bandwidth.response_rx(), "auto");
        assert_eq!(bandwidth.negotiated_tx(Some("20000000")), 0);
    }

    #[test]
    fn hy2_user_updates_never_register_empty_credentials() {
        let inbound = Hysteria2Inbound::new();
        inbound.update_users(vec![
            User {
                id: 1,
                password: Some("password-only".into()),
                ..Default::default()
            },
            User {
                id: 2,
                ..Default::default()
            },
            User {
                id: 3,
                uuid: "uuid".into(),
                password: Some("password".into()),
                ..Default::default()
            },
        ]);
        let users = inbound.users.read();
        assert!(!users.contains_key(""));
        assert_eq!(users.get("password-only").unwrap().id, 1);
        assert_eq!(users.get("uuid").unwrap().id, 3);
        assert_eq!(users.get("password").unwrap().id, 3);
        drop(users);
        inbound.update_users(Vec::new());
        assert!(inbound.users.read().is_empty());
    }

    #[tokio::test]
    async fn hy2_tcp_request_requires_complete_padding() {
        let mut request = Vec::new();
        write_quic_varint(&mut request, 12).unwrap();
        request.extend_from_slice(b"localhost:80");
        write_quic_varint(&mut request, 2).unwrap();
        request.push(0);
        assert!(read_hy2_tcp_target(&mut request.as_slice()).await.is_err());
        request.push(0);
        assert_eq!(
            read_hy2_tcp_target(&mut request.as_slice()).await.unwrap(),
            ("localhost".into(), 80)
        );
    }

    #[tokio::test]
    async fn hy2_partial_streams_and_malformed_headers_do_not_block_authentication() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.cert.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()).into(),
            )
            .unwrap();
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_nonblocking(true).unwrap();
        let server_config = hysteria_server_config(tls, &[b"h3"], true).unwrap();
        let server = create_hysteria_endpoint_with_config(
            socket,
            server_config.clone(),
            HysteriaObfuscator::None,
        )
        .unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.cert.der().clone()).unwrap();
        let mut tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap();
        let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));

        let geo = Arc::new(crate::geo::GeoEngine::default());
        let dialer = Arc::new(crate::proxy::router::OutboundDialer::new(
            Arc::new(crate::dns::DNSResolver::default()),
            None,
            None,
            false,
        ));
        let limiter = Arc::new(crate::limiter::DeviceLimiter::new(60, 32, 128, None));
        let ctx = InboundContext {
            ready: None,
            node_id: 1,
            listen_addr: "127.0.0.1".into(),
            port: 0,
            router: Arc::new(crate::proxy::router::Router::new(
                Default::default(),
                dialer,
                geo.clone(),
            )),
            rate_limiter: Arc::new(crate::limiter::RateLimiter::new()),
            conn_limiter: Arc::new(crate::limiter::ConnectionLimiter::new()),
            device_limiter: limiter.clone(),
            audit: Arc::new(crate::security::AuditController::new("", "", geo)),
            defense: Arc::new(crate::security::AttackDefenseManager::default()),
            tls_manager: Arc::new(crate::security::TLSManager::new(false, "localhost".into())),
            audit_logger: Arc::new(crate::observability::AuditLogger::new(None::<&str>)),
            clickhouse_logger: Arc::new(crate::observability::ClickHouseLogger::new(
                false,
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                None,
            )),
            on_traffic: Arc::new(|_, _, _| {}),
            global_config: Arc::new(crate::config::GlobalConfig::default()),
            ip_user_cache: Arc::new(crate::limiter::IpUserCache::new(1, false, "")),
        };
        let inbound = Hysteria2Inbound::new();
        inbound.update_users(vec![
            User {
                id: 7,
                password: Some("fixture".into()),
                ..Default::default()
            },
            User {
                id: 8,
                password: Some("another".into()),
                ..Default::default()
            },
        ]);
        let users = inbound.users.clone();
        let cancel = CancellationToken::new();
        let server_cancel = cancel.clone();
        let address = server.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            handle_hy2_connection(
                server.accept().await.unwrap(),
                users,
                ctx,
                NodeInfo::default(),
                server_config,
                server_cancel,
            )
            .await
            .unwrap();
        });
        let conn = tokio::time::timeout(
            Duration::from_secs(2),
            client.connect(address, "localhost").unwrap(),
        )
        .await
        .unwrap()
        .unwrap();
        let mut partials = Vec::new();
        for prefix in [
            &[0x40][..],
            &[H3_FRAME_HEADERS as u8, 0x40],
            &[H3_FRAME_HEADERS as u8, 10, 0, 0],
        ] {
            let (mut send, recv) = conn.open_bi().await.unwrap();
            send.write_all(prefix).await.unwrap();
            partials.push((send, recv));
        }
        tokio::time::sleep(Duration::from_millis(30)).await;

        async fn request_status(conn: &quinn::Connection, payload: &[u8]) -> String {
            let (mut send, mut recv) = conn.open_bi().await.unwrap();
            let mut frame = Vec::new();
            write_quic_varint(&mut frame, H3_FRAME_HEADERS).unwrap();
            write_quic_varint(&mut frame, payload.len() as u64).unwrap();
            frame.extend_from_slice(payload);
            send.write_all(&frame).await.unwrap();
            send.finish().unwrap();
            let reply = tokio::time::timeout(Duration::from_secs(2), recv.read_to_end(65536))
                .await
                .expect("another stream blocked authentication")
                .unwrap();
            let mut cursor = Cursor::new(reply.as_slice());
            assert_eq!(
                read_quic_varint_sync(&mut cursor).unwrap(),
                H3_FRAME_HEADERS
            );
            let len = read_quic_varint_sync(&mut cursor).unwrap() as usize;
            let start = cursor.position() as usize;
            parse_qpack_headers(&reply[start..start + len])
                .unwrap()
                .get_header(":status")
                .unwrap()
                .to_string()
        }

        // The original process-aborting allocation probe, sent before auth.
        let mut malicious = vec![0, 0, 0x50, 0x7f];
        malicious.extend_from_slice(&[0x81, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x0f]);
        assert_eq!(request_status(&conn, &malicious).await, "404");
        let mut auth = b"\x00\x00\xd4\x51\x05/auth\x50\x08hysteria".to_vec();
        assert_eq!(request_status(&conn, &auth).await, "404");
        auth.extend_from_slice(b"\x27\x06hysteria-auth\x00");
        assert_eq!(request_status(&conn, &auth).await, "404");
        assert!(limiter.get_online_devices(7).is_empty());
        auth.pop();
        auth.extend_from_slice(b"\x07fixture");
        assert_eq!(request_status(&conn, &auth).await, "233");
        assert_eq!(limiter.get_online_devices(7).len(), 1);
        auth.truncate(auth.len() - 7);
        auth.extend_from_slice(b"another");
        let (first, second) =
            tokio::join!(request_status(&conn, &auth), request_status(&conn, &auth));
        assert_eq!((first.as_str(), second.as_str()), ("233", "233"));
        assert_eq!(limiter.get_online_devices(7).len(), 1);
        assert!(
            limiter.get_online_devices(8).is_empty(),
            "reauthentication changed the connection's user"
        );
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(2), server_task)
            .await
            .unwrap()
            .unwrap();
        assert!(limiter.get_online_devices(7).is_empty());
        drop(partials);
    }

    #[test]
    fn test_hy2_parse_host_port() {
        assert_eq!(parse_host_port("1.1.1.1:53"), ("1.1.1.1".to_string(), 53));
        assert_eq!(
            parse_host_port("[2606:4700::1111]:443"),
            ("2606:4700::1111".to_string(), 443)
        );
        assert_eq!(
            parse_host_port("example.com:8080"),
            ("example.com".to_string(), 8080)
        );
    }

    #[test]
    fn test_hy2_defragmenter_roundtrip() {
        let defrag = Hy2Defragmenter::new();
        let frag0 = b"Hysteria 2 ".to_vec();
        let frag1 = b"Datagram ".to_vec();
        let frag2 = b"Reassembly!".to_vec();

        assert!(defrag
            .push_fragment(100, 5, 0, 3, "8.8.8.8:53".to_string(), frag0)
            .is_none());
        assert!(defrag
            .push_fragment(100, 5, 2, 3, "8.8.8.8:53".to_string(), frag2)
            .is_none());
        let res = defrag.push_fragment(100, 5, 1, 3, "8.8.8.8:53".to_string(), frag1);
        assert!(res.is_some());

        let (dest, payload) = res.unwrap();
        assert_eq!(dest, "8.8.8.8:53");
        assert_eq!(payload, b"Hysteria 2 Datagram Reassembly!");
    }

    #[test]
    fn test_hy2_defragmenter_rejections() {
        let defrag = Hy2Defragmenter::new();

        assert_eq!(
            defrag.push_fragment(1, 1, 255, 1, "8.8.8.8:53".into(), vec![1]),
            Some(("8.8.8.8:53".into(), vec![1]))
        );

        assert!(defrag
            .push_fragment(1, 1, 0, 0, "8.8.8.8:53".to_string(), vec![1])
            .is_none());

        assert!(defrag
            .push_fragment(1, 1, 2, 2, "8.8.8.8:53".to_string(), vec![1])
            .is_none());

        defrag.push_fragment(2, 10, 0, 2, "8.8.8.8:53".to_string(), vec![1, 2, 3]);

        assert!(defrag
            .push_fragment(2, 10, 1, 2, "1.1.1.1:53".to_string(), vec![4, 5, 6])
            .is_none());
    }
}
