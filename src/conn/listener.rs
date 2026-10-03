use std::io;
use std::net::SocketAddr;
use tokio::net::{lookup_host, TcpListener};

pub async fn bind_tcp_listener(addr_str: &str, mptcp: bool) -> io::Result<TcpListener> {
    if !mptcp {
        let listener = TcpListener::bind(addr_str).await?;
        configure_keepalive(&listener)?;
        return Ok(listener);
    }

    let addr: SocketAddr = if let Ok(sa) = addr_str.parse::<SocketAddr>() {
        sa
    } else {
        let mut addrs = lookup_host(addr_str).await?;
        addrs.next().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "Failed to resolve bind address",
            )
        })?
    };

    #[cfg(target_os = "linux")]
    {
        let listener = bind_mptcp_linux(addr)?;
        configure_keepalive(&listener)?;
        Ok(listener)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = addr;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "MPTCP is only supported on Linux kernel 5.6+ with net.mptcp.enabled=1",
        ))
    }
}

fn configure_keepalive(listener: &TcpListener) -> io::Result<()> {
    // Accepted Linux sockets inherit these settings. Detect a phone that loses
    // its network without sending FIN, including idle multiplexed sessions.
    #[cfg(target_os = "linux")]
    {
        let socket = socket2::SockRef::from(listener);
        let keepalive = socket2::TcpKeepalive::new()
            .with_time(std::time::Duration::from_secs(30))
            .with_interval(std::time::Duration::from_secs(10))
            .with_retries(3);
        socket.set_tcp_keepalive(&keepalive)?;
    }
    #[cfg(not(target_os = "linux"))]
    let _ = listener;
    Ok(())
}

#[cfg(target_os = "linux")]
fn bind_mptcp_linux(addr: SocketAddr) -> io::Result<TcpListener> {
    let domain = match addr {
        SocketAddr::V4(_) => socket2::Domain::IPV4,
        SocketAddr::V6(_) => socket2::Domain::IPV6,
    };

    const IPPROTO_MPTCP: i32 = 262;
    let protocol = socket2::Protocol::from(IPPROTO_MPTCP);
    let socket = socket2::Socket::new(domain, socket2::Type::STREAM, Some(protocol))
        .map_err(|e| {
            io::Error::new(
                e.kind(),
                format!(
                    "Failed to create MPTCP socket (IPPROTO_MPTCP 262). Ensure Linux kernel >= 5.6 and sysctl net.mptcp.enabled=1: {e}"
                ),
            )
        })?;

    socket.set_reuse_address(true)?;
    #[cfg(all(unix, not(target_os = "solaris"), not(target_os = "illumos")))]
    let _ = socket.set_reuse_port(true);
    socket.set_nonblocking(true)?;

    socket.bind(&addr.into())?;
    socket.listen(1024)?;

    let std_listener: std::net::TcpListener = socket.into();
    TcpListener::from_std(std_listener)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn accepted_connections_inherit_dead_peer_detection() {
        let listener = bind_tcp_listener("127.0.0.1:0", false).await.unwrap();
        let _client = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (stream, _) = listener.accept().await.unwrap();
        let socket = socket2::SockRef::from(&stream);
        assert!(socket.keepalive().unwrap());
        assert_eq!(
            socket.keepalive_time().unwrap(),
            std::time::Duration::from_secs(30)
        );
        assert_eq!(
            socket.keepalive_interval().unwrap(),
            std::time::Duration::from_secs(10)
        );
        assert_eq!(socket.keepalive_retries().unwrap(), 3);
    }
}
