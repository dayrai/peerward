// These counters measure the framed stream after carrier activation. They are
// neither packet-count estimates nor NIC/provider billing counters.
#[derive(Default)]
struct TrafficCounters {
    received_bytes: AtomicU64,
    accepted_bytes: AtomicU64,
    authenticated_peers: AtomicU64,
    authenticated_backbones: AtomicU64,
    invalid_forwarded_frames: Arc<AtomicU64>,
    no_route: Arc<AtomicU64>,
    queue_full: Arc<AtomicU64>,
    audit_queued: Arc<AtomicU64>,
    audit_dropped: Arc<AtomicU64>,
}

struct MeteredStream {
    inner: BoxStream,
    counters: Arc<TrafficCounters>,
}
impl MeteredStream {
    fn wrap(inner: BoxStream, counters: &Arc<TrafficCounters>) -> BoxStream {
        Box::new(Self {
            inner,
            counters: Arc::clone(counters),
        })
    }
}
impl tokio::io::AsyncRead for MeteredStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let result = std::pin::Pin::new(&mut self.inner).poll_read(cx, buf);
        let bytes = buf.filled().len().saturating_sub(before);
        self.counters
            .received_bytes
            .fetch_add(u64::try_from(bytes).unwrap_or(u64::MAX), Ordering::Relaxed);
        result
    }
}
impl tokio::io::AsyncWrite for MeteredStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let result = std::pin::Pin::new(&mut self.inner).poll_write(cx, buf);
        if let std::task::Poll::Ready(Ok(bytes)) = result {
            self.counters
                .accepted_bytes
                .fetch_add(u64::try_from(bytes).unwrap_or(u64::MAX), Ordering::Relaxed);
        }
        result
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
impl peerward_carrier::RelayIo for MeteredStream {
    fn carrier(&self) -> &'static str {
        self.inner.carrier()
    }
    fn is_quic(&self) -> bool {
        self.inner.is_quic()
    }
    fn take_quic(&mut self) -> Option<peerward_carrier::quic::Context> {
        self.inner.take_quic()
    }
}

struct AuthenticatedPeerCounter(Arc<RelayShared>);
struct AuthenticatedBackboneCounter(Arc<TrafficCounters>);
impl AuthenticatedBackboneCounter {
    fn acquire(traffic: &Arc<TrafficCounters>) -> Self {
        traffic
            .authenticated_backbones
            .fetch_add(1, Ordering::Relaxed);
        Self(Arc::clone(traffic))
    }
}
impl Drop for AuthenticatedBackboneCounter {
    fn drop(&mut self) {
        self.0
            .authenticated_backbones
            .fetch_sub(1, Ordering::Relaxed);
    }
}
impl AuthenticatedPeerCounter {
    fn acquire(shared: &Arc<RelayShared>) -> Self {
        shared.authenticated_peers.fetch_add(1, Ordering::Relaxed);
        shared
            .traffic
            .authenticated_peers
            .fetch_add(1, Ordering::Relaxed);
        Self(Arc::clone(shared))
    }
}
impl Drop for AuthenticatedPeerCounter {
    fn drop(&mut self) {
        self.0.authenticated_peers.fetch_sub(1, Ordering::Relaxed);
        self.0
            .traffic
            .authenticated_peers
            .fetch_sub(1, Ordering::Relaxed);
    }
}

fn traffic_metrics(traffic: &TrafficCounters) -> String {
    use std::fmt::Write as _;
    let mut text = String::new();
    for (name, help, kind, value) in [
        (
            "peerward_relay_framed_received_bytes_total",
            "Bytes read from activated framed carriers, excluding IP/TCP/TLS/QUIC overhead.",
            "counter",
            traffic.received_bytes.load(Ordering::Relaxed),
        ),
        (
            "peerward_relay_framed_accepted_bytes_total",
            "Bytes accepted by activated framed carriers; buffered acceptance is not network delivery.",
            "counter",
            traffic.accepted_bytes.load(Ordering::Relaxed),
        ),
        (
            "peerward_relay_authenticated_peer_sessions",
            "Actually admitted Peer sessions, excluding pending handshakes and backbone links.",
            "gauge",
            traffic.authenticated_peers.load(Ordering::Relaxed),
        ),
        (
            "peerward_relay_authenticated_backbone_sessions",
            "Established authenticated backbone sessions, excluding connecting channels.",
            "gauge",
            traffic.authenticated_backbones.load(Ordering::Relaxed),
        ),
        (
            "peerward_relay_host_no_route_total",
            "Frames rejected without an owned route during this host process.",
            "counter",
            traffic.no_route.load(Ordering::Relaxed),
        ),
        (
            "peerward_relay_host_queue_full_total",
            "Frames rejected at bounded routing capacity during this host process.",
            "counter",
            traffic.queue_full.load(Ordering::Relaxed),
        ),
        (
            "peerward_relay_host_invalid_forwarded_frames_total",
            "Malformed authenticated forwarded frames during this host process.",
            "counter",
            traffic.invalid_forwarded_frames.load(Ordering::Relaxed),
        ),
        (
            "peerward_relay_host_audit_queued_total",
            "Encrypted audit batches accepted by bounded actors during this host process.",
            "counter",
            traffic.audit_queued.load(Ordering::Relaxed),
        ),
        (
            "peerward_relay_host_audit_dropped_total",
            "Encrypted audit batches rejected at bounded actors during this host process.",
            "counter",
            traffic.audit_dropped.load(Ordering::Relaxed),
        ),
    ] {
        let _ = write!(
            text,
            "# HELP {name} {help}\n# TYPE {name} {kind}\n{name} {value}\n"
        );
    }
    text
}
