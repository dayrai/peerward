use std::{
    future::Future,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::{Arc, RwLock},
};

use peerward_service::RemoteServiceTable;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{Mutex, Semaphore, watch},
    task::JoinSet,
    time::{Duration, timeout},
};

use crate::{DirectPeerDirectory, PacketPolicy, firewall_allows_peer_dns, firewall_allows_service};

const DNS_HEADER: usize = 12;
const MAX_DNS_MESSAGE: usize = 4096;
const FORWARD_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_CONCURRENT_DNS_QUERIES: usize = 512;
const DYNAMIC_BIND_ATTEMPTS: usize = 32;

type BindFuture<T> = Pin<Box<dyn Future<Output = io::Result<T>> + Send>>;

trait DnsSocketBinder: Send + Sync {
    fn bind_udp(&self, address: SocketAddr) -> BindFuture<UdpSocket>;
    fn bind_tcp(&self, address: SocketAddr) -> BindFuture<TcpListener>;
}

struct TokioDnsSocketBinder;

impl DnsSocketBinder for TokioDnsSocketBinder {
    fn bind_udp(&self, address: SocketAddr) -> BindFuture<UdpSocket> {
        Box::pin(UdpSocket::bind(address))
    }

    fn bind_tcp(&self, address: SocketAddr) -> BindFuture<TcpListener> {
        Box::pin(TcpListener::bind(address))
    }
}

/// Runtime split-DNS settings.
#[derive(Debug, Clone)]
pub struct DnsServerConfig {
    /// UDP and TCP address used by the host split-DNS manager.
    pub listen: SocketAddr,
    /// Mesh suffix captured locally, without a trailing dot.
    pub suffix: String,
    /// Mesh IPv4 range whose reverse mappings are authoritative locally.
    pub network: ipnet::IpNet,
    /// Recursive resolvers for names outside the mesh suffix.
    pub upstreams: Vec<SocketAddr>,
}

/// Bound UDP/TCP DNS sockets and immutable routing configuration.
pub struct DnsServer {
    udp: UdpSocket,
    tcp: TcpListener,
    suffix: String,
    network: ipnet::IpNet,
    upstreams: Vec<SocketAddr>,
    management: Option<ManagedDns>,
}

#[derive(Clone)]
struct ManagedDns {
    core: Arc<Mutex<peerward_peer_core::WireguardRuntime>>,
    local_address: IpAddr,
    secondary_address: Option<IpAddr>,
    proxy: IpAddr,
    listener: SocketAddr,
    interface: String,
}

fn local_dns_source(
    source: IpAddr,
    primary: IpAddr,
    secondary: Option<IpAddr>,
    proxy: IpAddr,
) -> bool {
    // Linux installs the proxy as an address on our TUN. A query to that local
    // address can select the proxy itself as its source, before any TUN traffic.
    source.is_loopback() || source == primary || secondary == Some(source) || source == proxy
}

impl DnsServer {
    pub(crate) fn with_management(
        mut self,
        core: Arc<Mutex<peerward_peer_core::WireguardRuntime>>,
        local_address: IpAddr,
        secondary_address: Option<IpAddr>,
        proxy: IpAddr,
        interface: String,
    ) -> io::Result<Self> {
        self.management = Some(ManagedDns {
            core,
            local_address,
            secondary_address,
            proxy,
            listener: self.local_addr()?,
            interface,
        });
        Ok(self)
    }
    /// Validates configuration and binds UDP and TCP to the same port.
    pub async fn bind(config: DnsServerConfig) -> io::Result<Self> {
        Self::bind_with(config, &TokioDnsSocketBinder).await
    }

    async fn bind_with(config: DnsServerConfig, binder: &dyn DnsSocketBinder) -> io::Result<Self> {
        let suffix = canonical_suffix(&config.suffix)?;
        let dynamic = config.listen.port() == 0;
        let attempts = if dynamic { DYNAMIC_BIND_ATTEMPTS } else { 1 };
        let mut pair = None;
        for attempt in 0..attempts {
            let udp = binder.bind_udp(config.listen).await?;
            let bound = udp.local_addr()?;
            match binder.bind_tcp(bound).await {
                Ok(tcp) => {
                    pair = Some((udp, tcp, bound));
                    break;
                }
                Err(error) if dynamic && error.kind() == io::ErrorKind::AddrInUse => {
                    if attempt + 1 == attempts {
                        return Err(error);
                    }
                }
                Err(error) => return Err(error),
            }
        }
        let (udp, tcp, bound) = pair.expect("at least one DNS bind attempt is configured");
        if config.upstreams.iter().any(|upstream| {
            upstream.port() == bound.port()
                && (upstream.ip() == bound.ip() || bound.ip().is_unspecified())
        }) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "DNS forwarding loop",
            ));
        }
        Ok(Self {
            udp,
            tcp,
            suffix,
            network: config.network,
            upstreams: config.upstreams,
            management: None,
        })
    }

    /// Returns the common UDP/TCP listener address.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.udp.local_addr()
    }

    /// Serves until shutdown, rejecting malformed requests without mutating state.
    pub async fn serve<P>(
        self,
        directory: Arc<RwLock<DirectPeerDirectory>>,
        services: Arc<Mutex<RemoteServiceTable>>,
        firewall: Arc<P>,
        shutdown: watch::Receiver<bool>,
    ) -> io::Result<()>
    where
        P: PacketPolicy + 'static,
    {
        self.serve_inner(directory, services, firewall, None, shutdown)
            .await
    }

    /// Serves split DNS while publishing live query counters.
    pub async fn serve_observed<P>(
        self,
        directory: Arc<RwLock<DirectPeerDirectory>>,
        services: Arc<Mutex<RemoteServiceTable>>,
        firewall: Arc<P>,
        observability: peerward_service::PeerObservability,
        shutdown: watch::Receiver<bool>,
    ) -> io::Result<()>
    where
        P: PacketPolicy + 'static,
    {
        self.serve_inner(directory, services, firewall, Some(observability), shutdown)
            .await
    }

    async fn serve_inner<P>(
        self,
        directory: Arc<RwLock<DirectPeerDirectory>>,
        services: Arc<Mutex<RemoteServiceTable>>,
        firewall: Arc<P>,
        observability: Option<peerward_service::PeerObservability>,
        mut shutdown: watch::Receiver<bool>,
    ) -> io::Result<()>
    where
        P: PacketPolicy + 'static,
    {
        let Self {
            udp,
            tcp,
            suffix,
            network,
            upstreams,
            management,
        } = self;
        let udp_loop = serve_udp(
            udp,
            suffix.clone(),
            network,
            upstreams.clone(),
            management.clone(),
            Arc::clone(&directory),
            Arc::clone(&services),
            Arc::clone(&firewall),
            observability.clone(),
            shutdown.clone(),
        );
        let tcp_loop = serve_tcp(
            tcp,
            suffix,
            network,
            upstreams,
            management,
            directory,
            services,
            firewall,
            observability,
            shutdown.clone(),
        );
        tokio::pin!(udp_loop);
        tokio::pin!(tcp_loop);
        tokio::select! {
            result = &mut udp_loop => result,
            result = &mut tcp_loop => result,
            change = shutdown.changed() => { let _ = change; Ok(()) }
        }
    }
}

#[derive(Clone)]
struct Question {
    id: u16,
    flags: u16,
    name: String,
    qtype: u16,
    wire_end: usize,
    udp_limit: usize,
}

fn parse_question(message: &[u8]) -> io::Result<Question> {
    if message.len() < DNS_HEADER || message.len() > MAX_DNS_MESSAGE {
        return Err(invalid_dns());
    }
    let flags = read_u16(message, 2)?;
    if flags & 0x8000 != 0
        || flags & 0x7800 != 0
        || read_u16(message, 4)? != 1
        || read_u16(message, 6)? != 0
        || read_u16(message, 8)? != 0
    {
        return Err(invalid_dns());
    }
    let (name, name_end) = decode_name(message, DNS_HEADER)?;
    let wire_end = name_end
        .checked_add(4)
        .filter(|end| *end <= message.len())
        .ok_or_else(invalid_dns)?;
    let qtype = read_u16(message, name_end)?;
    if read_u16(message, name_end + 2)? != 1 {
        return Err(invalid_dns());
    }
    let additional = usize::from(read_u16(message, 10)?);
    let mut cursor = wire_end;
    let mut udp_limit = 512_usize;
    let mut seen_opt = false;
    for _ in 0..additional {
        let (owner, next) = decode_name(message, cursor)?;
        let fixed_end = next
            .checked_add(10)
            .filter(|end| *end <= message.len())
            .ok_or_else(invalid_dns)?;
        let rr_type = read_u16(message, next)?;
        let class = read_u16(message, next + 2)?;
        let ttl = u32::from_be_bytes(
            message[next + 4..next + 8]
                .try_into()
                .map_err(|_| invalid_dns())?,
        );
        let data_len = usize::from(read_u16(message, next + 8)?);
        cursor = fixed_end
            .checked_add(data_len)
            .filter(|end| *end <= message.len())
            .ok_or_else(invalid_dns)?;
        if rr_type != 41 || !owner.is_empty() || seen_opt || ttl & 0x00ff_0000 != 0 {
            return Err(invalid_dns());
        }
        seen_opt = true;
        udp_limit = usize::from(class).clamp(512, 1232);
    }
    if cursor != message.len() {
        return Err(invalid_dns());
    }
    Ok(Question {
        id: read_u16(message, 0)?,
        flags,
        name,
        qtype,
        wire_end,
        udp_limit,
    })
}

fn decode_name(message: &[u8], start: usize) -> io::Result<(String, usize)> {
    let mut labels = Vec::new();
    let mut cursor = start;
    let mut end = None;
    let mut jumps = 0_u8;
    let mut expanded = 0_usize;
    loop {
        let length = *message.get(cursor).ok_or_else(invalid_dns)?;
        if length & 0xc0 == 0xc0 {
            let second = *message.get(cursor + 1).ok_or_else(invalid_dns)?;
            let target = usize::from((u16::from(length & 0x3f) << 8) | u16::from(second));
            end.get_or_insert(cursor + 2);
            if target >= message.len() || jumps >= 16 {
                return Err(invalid_dns());
            }
            cursor = target;
            jumps += 1;
            continue;
        }
        if length & 0xc0 != 0 || length > 63 {
            return Err(invalid_dns());
        }
        cursor += 1;
        if length == 0 {
            return Ok((labels.join("."), end.unwrap_or(cursor)));
        }
        let label_end = cursor
            .checked_add(usize::from(length))
            .filter(|value| *value <= message.len())
            .ok_or_else(invalid_dns)?;
        let label = std::str::from_utf8(&message[cursor..label_end]).map_err(|_| invalid_dns())?;
        if !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(invalid_dns());
        }
        expanded += usize::from(length) + 1;
        if expanded > 254 {
            return Err(invalid_dns());
        }
        labels.push(label.to_ascii_lowercase());
        cursor = label_end;
    }
}
