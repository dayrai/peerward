use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use igd_next::{PortMappingProtocol, SearchOptions};
use rand::{RngCore, rngs::OsRng};
use tokio::net::UdpSocket;

use crate::P2pError;

const MAPPING_PORT: u16 = 5351;
const PCP_VERSION: u8 = 2;
const PCP_MAP_OPCODE: u8 = 1;
const UDP_PROTOCOL: u8 = 17;
const NAT_PMP_VERSION: u8 = 0;
const NAT_PMP_PUBLIC_ADDRESS: u8 = 0;
const NAT_PMP_UDP_MAPPING: u8 = 1;

/// Gateway mechanism that owns a discovered direct UDP mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MappingProtocol {
    /// RFC 6887 `PCP` MAP.
    Pcp,
    /// RFC 6886 `NAT-PMP` UDP mapping.
    NatPmp,
    /// `UPnP` IGD AddAnyPortMapping/AddPortMapping.
    Upnp,
}

/// Renewable local-gateway mapping for the Peer direct UDP port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappingLease {
    /// Successful mapping protocol.
    pub protocol: MappingProtocol,
    /// Public endpoint advertised as a mapped candidate.
    pub external: SocketAddr,
    /// Internal endpoint owned by the direct UDP socket.
    pub internal: SocketAddr,
    /// Granted lifetime in seconds.
    pub lifetime_seconds: u32,
    /// Gateway epoch when supplied by `PCP` or `NAT-PMP`.
    pub epoch: Option<u32>,
    nonce: Option<[u8; 12]>,
}

impl MappingLease {
    /// Whether deleting this lease can safely follow installing `replacement`
    /// on the same gateway. External address changes do not create a new `PCP`
    /// or `NAT-PMP` mapping: both protocols identify it by the internal endpoint.
    /// Cross-protocol requests may also manage the same gateway mapping.
    #[must_use]
    pub fn independently_deletable(&self, replacement: &Self) -> bool {
        match self.protocol {
            MappingProtocol::Upnp => self.external.port() != replacement.external.port(),
            MappingProtocol::Pcp | MappingProtocol::NatPmp => self.internal != replacement.internal,
        }
    }

    /// Renewal point at one half of the granted lifetime.
    pub fn renew_after(&self) -> Duration {
        Duration::from_secs(u64::from(self.lifetime_seconds.max(2) / 2))
    }
}

/// Attempts `PCP`, `NAT-PMP`, then `UPnP` for one existing direct UDP port.
pub async fn discover_port_mapping_with_transport(
    gateway: IpAddr,
    internal: SocketAddr,
    lifetime_seconds: u32,
    timeout: Duration,
    transport: Option<&dyn MappingTransport>,
) -> Result<MappingLease, P2pError> {
    if internal.port() == 0 || internal.ip().is_unspecified() || lifetime_seconds == 0 {
        return Err(P2pError::Mapping);
    }
    if let Ok(lease) = pcp_map(
        gateway,
        internal,
        lifetime_seconds,
        timeout,
        None,
        None,
        transport,
    )
    .await
    {
        return Ok(lease);
    }
    if let (IpAddr::V4(gateway), IpAddr::V4(_)) = (gateway, internal.ip())
        && let Ok(lease) = nat_pmp_map(
            gateway,
            internal,
            lifetime_seconds,
            timeout,
            None,
            transport,
        )
        .await
    {
        return Ok(lease);
    }
    upnp_map(gateway, internal, lifetime_seconds, timeout).await
}

/// Best-effort deletion for a mapping previously returned by discovery.
pub async fn delete_port_mapping_with_transport(
    gateway: IpAddr,
    lease: &MappingLease,
    timeout: Duration,
    transport: Option<&dyn MappingTransport>,
) -> Result<(), P2pError> {
    match lease.protocol {
        MappingProtocol::Pcp => pcp_map(
            gateway,
            lease.internal,
            0,
            timeout,
            lease.nonce,
            None,
            transport,
        )
        .await
        .map(|_| ()),
        MappingProtocol::NatPmp => {
            let IpAddr::V4(gateway) = gateway else {
                return Err(P2pError::Mapping);
            };
            nat_pmp_map(gateway, lease.internal, 0, timeout, None, transport)
                .await
                .map(|_| ())
        }
        MappingProtocol::Upnp => {
            let expected_gateway = gateway;
            let options = upnp_options(lease.internal, timeout);
            let gateway = igd_next::aio::tokio::search_gateway(options)
                .await
                .map_err(|_| P2pError::Mapping)?;
            if gateway.addr.ip() != expected_gateway {
                return Err(P2pError::Mapping);
            }
            tokio::time::timeout(
                timeout,
                gateway.remove_port(PortMappingProtocol::UDP, lease.external.port()),
            )
            .await
            .map_err(|_| P2pError::Timeout)?
            .map_err(|_| P2pError::Mapping)
        }
    }
}

/// Renews the same mapping and preserves `PCP`'s nonce and the assigned external port.
pub async fn renew_port_mapping_with_transport(
    gateway: IpAddr,
    lease: &MappingLease,
    timeout: Duration,
    transport: Option<&dyn MappingTransport>,
) -> Result<MappingLease, P2pError> {
    let renewed = match lease.protocol {
        MappingProtocol::Pcp => {
            pcp_map(
                gateway,
                lease.internal,
                lease.lifetime_seconds,
                timeout,
                lease.nonce,
                Some(lease.external),
                transport,
            )
            .await
        }
        MappingProtocol::NatPmp => {
            let IpAddr::V4(gateway) = gateway else {
                return Err(P2pError::Mapping);
            };
            nat_pmp_map(
                gateway,
                lease.internal,
                lease.lifetime_seconds,
                timeout,
                Some(lease.external.port()),
                transport,
            )
            .await
        }
        MappingProtocol::Upnp => {
            let expected_gateway = gateway;
            let gateway =
                igd_next::aio::tokio::search_gateway(upnp_options(lease.internal, timeout))
                    .await
                    .map_err(|_| P2pError::Mapping)?;
            if gateway.addr.ip() != expected_gateway {
                return Err(P2pError::Mapping);
            }
            tokio::time::timeout(
                timeout,
                gateway.add_port(
                    PortMappingProtocol::UDP,
                    lease.external.port(),
                    lease.internal,
                    lease.lifetime_seconds,
                    "Peerward direct UDP",
                ),
            )
            .await
            .map_err(|_| P2pError::Timeout)?
            .map_err(|_| P2pError::Mapping)?;
            let external_ip = tokio::time::timeout(timeout, gateway.get_external_ip())
                .await
                .map_err(|_| P2pError::Timeout)?
                .map_err(|_| P2pError::Mapping)?;
            let mut renewed = lease.clone();
            renewed.external.set_ip(external_ip);
            Ok(renewed)
        }
    }?;
    if gateway_epoch_restarted(lease.epoch, renewed.epoch) {
        return Err(P2pError::GatewayRestarted);
    }
    Ok(renewed)
}

/// Detects an epoch regression using serial-number arithmetic so a legitimate
/// `u32` wrap is not mistaken for a gateway reboot.
#[must_use]
pub const fn gateway_epoch_restarted(previous: Option<u32>, current: Option<u32>) -> bool {
    match (previous, current) {
        (Some(previous), Some(current)) => current.wrapping_sub(previous) > i32::MAX as u32,
        _ => false,
    }
}

async fn pcp_map(
    gateway: IpAddr,
    internal: SocketAddr,
    lifetime_seconds: u32,
    timeout: Duration,
    nonce: Option<[u8; 12]>,
    suggested: Option<SocketAddr>,
    transport: Option<&dyn MappingTransport>,
) -> Result<MappingLease, P2pError> {
    pcp_map_at(
        SocketAddr::new(gateway, MAPPING_PORT),
        internal,
        lifetime_seconds,
        timeout,
        nonce,
        suggested,
        transport,
    )
    .await
}

async fn pcp_map_at(
    server: SocketAddr,
    internal: SocketAddr,
    lifetime_seconds: u32,
    timeout: Duration,
    nonce: Option<[u8; 12]>,
    suggested: Option<SocketAddr>,
    transport: Option<&dyn MappingTransport>,
) -> Result<MappingLease, P2pError> {
    let mut request = PcpMappingRequest::new(internal, lifetime_seconds, nonce)?;
    if let Some(suggested) = suggested {
        request = request.suggest_external(suggested);
    }
    let response =
        mapping_exchange(transport, server, internal.ip(), request.bytes(), timeout).await?;
    request.accept(&response)
}

fn encode_pcp_map(internal: SocketAddr, lifetime_seconds: u32, nonce: [u8; 12]) -> [u8; 60] {
    let mut request = [0_u8; 60];
    request[0] = PCP_VERSION;
    request[1] = PCP_MAP_OPCODE;
    request[4..8].copy_from_slice(&lifetime_seconds.to_be_bytes());
    request[8..24].copy_from_slice(&ipv6_bytes(internal.ip()));
    request[24..36].copy_from_slice(&nonce);
    request[36] = UDP_PROTOCOL;
    request[40..42].copy_from_slice(&internal.port().to_be_bytes());
    request[42..44].copy_from_slice(&internal.port().to_be_bytes());
    request
}

fn decode_pcp_map(
    response: &[u8],
    internal: SocketAddr,
    nonce: [u8; 12],
    deleting: bool,
) -> Result<MappingLease, P2pError> {
    if response.len() != 60
        || response[0] != PCP_VERSION
        || response[1] != (0x80 | PCP_MAP_OPCODE)
        || response[2] != 0
        || response[3] != 0
        || response[12..24].iter().any(|byte| *byte != 0)
        || response[24..36] != nonce
        || response[36] != UDP_PROTOCOL
        || response[37..40] != [0, 0, 0]
        || u16::from_be_bytes([response[40], response[41]]) != internal.port()
    {
        return Err(P2pError::Mapping);
    }
    let lifetime_seconds =
        u32::from_be_bytes(response[4..8].try_into().map_err(|_| P2pError::Mapping)?);
    if lifetime_seconds == 0 && !deleting {
        return Err(P2pError::Mapping);
    }
    let epoch = u32::from_be_bytes(response[8..12].try_into().map_err(|_| P2pError::Mapping)?);
    let port = u16::from_be_bytes([response[42], response[43]]);
    let address = decode_ip(&response[44..60])?;
    if !deleting && (port == 0 || address.is_unspecified() || address.is_multicast()) {
        return Err(P2pError::Mapping);
    }
    Ok(MappingLease {
        protocol: MappingProtocol::Pcp,
        external: if deleting {
            internal
        } else {
            SocketAddr::new(address, port)
        },
        internal,
        lifetime_seconds,
        epoch: Some(epoch),
        nonce: Some(nonce),
    })
}

async fn nat_pmp_map(
    gateway: Ipv4Addr,
    internal: SocketAddr,
    lifetime_seconds: u32,
    timeout: Duration,
    suggested_port: Option<u16>,
    transport: Option<&dyn MappingTransport>,
) -> Result<MappingLease, P2pError> {
    nat_pmp_map_at(
        SocketAddr::new(IpAddr::V4(gateway), MAPPING_PORT),
        internal,
        lifetime_seconds,
        timeout,
        suggested_port,
        transport,
    )
    .await
}

async fn nat_pmp_map_at(
    server: SocketAddr,
    internal: SocketAddr,
    lifetime_seconds: u32,
    timeout: Duration,
    suggested_port: Option<u16>,
    transport: Option<&dyn MappingTransport>,
) -> Result<MappingLease, P2pError> {
    if !server.is_ipv4() || !internal.is_ipv4() {
        return Err(P2pError::Mapping);
    }
    let response = mapping_exchange(
        transport,
        server,
        internal.ip(),
        &NAT_PMP_PUBLIC_ADDRESS_REQUEST,
        timeout,
    )
    .await?;
    let (external_ip, _) = decode_nat_pmp_public_address(&response)?;
    let request = NatPmpMappingRequest::new(internal, lifetime_seconds)?
        .suggest_external_port(suggested_port.unwrap_or(internal.port()));
    let response =
        mapping_exchange(transport, server, internal.ip(), request.bytes(), timeout).await?;
    request.accept(&response, external_ip)
}

fn decode_nat_pmp_public_address(response: &[u8]) -> Result<(Ipv4Addr, u32), P2pError> {
    if response.len() != 12
        || response[0] != NAT_PMP_VERSION
        || response[1] != 128 + NAT_PMP_PUBLIC_ADDRESS
        || response[2..4] != [0, 0]
    {
        return Err(P2pError::Mapping);
    }
    let epoch = u32::from_be_bytes(response[4..8].try_into().map_err(|_| P2pError::Mapping)?);
    let external = Ipv4Addr::new(response[8], response[9], response[10], response[11]);
    if external.is_unspecified() || external.is_multicast() {
        return Err(P2pError::Mapping);
    }
    Ok((external, epoch))
}

fn decode_nat_pmp_map(
    response: &[u8],
    internal: SocketAddr,
    external_ip: Ipv4Addr,
    deleting: bool,
) -> Result<MappingLease, P2pError> {
    if response.len() != 16
        || response[0] != NAT_PMP_VERSION
        || response[1] != 128 + NAT_PMP_UDP_MAPPING
        || response[2..4] != [0, 0]
        || u16::from_be_bytes([response[8], response[9]]) != internal.port()
    {
        return Err(P2pError::Mapping);
    }
    let epoch = u32::from_be_bytes(response[4..8].try_into().map_err(|_| P2pError::Mapping)?);
    let port = u16::from_be_bytes([response[10], response[11]]);
    let lifetime_seconds =
        u32::from_be_bytes(response[12..16].try_into().map_err(|_| P2pError::Mapping)?);
    if !deleting
        && (port == 0
            || lifetime_seconds == 0
            || external_ip.is_unspecified()
            || external_ip.is_multicast())
    {
        return Err(P2pError::Mapping);
    }
    Ok(MappingLease {
        protocol: MappingProtocol::NatPmp,
        external: if deleting {
            internal
        } else {
            SocketAddr::new(IpAddr::V4(external_ip), port)
        },
        internal,
        lifetime_seconds,
        epoch: Some(epoch),
        nonce: None,
    })
}

include!("mapping_upnp.rs");

async fn udp_exchange(
    server: SocketAddr,
    source: IpAddr,
    request: &[u8],
    timeout: Duration,
) -> Result<Vec<u8>, P2pError> {
    let bind = SocketAddr::new(source, 0);
    let socket = UdpSocket::bind(bind).await?;
    socket.connect(server).await?;
    socket.send(request).await?;
    let mut response = vec![0_u8; 1_024];
    let length = tokio::time::timeout(timeout, socket.recv(&mut response))
        .await
        .map_err(|_| P2pError::Timeout)??;
    response.truncate(length);
    Ok(response)
}

fn ipv6_bytes(address: IpAddr) -> [u8; 16] {
    match address {
        IpAddr::V4(address) => address.to_ipv6_mapped().octets(),
        IpAddr::V6(address) => address.octets(),
    }
}

fn decode_ip(bytes: &[u8]) -> Result<IpAddr, P2pError> {
    let bytes: [u8; 16] = bytes.try_into().map_err(|_| P2pError::Mapping)?;
    let address = Ipv6Addr::from(bytes);
    Ok(address
        .to_ipv4_mapped()
        .map_or(IpAddr::V6(address), IpAddr::V4))
}

/// Exercises the bounded `PCP` and `NAT-PMP` response decoders without network I/O.
///
/// This is only exposed to the separate fuzz workspace and is not part of the
/// default Peerward build.
#[cfg(feature = "fuzzing")]
pub fn fuzz_mapping_codecs(response: &[u8]) {
    let internal = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 41_000);
    let _ = decode_pcp_map(response, internal, [7; 12], false);
    let _ = decode_nat_pmp_map(response, internal, Ipv4Addr::new(203, 0, 113, 10), false);
}

/// Generates a tightly bounded prediction window for stable endpoint-dependent mappings.
pub fn predicted_ports(observations: &[SocketAddr]) -> Vec<u16> {
    if observations.len() < 3
        || observations
            .windows(2)
            .any(|pair| pair[0].ip() != pair[1].ip())
    {
        return Vec::new();
    }
    let deltas = observations
        .windows(2)
        .map(|pair| i32::from(pair[1].port()) - i32::from(pair[0].port()))
        .collect::<Vec<_>>();
    let Some((&minimum, &maximum)) = deltas.iter().min().zip(deltas.iter().max()) else {
        return Vec::new();
    };
    if maximum - minimum > 1 || maximum.unsigned_abs() > 1_024 {
        return Vec::new();
    }
    let delta = deltas.iter().sum::<i32>() / i32::try_from(deltas.len()).unwrap_or(1);
    let center = i32::from(
        observations
            .last()
            .expect("three observations exist")
            .port(),
    ) + delta;
    (-2..=2)
        .filter_map(|offset| u16::try_from(center + offset).ok())
        .filter(|port| *port != 0)
        .collect()
}

/// Rate and failure gate for the opt-in symmetric-NAT prediction heuristic.
#[derive(Debug, Default)]
pub struct SymmetricNatPredictionGate {
    last_round: Option<u64>,
    consecutive_failures: u8,
    cooldown_until: u64,
}

impl SymmetricNatPredictionGate {
    /// Starts at most one prediction round every 30 seconds and observes cooldown.
    pub fn begin_round(&mut self, now: u64) -> bool {
        if now < self.cooldown_until
            || self
                .last_round
                .is_some_and(|last| now.saturating_sub(last) < 30)
        {
            return false;
        }
        self.last_round = Some(now);
        true
    }

    /// Completes a round and enters a ten-minute cooldown after three failures.
    pub fn complete_round(&mut self, now: u64, stable: bool) {
        if stable {
            self.consecutive_failures = 0;
            return;
        }
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        if self.consecutive_failures >= 3 {
            self.consecutive_failures = 0;
            self.cooldown_until = now.saturating_add(10 * 60);
        }
    }
}

include!("mapping_codec.rs");

#[cfg(test)]
#[path = "mapping_tests.rs"]
mod tests;

/// Platform-owned mapping exchange, demultiplexed on the actual protected data socket.
#[async_trait::async_trait]
pub trait MappingTransport: Send + Sync {
    async fn exchange(
        &self,
        server: SocketAddr,
        request: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, P2pError>;
}

async fn mapping_exchange(
    transport: Option<&dyn MappingTransport>,
    server: SocketAddr,
    source: IpAddr,
    request: &[u8],
    timeout: Duration,
) -> Result<Vec<u8>, P2pError> {
    match transport {
        Some(transport) => transport.exchange(server, request, timeout).await,
        None => udp_exchange(server, source, request, timeout).await,
    }
}
