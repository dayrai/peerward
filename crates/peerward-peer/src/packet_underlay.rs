//! The only DNS bypass is for endpoints explicitly configured for control and NAT discovery.
use crate::{PeerConfig, PeerError};
use peerward_platform::{LinuxUnderlayNetwork, PlatformError, UnderlayNetwork};
use std::{
    collections::BTreeSet,
    net::{IpAddr, SocketAddr},
};
use tokio::{
    net::{TcpStream, UdpSocket},
    sync::watch,
};

pub(crate) struct PacketUnderlay {
    network: LinuxUnderlayNetwork,
    upstreams: Vec<SocketAddr>,
    endpoints: BTreeSet<(String, u16)>,
    dns_budget: tokio::sync::Semaphore,
}
impl PacketUnderlay {
    pub(crate) fn new(config: &PeerConfig) -> Result<Self, PeerError> {
        let linux = config.linux.as_ref().ok_or(PeerError::InvalidConfig)?;
        let mut endpoints: BTreeSet<_> = config
            .relays
            .iter()
            .flat_map(|relay| relay.endpoints.iter())
            .map(|endpoint| (endpoint.host(), endpoint.port()))
            .collect();
        endpoints.extend(
            config
                .stun_servers
                .iter()
                .map(|endpoint| (endpoint.host(), endpoint.port())),
        );
        if let Some(proxy) = &config.relay_transport.http_connect_proxy {
            endpoints.insert((proxy.host(), proxy.port()));
        }
        Ok(Self {
            network: LinuxUnderlayNetwork::protected(),
            upstreams: linux.dns_upstreams.clone(),
            endpoints,
            dns_budget: tokio::sync::Semaphore::new(16),
        })
    }
}
#[async_trait::async_trait]
impl UnderlayNetwork for PacketUnderlay {
    async fn resolve_host(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, PlatformError> {
        if !self.endpoints.contains(&(host.to_owned(), port)) {
            return Err(PlatformError::Command(
                "unconfigured underlay DNS endpoint".into(),
            ));
        }
        if let Ok(address) = host.parse::<IpAddr>() {
            return Ok(vec![SocketAddr::new(address, port)]);
        }
        let _permit = self
            .dns_budget
            .acquire()
            .await
            .map_err(|_| PlatformError::Command("underlay DNS unavailable".into()))?;
        crate::dns::resolve_bootstrap(&self.network, &self.upstreams, host, port)
            .await
            .map_err(PlatformError::Io)
    }
    async fn bind_udp(&self, address: SocketAddr) -> Result<UdpSocket, PlatformError> {
        self.network.bind_udp(address).await
    }
    async fn bind_udp_on(
        &self,
        address: SocketAddr,
        interface: &str,
    ) -> Result<UdpSocket, PlatformError> {
        self.network.bind_udp_on(address, interface).await
    }
    async fn connect_tcp(&self, address: SocketAddr) -> Result<TcpStream, PlatformError> {
        self.network.connect_tcp(address).await
    }
    async fn default_gateway(&self) -> Result<IpAddr, PlatformError> {
        self.network.default_gateway().await
    }
    fn network_changes(&self) -> watch::Receiver<u64> {
        self.network.network_changes()
    }
}
