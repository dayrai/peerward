/// Strict platform-neutral peer configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerConfig {
    /// Must equal four; earlier profiles must rejoin.
    pub config_version: u32,
    /// Configured mesh.
    pub mesh_id: MeshId,
    /// Local peer identity.
    pub peer_id: PeerId,
    /// Authority-signed credential file.
    pub credential_file: PathBuf,
    /// Ed25519 identity signing key file.
    pub identity_private_key_file: PathBuf,
    /// X25519 static private key file.
    pub private_key_file: PathBuf,
    /// Independent `WireGuard` data-plane private key file.
    pub wireguard_private_key_file: PathBuf,
    /// Offline Root verifier used to authenticate all online Authorities.
    pub root_public_key_file: Option<PathBuf>,
    /// Root-signed Authority certificates accepted during overlap.
    #[serde(default)]
    pub authority_certificate_files: Vec<PathBuf>,
    /// Authority-signed binding for directory and service verifiers.
    pub distribution_certificate_file: Option<PathBuf>,
    /// Initial relay choices; signed directories replace these endpoints.
    pub relays: Vec<RelayTarget>,
    /// Local WSS trust and explicit HTTP CONNECT proxy settings.
    #[serde(default)]
    pub relay_transport: peerward_carrier::ClientOptions,
    /// Bounded packets awaiting transport.
    #[serde(default = "default_queue_capacity")]
    pub packet_queue_capacity: usize,
    /// Keepalive cadence in seconds.
    #[serde(default = "default_keepalive_seconds")]
    pub keepalive_seconds: u64,
    /// Consecutive unanswered probes before failover.
    #[serde(default = "default_missed_keepalives")]
    pub unhealthy_after_missed: u8,
    /// Protected local management socket.
    #[serde(default = "default_management_socket")]
    pub management_socket: PathBuf,
    /// Durable published-service state.
    #[serde(default = "default_service_state_file")]
    pub service_state_file: PathBuf,
    /// Optional Linux system integration; absence retains transport-only operation.
    pub linux: Option<LinuxConfig>,
    /// STUN servers used for direct candidate discovery.
    #[serde(default)]
    pub stun_servers: Vec<peerward_types::StunEndpoint>,
    /// Operator-provided direct UDP candidates.
    #[serde(default)]
    pub p2p_endpoints: Vec<SocketAddr>,
    /// Automatic PCP, NAT-PMP, and `UPnP` port mapping policy.
    #[serde(default = "default_nat_mapping")]
    pub nat_mapping: NatMappingMode,
    /// Experimental bounded symmetric-NAT port prediction.
    #[serde(default)]
    pub symmetric_nat_prediction: bool,
    /// Maximum concurrently maintained Relay sessions.
    #[serde(default = "default_relay_pool_size")]
    pub relay_pool_size: u8,
    /// Ed25519 public key for signed peer, policy, and service distributions.
    pub distribution_public_key: Option<String>,
    /// Ed25519 public key for independently signed service snapshots.
    pub service_distribution_public_key: Option<String>,
    /// X25519 Control recipient key used for encrypted payload-free audit batches.
    pub audit_public_key: Option<String>,
}

fn require_version_first(contents: &str) -> Result<(), PeerError> {
    let first = contents
        .lines()
        .find(|line| !line.trim().is_empty() && !line.trim_start().starts_with('#'))
        .map(str::trim);
    if first == Some("config_version = 4") {
        Ok(())
    } else if matches!(
        first,
        Some("config_version = 1" | "config_version = 2" | "config_version = 3")
    ) {
        Err(PeerError::LegacyProfile)
    } else {
        Err(PeerError::InvalidConfig)
    }
}

/// Linux data-plane portion of the peer document.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxConfig {
    /// TUN interface name.
    #[serde(default = "default_interface")]
    pub interface: String,
    /// Assigned peer address and mesh prefix.
    pub address: ipnet::IpNet,
    /// Optional assigned host address in the opposite family.
    #[serde(default)]
    pub secondary_address: Option<ipnet::IpNet>,
    /// Mesh routes.
    pub routes: Vec<ipnet::IpNet>,
    /// Mesh DNS suffix.
    pub dns_suffix: String,
    /// Mesh DNS gateway.
    pub dns_server: std::net::IpAddr,
    /// Recursive resolvers used only for names outside the mesh suffix.
    #[serde(default)]
    pub dns_upstreams: Vec<SocketAddr>,
    /// Host split-DNS mechanism.
    #[serde(default)]
    pub dns_backend: LinuxDnsBackend,
    /// `NetworkManager` profile, required for that backend.
    pub network_manager_connection: Option<String>,
    /// Resolver file used by the direct fallback.
    #[serde(default = "default_resolv_conf_path")]
    pub resolv_conf_path: PathBuf,
    /// Durable host-network rollback journal.
    #[serde(default = "default_platform_state_file")]
    pub platform_state_file: PathBuf,
    /// Initial nftables allow entries; the packet ACL remains authoritative.
    #[serde(default)]
    pub nft_allow: Vec<LinuxNftAllow>,
    /// TUN MTU.
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    /// Optional inherited TUN descriptor path; absence creates the interface in-process.
    pub attached_tun_file: Option<PathBuf>,
    /// Maximum stateful flows across all shards.
    #[serde(default = "default_packet_state_limit")]
    pub packet_state_limit: usize,
    /// Independent state shards.
    #[serde(default = "default_packet_state_shards")]
    pub packet_state_shards: usize,
}

/// Supported Linux split-DNS manager.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum LinuxDnsBackend {
    /// Probe managed resolvers, openresolv, then resolv.conf.
    #[default]
    Auto,
    /// Per-link `systemd-resolved` configuration.
    SystemdResolved,
    /// Existing `NetworkManager` profile.
    NetworkManager,
    /// Host integration through openresolv.
    #[serde(rename = "openresolv", alias = "open_resolv")]
    OpenResolv,
    /// Direct transactional resolver-file management.
    ResolvConf,
}

/// Automatic local-gateway port mapping policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NatMappingMode {
    /// Try PCP, NAT-PMP, then `UPnP` and retain Relay fallback.
    Auto,
    /// Do not create local-gateway mappings.
    Off,
}

/// Typed nftables allow entry.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxNftAllow {
    /// Destination prefix.
    pub destination: ipnet::IpNet,
    /// Optional `tcp` or `udp`.
    pub protocol: Option<String>,
    /// Optional destination port.
    pub destination_port: Option<u16>,
}

impl LinuxConfig {
    /// Captures recursive resolvers before a local-proxy DNS backend takes ownership.
    pub fn populate_dns_upstreams(&mut self) -> Result<(), PeerError> {
        if !self.dns_upstreams.is_empty() {
            return Ok(());
        }
        let contents = read_resolver_file(&self.resolv_conf_path)?;
        self.dns_upstreams = safe_dns_upstreams(&contents, self);
        if self.dns_upstreams.is_empty()
            && let Some(upstream_path) = systemd_resolved_upstream_path(&self.resolv_conf_path)
            && let Ok(contents) = read_resolver_file(&upstream_path)
        {
            self.dns_upstreams = safe_dns_upstreams(&contents, self);
        }
        if self.dns_upstreams.is_empty() {
            return Err(PeerError::InvalidConfig);
        }
        Ok(())
    }

    /// Converts the document into validated platform intent.
    pub fn platform_config(&self) -> Result<LinuxNetworkConfig, PeerError> {
        let dns_backend = match self.dns_backend {
            LinuxDnsBackend::Auto => DnsBackend::Auto {
                connection: self.network_manager_connection.clone(),
                resolv_conf: self.resolv_conf_path.clone(),
            },
            LinuxDnsBackend::SystemdResolved => DnsBackend::SystemdResolved,
            LinuxDnsBackend::NetworkManager => DnsBackend::NetworkManager {
                connection: self
                    .network_manager_connection
                    .clone()
                    .filter(|value| !value.is_empty())
                    .ok_or(PeerError::InvalidConfig)?,
            },
            LinuxDnsBackend::OpenResolv => DnsBackend::OpenResolv,
            LinuxDnsBackend::ResolvConf => DnsBackend::ResolvConf {
                path: self.resolv_conf_path.clone(),
            },
        };
        let nft_allow = self
            .nft_allow
            .iter()
            .map(|rule| {
                let protocol = match rule.protocol.as_deref() {
                    None => None,
                    Some("tcp") => Some("tcp"),
                    Some("udp") => Some("udp"),
                    Some(_) => return Err(PeerError::InvalidConfig),
                };
                Ok(NftAllow {
                    destination: rule.destination,
                    protocol,
                    destination_port: rule.destination_port,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(LinuxNetworkConfig {
            interface: self.interface.clone(),
            interface_precreated: true,
            address: self.address,
            secondary_address: self.secondary_address,
            mtu: self.mtu,
            routes: self.routes.clone(),
            dns_suffix: self.dns_suffix.clone(),
            dns_server: self.dns_server,
            dns_backend,
            nft_allow,
        })
    }

    /// Builds the initial packet policy; replacement with signed revisions clears this state.
    pub fn packet_firewall(&self) -> Result<Firewall, PeerError> {
        if self.packet_state_limit == 0 || self.packet_state_shards == 0 {
            return Err(PeerError::InvalidConfig);
        }
        let rules = self
            .nft_allow
            .iter()
            .enumerate()
            .map(|(priority, rule)| {
                let protocol = match rule.protocol.as_deref() {
                    None => None,
                    Some("tcp") => Some(6),
                    Some("udp") => Some(17),
                    Some(_) => return Err(PeerError::InvalidConfig),
                };
                Ok(PacketRule {
                    id: RuleId::new(),
                    priority: u32::try_from(priority).map_err(|_| PeerError::InvalidConfig)?,
                    action: PacketAction::Allow,
                    source: None,
                    destination: Some(rule.destination),
                    protocol,
                    destination_ports: rule
                        .destination_port
                        .map_or_else(Vec::new, |port| vec![port..=port]),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Firewall::new(
            1,
            PacketAction::Deny,
            rules,
            self.packet_state_limit,
            self.packet_state_shards,
        ))
    }
}

fn read_resolver_file(path: &Path) -> Result<String, PeerError> {
    String::from_utf8(read_bounded_regular_file(path, 65_536)?)
        .map_err(|_| PeerError::InvalidConfig)
}

fn safe_dns_upstreams(contents: &str, config: &LinuxConfig) -> Vec<SocketAddr> {
    contents
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            (fields.next() == Some("nameserver"))
                .then(|| fields.next()?.parse::<std::net::IpAddr>().ok())
                .flatten()
        })
        .filter(|address| {
            *address != config.dns_server
                && *address != config.address.addr()
                && config
                    .secondary_address
                    .is_none_or(|secondary| secondary.addr() != *address)
                && !address.is_unspecified()
                && !address.is_loopback()
                && !address.is_multicast()
                && !is_link_local(*address)
        })
        .map(|address| SocketAddr::new(address, 53))
        .take(8)
        .collect()
}

fn systemd_resolved_upstream_path(path: &Path) -> Option<PathBuf> {
    let canonical = std::fs::canonicalize(path).ok()?;
    (canonical.file_name()?.to_str()? == "stub-resolv.conf")
        .then(|| canonical.with_file_name("resolv.conf"))
}

fn is_link_local(address: std::net::IpAddr) -> bool {
    match address {
        std::net::IpAddr::V4(address) => address.is_link_local(),
        std::net::IpAddr::V6(address) => address.is_unicast_link_local(),
    }
}

/// Bootstrap relay identity and endpoint.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayTarget {
    /// Relay identity.
    pub relay_id: RelayId,
    /// Ordered Peer-facing endpoints, re-resolved on every reconnect.
    pub endpoints: Vec<NetworkEndpoint>,
    /// Expected X25519 static public key as hexadecimal.
    pub public_key: String,
}

impl PeerConfig {
    /// Parses a versioned document and resolves credential paths from its directory.
    pub fn parse(contents: &str, config_path: &Path) -> Result<Self, PeerError> {
        require_version_first(contents)?;
        let mut config: Self = toml::from_str(contents)?;
        config.relay_transport.validate()?;
        if config.config_version != 4
            || config.relays.is_empty()
            || config.packet_queue_capacity == 0
            || config.keepalive_seconds == 0
            || config.unhealthy_after_missed == 0
            || !(1..=4).contains(&config.relay_pool_size)
            || peerward_types::validate_stun_servers(&config.stun_servers).is_err()
            || config.p2p_endpoints.len() > 8
            || config.p2p_endpoints.iter().any(|endpoint| {
                endpoint.port() == 0
                    || endpoint.ip().is_unspecified()
                    || endpoint.ip().is_multicast()
            })
            || config
                .relays
                .iter()
                .any(|relay| validate_endpoint_list(&relay.endpoints).is_err())
            || config.linux.as_ref().is_some_and(|linux| {
                linux.dns_upstreams.iter().any(|upstream| {
                    upstream.port() == 0 || (*upstream == SocketAddr::new(linux.dns_server, 53))
                })
            })
            || config
                .distribution_public_key
                .as_ref()
                .is_some_and(|value| {
                    hex::decode(value)
                        .ok()
                        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
                        .is_none()
                })
            || config
                .service_distribution_public_key
                .as_ref()
                .is_some_and(|value| {
                    hex::decode(value)
                        .ok()
                        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
                        .is_none()
                })
            || config.audit_public_key.as_ref().is_some_and(|value| {
                hex::decode(value)
                    .ok()
                    .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
                    .is_none()
            })
        {
            return Err(PeerError::InvalidConfig);
        }
        let base = config_path.parent().unwrap_or_else(|| Path::new("."));
        if config.credential_file.is_relative() {
            config.credential_file = base.join(&config.credential_file);
        }
        if config.identity_private_key_file.is_relative() {
            config.identity_private_key_file = base.join(&config.identity_private_key_file);
        }
        if config.wireguard_private_key_file.is_relative() {
            config.wireguard_private_key_file = base.join(&config.wireguard_private_key_file);
        }
        if config.private_key_file.is_relative() {
            config.private_key_file = base.join(&config.private_key_file);
        }
        if let Some(path) = &mut config.root_public_key_file
            && path.is_relative()
        {
            *path = base.join(&*path);
        }
        for path in &mut config.authority_certificate_files {
            if path.is_relative() {
                *path = base.join(&*path);
            }
        }
        if let Some(path) = &mut config.distribution_certificate_file
            && path.is_relative()
        {
            *path = base.join(&*path);
        }
        if config.management_socket.is_relative() {
            config.management_socket = base.join(&config.management_socket);
        }
        if config.service_state_file.is_relative() {
            config.service_state_file = base.join(&config.service_state_file);
        }
        if let Some(linux) = &config.linux {
            linux.platform_config()?;
            linux.packet_firewall()?;
        }
        if let Some(linux) = &mut config.linux {
            if let Some(attached) = &mut linux.attached_tun_file
                && attached.is_relative()
            {
                *attached = base.join(&*attached);
            }
            if linux.platform_state_file.is_relative() {
                linux.platform_state_file = base.join(&linux.platform_state_file);
            }
        }
        Ok(config)
    }
}

const fn default_queue_capacity() -> usize {
    256
}

const fn default_keepalive_seconds() -> u64 {
    10
}

const fn default_missed_keepalives() -> u8 {
    3
}

const fn default_nat_mapping() -> NatMappingMode {
    NatMappingMode::Auto
}

const fn default_relay_pool_size() -> u8 {
    3
}

fn default_management_socket() -> PathBuf {
    "/run/peerward/peer.sock".into()
}

fn default_service_state_file() -> PathBuf {
    "/var/lib/peerward/services.json".into()
}

fn default_resolv_conf_path() -> PathBuf {
    "/etc/resolv.conf".into()
}

fn default_platform_state_file() -> PathBuf {
    "/var/lib/peerward/network-state-v1.json".into()
}

fn default_interface() -> String {
    "peerward0".into()
}

const fn default_mtu() -> u16 {
    1280
}

const fn default_packet_state_limit() -> usize {
    65_536
}

const fn default_packet_state_shards() -> usize {
    16
}
