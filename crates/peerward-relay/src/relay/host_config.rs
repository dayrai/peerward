/// Installation-level configuration, independent of the number of Meshes.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayHostConfig {
    pub config_version: u32,
    /// One optional WSS listener shared by Peer and backbone sessions.
    #[serde(default)]
    pub wss: Option<WssListenerConfig>,
    /// Fixed UDP listener shared by authenticated Peer and backbone connections.
    #[serde(default)]
    pub quic: Option<QuicListenerConfig>,
    #[serde(default)]
    pub relay_transport: peerward_carrier::ClientOptions,
    pub host_id: uuid::Uuid,
    pub control_url: String,
    pub ca_file: PathBuf,
    pub certificate_file: PathBuf,
    pub private_key_file: PathBuf,
    pub state_directory: PathBuf,
    pub database_url: Option<String>,
    #[serde(default = "default_peer_address")]
    pub peer_address: SocketAddr,
    #[serde(default = "default_backbone_address")]
    pub backbone_address: SocketAddr,
    pub health_address: SocketAddr,
    /// Optional host-level Binding listeners, at most one per IP family.
    /// Empty disables public STUN. These ports are shared by all Meshes.
    #[serde(default)]
    pub stun_addresses: Vec<SocketAddr>,
    #[serde(default = "default_max_peer_sessions")]
    pub max_peer_sessions: usize,
    #[serde(default = "default_max_mesh_contexts")]
    pub max_mesh_contexts: usize,
    #[serde(default = "default_max_pending_handshakes")]
    pub max_pending_handshakes: usize,
    #[serde(default = "default_max_pending_handshakes_per_ip")]
    pub max_pending_handshakes_per_ip: usize,
}

impl RelayHostConfig {
    pub fn parse(text: &str, path: &Path, database: Option<String>) -> Result<Self, RelayError> {
        let mut value: Self = toml::from_str(text).map_err(|_| RelayError::InvalidConfig)?;
        if value.database_url.is_none() {
            value.database_url = database;
        }
        if value.config_version != 2
            || value.host_id.get_version_num() != 4
            || !value.control_url.starts_with("https://")
            || value.database_url.as_deref().is_none_or(str::is_empty)
            || value.max_mesh_contexts == 0
            || value.max_peer_sessions == 0
            || value.max_pending_handshakes == 0
            || value.max_pending_handshakes_per_ip == 0
            || value.peer_address == value.backbone_address
            || [value.peer_address, value.backbone_address].contains(&value.health_address)
            || value.stun_addresses.len() > 2
            || value.stun_addresses.iter().any(|address| address.port() == 0 || address.ip().is_multicast())
            || (value.stun_addresses.len() == 2 && value.stun_addresses[0].is_ipv4() == value.stun_addresses[1].is_ipv4())
        {
            return Err(RelayError::InvalidConfig);
        }
        value.relay_transport.validate()?;
        if let Some(wss) = &mut value.wss {
            wss.validate(path, &[value.peer_address, value.backbone_address, value.health_address])?;
        }
        if let Some(quic) = &mut value.quic {
            quic.validate(path, &value.stun_addresses)?;
        }
        let base = path.parent().unwrap_or_else(|| Path::new("."));
        for file in [
            &mut value.ca_file,
            &mut value.certificate_file,
            &mut value.private_key_file,
            &mut value.state_directory,
        ] {
            if file.is_relative() {
                *file = base.join(&*file);
            }
        }
        Ok(value)
    }

    fn client(&self) -> Result<reqwest::Client, RelayError> {
        let mut identity = Zeroizing::new(read_bounded_regular_file(
            &self.certificate_file,
            1024 * 1024,
        )?);
        identity.extend_from_slice(&read_private(&self.private_key_file, 65_536)?);
        reqwest::Client::builder()
            .https_only(true)
            .tls_built_in_root_certs(false)
            .add_root_certificate(
                reqwest::Certificate::from_pem(&read_bounded_regular_file(
                    &self.ca_file,
                    1024 * 1024,
                )?)
                    .map_err(|_| RelayError::InvalidConfig)?,
            )
            .identity(
                reqwest::Identity::from_pem(&identity).map_err(|_| RelayError::InvalidConfig)?,
            )
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|_| RelayError::InvalidConfig)
    }
}

fn default_max_mesh_contexts() -> usize { 1024 }
