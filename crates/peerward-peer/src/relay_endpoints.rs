struct RelayEndpointPool {
    admit_presence: bool,
    options: peerward_carrier::ClientOptions,
    preferred: Option<String>,
    failures: std::collections::BTreeMap<String, u32>,
    underlay: Arc<dyn UnderlayNetwork>,
}

impl Default for RelayEndpointPool {
    fn default() -> Self {
        Self::with_underlay(Arc::new(LinuxUnderlayNetwork::default()))
    }
}

impl RelayEndpointPool {
    fn with_underlay(underlay: Arc<dyn UnderlayNetwork>) -> Self {
        Self {
            admit_presence: true,
            options: peerward_carrier::ClientOptions::default(),
            preferred: None,
            failures: std::collections::BTreeMap::new(),
            underlay,
        }
    }

    fn with_options(mut self, options: peerward_carrier::ClientOptions) -> Self {
        self.options = options;
        self
    }

    #[allow(clippy::too_many_arguments)]
    async fn connect_trusted(
        &mut self,
        endpoints: &[NetworkEndpoint],
        local_private: &[u8; 32],
        remote_public: &[u8; 32],
        expected_relay: RelayId,
        expected_mesh: MeshId,
        trust: &TrustSet,
        now: peerward_types::UnixTime,
        hello: HandshakePayload,
    ) -> Result<(BoxStream, StreamTransport, HandshakePayload), PeerError> {
        validate_endpoint_list(endpoints).map_err(|_| PeerError::InvalidConfig)?;
        self.failures
            .retain(|endpoint, _| endpoints.iter().any(|item| item.as_str() == endpoint));
        let mut ordered = endpoints.iter().collect::<Vec<_>>();
        ordered.sort_by_key(|endpoint| {
            (
                endpoint.carrier_priority(),
                usize::from(self.preferred.as_deref() != Some(endpoint.as_str())),
                self.failures.get(endpoint.as_str()).copied().unwrap_or(0),
            )
        });
        // Root-authenticate candidates in parallel; only the selected one sends
        // link_admit, so losing candidates cannot replace its primary lease.
        let mut tasks = tokio::task::JoinSet::new();
        for (index, endpoint) in ordered
            .into_iter()
            .filter(|endpoint| self.options.http_connect_proxy.is_none() || endpoint.is_wss())
            .enumerate()
        {
            let endpoint = endpoint.clone();
            let underlay = Arc::clone(&self.underlay);
            let options = self.options.clone();
            let private = *local_private;
            let public = *remote_public;
            let trust = trust.clone();
            let hello = hello.clone();
            tasks.spawn(async move {
                tokio::time::sleep(Duration::from_millis(
                    u64::try_from(index).unwrap_or(16) * 250,
                ))
                .await;
                let result = tokio::time::timeout(Duration::from_secs(8), async {
                    let addresses =
                        resolve_endpoint(options.dial_endpoint(&endpoint)?, underlay.as_ref())
                            .await?;
                    prepare_resolved_trusted(
                        addresses,
                        private,
                        public,
                        expected_relay,
                        expected_mesh,
                        trust,
                        now,
                        hello,
                        underlay,
                        endpoint.clone(),
                        options,
                    )
                    .await
                })
                .await
                .unwrap_or_else(|_| Err(PeerError::Io(std::io::ErrorKind::TimedOut.into())));
                (endpoint, result)
            });
        }
        let mut last_error = None;
        while let Some(result) = tasks.join_next().await {
            let Ok((endpoint, result)) = result else {
                continue;
            };
            let result = match result {
                Ok(prepared) if self.admit_presence => tokio::time::timeout(
                    Duration::from_secs(5),
                    commit_relay_connection(prepared, expected_mesh),
                )
                .await
                .unwrap_or_else(|_| Err(PeerError::Io(std::io::ErrorKind::TimedOut.into()))),
                Ok(prepared) => Ok(prepared),
                Err(error) => Err(error),
            };
            match result {
                Ok(connected) => {
                    tasks.abort_all();
                    self.preferred = Some(endpoint.to_string());
                    self.failures.insert(endpoint.to_string(), 0);
                    return Ok(connected);
                }
                Err(error @ PeerError::MeshTerminated(_)) => return Err(error),
                Err(error) => last_error = Some(error),
            }
            self.failed(&endpoint);
        }
        Err(last_error.unwrap_or(PeerError::InvalidConfig))
    }

    fn failed(&mut self, endpoint: &NetworkEndpoint) {
        self.failures
            .entry(endpoint.to_string())
            .and_modify(|failures| *failures = failures.saturating_add(1))
            .or_insert(1);
    }
}

async fn resolve_endpoint(
    endpoint: &NetworkEndpoint,
    underlay: &dyn UnderlayNetwork,
) -> Result<Vec<SocketAddr>, std::io::Error> {
    let resolved = underlay
        .resolve_host(&endpoint.host(), endpoint.port())
        .await
        .map_err(std::io::Error::other)?;
    let addresses = interleave_addresses(resolved.into_iter().take(16));
    if addresses.is_empty() {
        Err(std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            "Relay endpoint resolved to no addresses",
        ))
    } else {
        Ok(addresses)
    }
}

fn interleave_addresses(resolved: impl IntoIterator<Item = SocketAddr>) -> Vec<SocketAddr> {
    let mut ipv6 = Vec::new();
    let mut ipv4 = Vec::new();
    for address in resolved {
        let family = if address.is_ipv6() {
            &mut ipv6
        } else {
            &mut ipv4
        };
        if !family.contains(&address) {
            family.push(address);
        }
    }
    let mut addresses = Vec::with_capacity(ipv6.len() + ipv4.len());
    for index in 0..ipv6.len().max(ipv4.len()) {
        if let Some(address) = ipv6.get(index) {
            addresses.push(*address);
        }
        if let Some(address) = ipv4.get(index) {
            addresses.push(*address);
        }
    }
    addresses
}

async fn prepare_resolved_trusted(
    addresses: Vec<SocketAddr>,
    private: [u8; 32],
    public: [u8; 32],
    expected_relay: RelayId,
    expected_mesh: MeshId,
    trust: TrustSet,
    now: UnixTime,
    hello: HandshakePayload,
    underlay: Arc<dyn UnderlayNetwork>,
    endpoint: NetworkEndpoint,
    options: peerward_carrier::ClientOptions,
) -> Result<HeadlessRelayConnection, PeerError> {
    let (sender, mut receiver) = tokio::sync::mpsc::channel(addresses.len());
    let mut tasks = tokio::task::JoinSet::new();
    for (index, address) in addresses.into_iter().enumerate() {
        let sender = sender.clone();
        let underlay = Arc::clone(&underlay);
        let endpoint = endpoint.clone();
        let options = options.clone();
        let trust = trust.clone();
        let hello = hello.clone();
        tasks.spawn(async move {
            tokio::time::sleep(Duration::from_millis(
                u64::try_from(index).unwrap_or(u64::MAX).saturating_mul(250),
            ))
            .await;
            let result = tokio::time::timeout(Duration::from_secs(5), async {
                let socket =
                    dial_relay_carrier(address, underlay.as_ref(), Some((&endpoint, &options)))
                        .await?;
                let (socket, transport, welcome) = connect_relay_ik_stream(
                    socket,
                    &private,
                    &public,
                    hello,
                    Some(peerward_wire::RelayPreface {
                        mesh_id: expected_mesh,
                        target: expected_relay,
                        source: None,
                    }),
                    Some(&trust),
                )
                .await?;
                validate_relay_connection(
                    socket,
                    transport,
                    welcome,
                    &public,
                    expected_relay,
                    expected_mesh,
                    &trust,
                    now,
                )
                .await
            })
            .await
            .unwrap_or_else(|_| {
                Err(PeerError::Io(std::io::Error::from(
                    std::io::ErrorKind::TimedOut,
                )))
            });
            let _ = sender.send(result).await;
        });
    }
    drop(sender);
    let mut last_error = None;
    while let Some(result) = receiver.recv().await {
        match result {
            Ok(connected) => {
                tasks.abort_all();
                return Ok(connected);
            }
            Err(error @ PeerError::MeshTerminated(_)) => return Err(error),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or(PeerError::NoRelay))
}

/// Establishes a Root-authenticated connection using local WSS/CONNECT options.
pub async fn connect_relay_endpoints_with_options(
    endpoints: &[NetworkEndpoint],
    local_private: &[u8; 32],
    remote_public: &[u8; 32],
    expected_relay: RelayId,
    expected_mesh: MeshId,
    trust: &TrustSet,
    now: peerward_types::UnixTime,
    hello: HandshakePayload,
    options: &peerward_carrier::ClientOptions,
) -> Result<(BoxStream, StreamTransport, HandshakePayload), PeerError> {
    RelayEndpointPool::default()
        .with_options(options.clone())
        .connect_trusted(
            endpoints,
            local_private,
            remote_public,
            expected_relay,
            expected_mesh,
            trust,
            now,
            hello,
        )
        .await
}

/// Authenticates a Relay for diagnostics without acquiring a presence lease.
#[allow(clippy::too_many_arguments)]
pub async fn probe_relay_endpoints_with_options(
    endpoints: &[NetworkEndpoint],
    local_private: &[u8; 32],
    remote_public: &[u8; 32],
    expected_relay: RelayId,
    expected_mesh: MeshId,
    trust: &TrustSet,
    now: UnixTime,
    hello: HandshakePayload,
    options: &peerward_carrier::ClientOptions,
) -> Result<(), PeerError> {
    let mut pool = RelayEndpointPool::default().with_options(options.clone());
    pool.admit_presence = false;
    pool.connect_trusted(
        endpoints,
        local_private,
        remote_public,
        expected_relay,
        expected_mesh,
        trust,
        now,
        hello,
    )
    .await
    .map(|_| ())
}
