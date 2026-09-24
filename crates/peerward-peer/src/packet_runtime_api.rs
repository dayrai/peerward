/// Concrete live relay/direct transport components ready for the packet pump and control loop.
pub struct LivePacketPaths {
    /// Cloneable encrypted control writer.
    pub relay_control: RelayPoolSender,
    /// Control messages separated from packet records.
    pub controls: mpsc::Receiver<ControlEnvelope>,
    sockets: UdpSockets,
    /// Stops both relay slot workers during runtime cleanup.
    pub relay_shutdown: watch::Sender<bool>,
    relay_workers: Option<RelayWorkerSet>,
    /// Atomically replaces credentials used by both Relay attachment workers.
    identity: watch::Sender<RelayIdentity>,
}

struct RelayWorkerSet {
    shutdown: watch::Sender<bool>,
    workers: Vec<tokio::task::JoinHandle<()>>,
}

impl RelayWorkerSet {
    async fn shutdown(&mut self) {
        let _ = self.shutdown.send(true);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        for mut worker in self.workers.drain(..) {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() || tokio::time::timeout(remaining, &mut worker).await.is_err() {
                worker.abort();
                let _ = worker.await;
            }
        }
    }
}

impl Drop for RelayWorkerSet {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
        for worker in &self.workers {
            worker.abort();
        }
    }
}

/// Establishes live packet paths through an injected platform underlay adapter.
fn establish_live_packet_paths_with_underlay(
    config: &PeerConfig,
    local_private: &[u8; 32],
    credential: &[u8],
    trust: DynamicTrust,
    observability: Option<peerward_service::PeerObservability>,
    underlay: Arc<dyn UnderlayNetwork>,
) -> Result<LivePacketPaths, PeerError> {
    if config.relays.is_empty() {
        return Err(PeerError::NoRelay);
    }
    let (packet_tx, _packet_rx) = mpsc::channel(config.packet_queue_capacity);
    let (control_tx, controls) = mpsc::channel(config.packet_queue_capacity);
    let (relay_shutdown, relay_shutdown_rx) = watch::channel(false);
    let (identity, identity_rx) = watch::channel(RelayIdentity {
        private_key: *local_private,
        credential: credential.to_vec(),
    });
    let relay_count = config.relays.len().min(usize::from(config.relay_pool_size));
    let relay_health = Arc::new(Mutex::new(
        (0..relay_count)
            .map(|_| RelaySlotHealth::default())
            .collect::<Vec<_>>(),
    ));
    let mut slots = Vec::new();
    let mut relay_workers = Vec::with_capacity(relay_count);
    for (index, target) in config
        .relays
        .iter()
        .take(usize::from(config.relay_pool_size))
        .cloned()
        .enumerate()
    {
        let (command_tx, command_rx) = mpsc::channel(config.packet_queue_capacity);
        slots.push(command_tx);
        relay_workers.push(tokio::spawn(relay_slot_worker(
            index,
            target,
            config.mesh_id,
            identity_rx.clone(),
            trust.clone(),
            config.packet_queue_capacity,
            config.keepalive_seconds,
            config.unhealthy_after_missed,
            index == 0,
            command_rx,
            packet_tx.clone(),
            control_tx.clone(),
            relay_shutdown_rx.clone(),
            observability.clone(),
            Arc::clone(&relay_health),
            Arc::clone(&underlay),
            config.relay_transport.clone(),
        )));
    }
    let relay_sender = RelayPoolSender {
        state: Arc::new(Mutex::new(RelayPoolState {
            primary: 0,
            primary_since: monotonic_seconds(),
            better_streak: vec![0; slots.len()],
            slots,
            flow_assignments: BTreeMap::new(),
        })),
        health: relay_health,
        observability: observability.clone(),
    };
    Ok(LivePacketPaths {
        relay_control: relay_sender,
        controls,
        sockets: Arc::new(StdRwLock::new(BTreeMap::new())),
        relay_shutdown: relay_shutdown.clone(),
        relay_workers: Some(RelayWorkerSet {
            shutdown: relay_shutdown.clone(),
            workers: relay_workers,
        }),
        identity,
    })
}

/// Stops and awaits child host transactions when the owning local-management service stops.
pub async fn run_packet_runtime_managed<R: PacketReader, W: PacketWriter>(
    config: PeerConfig,
    local_private: [u8; 32],
    credential: Vec<u8>,
    trust: Arc<TrustSet>,
    tun_reader: R,
    tun_writer: W,
    service_changes: mpsc::Receiver<ServiceChange>,
    observability: peerward_service::PeerObservability,
    dns: crate::DnsServer,
    shutdown: watch::Receiver<bool>,
) -> Result<PacketCounters, PeerError> {
    run_packet_runtime_inner(
        config,
        local_private,
        credential,
        trust,
        tun_reader,
        tun_writer,
        Some(service_changes),
        Some(observability),
        Some(dns),
        Some(shutdown),
    )
    .await
}

/// Binds the Linux DNS listener without starting the packet runtime.
pub async fn bind_peer_dns(config: &PeerConfig) -> Result<crate::DnsServer, PeerError> {
    let linux = config.linux.as_ref().ok_or(PeerError::InvalidConfig)?;
    Ok(crate::DnsServer::bind(crate::DnsServerConfig {
        listen: SocketAddr::new(linux.dns_server, 53),
        suffix: linux.dns_suffix.clone(),
        network: linux.address,
        upstreams: linux.dns_upstreams.clone(),
    })
    .await?)
}
