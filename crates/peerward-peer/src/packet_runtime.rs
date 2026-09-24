include!("packet_runtime_api.rs");
include!("packet_runtime_tasks.rs");
async fn run_packet_runtime_inner<R, W>(
    config: PeerConfig,
    local_private: [u8; 32],
    credential: Vec<u8>,
    trust: Arc<TrustSet>,
    tun_reader: R,
    tun_writer: W,
    service_changes: Option<mpsc::Receiver<ServiceChange>>,
    observability: Option<peerward_service::PeerObservability>,
    prebound_dns: Option<crate::DnsServer>,
    external_shutdown: Option<watch::Receiver<bool>>,
) -> Result<PacketCounters, PeerError>
where
    R: PacketReader,
    W: PacketWriter,
{
    let local_private = zeroize::Zeroizing::new(local_private);
    let termination_path = config.private_key_file.with_extension("mesh-terminated");
    if termination_path.exists() {
        let bytes = peerward_credentials::private_files::read_private(&termination_path, 228)
            .map_err(PeerError::Io)?;
        let terminal = peerward_credentials::MeshTermination::decode(&bytes)?;
        trust.verify_termination(
            &terminal,
            0,
            peerward_types::UnixTime(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|_| PeerError::InvalidConfig)?
                    .as_secs(),
            ),
        )?;
        return Err(PeerError::NoRelay);
    }
    let trust = DynamicTrust::new((*trust).clone());
    let linux = config.linux.as_ref().ok_or(PeerError::InvalidConfig)?;
    if let Some(observability) = &observability {
        observability.initialize(
            config.mesh_id,
            config.peer_id,
            &config
                .relays
                .iter()
                .take(usize::from(config.relay_pool_size))
                .map(|relay| relay.relay_id.to_string())
                .collect::<Vec<_>>(),
        );
        observability.set_tun(true);
    }
    let verifier_bytes: [u8; 32] = hex::decode(
        config
            .distribution_public_key
            .as_deref()
            .ok_or(PeerError::InvalidConfig)?,
    )
    .map_err(|_| PeerError::InvalidConfig)?
    .try_into()
    .map_err(|_| PeerError::InvalidConfig)?;
    let directory_verifier =
        DirectoryPublicKey::from_bytes(&verifier_bytes).map_err(PeerError::Directory)?;
    let distribution_file = config
        .distribution_certificate_file
        .as_ref()
        .ok_or(PeerError::InvalidConfig)?;
    let distribution = peerward_credentials::DistributionCertificate::decode(
        &peerward_credentials::private_files::read_bounded_regular_file(
            distribution_file,
            65_536,
        )?,
    )?;
    let data_private = zeroize::Zeroizing::new(
        read_identity_private_key(&config.wireguard_private_key_file)
            .map_err(packet_error_to_peer)?,
    );
    let mut data_runtime = peerward_peer_core::WireguardRuntime::new(
        config.mesh_id,
        config.peer_id,
        trust.snapshot()?,
        &distribution,
        SubjectCredential::decode(&credential)?,
        x25519_dalek::StaticSecret::from(*data_private),
        usize::from(linux.mtu),
        linux.packet_state_limit,
        linux.packet_state_shards,
        UnixTime(wall_clock_seconds()),
    )?;
    data_runtime.set_resource_platform_ready(false);
    let preferences = ClientPreferenceStore::load(
        &linux.platform_state_file.with_extension("preferences.json"),
        config.mesh_id,
        config.peer_id,
    )
    .map_err(|error| PeerError::Io(std::io::Error::other(error)))?;
    data_runtime.set_preferences(preferences.saved().preferences.clone())?;
    data_runtime.enable_checkpoint(
        &config.private_key_file.with_extension("wireguard-state"),
        UnixTime(wall_clock_seconds()),
    )?;
    let mut carrier_trust = trust.snapshot()?;
    data_runtime.restore_carrier_trust(&mut carrier_trust)?;
    let trust = DynamicTrust::new(carrier_trust);
    drop(data_private);
    let live_policy = Arc::new(LivePeerPolicy {
        mesh_id: config.mesh_id,
        termination_path: Some(termination_path),
        engine: data_runtime.policy(),
    });
    let wireguard_core = Arc::new(Mutex::new(data_runtime));
    let service_verifier_bytes: [u8; 32] = hex::decode(
        config
            .service_distribution_public_key
            .as_deref()
            .ok_or(PeerError::InvalidConfig)?,
    )
    .map_err(|_| PeerError::InvalidConfig)?
    .try_into()
    .map_err(|_| PeerError::InvalidConfig)?;
    let service_verifier = ServiceSnapshotVerifier::from_bytes(&service_verifier_bytes)
        .map_err(|_| PeerError::InvalidConfig)?;
    let underlay: Arc<dyn UnderlayNetwork> =
        Arc::new(crate::packet_underlay::PacketUnderlay::new(&config)?);
    let mut paths = establish_live_packet_paths_with_underlay(
        &config,
        &local_private,
        &credential,
        trust.clone(),
        observability.clone(),
        Arc::clone(&underlay),
    )?;
    let mut relay_workers = paths.relay_workers.take().expect("relay workers are owned");
    let (local_candidates, direct_datagrams, mut candidate_refresh) = start_udp_paths(
        config.clone(),
        underlay,
        Arc::clone(&paths.sockets),
        paths.relay_shutdown.subscribe(),
        observability.clone(),
    );
    let directory = Arc::new(StdRwLock::new(DirectPeerDirectory::new(
        config.mesh_id,
        directory_verifier,
    )));
    let services = Arc::new(Mutex::new(RemoteServiceTable::new(
        config.mesh_id,
        service_verifier,
    )));
    let rotator = Arc::new(Mutex::new(
        CredentialRotator::new(&config, &credential, trust.clone(), paths.identity.clone())
            .map_err(packet_error_to_peer)?,
    ));
    rotator
        .lock()
        .await
        .request_if_due(&paths.relay_control)
        .await
        .map_err(packet_error_to_peer)?;
    let dns = match prebound_dns {
        Some(dns) => dns,
        None => bind_peer_dns(&config).await?,
    }
    .with_management(
        Arc::clone(&wireguard_core),
        config
            .linux
            .as_ref()
            .ok_or(PeerError::InvalidConfig)?
            .address
            .addr(),
        config
            .linux
            .as_ref()
            .and_then(|linux| linux.secondary_address.map(|address| address.addr())),
        config
            .linux
            .as_ref()
            .ok_or(PeerError::InvalidConfig)?
            .dns_server,
        config
            .linux
            .as_ref()
            .ok_or(PeerError::InvalidConfig)?
            .interface
            .clone(),
    )?;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (audit, mut audit_worker) = start_audit_reporter(
        &config,
        paths.relay_control.clone(),
        shutdown_rx.clone(),
        observability.clone(),
    )
    .map_err(packet_error_to_peer)?;
    let signal = shutdown_tx.clone();
    let signal_task = tokio::spawn(async move {
        let _ = peerward_service::shutdown_signal().await;
        let _ = signal.send(true);
    });
    if let Some(observability) = &observability {
        observability.set_task(peerward_service::PeerTask::Packet, true);
        observability.set_task(peerward_service::PeerTask::Control, true);
        observability.set_task(peerward_service::PeerTask::Dns, true);
    }
    let pump_shutdown = shutdown_rx.clone();
    let pump_mtu = usize::from(linux.mtu);
    let (incoming, pump_receiver) = mpsc::channel(config.packet_queue_capacity);
    let wireguard = WireguardPath {
        core: Arc::clone(&wireguard_core),
        relay: paths.relay_control.clone(),
        sockets: Arc::clone(&paths.sockets),
        incoming,
        audit,
        observability: observability.clone(),
        counters: Arc::new(CounterSet::default()),
        mesh: config.mesh_id,
    };
    let data_worker =
        spawn_wireguard_worker(wireguard.clone(), direct_datagrams, shutdown_rx.clone());
    rotator.lock().await.wireguard = Some(Arc::clone(&wireguard_core));
    let pump_sender = wireguard.clone();
    let pump = async move {
        run_wireguard_pump(
            tun_reader,
            tun_writer,
            pump_sender,
            pump_receiver,
            pump_mtu,
            pump_shutdown,
        )
        .await
    };
    let counters = Arc::clone(&wireguard.counters);
    let (client_sender, client_commands) = mpsc::channel(32);
    if let Some(observed) = &observability {
        observed.set_client_management(Arc::new(LocalClientHandle {
            sender: client_sender,
        }));
    }
    let target_health_worker = tokio::spawn(run_target_health(
        paths.relay_control.clone(),
        Arc::clone(&rotator),
        wireguard.clone(),
        shutdown_rx.clone(),
    ));
    let device_evidence_worker=tokio::spawn(run_device_evidence(
        paths.relay_control.clone(),Arc::clone(&rotator),wireguard.clone(),shutdown_rx.clone(),
    ));
    let mut resource_worker = tokio::spawn(run_resource_platform(
        config.linux.clone().ok_or(PeerError::InvalidConfig)?,
        paths.relay_control.clone(),
        Arc::clone(&rotator),
        wireguard.clone(),
        shutdown_rx.clone(),
        preferences,
        client_commands,
    ));
    let control = Box::pin(run_peer_control(
        paths.controls,
        paths.relay_control,
        local_candidates,
        trust,
        Arc::new(StdRwLock::new(ChunkAssembler::new(
            config.mesh_id,
            MAX_SIGNED_STATE_CHUNKS,
            MAX_SIGNED_STATE_BYTES,
        ))),
        Some(Arc::clone(&directory)),
        config.peer_id,
        Some(Arc::clone(&services)),
        Arc::clone(&live_policy),
        Some(rotator),
        service_changes,
        observability.clone(),
        shutdown_rx.clone(),
        wireguard,
    ));
    let dns_observability = observability.clone();
    let dns = async move {
        match dns_observability {
            Some(observability) => {
                dns.serve_observed(directory, services, live_policy, observability, shutdown_rx)
                    .await
            }
            None => {
                dns.serve(directory, services, live_policy, shutdown_rx)
                    .await
            }
        }
    };
    let mut resource_finished = false;
    let cancellation = async move {
        let Some(mut receiver) = external_shutdown else {
            return std::future::pending::<()>().await;
        };
        loop {
            let stopped = *receiver.borrow();
            if stopped || receiver.changed().await.is_err() {
                break;
            }
        }
    };
    let mut result = tokio::select! {
        ()=cancellation=>Ok(counters.snapshot()),
        result=race_packet_tasks(pump,control,dns,Arc::clone(&counters))=>result,
        result=&mut resource_worker=>{
            resource_finished=true;
            match result { Ok(Err(error))=>Err(packet_error_to_peer(error)), _=>Err(PeerError::InvalidConfig) }
        }
    };
    let _ = shutdown_tx.send(true);
    target_health_worker.abort();
    let _ = target_health_worker.await;
    device_evidence_worker.abort();
    let _ = device_evidence_worker.await;
    if !resource_finished {
        match resource_worker.await {
            Ok(Ok(())) => {}
            failed => {
                tracing::error!(?failed, "resource network rollback incomplete");
                if result.is_ok() {
                    result = Err(PeerError::InvalidConfig);
                }
            }
        }
    }
    if tokio::time::timeout(Duration::from_secs(3), &mut audit_worker)
        .await
        .is_err()
    {
        audit_worker.abort();
        let _ = audit_worker.await;
    }
    relay_workers.shutdown().await;
    if let Some(observability) = &observability {
        for task in [
            peerward_service::PeerTask::Packet,
            peerward_service::PeerTask::Control,
            peerward_service::PeerTask::Dns,
        ] {
            observability.set_task(task, false);
        }
        observability.set_tun(false);
    }
    // Cancel all owners of runtime locks before destroying session state.
    data_worker.abort();
    let _ = data_worker.await;
    wireguard_core.lock().await.close();
    signal_task.abort();
    let _ = signal_task.await;
    if tokio::time::timeout(Duration::from_secs(3), &mut candidate_refresh)
        .await
        .is_err()
    {
        candidate_refresh.abort();
        let _ = candidate_refresh.await;
    }
    result
}

fn packet_error_to_peer(error: PacketPumpError) -> PeerError {
    match error {
        PacketPumpError::Io(error) => PeerError::Io(error),
        PacketPumpError::Wire(error) => PeerError::Wire(error),
        PacketPumpError::InvalidPacket => PeerError::InvalidPacket,
        PacketPumpError::QueueFull => PeerError::QueueFull,
        PacketPumpError::NoRoute => PeerError::NoRoute,
        error @ (PacketPumpError::Direct(_)
        | PacketPumpError::InvalidControl
        | PacketPumpError::SessionPending) => PeerError::PacketRuntime(Box::new(error)),
    }
}

#[async_trait]
impl PacketSender for NoiseRelaySender {
    async fn send_packet(&mut self, _: &[u8], _: u64) -> Result<DataPath, PacketPumpError> {
        Err(PacketPumpError::InvalidControl)
    }
}

#[async_trait]
impl OpaqueRelaySender for NoiseRelaySender {
    async fn send_opaque(
        &mut self,
        mesh_id: MeshId,
        destination: PeerId,
        ciphertext: &[u8],
    ) -> Result<DataPath, PacketPumpError> {
        self.send_control(ControlEnvelope {
            trace_context: None,
            message: Some(ControlMessage::Opaque(RelayEnvelopeV2 {
                major: PROTOCOL_MAJOR,
                mesh_id: mesh_id.as_bytes().to_vec(),
                destination_peer: destination.as_bytes().to_vec(),
                source_peer: Vec::new(),
                kind: OpaqueFrameKind::Session as i32,
                opaque: ciphertext.to_vec(),
            })),
        })
        .await?;
        Ok(DataPath::Relay)
    }
}

impl NoiseRelaySender {
    /// Encrypts one control envelope on the same ordered relay stream.
    pub async fn send_control(&self, control: ControlEnvelope) -> Result<(), PacketPumpError> {
        let mut writer = self.writer.lock().await;
        let frame = self
            .transport
            .lock()
            .await
            .encode(&Record::Control(control))?;
        writer.write_all(&frame).await?;
        writer.flush().await?;
        Ok(())
    }
}

/// Ordered encrypted control output used by direct and directory processing.
#[async_trait]
pub trait ControlSender: Clone + Send + Sync {
    /// Sends one authenticated control message.
    async fn send_control(&self, control: ControlEnvelope) -> Result<(), PacketPumpError>;
}

#[async_trait]
impl ControlSender for NoiseRelaySender {
    async fn send_control(&self, control: ControlEnvelope) -> Result<(), PacketPumpError> {
        NoiseRelaySender::send_control(self, control).await
    }
}

include!("noise_relay_reader.rs");
