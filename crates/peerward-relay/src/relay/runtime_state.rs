async fn run_health_server(
    listener: TcpListener,
    shared: Arc<RelayShared>,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let Ok((socket, remote)) = accepted else { return; };
                let state = Arc::clone(&shared);
                tokio::spawn(async move {
                    if let Err(error) = respond_health(socket, &state).await {
                        tracing::debug!(%remote, ?error, "Relay health request failed");
                    }
                });
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return;
                }
            }
        }
    }
}

#[derive(Default)]
struct DeliveredRevisions {
    configuration: Option<u64>,
    authorities: Option<u64>,
    peers: Option<u64>,
    relays: Option<u64>,
    policy: Option<u64>,
    services: Option<u64>,
    revocations: Option<u64>,
}

async fn send_initial_state(
    socket: &mut (impl peerward_carrier::RelayIo + ?Sized),
    transport: &mut StreamTransport,
    shared: &RelayShared,
    capabilities: u64,
) -> Result<DeliveredRevisions, RelayError> {
    let mut delivered = DeliveredRevisions::default();
    send_state_updates(socket, transport, shared, &mut delivered, capabilities).await?;
    if delivered.configuration.is_none()
        || delivered.authorities.is_none()
        || delivered.peers.is_none()
        || delivered.relays.is_none()
        || delivered.policy.is_none()
        || delivered.services.is_none()
        || delivered.revocations.is_none()
    {
        return Err(RelayError::NoRoute);
    }
    Ok(delivered)
}

async fn send_state_updates(
    socket: &mut (impl peerward_carrier::RelayIo + ?Sized),
    transport: &mut StreamTransport,
    shared: &RelayShared,
    delivered: &mut DeliveredRevisions,
    capabilities: u64,
) -> Result<(), RelayError> {
    let (
        authorities,
        peers,
        relays,
        policy,
        services,
        revocations,
        configuration,
        publication_context,
    ) = {
        let state = shared.distributions.read().await;
        (
            state.authorities.clone(),
            state.peers.clone(),
            state.relays.clone(),
            state.policy.clone(),
            state.services.clone(),
            state.revocations.clone(),
            state.configuration.clone(),
            state.publication_context,
        )
    };
    if let Some(update) = authorities.filter(|update| {
        delivered
            .authorities
            .is_none_or(|revision| revision < update.bundle.revision)
    }) {
        let encoded = update.encode()?;
        for chunk in split_chunks(
            shared.config.mesh_id,
            update.bundle.revision,
            &encoded,
            48 * 1024,
        )? {
            let control = ControlEnvelope {
                trace_context: state_trace_context(publication_context, capabilities),
                message: Some(ControlMessage::AuthorityDirectory(
                    AuthorityDirectoryChunk {
                        mesh_id: chunk.mesh_id.as_bytes().to_vec(),
                        revision: chunk.revision,
                        index: chunk.index,
                        count: chunk.count,
                        body: chunk.body,
                    },
                )),
            };
            write_noise_record(socket, transport, &Record::Control(control)).await?;
        }
        delivered.authorities = Some(update.bundle.revision);
    }
    if let Some(update) = peers.filter(|update| {
        delivered
            .peers
            .is_none_or(|revision| revision < update.directory.revision)
    }) {
        for mut control in peer_directory_delivery(&update, 48 * 1024)? {
            control.trace_context = state_trace_context(publication_context, capabilities);
            write_noise_record(socket, transport, &Record::Control(control)).await?;
        }
        delivered.peers = Some(update.directory.revision);
    }
    if let Some(update) = relays.filter(|update| {
        delivered
            .relays
            .is_none_or(|revision| revision < update.directory.revision)
    }) {
        for mut control in relay_directory_delivery(&update, 48 * 1024)? {
            control.trace_context = state_trace_context(publication_context, capabilities);
            write_noise_record(socket, transport, &Record::Control(control)).await?;
        }
        delivered.relays = Some(update.directory.revision);
    }
    if let Some(update) = policy.filter(|update| {
        delivered
            .policy
            .is_none_or(|revision| revision < update.bundle.revision)
    }) {
        for mut control in policy_delivery(&update, 48 * 1024)? {
            control.trace_context = state_trace_context(publication_context, capabilities);
            write_noise_record(socket, transport, &Record::Control(control)).await?;
        }
        delivered.policy = Some(update.bundle.revision);
    }
    if let Some(update) = services.filter(|update| {
        delivered
            .services
            .is_none_or(|revision| revision < update.snapshot.revision)
    }) {
        for mut control in service_snapshot_delivery(&update, 48 * 1024)? {
            control.trace_context = state_trace_context(publication_context, capabilities);
            write_noise_record(socket, transport, &Record::Control(control)).await?;
        }
        delivered.services = Some(update.snapshot.revision);
    }
    if let Some(update) = revocations.filter(|update| {
        delivered
            .revocations
            .is_none_or(|revision| revision < update.bundle.revision)
    }) {
        for mut control in revocation_delivery(&update, 48 * 1024)? {
            control.trace_context = state_trace_context(publication_context, capabilities);
            write_noise_record(socket, transport, &Record::Control(control)).await?;
        }
        delivered.revocations = Some(update.bundle.revision);
    }
    if let Some(update) = configuration.filter(|update| {
        delivered
            .configuration
            .is_none_or(|sequence| sequence < update.lease.lease.sequence)
    }) {
        let sequence = update.lease.lease.sequence;
        let bytes = serde_json::to_vec(&update).map_err(|_| RelayError::InvalidConfig)?;
        for chunk in split_chunks(shared.config.mesh_id, sequence, &bytes, 48 * 1024)? {
            let control = ControlEnvelope {
                trace_context: state_trace_context(publication_context, capabilities),
                message: Some(ControlMessage::Configuration(PeerDirectoryChunk {
                    mesh_id: shared.config.mesh_id.as_bytes().to_vec(),
                    revision: sequence,
                    index: chunk.index,
                    count: chunk.count,
                    body: chunk.body,
                })),
            };
            write_noise_record(socket, transport, &Record::Control(control)).await?;
        }
        delivered.configuration = Some(sequence);
    }
    Ok(())
}

fn state_trace_context(
    context: Option<peerward_types::CorrelationContext>,
    capabilities: u64,
) -> Option<peerward_wire::TraceContextV1> {
    if capabilities & peerward_wire::TRACE_CONTEXT_V1_CAPABILITY == 0 {
        return None;
    }
    context.map(|context| peerward_wire::TraceContextV1::from_context(context.child()))
}

async fn respond_health(mut socket: TcpStream, shared: &RelayShared) -> Result<(), RelayError> {
    let mut request = [0_u8; 1024];
    let size = tokio::time::timeout(Duration::from_secs(2), socket.read(&mut request))
        .await
        .map_err(|_| RelayError::NoRoute)??;
    let first_line = std::str::from_utf8(&request[..size])
        .ok()
        .and_then(|text| text.lines().next())
        .unwrap_or_default();
    let path = first_line.split_whitespace().nth(1).unwrap_or_default();
    let stale_for = database_stale_for(shared);
    let complete = shared.distributions.read().await.complete();
    let audit_queued = shared.audit_queued.load(Ordering::Relaxed);
    let audit_dropped = shared.audit_dropped.load(Ordering::Relaxed);
    let link_rekeys = shared.link_rekeys.load(Ordering::Relaxed);
    let invalid_forwarded_frames = shared.invalid_forwarded_frames.load(Ordering::Relaxed);
    let no_route = shared.no_route.load(Ordering::Relaxed);
    let queue_full = shared.queue_full.load(Ordering::Relaxed);
    let backbone_ttl_drops = shared.backbone_ttl_drops.load(Ordering::Relaxed);
    let backbone_loop_drops = shared.backbone_loop_drops.load(Ordering::Relaxed);
    let backbone_forwarded_hops = shared.backbone_forwarded_hops.load(Ordering::Relaxed);
    let topology_revision = shared.topology_revision.load(Ordering::Relaxed);
    let backbone_sessions = shared.traffic.authenticated_backbones.load(Ordering::Relaxed);
    let (backbone_rtt_millis, backbone_loss_permyriad, backbone_health_samples) = {
        let health = shared.backbone_health.lock().await;
        let links = u64::try_from(health.len()).unwrap_or(u64::MAX);
        (
            health
                .values()
                .map(|item| u64::from(item.rtt_millis))
                .sum::<u64>()
                .checked_div(links)
                .unwrap_or_default(),
            health
                .values()
                .map(|item| u64::from(item.loss_permyriad))
                .sum::<u64>()
                .checked_div(links)
                .unwrap_or_default(),
            health
                .values()
                .map(|item| u64::from(item.samples))
                .sum::<u64>(),
        )
    };
    let peer_sessions = shared.authenticated_peers.load(Ordering::Relaxed);
    let (status, content_type, body) = match path {
        "/livez" => (
            "200 OK",
            "application/json",
            "{\"status\":\"live\"}\n".to_owned(),
        ),
        "/readyz" if complete && database_accepts_new_sessions(shared) => (
            "200 OK",
            "application/json",
            "{\"status\":\"ready\"}\n".to_owned(),
        ),
        "/readyz" => (
            "503 Service Unavailable",
            "application/json",
            format!("{{\"status\":\"unready\",\"database_stale_seconds\":{stale_for}}}\n"),
        ),
        "/metrics" => (
            "200 OK",
            "text/plain; version=0.0.4",
            format!(
                "# HELP peerward_relay_ready Relay has complete signed state and fresh database access.\n# TYPE peerward_relay_ready gauge\npeerward_relay_ready {}\n# HELP peerward_relay_database_stale_seconds Seconds since the last successful database operation.\n# TYPE peerward_relay_database_stale_seconds gauge\npeerward_relay_database_stale_seconds {stale_for}\n# HELP peerward_relay_audit_batches_queued_total Encrypted audit batches accepted into the bounded persistence actor.\n# TYPE peerward_relay_audit_batches_queued_total counter\npeerward_relay_audit_batches_queued_total {audit_queued}\n# HELP peerward_relay_audit_batches_dropped_total Encrypted audit batches rejected because the bounded queue was unavailable.\n# TYPE peerward_relay_audit_batches_dropped_total counter\npeerward_relay_audit_batches_dropped_total {audit_dropped}\n# HELP peerward_relay_link_rekeys_total Authenticated links replaced before their hard key limit.\n# TYPE peerward_relay_link_rekeys_total counter\npeerward_relay_link_rekeys_total {link_rekeys}\n# HELP peerward_relay_invalid_forwarded_frames_total Strict opaque/control backbone decoding failures.\n# TYPE peerward_relay_invalid_forwarded_frames_total counter\npeerward_relay_invalid_forwarded_frames_total {invalid_forwarded_frames}\n# HELP peerward_relay_no_route_total Opaque/control frames without an owned route.\n# TYPE peerward_relay_no_route_total counter\npeerward_relay_no_route_total {no_route}\n# HELP peerward_relay_queue_full_total Bounded-capacity backpressure rejections.\n# TYPE peerward_relay_queue_full_total counter\npeerward_relay_queue_full_total {queue_full}\n# HELP peerward_relay_peer_sessions Active authenticated Peer sessions.\n# TYPE peerward_relay_peer_sessions gauge\npeerward_relay_peer_sessions {peer_sessions}\n# HELP peerward_relay_backbone_sessions Active authenticated Relay backbone sessions.\n# TYPE peerward_relay_backbone_sessions gauge\npeerward_relay_backbone_sessions {backbone_sessions}\n# HELP peerward_relay_backbone_rtt_milliseconds Average authenticated keepalive RTT without identity labels.\n# TYPE peerward_relay_backbone_rtt_milliseconds gauge\npeerward_relay_backbone_rtt_milliseconds {backbone_rtt_millis}\n# HELP peerward_relay_backbone_loss_permyriad Average loss in the latest 32-probe windows.\n# TYPE peerward_relay_backbone_loss_permyriad gauge\npeerward_relay_backbone_loss_permyriad {backbone_loss_permyriad}\n# HELP peerward_relay_backbone_health_samples Total bounded observations represented by the aggregate.\n# TYPE peerward_relay_backbone_health_samples gauge\npeerward_relay_backbone_health_samples {backbone_health_samples}\n# HELP peerward_relay_backbone_forwarded_hops_total Aggregate sparse-backbone forwarding hops.\n# TYPE peerward_relay_backbone_forwarded_hops_total counter\npeerward_relay_backbone_forwarded_hops_total {backbone_forwarded_hops}\n# HELP peerward_relay_backbone_ttl_drops_total Sparse routes dropped at the hop bound.\n# TYPE peerward_relay_backbone_ttl_drops_total counter\npeerward_relay_backbone_ttl_drops_total {backbone_ttl_drops}\n# HELP peerward_relay_backbone_loop_drops_total Sparse routes dropped after loop detection.\n# TYPE peerward_relay_backbone_loop_drops_total counter\npeerward_relay_backbone_loop_drops_total {backbone_loop_drops}\n# HELP peerward_relay_topology_revision Current signed Relay topology revision.\n# TYPE peerward_relay_topology_revision gauge\npeerward_relay_topology_revision {topology_revision}\n",
                u8::from(complete && database_accepts_new_sessions(shared)),
            ),
        ),
        _ => (
            "404 Not Found",
            "application/json",
            "{\"error\":\"not_found\"}\n".to_owned(),
        ),
    };
    let body = if path == "/metrics" { body + &traffic_metrics(&shared.traffic) } else { body };
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len(),
    );
    socket.write_all(response.as_bytes()).await?;
    socket.shutdown().await?;
    Ok(())
}

async fn load_admission_snapshot(
    shared: &RelayShared,
    verifier: DirectoryPublicKey,
) -> Result<(), RelayError> {
    let presence_revision = shared.presence.lock().await.revision;
    let snapshot = shared
        .store
        .relay_admission_snapshot(shared.config.mesh_id)
        .await?;
    shared
        .presence
        .lock()
        .await
        .install_snapshot(&snapshot.presence, presence_revision)?;
    shared
        .gate
        .install_admissions(&snapshot.peer_credentials, &snapshot.relay_credentials)?;
    install_signed_states(shared, verifier, snapshot.signed_states).await?;
    shared.event_sequence.store(
        u64::try_from(snapshot.event_high_water).map_err(|_| RelayError::InvalidConfig)?,
        Ordering::Relaxed,
    );
    shared
        .last_database_success
        .store(unix_time().0, Ordering::Relaxed);
    Ok(())
}

async fn catch_up_state(
    shared: &RelayShared,
    verifier: DirectoryPublicKey,
) -> Result<(), RelayError> {
    let after = i64::try_from(shared.event_sequence.load(Ordering::Relaxed))
        .map_err(|_| RelayError::InvalidConfig)?;
    let batch = shared
        .store
        .event_batch_after_sequence(shared.config.mesh_id, after, 500)
        .await?;
    if batch.retention_gap || !batch.events.is_empty() {
        return load_admission_snapshot(shared, verifier).await;
    }
    shared.event_sequence.store(
        u64::try_from(batch.high_water_sequence).map_err(|_| RelayError::InvalidConfig)?,
        Ordering::Relaxed,
    );
    shared
        .last_database_success
        .store(unix_time().0, Ordering::Relaxed);
    Ok(())
}

async fn install_signed_states(
    shared: &RelayShared,
    verifier: DirectoryPublicKey,
    states: Vec<peerward_store::SignedStateRevision>,
) -> Result<(), RelayError> {
    let mut distributions = shared.distributions.write().await;
    let mut router = shared.router.lock().await;
    for state in states {
        let apply_context = if let (Some(request_id), Some(traceparent)) =
            (state.request_id, &state.traceparent)
            && let Ok(context) =
                peerward_types::CorrelationContext::from_traceparent(request_id, traceparent)
        {
            distributions.publication_context = Some(context.child());
            Some(context)
        } else {
            None
        };
        let apply_span = tracing::info_span!(
            "relay.state.apply",
            request_id = tracing::field::Empty,
            traceparent = tracing::field::Empty,
            stage = "relay.apply",
        );
        if let Some(context) = apply_context {
            let _ = apply_span.set_parent(remote_trace_parent(context));
            apply_span.record("request_id", context.request_id.to_string());
            apply_span.record("traceparent", context.traceparent());
        }
        match state.kind {
            SignedStateKind::Configuration => {
                let update: peerward_management::ConfigurationDelivery =
                    serde_json::from_slice(&state.body).map_err(|_| RelayError::InvalidConfig)?;
                verifier
                    .verify_configuration(&update, shared.config.mesh_id)
                    .map_err(|_| RelayError::InvalidConfig)?;
                if update.lease.lease.sequence != state.revision {
                    return Err(RelayError::InvalidConfig);
                }
                if distributions.configuration.as_ref().is_none_or(|current| {
                    current.lease.lease.sequence < update.lease.lease.sequence
                }) {
                    distributions.configuration = Some(update);
                }
            }
            SignedStateKind::Authorities => {
                let update = SignedAuthorityBundle::decode(&state.body)?;
                if distributions
                    .authorities
                    .as_ref()
                    .is_none_or(|current| current.bundle.revision < update.bundle.revision)
                {
                    shared.gate.install_authorities(&update, unix_time())?;
                    distributions.authorities = Some(update);
                }
            }
            SignedStateKind::Peers => {
                let update = decode_peer_directory(&state.body)?;
                if distributions
                    .peers
                    .as_ref()
                    .is_none_or(|current| current.directory.revision < update.directory.revision)
                {
                    router.install_directory(&update)?;
                    distributions.peers = Some(update);
                }
            }
            SignedStateKind::Relays => {
                let update = decode_relay_directory(&state.body)?;
                if distributions
                    .relays
                    .as_ref()
                    .is_none_or(|current| current.directory.revision < update.directory.revision)
                {
                    router.install_relays(&update)?;
                    distributions.relays = Some(update);
                }
            }
            SignedStateKind::RelayTopology => {
                let update = decode_relay_topology(&state.body)?;
                if distributions
                    .topology
                    .as_ref()
                    .is_none_or(|current| current.topology.revision < update.topology.revision)
                {
                    verifier.verify_relay_topology(
                        &update,
                        shared.config.mesh_id,
                        distributions
                            .topology
                            .as_ref()
                            .map(|current| current.topology.revision),
                    )?;
                    shared
                        .topology_revision
                        .store(update.topology.revision, Ordering::Relaxed);
                    if let Some(previous) = distributions.topology.replace(update) {
                        distributions.previous_topology = Some((
                            tokio::time::Instant::now() + Duration::from_mins(1),
                            previous,
                        ));
                    }
                }
            }
            SignedStateKind::Policy => {
                let update = decode_policy(&state.body)?;
                if distributions
                    .policy
                    .as_ref()
                    .is_none_or(|current| current.bundle.revision < update.bundle.revision)
                {
                    router.install_policy(&update)?;
                    distributions.policy = Some(update);
                }
            }
            SignedStateKind::Services => {
                let update: SignedRemoteServiceSnapshot =
                    serde_json::from_slice(&state.body).map_err(|_| RelayError::InvalidConfig)?;
                if distributions
                    .services
                    .as_ref()
                    .is_none_or(|current| current.snapshot.revision < update.snapshot.revision)
                {
                    shared
                        .services
                        .lock()
                        .await
                        .reconcile(&update)
                        .map_err(|_| RelayError::InvalidConfig)?;
                    distributions.services = Some(update);
                }
            }
            SignedStateKind::Revocations => {
                let update = decode_revocations(&state.body)?;
                if distributions
                    .revocations
                    .as_ref()
                    .is_none_or(|current| current.bundle.revision < update.bundle.revision)
                {
                    verifier.verify_revocations(
                        &update,
                        shared.config.mesh_id,
                        distributions
                            .revocations
                            .as_ref()
                            .map(|current| current.bundle.revision),
                    )?;
                    for serial in &update.bundle.serials {
                        shared.gate.revoke(*serial);
                        router.revoke(*serial);
                        shared.services.lock().await.revoke_credential(*serial);
                    }
                    distributions.revocations = Some(update);
                }
            }
        }
    }
    Ok(())
}
