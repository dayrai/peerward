async fn run_outgoing_backbone(
    shared: Arc<RelayShared>,
    remote_id: RelayId,
    mut outbound: mpsc::Receiver<BackbonePayload>,
) {
    let mut attempt = 0_u8;
    let mut ready_connection = None;
    loop {
        if !is_backbone_neighbor(&shared, remote_id).await {
            return;
        }
        if !database_accepts_new_sessions(&shared) {
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        }
        let Ok(remote) = current_relay_entry(&shared, remote_id).await else {
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        };
        if shared.gate.is_revoked(remote.credential_serial).unwrap_or(true)
            || !shared
                .gate
                .relay_admitted(remote.relay_id, remote.credential_serial)
                .unwrap_or(false)
        {
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        }
        let connection = if let Some(connection) = ready_connection.take() {
            Ok(connection)
        } else {
            connect_backbone(Arc::clone(&shared), remote_id).await
        };
        let Ok((mut socket, transport, bootstrap)) = connection else {
            tokio::time::sleep(reconnect_delay(attempt, remote.relay_id)).await;
            attempt = attempt.saturating_add(1);
            continue;
        };
        attempt = 0;
        let _authenticated=AuthenticatedBackboneCounter::acquire(&shared.traffic);
        match drive_backbone(
            &mut socket,
            transport,
            &shared,
            remote.relay_id,
            remote.credential_serial,
            &mut outbound,
            Some(remote_id),
            bootstrap,
        )
        .await
        {
            Ok(Some(connection)) => {
                ready_connection = Some(connection);
                continue;
            }
            Err(error) => {
                tracing::debug!(%remote_id, ?error, "Outgoing Relay backbone ended");
                shared.backbone_health.lock().await.remove(&remote_id);
            }
            Ok(None) => {
                shared.backbone_health.lock().await.remove(&remote_id);
            }
        }
        tokio::time::sleep(reconnect_delay(attempt, remote.relay_id)).await;
        attempt = attempt.saturating_add(1);
    }
}

async fn run_incoming_backbone(
    mut socket: impl peerward_carrier::RelayIo + 'static,
    shared: Arc<RelayShared>,
) -> Result<(), RelayError> {
    let mut bytes = [0; peerward_wire::RELAY_PREFACE_LEN];
    tokio::time::timeout(Duration::from_secs(5), socket.read_exact(&mut bytes)).await.map_err(|_| RelayError::HandshakeLimited)??;
    let preface = peerward_wire::RelayPreface::decode(&bytes)?;
    if preface.mesh_id != shared.config.mesh_id || preface.target != shared.config.relay_id || preface.source.is_none() {
        return Err(RelayError::NoRoute);
    }
    run_incoming_backbone_prefaced(socket, shared, Some(preface), None).await
}

async fn run_incoming_backbone_prefaced(
    mut socket: impl peerward_carrier::RelayIo + 'static, shared: Arc<RelayShared>, preface: Option<peerward_wire::RelayPreface>,
    host_permits: Option<(tokio::sync::OwnedSemaphorePermit, IpHandshakePermit)>,
) -> Result<(), RelayError> {
    if !database_accepts_new_sessions(&shared) { return Err(RelayError::NoRoute); }
    let mut raw_id = [0_u8; 16];
    if let Some(preface) = preface {
        raw_id = *preface.source.ok_or(RelayError::NoRoute)?.as_bytes();
    } else {
        tokio::time::timeout(Duration::from_secs(3), socket.read_exact(&mut raw_id))
            .await.map_err(|_| RelayError::NoRoute)??;
    }
    let remote_id = RelayId::from_uuid(uuid::Uuid::from_bytes(raw_id))
        .map_err(|_| RelayError::NoRoute)?;
    if !should_initiate(remote_id, shared.config.relay_id) {
        return Err(RelayError::NoRoute);
    }
    if !is_backbone_neighbor(&shared, remote_id).await {
        return Err(RelayError::NoRoute);
    }
    let remote = shared
        .distributions
        .read()
        .await
        .relays
        .as_ref()
        .and_then(|directory| {
            directory
                .directory
                .entries
                .iter()
                .find(|entry| entry.relay_id == remote_id)
                .cloned()
        })
        .ok_or(RelayError::NoRoute)?;
    if shared.gate.is_revoked(remote.credential_serial)?
        || !shared
            .gate
            .relay_admitted(remote.relay_id, remote.credential_serial)?
    {
        return Err(RelayError::NoRoute);
    }
    let handshake_permit = Arc::clone(&shared.handshakes)
        .try_acquire_owned()
        .map_err(|_| RelayError::HandshakeLimited)?;
    let transport = tokio::time::timeout(
        Duration::from_secs(shared.config.handshake_timeout_seconds),
        relay_kk_prefaced(
            &mut socket,
            false,
            &shared.local_private,
            &remote.noise_public_key,
            preface,
        ),
    )
    .await
    .map_err(|_| RelayError::HandshakeLimited)??;
    let (socket, transport) = peerward_carrier::quic::activate(Box::new(socket), transport, preface, monotonic_seconds()).await?;
    let mut socket=MeteredStream::wrap(socket,&shared.traffic);
    let _authenticated=AuthenticatedBackboneCounter::acquire(&shared.traffic);
    drop(handshake_permit);
    drop(host_permits);
    let (sender, mut outbound) = mpsc::channel(shared.config.queue_capacity);
    let previous = {
        let mut registry = shared.backbones.lock().await;
        registry.insert(remote_id, sender.clone())
    };
    let result = drive_backbone(
        &mut socket,
        transport,
        &shared,
        remote_id,
        remote.credential_serial,
        &mut outbound,
        None,
        Vec::new(),
    )
    .await;
    if result.is_err() {
        shared.backbone_health.lock().await.remove(&remote_id);
    }
    let mut registry = shared.backbones.lock().await;
    if registry
        .get(&remote_id)
        .is_some_and(|current| current.same_channel(&sender))
    {
        if let Some(previous) = previous.filter(|previous| !previous.is_closed()) {
            registry.insert(remote_id, previous);
        } else {
            registry.remove(&remote_id);
        }
    }
    result.map(|_| ())
}

async fn drive_backbone(
    socket: &mut (impl peerward_carrier::RelayIo + ?Sized),
    mut transport: StreamTransport,
    shared: &Arc<RelayShared>,
    remote_relay: RelayId,
    remote_credential: CredentialSerial,
    outbound: &mut mpsc::Receiver<BackbonePayload>,
    rollover_remote: Option<RelayId>,
    bootstrap: Vec<Record>,
) -> Result<Option<BackboneConnection>, RelayError> {
    let snapshot = shared
        .presence
        .lock()
        .await
        .announcements_owned_by(shared.config.relay_id);
    if snapshot.len() > shared.config.queue_capacity.saturating_mul(16) {
        return Err(RelayError::QueueFull);
    }
    for update in snapshot {
        let payload = if let Some(topology) = sparse_topology(shared).await {
            BackbonePayload::RoutedPresence(
                update,
                BackboneRoute {
                    origin: shared.config.relay_id,
                    destination: None,
                    topology_revision: topology.revision,
                    hop_limit: 4,
                    visited: vec![shared.config.relay_id],
                },
            )
        } else {
            BackbonePayload::Presence(update)
        };
        let control = backbone_control_envelope(shared.config.mesh_id, &payload)?;
        write_noise_record(socket, &mut transport, &Record::Control(control)).await?;
    }
    if rollover_remote.is_none() {
        write_link_ready(socket, &mut transport, shared.config.mesh_id).await?;
    }
    let mut health = ConnectionHealth::new(3)?;
    for record in bootstrap {
        handle_backbone_record(
            record,
            socket,
            &mut transport,
            shared,
            remote_relay,
            &mut health,
        )
        .await?;
    }
    let first_probe = tokio::time::Instant::now() + Duration::from_secs(15);
    let mut probe = tokio::time::interval_at(first_probe, Duration::from_secs(15));
    probe.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut replacement: Option<
        tokio::task::JoinHandle<Result<BackboneConnection, RelayError>>,
    > = None;
    let mut replacement_attempt = 0_u8;
    let mut retry_replacement_at = 0_u64;
    loop {
        let now = monotonic_seconds();
        if transport.hard_expired(now) {
            if let Some(task) = replacement.take() {
                task.abort();
            }
            return Err(RelayError::Wire(WireError::RekeyRequired));
        }
        if transport.rekey_due(now)
            && replacement.is_none()
            && now >= retry_replacement_at
            && let Some(remote_id) = rollover_remote
        {
            let state = Arc::clone(shared);
            let cancel = shared.cancel.clone();
            replacement = Some(shared.tasks.spawn(async move {
                tokio::select! {
                    () = cancel.cancelled() => Err(RelayError::NoRoute),
                    result = connect_backbone(state, remote_id) => result,
                }
            }));
        }
        if !database_allows_existing_sessions(shared) {
            return Err(RelayError::NoRoute);
        }
        if !is_backbone_neighbor(shared, remote_relay).await {
            return Err(RelayError::NoRoute);
        }
        if shared.gate.is_revoked(remote_credential)?
            || !shared
                .gate
                .relay_admitted(remote_relay, remote_credential)?
        {
            return Err(RelayError::NoRoute);
        }
        for _ in 0..64 {
            let Ok(payload) = outbound.try_recv() else {
                break;
            };
            let control = backbone_control_envelope(shared.config.mesh_id, &payload)?;
            write_noise_record(socket, &mut transport, &Record::Control(control)).await?;
        }
        tokio::select! {
            completed = await_backbone_replacement(&mut replacement) => {
                replacement = None;
                match completed {
                    Ok(connection) => {
                        shared.link_rekeys.fetch_add(1, Ordering::Relaxed);
                        let _ = write_noise_record(
                            socket,
                            &mut transport,
                            &Record::Control(ControlEnvelope {
                                trace_context: None,
                                message: Some(ControlMessage::Close(peerward_wire::GracefulClose {
                                    mesh_id: shared.config.mesh_id.as_bytes().to_vec(),
                                    body: b"link_rekey".to_vec(),
                                })),
                            }),
                        ).await;
                        return Ok(Some(connection));
                    }
                    Err(error) => {
                        tracing::warn!(%remote_relay, ?error, "Parallel Relay backbone replacement failed");
                        replacement_attempt = replacement_attempt.saturating_add(1);
                        retry_replacement_at = monotonic_seconds().saturating_add(
                            reconnect_delay(replacement_attempt, remote_relay).as_secs().max(1),
                        );
                    }
                }
            }
            incoming = tokio::time::timeout(
                Duration::from_millis(10),
                read_noise_record(socket, &mut transport),
            ) => match incoming {
                Err(_) => {}
                Ok(Err(error)) => return Err(error),
                Ok(Ok(record)) => handle_backbone_record(
                    record,
                    socket,
                    &mut transport,
                    shared,
                    remote_relay,
                    &mut health,
                ).await?,
            },
            _ = probe.tick() => {
                let parity = u64::from(shared.config.relay_id.as_bytes() > remote_relay.as_bytes());
                let timestamp = (monotonic_millis() & !1) | parity;
                let unhealthy = health.probe(timestamp);
                record_backbone_health(shared, remote_relay, &health).await;
                if unhealthy {
                    return Err(RelayError::NoRoute);
                }
                write_noise_record(
                    socket,
                    &mut transport,
                    &Record::Control(ControlEnvelope {
                        trace_context: None,
                        message: Some(ControlMessage::Keepalive(Keepalive {
                            monotonic_timestamp: timestamp,
                        })),
                    }),
                ).await?;
            },
        }
    }
}

include!("runtime_backbone_support.rs");

async fn run_incoming_backbone_host(socket: impl peerward_carrier::RelayIo + 'static, shared: Arc<RelayShared>,
    preface: peerward_wire::RelayPreface, handshake: tokio::sync::OwnedSemaphorePermit, ip: IpHandshakePermit,
) -> Result<(), RelayError> {
    run_incoming_backbone_prefaced(socket, shared, Some(preface), Some((handshake, ip))).await
}
