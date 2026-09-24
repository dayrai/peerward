async fn initialize_mesh_runtime(
    config: RelayConfig,
    local_private: [u8; 32],
    local_credential: Vec<u8>,
    distribution: DistributionCertificate,
    credential_gate: Arc<CredentialGate>,
    store: Store,
    shutdown: watch::Receiver<bool>,
    database_policy: RelayDatabasePolicy,
    routed: bool,
    traffic: Arc<TrafficCounters>,
) -> Result<MeshRuntime, RelayError> {
    if distribution.mesh_id != config.mesh_id {
        return Err(RelayError::InvalidConfig);
    }
    let directory_verifier = DirectoryPublicKey::from_bytes(&distribution.directory_public_key)?;
    let service_verifier = ServiceSnapshotVerifier::from_bytes(&distribution.service_public_key)
        .map_err(|_| RelayError::InvalidConfig)?;
    let private = Arc::new(zeroize::Zeroizing::new(local_private));
    let (audit_sender, audit_receiver) = mpsc::channel(config.queue_capacity);
    let shared = Arc::new(RelayShared {
        traffic: Arc::clone(&traffic),
        authenticated_peers: AtomicU64::new(0),
        routed,
        accepting_peers: std::sync::atomic::AtomicBool::new(true),
        admission_lock: Mutex::new(()),
        router: Mutex::new(OpaqueRouter::new(
            config.mesh_id,
            config.relay_id,
            directory_verifier,
            config.queue_capacity,
        )?),
        services: Mutex::new(RemoteServiceTable::new(config.mesh_id, service_verifier)),
        presence: Mutex::new(PresenceCache::default()),
        distributions: AsyncRwLock::new(RelayDistributions::default()),
        backbones: Mutex::new(BTreeMap::new()),
        backbone_health: Mutex::new(BTreeMap::new()),
        local_private: Arc::clone(&private),
        local_credential: Arc::new(local_credential),
        last_database_success: AtomicU64::new(unix_time().0),
        event_sequence: AtomicU64::new(0),
        database_policy,
        peer_sessions: Arc::new(Semaphore::new(config.max_peer_sessions)),
        handshakes: Arc::new(Semaphore::new(config.max_pending_handshakes)),
        pending_routes: Semaphore::new(64),
        ip_handshakes: Arc::new(IpHandshakeLimiter::new(
            config.max_pending_handshakes_per_ip,
        )),
        audit_sender,
        audit_queued: Arc::clone(&traffic.audit_queued),
        audit_dropped: Arc::clone(&traffic.audit_dropped),
        link_rekeys: AtomicU64::new(0),
        invalid_forwarded_frames: Arc::clone(&traffic.invalid_forwarded_frames),
        no_route: Arc::clone(&traffic.no_route),
        queue_full: Arc::clone(&traffic.queue_full),
        backbone_ttl_drops: AtomicU64::new(0),
        backbone_loop_drops: AtomicU64::new(0),
        backbone_forwarded_hops: AtomicU64::new(0),
        topology_revision: AtomicU64::new(0),
        config: config.clone(),
        store,
        gate: credential_gate,
        cancel: tokio_util::sync::CancellationToken::new(),
        tasks: tokio_util::task::TaskTracker::new(),
        termination: watch::channel(None).0,
    });
    load_admission_snapshot(&shared, directory_verifier).await?;
    if !shared.distributions.read().await.complete() {
        return Err(RelayError::NoRoute);
    }
    let own_credential = SubjectCredential::decode(&shared.local_credential)?;
    if routed
        && !shared
            .distributions
            .read()
            .await
            .relays
            .as_ref()
            .is_some_and(|signed| {
                signed.directory.entries.iter().any(|entry| {
                    entry.relay_id == config.relay_id
                        && entry.noise_public_key == own_credential.public_noise_key
                        && entry.credential_serial == own_credential.serial
                })
            })
    {
        return Err(RelayError::NoRoute);
    }

    let instance_id = uuid::Uuid::new_v4();
    let runtime_generation = shared
        .store
        .acquire_relay_runtime_with_capabilities(
            config.mesh_id,
            config.relay_id,
            instance_id,
            OffsetDateTime::now_utc() + time::Duration::seconds(30),
            peerward_wire::SUPPORTED_CAPABILITIES,
        )
        .await?;

    let audit_task = spawn_mesh_task(
        &shared,
        run_audit_ingress(Arc::clone(&shared), audit_receiver, shutdown),
    );
    watch_database_expiry(&shared);
    Ok(MeshRuntime {
        shared,
        directory_verifier,
        instance_id,
        runtime_generation,
        audit_task,
    })
}

include!("runtime_distributions.rs");

include!("runtime_peer_limits.rs");

include!("runtime_serve.rs");

include!("runtime_peer_session.rs");
async fn drive_fenced_peer_records(
    socket: &mut (impl peerward_carrier::RelayIo + ?Sized),
    mut transport: StreamTransport,
    shared: &RelayShared,
    lease: &mut PresenceLease,
    generation: &mut i64,
    credential_serial: CredentialSerial,
    capabilities: u64,
) -> Result<(), RelayError> {
    use futures_util::StreamExt as _;
    let mut pending = futures_util::stream::FuturesUnordered::new();
    write_link_ready(socket, &mut transport, shared.config.mesh_id).await?;
    let mut delivered_state =
        send_initial_state(socket, &mut transport, shared, capabilities).await?;
    let renew_seconds = shared
        .config
        .keepalive_seconds
        .min(shared.config.lease_seconds);
    let mut renewal = tokio::time::interval(Duration::from_secs(renew_seconds));
    renewal.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    renewal.tick().await;
    let mut delivery = tokio::time::interval(Duration::from_millis(10));
    delivery.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    delivery.tick().await;
    let mut rotation_delivery = tokio::time::interval(Duration::from_secs(1));
    rotation_delivery.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    rotation_delivery.tick().await;
    let mut state_delivery = tokio::time::interval(Duration::from_secs(1));
    state_delivery.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    state_delivery.tick().await;
    let mut termination = shared.termination.subscribe();
    let mut delivered_rotation = None;
    let mut delivered_renewal = None;
    shared
        .store
        .observe_peer_renewal_capability(
            shared.config.mesh_id,
            lease.peer_id,
            credential_serial,
            capabilities & peerward_wire::CREDENTIAL_RENEWAL_V1_CAPABILITY != 0,
        )
        .await?;
    loop {
        if transport.hard_expired(monotonic_seconds()) {
            return Err(RelayError::Wire(WireError::RekeyRequired));
        }
        if shared.gate.is_revoked(credential_serial)? {
            return Err(RelayError::Credential(CredentialError::Revoked));
        }
        if !shared
            .presence
            .lock()
            .await
            .matches_attachment(lease, *generation)
        {
            return Err(RelayError::StaleFence);
        }
        if lease.role == PresenceRole::Primary {
            for _ in 0..64 {
                let Some(control) = shared
                    .router
                    .lock()
                    .await
                    .receive_control(lease.peer_id, *generation)?
                else {
                    break;
                };
                write_noise_record(socket, &mut transport, &Record::Control(control)).await?;
            }
        }
        tokio::select! {
            Some(result) = pending.next(), if !pending.is_empty() => {
                if let Err(error) = result {
                    record_forwarding_error(shared, &error);
                    if !matches!(error, RelayError::NoRoute | RelayError::QueueFull) {
                        return Err(error);
                    }
                }
            }
            changed = termination.changed() => {
                let terminal = termination.borrow_and_update().clone();
                if let Some(body) = terminal {
                    let close = Record::Control(ControlEnvelope { trace_context: None,
                        message: Some(ControlMessage::Close(peerward_wire::GracefulClose {
                            mesh_id: shared.config.mesh_id.as_bytes().to_vec(), body,
                        })) });
                    let _ = tokio::time::timeout(Duration::from_secs(2), write_noise_record(socket, &mut transport, &close)).await;
                    return Ok(());
                }
                if changed.is_err() { return Ok(()); }
            }
            record = read_noise_record(socket, &mut transport) => {
                match record? {
                    Record::Control(ControlEnvelope {
                        trace_context: _,
                        message: Some(ControlMessage::Keepalive(keepalive)),
                    }) => {
                        write_noise_record(socket, &mut transport, &Record::Control(ControlEnvelope {
                            trace_context: None,
                            message: Some(ControlMessage::Keepalive(Keepalive {
                                monotonic_timestamp: keepalive.monotonic_timestamp,
                            })),
                        })).await?;
                    }
                    Record::Control(ControlEnvelope {
                        trace_context: _,
                        message: Some(ControlMessage::Close(close)),
                    }) => {
                        record_link_close(shared, &close);
                        return Ok(());
                    }
                    Record::Control(envelope @ ControlEnvelope {
                        trace_context: _,
                        message: Some(ControlMessage::Opaque(_)),
                    }) => {
                        if let Err(error) = route_peer_control(shared, lease.peer_id, *generation, envelope.clone()).await {
                            // Destination availability and backpressure are packet outcomes.
                            // They must not tear down an unrelated authenticated source link.
                            if matches!(error, RelayError::NoRoute) && pending.len() < 4
                                && let (Ok(mesh), Ok(process)) = (
                                    shared.pending_routes.try_acquire(), PENDING_ROUTES.try_acquire(),
                                ) {
                                pending.push(retry_peer_control(shared, lease.clone(), *generation,
                                    credential_serial, envelope, mesh, process));
                                continue;
                            }
                            record_forwarding_error(shared, &error);
                            if !matches!(error, RelayError::NoRoute | RelayError::QueueFull) {
                                return Err(error);
                            }
                        }
                    }
                    Record::Control(ControlEnvelope {
                        trace_context: _,
                        message: Some(ControlMessage::RotationRequest(request)),
                    }) => {
                        let request_id = validate_rotation_request(
                            shared.config.mesh_id,
                            credential_serial,
                            &request,
                        )?;
                        let identity_public_key = request.identity_public_key.as_slice().try_into()
                            .map_err(|_| RelayError::InvalidConfig)?;
                        let session_public_key = request.session_public_key.as_slice().try_into()
                            .map_err(|_| RelayError::InvalidConfig)?;
                        let wireguard_public_key = request.wireguard_public_key.as_slice().try_into()
                            .map_err(|_| RelayError::InvalidConfig)?;
                        let signature = request.signature.as_slice().try_into()
                            .map_err(|_| RelayError::InvalidConfig)?;
                        match shared.store.request_peer_rotation(
                            request_id,
                            shared.config.mesh_id,
                            lease.peer_id,
                            credential_serial,
                            identity_public_key,
                            session_public_key,
                            wireguard_public_key,
                            signature,
                        ).await {
                            Ok(()) => shared.last_database_success.store(unix_time().0, Ordering::Relaxed),
                            Err(StoreError::Database(error)) => {
                                tracing::warn!(?error, peer_id = %lease.peer_id, "Peer rotation request will be retried");
                            }
                            Err(error) => return Err(RelayError::Store(error)),
                        }
                    }
                    Record::Control(ControlEnvelope {
                        trace_context: _,
                        message: Some(ControlMessage::Activation(activation)),
                    }) => {
                        if activation.mesh_id != shared.config.mesh_id.as_bytes()
                            || activation.signature.len() != 64
                        {
                            return Err(RelayError::InvalidConfig);
                        }
                        let request_id = RotationId::from_uuid(
                            uuid::Uuid::from_slice(&activation.request_id)
                                .map_err(|_| RelayError::InvalidConfig)?,
                        )
                        .map_err(|_| RelayError::InvalidConfig)?;
                        let issued_serial = CredentialSerial::from_uuid(
                            uuid::Uuid::from_slice(&activation.issued_serial)
                                .map_err(|_| RelayError::InvalidConfig)?,
                        )
                        .map_err(|_| RelayError::InvalidConfig)?;
                        let signature = activation.signature.as_slice().try_into()
                            .map_err(|_| RelayError::InvalidConfig)?;
                        if !shared.store.activate_peer_rotation(
                            shared.config.mesh_id,
                            lease.peer_id,
                            request_id,
                            issued_serial,
                            signature,
                        ).await? {
                            return Err(RelayError::InvalidConfig);
                        }
                        shared.last_database_success.store(unix_time().0, Ordering::Relaxed);
                    }
                    Record::Control(ControlEnvelope {
                        trace_context: _,
                        message: Some(ControlMessage::ServicePublish(request)),
                    }) => {
                        promote_standby(shared, lease, generation, credential_serial).await?;
                        let result = publish_peer_service(
                            shared,
                            lease.peer_id,
                            credential_serial,
                            &request,
                        ).await;
                        write_noise_record(socket, &mut transport, &Record::Control(
                            ControlEnvelope {
                                message: Some(ControlMessage::ServiceResult(result)),
                                trace_context: None,
                            }
                        )).await?;
                    }
                    Record::Control(ControlEnvelope {
                        trace_context: _,
                        message: Some(ControlMessage::ServiceRemove(request)),
                    }) => {
                        promote_standby(shared, lease, generation, credential_serial).await?;
                        let result = remove_peer_service(
                            shared,
                            lease.peer_id,
                            credential_serial,
                            &request,
                        ).await;
                        write_noise_record(socket, &mut transport, &Record::Control(
                            ControlEnvelope {
                                message: Some(ControlMessage::ServiceResult(result)),
                                trace_context: None,
                            }
                        )).await?;
                    }
                    Record::Control(ControlEnvelope { message: Some(ControlMessage::PeerManagement(request)), .. }) => {
                        if request.body.len() > 4096 { return Err(RelayError::InvalidConfig); }
                        let signed: peerward_management::SignedPeerCommand = serde_json::from_slice(&request.body).map_err(|_| RelayError::InvalidConfig)?;
                        if signed.command.mesh_id != shared.config.mesh_id || signed.command.peer_id != lease.peer_id || signed.command.credential_serial != credential_serial {
                            return Err(RelayError::InvalidConfig);
                        }
                        let result = shared.store.apply_peer_command(&signed).await;
                        let reply = peerward_wire::PeerManagementResult { request_id: signed.command.request_id.as_bytes().to_vec(), committed: result.is_ok(),
                            error: if result.is_ok() { String::new() } else { "command_rejected".into() } };
                        write_noise_record(socket, &mut transport, &Record::Control(ControlEnvelope {trace_context: None,
                            message: Some(ControlMessage::PeerManagementResult(reply))})).await?;
                    }
                    Record::Ipv4(_) | Record::Ipv6(_) => {
                        return Err(RelayError::Wire(WireError::KindMismatch));
                    }
                    Record::Control(_) => return Err(RelayError::Wire(WireError::KindMismatch)),
                }
            }
            _ = renewal.tick() => {
                let lease_seconds = i64::try_from(shared.config.lease_seconds)
                    .map_err(|_| RelayError::InvalidConfig)?;
                lease.lease_deadline = OffsetDateTime::now_utc()
                    + time::Duration::seconds(lease_seconds);
                if let Err(error) = OpaqueRouter::persist_renewal(
                    &shared.store,
                    lease,
                    *generation,
                ).await {
                    if matches!(error, RelayError::StaleFence) {
                        return Err(error);
                    }
                    if !database_allows_existing_sessions(shared) {
                        return Err(error);
                    }
                } else {
                    shared.last_database_success.store(unix_time().0, Ordering::Relaxed);
                    let entry = PresenceCacheEntry {
                        peer_id: lease.peer_id,
                        relay_id: lease.relay_id,
                        attachment_id: lease.attachment_id,
                        role: lease.role,
                        generation: *generation,
                        lease_deadline: lease.lease_deadline,
                    };
                    shared.presence.lock().await.observe_local(entry)?;
                    broadcast_presence(shared, PresenceAnnouncement {
                        entry,
                        released: false,
                    }).await;
                }
            }
            _ = delivery.tick() => {}
            _ = rotation_delivery.tick() => {
                if capabilities & peerward_wire::CREDENTIAL_RENEWAL_V1_CAPABILITY != 0
                    && let Ok(Some(command))=shared.store.pending_credential_renewal(shared.config.mesh_id,lease.peer_id,credential_serial).await
                        && delivered_renewal!=Some(command.command.request_id) {
                            let body=serde_json::to_vec(&command).map_err(|_|RelayError::InvalidConfig)?;
                            write_noise_record(socket,&mut transport,&Record::Control(ControlEnvelope{trace_context:None,message:Some(ControlMessage::CredentialRenewal(peerward_wire::CredentialRenewal{body}))})).await?;
                            shared.store.mark_credential_renewal_delivered(shared.config.mesh_id,lease.peer_id,command.command.request_id).await?;
                            delivered_renewal=Some(command.command.request_id);
                        }
                match shared.store.issued_peer_rotation(
                    shared.config.mesh_id,
                    lease.peer_id,
                    credential_serial,
                ).await {
                    Ok(Some(issued)) if delivered_rotation != Some(issued.id) => {
                        write_noise_record(socket, &mut transport, &Record::Control(ControlEnvelope {
                            trace_context: None,
                            message: Some(ControlMessage::Replacement(CredentialReplacement {
                                mesh_id: shared.config.mesh_id.as_bytes().to_vec(),
                                request_id: issued.id.as_bytes().to_vec(),
                                credential: issued.credential,
                                activation_challenge: issued.activation_challenge.to_vec(),
                            })),
                        })).await?;
                        delivered_rotation = Some(issued.id);
                        shared.last_database_success.store(unix_time().0, Ordering::Relaxed);
                    }
                    Ok(_) => shared.last_database_success.store(unix_time().0, Ordering::Relaxed),
                    Err(error) => {
                        if !database_allows_existing_sessions(shared) {
                            return Err(RelayError::Store(error));
                        }
                    }
                }
            }
            _ = state_delivery.tick() => {
                send_state_updates(
                    socket,
                    &mut transport,
                    shared,
                    &mut delivered_state,
                    capabilities,
                ).await?;
            }
        }
    }
}
