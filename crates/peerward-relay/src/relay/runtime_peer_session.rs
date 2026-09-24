fn record_forwarding_error(shared: &RelayShared, error: &RelayError) {
    let counter = match error {
        RelayError::MalformedForwarded => &shared.invalid_forwarded_frames,
        RelayError::NoRoute => &shared.no_route,
        RelayError::QueueFull => &shared.queue_full,
        _ => return,
    };
    counter.fetch_add(1, Ordering::Relaxed);
}

async fn run_peer_session(
    mut socket: impl peerward_carrier::RelayIo + 'static,
    local_private: Arc<zeroize::Zeroizing<[u8; 32]>>,
    shared: Arc<RelayShared>,
    ip_permit: IpHandshakePermit,
    preface: Option<peerward_wire::RelayPreface>,
    host_handshake: Option<tokio::sync::OwnedSemaphorePermit>,
) -> Result<(), RelayError> {
    let preface = if let Some(preface) = preface {
        preface
    } else {
        let mut bytes = [0; peerward_wire::RELAY_PREFACE_LEN];
        tokio::time::timeout(
            Duration::from_secs(shared.config.handshake_timeout_seconds),
            socket.read_exact(&mut bytes),
        )
        .await
        .map_err(|_| RelayError::HandshakeLimited)??;
        peerward_wire::RelayPreface::decode(&bytes)?
    };
    if preface.mesh_id != shared.config.mesh_id
        || preface.target != shared.config.relay_id
        || preface.source.is_some()
    {
        return Err(RelayError::NoRoute);
    }
    let now = unix_time();
    if !database_accepts_new_sessions(&shared) || !shared.accepting_peers.load(Ordering::Acquire) {
        return Err(RelayError::NoRoute);
    }
    let handshake_permit = Arc::clone(&shared.handshakes)
        .try_acquire_owned()
        .map_err(|_| RelayError::HandshakeLimited)?;
    let authenticated = tokio::time::timeout(
        Duration::from_secs(shared.config.handshake_timeout_seconds),
        authenticate_peer_prefaced(
            &mut socket,
            &local_private,
            &shared.local_credential,
            peerward_wire::SUPPORTED_CAPABILITIES | peerward_wire::PRIMARY_ATTACHMENT_CAPABILITY,
            &shared.gate,
            now,
            Some(preface),
        ),
    )
    .await
    .map_err(|_| RelayError::HandshakeLimited)??;
    let (socket, mut transport) = peerward_carrier::quic::activate(
        Box::new(socket),
        authenticated.transport,
        Some(preface),
        monotonic_seconds(),
    )
    .await?;
    let mut socket=MeteredStream::wrap(socket,&shared.traffic);
    // A prepared candidate is not a presence owner. Only the winner selected
    // by the client may acquire/replace its primary or standby lease.
    let selected = tokio::time::timeout(
        Duration::from_secs(5),
        read_noise_record(&mut socket, &mut transport),
    )
    .await
    .map_err(|_| RelayError::HandshakeLimited)??;
    if !matches!(selected, Record::Control(ControlEnvelope { trace_context: None,
        message: Some(ControlMessage::Welcome(peerward_wire::Welcome { mesh_id, body }))
    }) if mesh_id == preface.mesh_id.as_bytes() && body == b"link_admit")
    {
        return Err(RelayError::NoRoute);
    }
    // Join commits admission before the asynchronously signed directory is published.
    // Do not acknowledge readiness and send a pre-Join snapshot that the client must
    // interpret as a trusted deletion. Keep handshake permits while waiting, so new
    // joins cannot create an unbounded set of pending presence owners.
    wait_for_peer_directory(
        &shared,
        authenticated.peer_id,
        authenticated.credential_serial,
    )
    .await?;
    // Drain acknowledgement waits for any registration already in progress.
    // A handshake that finishes later must recheck admission under the same lock.
    let admission = shared.admission_lock.lock().await;
    if !shared.accepting_peers.load(Ordering::Acquire) {
        return Err(RelayError::NoRoute);
    }
    drop(handshake_permit);
    drop(host_handshake);
    drop(ip_permit);
    let lease_seconds =
        i64::try_from(shared.config.lease_seconds).map_err(|_| RelayError::InvalidConfig)?;
    let mut lease = PresenceLease {
        mesh_id: shared.config.mesh_id,
        peer_id: authenticated.peer_id,
        relay_id: shared.config.relay_id,
        attachment_id: authenticated.attachment_id,
        role: if authenticated.primary_attachment {
            PresenceRole::Primary
        } else {
            PresenceRole::Standby
        },
        lease_deadline: OffsetDateTime::now_utc() + time::Duration::seconds(lease_seconds),
    };
    let presence_generation = shared.store.acquire_presence(&lease).await?;
    let attachment = shared.router.lock().await.install_acquired(
        lease.clone(),
        authenticated.credential_serial,
        presence_generation,
    )?;
    let entry = PresenceCacheEntry {
        peer_id: lease.peer_id,
        relay_id: lease.relay_id,
        attachment_id: lease.attachment_id,
        role: lease.role,
        generation: attachment.generation,
        lease_deadline: lease.lease_deadline,
    };
    shared.presence.lock().await.observe_local(entry)?;
    let _authenticated=AuthenticatedPeerCounter::acquire(&shared);
    drop(admission);
    broadcast_presence(
        shared.as_ref(),
        PresenceAnnouncement {
            entry,
            released: false,
        },
    )
    .await;
    let mut generation = attachment.generation;
    let result = drive_fenced_peer_records(
        &mut socket,
        transport,
        &shared,
        &mut lease,
        &mut generation,
        authenticated.credential_serial,
        authenticated.capabilities,
    )
    .await;
    shared
        .router
        .lock()
        .await
        .detach(authenticated.peer_id, generation);
    let released = PresenceCacheEntry {
        peer_id: lease.peer_id,
        relay_id: lease.relay_id,
        attachment_id: lease.attachment_id,
        role: lease.role,
        generation,
        lease_deadline: lease.lease_deadline,
    };
    if shared
        .presence
        .lock()
        .await
        .release_local(released)
        .is_ok_and(|changed| changed)
    {
        broadcast_presence(
            shared.as_ref(),
            PresenceAnnouncement {
                entry: released,
                released: true,
            },
        )
        .await;
    }
    if let Err(error) = shared.store.release_presence(&lease, generation).await {
        tracing::warn!(?error, "Relay presence release failed");
    }
    result
}

async fn wait_for_peer_directory(
    shared: &RelayShared,
    peer: PeerId,
    serial: CredentialSerial,
) -> Result<(), RelayError> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        if shared.gate.is_revoked(serial)? || shared.cancel.is_cancelled() {
            return Err(RelayError::NoRoute);
        }
        let now = unix_time();
        let ready = shared
            .distributions
            .read()
            .await
            .peers
            .as_ref()
            .is_some_and(|signed| {
                signed.directory.entries.iter().any(|entry| {
                    entry.entry.peer_id == peer
                        && entry.entry.enabled
                        && entry
                            .entry
                            .accepted_credentials
                            .iter()
                            .any(|binding| binding.serial == serial && binding.valid_at(now))
                })
            });
        if ready {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(RelayError::NoRoute);
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}
