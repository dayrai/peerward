static PENDING_ROUTES: Semaphore = Semaphore::const_new(256);

/// Pending ciphertext is scoped to its source session and canceled on departure.
async fn retry_peer_control(
    shared: &RelayShared,
    lease: PresenceLease,
    generation: i64,
    serial: CredentialSerial,
    envelope: ControlEnvelope,
    _mesh: tokio::sync::SemaphorePermit<'_>,
    _process: tokio::sync::SemaphorePermit<'_>,
) -> Result<(), RelayError> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        if tokio::time::Instant::now() >= deadline {
            return Err(RelayError::NoRoute);
        }
        if shared.gate.is_revoked(serial)?
            || shared.cancel.is_cancelled()
            || !shared
                .presence
                .lock()
                .await
                .matches_attachment(&lease, generation)
        {
            return Err(RelayError::StaleFence);
        }
        match route_peer_control(shared, lease.peer_id, generation, envelope.clone()).await {
            Err(RelayError::NoRoute) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            result => return result,
        }
    }
}

async fn route_peer_control(
    shared: &RelayShared,
    source: PeerId,
    generation: i64,
    mut envelope: ControlEnvelope,
) -> Result<(), RelayError> {
    if queue_control_audit(shared, source, &envelope)? {
        return Ok(());
    }
    let correlation = envelope
        .correlation_context()
        .map_err(|_| RelayError::Wire(WireError::KindMismatch))?;
    let consumer_span = tracing::info_span!(
        "relay.control.consume",
        request_id = tracing::field::Empty,
        traceparent = tracing::field::Empty,
        stage = "relay.receive",
    );
    if let Some(context) = correlation {
        let _ = consumer_span.set_parent(remote_trace_parent(context));
        consumer_span.record("request_id", context.request_id.to_string());
        consumer_span.record("traceparent", context.traceparent());
        tracing::debug!(
            parent: &consumer_span,
            request_id = %context.request_id,
            traceparent = %context.traceparent(),
            stage = "relay.receive",
            "Relay accepted correlated control message"
        );
        envelope
            .advance_trace()
            .map_err(|_| RelayError::Wire(WireError::KindMismatch))?;
    }
    let destination = normalize_direct_control(shared.config.mesh_id, source, &mut envelope)?;
    let routed = RoutedControl {
        source,
        destination,
        generation,
        envelope,
    };
    match shared
        .router
        .lock()
        .await
        .route_authenticated_control(routed.clone())
    {
        Ok(()) => return Ok(()),
        Err(RelayError::NoRoute) => {}
        Err(error) => return Err(error),
    }
    // WireGuard retransmits its handshake; an offline destination must not block
    // this source's keepalives, signed state or traffic to other destinations.
    let owner = cached_presence_owner(shared, destination).await?;
    if owner.relay_id == shared.config.relay_id {
        return Err(RelayError::NoRoute);
    }
    if let Some(topology) = sparse_topology(shared).await {
        let route = BackboneRoute {
            origin: shared.config.relay_id,
            destination: Some(owner.relay_id),
            topology_revision: topology.revision,
            hop_limit: 4,
            visited: vec![shared.config.relay_id],
        };
        send_sparse_control(shared, &topology, routed, route).await
    } else {
        let sender = shared
            .backbones
            .lock()
            .await
            .get(&owner.relay_id)
            .cloned()
            .ok_or(RelayError::NoRoute)?;
        sender
            .try_send(BackbonePayload::Control(routed))
            .map_err(map_backbone_send_error)
    }
}

async fn send_sparse_control(
    shared: &RelayShared,
    topology: &peerward_directory::RelayTopologyV1,
    control: RoutedControl,
    route: BackboneRoute,
) -> Result<(), RelayError> {
    let destination = route.destination.ok_or(RelayError::NoRoute)?;
    let senders = shared.backbones.lock().await.clone();
    for next in topology.next_hops(shared.config.relay_id, destination) {
        if route.visited.contains(&next) {
            continue;
        }
        let Some(sender) = senders.get(&next) else {
            continue;
        };
        match sender.try_send(BackbonePayload::RoutedControl(
            control.clone(),
            route.clone(),
        )) {
            Ok(()) => return Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => return Err(RelayError::QueueFull),
            Err(mpsc::error::TrySendError::Closed(_)) => {}
        }
    }
    Err(RelayError::NoRoute)
}

fn map_backbone_send_error(error: mpsc::error::TrySendError<BackbonePayload>) -> RelayError {
    match error {
        mpsc::error::TrySendError::Full(_) => RelayError::QueueFull,
        mpsc::error::TrySendError::Closed(_) => RelayError::NoRoute,
    }
}

fn queue_control_audit(
    shared: &RelayShared,
    source: PeerId,
    envelope: &ControlEnvelope,
) -> Result<bool, RelayError> {
    let Some(ingress) = normalize_control_audit(shared.config.mesh_id, source, envelope)? else {
        return Ok(false);
    };
    shared.audit_sender.try_send(ingress).map_err(|error| {
        shared.audit_dropped.fetch_add(1, Ordering::Relaxed);
        match error {
            mpsc::error::TrySendError::Full(_) => RelayError::QueueFull,
            mpsc::error::TrySendError::Closed(_) => RelayError::NoRoute,
        }
    })?;
    shared.audit_queued.fetch_add(1, Ordering::Relaxed);
    Ok(true)
}

fn normalize_control_audit(
    mesh_id: MeshId,
    source: PeerId,
    envelope: &ControlEnvelope,
) -> Result<Option<RelayAuditIngress>, RelayError> {
    let Some(ControlMessage::Opaque(message)) = envelope.message.as_ref() else {
        return Ok(None);
    };
    if message.kind != peerward_wire::OpaqueFrameKind::Audit as i32 {
        return Ok(None);
    }
    message.validate_from_peer()?;
    if message.mesh_id != mesh_id.as_bytes()
        || message.destination_peer != peerward_wire::CONTROL_AUDIT_DESTINATION
    {
        return Err(RelayError::Wire(WireError::KindMismatch));
    }
    Ok(Some(RelayAuditIngress {
        source_peer: source,
        envelope: message.opaque.clone(),
    }))
}

fn normalize_direct_control(
    mesh: MeshId,
    source: PeerId,
    envelope: &mut ControlEnvelope,
) -> Result<PeerId, RelayError> {
    if let Some(ControlMessage::Opaque(message)) = envelope.message.as_mut() {
        message.validate_from_peer()?;
        if message.mesh_id != mesh.as_bytes() {
            return Err(RelayError::Wire(WireError::KindMismatch));
        }
        let destination = PeerId::from_uuid(
            uuid::Uuid::from_slice(&message.destination_peer)
                .map_err(|_| RelayError::Wire(WireError::KindMismatch))?,
        )
        .map_err(|_| RelayError::Wire(WireError::KindMismatch))?;
        if destination == source {
            return Err(RelayError::NoRoute);
        }
        message.bind_authenticated_source(*source.as_bytes());
        return Ok(destination);
    }
    Err(RelayError::Wire(WireError::KindMismatch))
}
