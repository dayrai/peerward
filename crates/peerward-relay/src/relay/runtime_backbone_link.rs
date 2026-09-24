type BackboneConnection = (BoxStream, StreamTransport, Vec<Record>);

async fn write_link_ready(
    socket: &mut (impl peerward_carrier::RelayIo + ?Sized),
    transport: &mut StreamTransport,
    mesh_id: MeshId,
) -> Result<(), RelayError> {
    write_noise_record(
        socket,
        transport,
        &Record::Control(ControlEnvelope {
            trace_context: None,
            message: Some(ControlMessage::Welcome(peerward_wire::Welcome {
                mesh_id: mesh_id.as_bytes().to_vec(),
                body: b"link_ready".to_vec(),
            })),
        }),
    )
    .await
}

fn backbone_control_envelope(
    mesh_id: MeshId,
    payload: &BackbonePayload,
) -> Result<ControlEnvelope, RelayError> {
    match payload {
        BackbonePayload::Presence(update) => Ok(ControlEnvelope {
            trace_context: None,
            message: Some(ControlMessage::Presence(PresenceUpdate {
                mesh_id: mesh_id.as_bytes().to_vec(),
                body: encode_presence(*update),
            })),
        }),
        BackbonePayload::Control(_)
        | BackbonePayload::RoutedControl(_, _)
        | BackbonePayload::RoutedPresence(_, _) => backbone_payload_envelope(mesh_id, payload),
    }
}

fn record_link_close(shared: &RelayShared, close: &peerward_wire::GracefulClose) {
    if close.mesh_id == shared.config.mesh_id.as_bytes() && close.body == b"link_rekey" {
        shared.link_rekeys.fetch_add(1, Ordering::Relaxed);
    }
}

async fn current_relay_entry(
    shared: &RelayShared,
    remote_id: RelayId,
) -> Result<RelayEntry, RelayError> {
    shared
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
        .ok_or(RelayError::NoRoute)
}

async fn connect_backbone(
    shared: Arc<RelayShared>,
    remote_id: RelayId,
) -> Result<BackboneConnection, RelayError> {
    if !database_accepts_new_sessions(&shared) {
        return Err(RelayError::NoRoute);
    }
    if !is_backbone_neighbor(&shared, remote_id).await {
        return Err(RelayError::NoRoute);
    }
    let remote = current_relay_entry(&shared, remote_id).await?;
    if shared.gate.is_revoked(remote.credential_serial)?
        || !shared
            .gate
            .relay_admitted(remote.relay_id, remote.credential_serial)?
    {
        return Err(RelayError::NoRoute);
    }
    let mut socket = EndpointDialer::default()
        .connect(&remote.backbone_endpoints, &shared.config.relay_transport)
        .await?;
    let preface = shared.routed.then_some(peerward_wire::RelayPreface {
        mesh_id: shared.config.mesh_id,
        target: remote_id,
        source: Some(shared.config.relay_id),
    });
    if let Some(preface) = preface {
        socket.write_all(&preface.encode()).await?;
    } else {
        socket.write_all(shared.config.relay_id.as_bytes()).await?;
    }
    let transport = tokio::time::timeout(
        Duration::from_secs(shared.config.handshake_timeout_seconds),
        relay_kk_prefaced(
            &mut socket,
            true,
            &shared.local_private,
            &remote.noise_public_key,
            preface,
        ),
    )
    .await
    .map_err(|_| RelayError::HandshakeLimited)??;
    let (upgraded_socket, mut transport) =
        peerward_carrier::quic::activate(socket, transport, preface, monotonic_seconds()).await?;
    socket = MeteredStream::wrap(upgraded_socket,&shared.traffic);
    let mut bootstrap = Vec::new();
    let limit = shared.config.queue_capacity.saturating_mul(16);
    loop {
        let record = tokio::time::timeout(
            Duration::from_secs(shared.config.handshake_timeout_seconds),
            read_noise_record(&mut socket, &mut transport),
        )
        .await
        .map_err(|_| RelayError::HandshakeLimited)??;
        match record {
            Record::Control(ControlEnvelope {
                trace_context: _,
                message: Some(ControlMessage::Welcome(peerward_wire::Welcome { mesh_id, body })),
            }) if mesh_id == shared.config.mesh_id.as_bytes() && body == b"link_ready" => break,
            record @ Record::Control(ControlEnvelope {
                trace_context: _,
                message: Some(ControlMessage::Presence(_)),
            }) => {
                if bootstrap.len() >= limit {
                    return Err(RelayError::QueueFull);
                }
                bootstrap.push(record);
            }
            _ => return Err(RelayError::Wire(WireError::KindMismatch)),
        }
    }
    Ok((socket, transport, bootstrap))
}

async fn await_backbone_replacement(
    task: &mut Option<tokio::task::JoinHandle<Result<BackboneConnection, RelayError>>>,
) -> Result<BackboneConnection, RelayError> {
    match task {
        Some(task) => task.await.map_err(|_| RelayError::NoRoute)?,
        None => std::future::pending().await,
    }
}

async fn handle_backbone_record(
    record: Record,
    socket: &mut (impl peerward_carrier::RelayIo + ?Sized),
    transport: &mut StreamTransport,
    shared: &RelayShared,
    remote_relay: RelayId,
    health: &mut ConnectionHealth,
) -> Result<(), RelayError> {
    match record {
        Record::Control(ControlEnvelope {
            trace_context: _,
            message: Some(ControlMessage::Forwarded(forwarded)),
        }) => {
            if forwarded.mesh_id != shared.config.mesh_id.as_bytes() {
                return Err(RelayError::NoRoute);
            }
            match decode_backbone_payload(&forwarded.body)? {
                BackbonePayload::Control(control) => {
                    if !cached_presence_source(
                        shared,
                        control.source,
                        remote_relay,
                        control.generation,
                    )
                    .await
                    {
                        return Err(RelayError::StaleFence);
                    }
                    let mut router = shared.router.lock().await;
                    // Source was checked against role-scoped presence above. A
                    // standby's generation must never replace the primary fence.
                    accept_backbone_delivery(
                        router.accept_cross_relay_control(control),
                        &shared.no_route,
                        &shared.queue_full,
                    )?;
                }
                BackbonePayload::RoutedControl(control, mut route) => {
                    let topology = validate_sparse_route(shared, remote_relay, &route).await?;
                    if !cached_presence_source(
                        shared,
                        control.source,
                        route.origin,
                        control.generation,
                    )
                    .await
                    {
                        return Err(RelayError::StaleFence);
                    }
                    let destination = route.destination.ok_or(RelayError::NoRoute)?;
                    if destination == shared.config.relay_id {
                        let mut router = shared.router.lock().await;
                        accept_backbone_delivery(
                            router.accept_cross_relay_control(control),
                            &shared.no_route,
                            &shared.queue_full,
                        )?;
                    } else {
                        if route.hop_limit <= 1 || route.visited.len() >= 4 {
                            shared.backbone_ttl_drops.fetch_add(1, Ordering::Relaxed);
                            return Err(RelayError::NoRoute);
                        }
                        route.hop_limit -= 1;
                        route.visited.push(shared.config.relay_id);
                        if accept_backbone_delivery(
                            send_sparse_control(shared, &topology, control, route).await,
                            &shared.no_route,
                            &shared.queue_full,
                        )? {
                            shared
                                .backbone_forwarded_hops
                                .fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                BackbonePayload::RoutedPresence(update, route) => {
                    let topology = validate_sparse_route(shared, remote_relay, &route).await?;
                    if route.destination.is_some() || update.entry.relay_id != route.origin {
                        return Err(RelayError::NoRoute);
                    }
                    let advanced = shared.presence.lock().await.observe(route.origin, update)?;
                    if !update.released && advanced && update.entry.role == PresenceRole::Primary {
                        shared
                            .router
                            .lock()
                            .await
                            .observe_fence(update.entry.peer_id, update.entry.generation)?;
                    }
                    if advanced {
                        forward_sparse_presence(shared, &topology, update, route).await?;
                    }
                }
                BackbonePayload::Presence(_) => {
                    return Err(RelayError::Wire(WireError::KindMismatch));
                }
            }
        }
        Record::Control(ControlEnvelope {
            trace_context: _,
            message: Some(ControlMessage::Presence(update)),
        }) => {
            if update.mesh_id != shared.config.mesh_id.as_bytes() {
                return Err(RelayError::NoRoute);
            }
            let update = decode_presence(&update.body)?;
            let advanced = shared.presence.lock().await.observe(remote_relay, update)?;
            if !update.released && advanced && update.entry.role == PresenceRole::Primary {
                shared
                    .router
                    .lock()
                    .await
                    .observe_fence(update.entry.peer_id, update.entry.generation)?;
            }
        }
        Record::Control(ControlEnvelope {
            trace_context: _,
            message: Some(ControlMessage::Keepalive(keepalive)),
        }) => {
            if health.reply(keepalive.monotonic_timestamp, monotonic_millis()) {
                record_backbone_health(shared, remote_relay, health).await;
            } else {
                write_noise_record(
                    socket,
                    transport,
                    &Record::Control(ControlEnvelope {
                        trace_context: None,
                        message: Some(ControlMessage::Keepalive(keepalive)),
                    }),
                )
                .await?;
            }
        }
        Record::Control(ControlEnvelope {
            trace_context: _,
            message: Some(ControlMessage::Close(close)),
        }) => {
            record_link_close(shared, &close);
            return Err(RelayError::NoRoute);
        }
        _ => return Err(RelayError::Wire(WireError::KindMismatch)),
    }
    Ok(())
}

// A destination disappearing or reaching its queue bound drops only this frame.
// Mesh/source/route validation above remains fatal and never reaches this boundary.
fn accept_backbone_delivery(
    result: Result<(), RelayError>,
    no_route: &AtomicU64,
    queue_full: &AtomicU64,
) -> Result<bool, RelayError> {
    match result {
        Ok(()) => Ok(true),
        Err(RelayError::NoRoute) => {
            no_route.fetch_add(1, Ordering::Relaxed);
            Ok(false)
        }
        Err(RelayError::QueueFull) => {
            queue_full.fetch_add(1, Ordering::Relaxed);
            Ok(false)
        }
        Err(error) => Err(error),
    }
}

async fn read_noise_record(
    socket: &mut (impl peerward_carrier::RelayIo + ?Sized),
    transport: &mut StreamTransport,
) -> Result<Record, RelayError> {
    let frame = transport.read_frame(socket).await?;
    Ok(transport.decode(&frame)?)
}

async fn write_noise_record(
    socket: &mut (impl peerward_carrier::RelayIo + ?Sized),
    transport: &mut StreamTransport,
    record: &Record,
) -> Result<(), RelayError> {
    socket.write_all(&transport.encode(record)?).await?;
    socket.flush().await?;
    Ok(())
}

/// Bounded reconnect schedule with per-relay deterministic jitter.
pub fn reconnect_delay(attempt: u8, relay: RelayId) -> Duration {
    let base = 200_u64
        .saturating_mul(1_u64 << u32::from(attempt.min(6)))
        .min(8_000);
    let jitter = relay
        .as_bytes()
        .iter()
        .fold(0_u64, |sum, byte| sum + u64::from(*byte))
        % 401;
    Duration::from_millis(base + jitter)
}
