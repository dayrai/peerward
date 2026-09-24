#[derive(Clone)]
struct RelayIdentity {
    private_key: [u8; 32],
    credential: Vec<u8>,
}

impl Drop for RelayIdentity {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.private_key.zeroize();
        self.credential.zeroize();
    }
}

fn relay_hello(identity: &RelayIdentity, primary_attachment: bool) -> HandshakePayload {
    HandshakePayload {
        major: peerward_wire::PROTOCOL_MAJOR,
        minor: 0,
        capabilities: if primary_attachment {
            peerward_wire::SUPPORTED_CAPABILITIES
                | peerward_wire::PRIMARY_ATTACHMENT_CAPABILITY
        } else {
            peerward_wire::SUPPORTED_CAPABILITIES
        },
        credential: identity.credential.clone(),
        attachment_id: peerward_types::AttachmentId::new().as_bytes().to_vec(),
    }
}

async fn connect_replacement(
    target: crate::RelayTarget,
    mesh_id: MeshId,
    identity: RelayIdentity,
    trust: DynamicTrust,
    remote_public: [u8; 32],
    primary_attachment: bool,
    underlay: Arc<dyn UnderlayNetwork>,
    carrier_options: peerward_carrier::ClientOptions,
) -> Result<RelayConnection, PeerError> {
    let trust_snapshot = trust.snapshot()?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(UnixTime(0), |duration| UnixTime(duration.as_secs()));
    crate::RelayEndpointPool::with_underlay(underlay).with_options(carrier_options)
        .connect_trusted(
            &target.endpoints,
            &identity.private_key,
            &remote_public,
            target.relay_id,
            mesh_id,
            &trust_snapshot,
            now,
            relay_hello(&identity, primary_attachment),
        )
        .await
}

async fn relay_slot_worker(
    slot_index: usize,
    target: crate::RelayTarget,
    mesh_id: MeshId,
    mut identity: watch::Receiver<RelayIdentity>,
    trust: DynamicTrust,
    capacity: usize,
    keepalive_seconds: u64,
    unhealthy_after: u8,
    primary_attachment: bool,
    mut commands: mpsc::Receiver<RelaySlotCommand>,
    packets: mpsc::Sender<(DataPath, Vec<u8>)>,
    controls: mpsc::Sender<ControlEnvelope>,
    mut shutdown: watch::Receiver<bool>,
    observability: Option<peerward_service::PeerObservability>,
    health: Arc<Mutex<Vec<RelaySlotHealth>>>,
    underlay: Arc<dyn UnderlayNetwork>,
    carrier_options: peerward_carrier::ClientOptions,
) {
    let Some(remote_public) = hex::decode(&target.public_key)
        .ok()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
    else {
        return;
    };
    let mut reconnect_attempt = 0_u8;
    let mut endpoint_pool = crate::RelayEndpointPool::with_underlay(Arc::clone(&underlay)).with_options(carrier_options.clone());
    let mut ready_connection = None;
    loop {
        let current_identity = identity.borrow().clone();
        let connected = if let Some(connection) = ready_connection.take() {
            Ok(connection)
        } else {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(UnixTime(0), |duration| UnixTime(duration.as_secs()));
            let Ok(trust_snapshot) = trust.snapshot() else {
                return;
            };
            let connection = endpoint_pool.connect_trusted(
                &target.endpoints,
                &current_identity.private_key,
                &remote_public,
                target.relay_id,
                mesh_id,
                &trust_snapshot,
                now,
                relay_hello(&current_identity, primary_attachment),
            );
            tokio::select! {
                result = wait_with_rejected_commands(connection, &mut commands) => {
                    let Some(result) = result else { return; };
                    result
                }
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() { return; }
                    continue;
                }
                changed = identity.changed() => {
                    if changed.is_err() { return; }
                    continue;
                }
            }
        };
        let Ok((socket, transport, _)) = connected else {
            if let Err(PeerError::MeshTerminated(body)) = &connected {
                let _ = controls.send(ControlEnvelope { trace_context: None, message: Some(ControlMessage::Close(peerward_wire::GracefulClose {
                    mesh_id: mesh_id.as_bytes().to_vec(), body: body.clone(),
                })) }).await;
                return;
            }

            if let Err(error) = &connected {
                tracing::warn!(relay_id = %target.relay_id, ?error, "Peer Relay connection failed");
            }
            if let Some(slot) = health.lock().await.get_mut(slot_index) {
                slot.connected = false;
                slot.reconnects = slot.reconnects.saturating_add(1);
            }
            if let Some(observability) = &observability {
                observability.set_relay(slot_index, false);
                observability.record_reconnect();
            }
            reconnect_attempt = reconnect_attempt.saturating_add(1);
            let delay = crate::SessionManager::reconnect_delay(reconnect_attempt, target.relay_id);
            tokio::select! {
                result = wait_with_rejected_commands(tokio::time::sleep(delay), &mut commands) => {
                    if result.is_none() { return; }
                }
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() { return; }
                }
                changed = identity.changed() => {
                    if changed.is_err() { return; }
                }
            }
            continue;
        };
        reconnect_attempt = 0;
        if let Some(slot) = health.lock().await.get_mut(slot_index) {
            slot.connected = true;
        }
        if let Some(observability) = &observability {
            observability.set_relay(slot_index, true);
            observability.set_relay_carrier(slot_index, socket.carrier());
        }
        let (slot_control_tx, mut slot_controls) = mpsc::channel(capacity);
        let (sender, mut receiver) = split_noise_relay(socket, transport, slot_control_tx);
        let mut keepalive =
            tokio::time::interval(std::time::Duration::from_secs(keepalive_seconds));
        let mut epoch = tokio::time::interval(std::time::Duration::from_secs(1));
        epoch.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut missed = 0_u8;
        let mut outstanding_probe: Option<(u64, Instant)> = None;
        let mut replacement = None;
        let mut replacement_attempt = 0_u8;
        let mut retry_replacement_at = 0_u64;
        let mut replaced = false;
        loop {
            let healthy = tokio::select! {
                command = commands.recv() => {
                    match command {
                        Some(command) => forward_slot_command(command, &sender).await,
                        None => return,
                    }
                }
                incoming = receiver.receive_packet() => {
                    match incoming {
                        Ok(packet) => packets.send(packet).await.is_ok(),
                        Err(error) => {
                            tracing::warn!(relay_id = %target.relay_id, ?error, "Peer Relay stream read failed");
                            false
                        }
                    }
                }
                control = slot_controls.recv() => {
                    match control {
                        Some(ControlEnvelope { message: Some(ControlMessage::Keepalive(reply)), .. }) => {
                            if let Some((timestamp, sent_at)) = outstanding_probe.take()
                                && timestamp == reply.monotonic_timestamp
                            {
                                missed = 0;
                                let sample = u64::try_from(sent_at.elapsed().as_millis())
                                    .unwrap_or(u64::MAX);
                                if let Some(slot) = health.lock().await.get_mut(slot_index) {
                                    slot.record_probe(true, Some(sample));
                                }
                                if let Some(observability) = &observability {
                                    observability.record_relay_probe(true, Some(sample));
                                }
                                true
                            } else {
                                true
                            }
                        }
                        Some(control) => controls.send(control).await.is_ok(),
                        None => false,
                    }
                }
                _ = keepalive.tick() => {
                    if outstanding_probe.take().is_some() {
                        missed = missed.saturating_add(1);
                        if let Some(slot) = health.lock().await.get_mut(slot_index) {
                            slot.record_probe(false, None);
                        }
                        if let Some(observability) = &observability {
                            observability.record_relay_probe(false, None);
                        }
                    }
                    if missed >= unhealthy_after { false } else {
                        let timestamp = monotonic_seconds();
                        let sent = sender.send_control(ControlEnvelope {
                            trace_context: None,
                            message: Some(ControlMessage::Keepalive(peerward_wire::Keepalive {
                                monotonic_timestamp: timestamp,
                            })),
                        }).await.is_ok();
                        if sent {
                            outstanding_probe = Some((timestamp, Instant::now()));
                        }
                        sent
                    }
                }
                _ = epoch.tick() => {
                    let now = monotonic_seconds();
                    match link_epoch_action(&*sender.transport.lock().await, now) {
                        LinkEpochAction::Continue => true,
                        LinkEpochAction::FailClosed => false,
                        LinkEpochAction::Replace if replacement.is_some() || now < retry_replacement_at => true,
                        LinkEpochAction::Replace => {
                            let target = target.clone();
                            let identity = current_identity.clone();
                            let trust = trust.clone();
                            let replacement_underlay = Arc::clone(&underlay);
                            let replacement_options = carrier_options.clone();
                            replacement = Some(tokio::spawn(async move {
                                connect_replacement(
                                    target,
                                    mesh_id,
                                    identity,
                                    trust,
                                    remote_public,
                                    primary_attachment,
                                    replacement_underlay,
                                    replacement_options,
                                ).await
                            }));
                            true
                        }
                    }
                }
                completed = async {
                    match replacement.as_mut() {
                        Some(task) => Some(task.await),
                        None => std::future::pending().await,
                    }
                } => {
                    replacement = None;
                    match completed {
                        Some(Ok(Ok(connection))) => {
                            ready_connection = Some(connection);
                            replaced = true;
                            if let Some(observability) = &observability {
                                observability.record_rekey();
                            }
                            let _ = sender.send_control(ControlEnvelope {
                                trace_context: None,
                                message: Some(ControlMessage::Close(peerward_wire::GracefulClose {
                                    mesh_id: mesh_id.as_bytes().to_vec(),
                                    body: b"link_rekey".to_vec(),
                                })),
                            }).await;
                            false
                        }
                        Some(Ok(Err(PeerError::MeshTerminated(body)))) => {
                            let _ = controls.send(ControlEnvelope { trace_context: None, message: Some(ControlMessage::Close(peerward_wire::GracefulClose {
                                mesh_id: mesh_id.as_bytes().to_vec(), body,
                            })) }).await;
                            return;
                        }
                        Some(Ok(Err(error))) => {
                            tracing::warn!(relay_id = %target.relay_id, ?error, "Parallel Relay link replacement failed");
                            replacement_attempt = replacement_attempt.saturating_add(1);
                            retry_replacement_at = monotonic_seconds().saturating_add(
                                crate::SessionManager::reconnect_delay(replacement_attempt, target.relay_id)
                                    .as_secs().max(1),
                            );
                            true
                        }
                        Some(Err(error)) => {
                            tracing::warn!(relay_id = %target.relay_id, ?error, "Relay link replacement task failed");
                            replacement_attempt = replacement_attempt.saturating_add(1);
                            retry_replacement_at = monotonic_seconds().saturating_add(1);
                            true
                        }
                        None => true,
                    }
                }
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() { return; }
                    true
                }
                changed = identity.changed() => {
                    let _ = changed;
                    false
                }
            };
            if !healthy {
                if let Some(task) = replacement.take() {
                    task.abort();
                }
                if !replaced {
                    if let Some(slot) = health.lock().await.get_mut(slot_index) {
                        slot.connected = false;
                    }
                    if let Some(observability) = &observability {
                        observability.set_relay(slot_index, false);
                        observability.record_reconnect();
                    }
                }
                break;
            }
        }
    }
}

#[cfg(test)]
#[path = "relay_pool_tests.rs"]
mod relay_pool_tests;

fn reject_slot_command(command: Option<RelaySlotCommand>) {
    match command {
        Some(RelaySlotCommand::Control(_, reply)) => {
            let _ = reply.send(false);
        }
        Some(RelaySlotCommand::Wireguard(_, _)) | None => {}
    }
}

async fn forward_slot_command<C: ControlSender>(command: RelaySlotCommand, sender: &C) -> bool {
    match command {
        RelaySlotCommand::Control(control, reply) => {
            if reply.is_closed() { return true; }
            let sent = sender.send_control(control).await.is_ok();
            let _ = reply.send(sent);
            sent
        }
        RelaySlotCommand::Wireguard(control, guard) => {
            if !guard.current().await { return true; }
            sender.send_control(control).await.is_ok()
        }
    }
}

// Dispatch retries while a slot is offline. Keep the same handshake/backoff
// future alive across those retries; cancelling it starves links with RTT > 100ms.
async fn wait_with_rejected_commands<F: std::future::Future>(
    operation: F,
    commands: &mut mpsc::Receiver<RelaySlotCommand>,
) -> Option<F::Output> {
    tokio::pin!(operation);
    loop {
        tokio::select! {
            result = &mut operation => return Some(result),
            command = commands.recv() => {
                let command = command?;
                reject_slot_command(Some(command));
            }
        }
    }
}
