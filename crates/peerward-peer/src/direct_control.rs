fn trace_control_state(envelope: &ControlEnvelope) {
    let (family, revision, index, count) = match &envelope.message {
        Some(ControlMessage::AuthorityDirectory(chunk)) => {
            ("authorities", chunk.revision, chunk.index, chunk.count)
        }
        Some(ControlMessage::PeerDirectory(chunk)) => {
            ("peers", chunk.revision, chunk.index, chunk.count)
        }
        Some(ControlMessage::RelayDirectory(chunk)) => {
            ("relays", chunk.revision, chunk.index, chunk.count)
        }
        Some(ControlMessage::Policy(chunk)) => ("policy", chunk.revision, chunk.index, chunk.count),
        Some(ControlMessage::Services(chunk)) => {
            ("services", chunk.revision, chunk.index, chunk.count)
        }
        Some(ControlMessage::Revocation(chunk)) => {
            ("revocations", chunk.revision, chunk.index, chunk.count)
        }
        _ => return,
    };
    tracing::debug!(
        family,
        revision,
        index,
        count,
        "Peer received signed state chunk"
    );
}

/// Applies authenticated Wire 4 control updates to the shared `WireGuard` runtime.
async fn run_peer_control<C: ControlSender>(
    mut controls: mpsc::Receiver<ControlEnvelope>,
    relay: C,
    mut local_candidates: watch::Receiver<LocalPaths>,
    trust: DynamicTrust,
    authority_chunks: Arc<StdRwLock<ChunkAssembler>>,
    directory: Option<Arc<StdRwLock<DirectPeerDirectory>>>,
    local_peer: PeerId,
    services: Option<Arc<Mutex<RemoteServiceTable>>>,
    live_policy: Arc<LivePeerPolicy>,
    rotation: Option<Arc<Mutex<CredentialRotator>>>,
    mut service_changes: Option<mpsc::Receiver<ServiceChange>>,
    observability: Option<peerward_service::PeerObservability>,
    mut shutdown: watch::Receiver<bool>,
    wireguard: WireguardPath,
) -> Result<(), PacketPumpError> {
    let initial = local_candidates.borrow().clone();
    wireguard
        .core
        .lock()
        .await
        .update_local_paths(initial.local, initial.candidates)
        .map_err(core_packet_error)?;
    let mut rotation_check = tokio::time::interval(std::time::Duration::from_mins(1));
    rotation_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    rotation_check.tick().await;
    let mut receipts = ReceiptDelivery::new();
    let mut management_check = tokio::time::interval(std::time::Duration::from_secs(2));
    management_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut service_waiters = BTreeMap::new();
    let mut configuration_chunks = ChunkAssembler::new(
        live_policy.mesh_id,
        MAX_SIGNED_STATE_CHUNKS,
        MAX_SIGNED_STATE_BYTES,
    );
    let mut policy_chunks = ChunkAssembler::new(
        live_policy.mesh_id,
        MAX_SIGNED_STATE_CHUNKS,
        MAX_SIGNED_STATE_BYTES,
    );
    let mut service_chunks = ChunkAssembler::new(
        live_policy.mesh_id,
        MAX_SIGNED_STATE_CHUNKS,
        MAX_SIGNED_STATE_BYTES,
    );
    let mut revocation_chunks = ChunkAssembler::new(
        live_policy.mesh_id,
        MAX_SIGNED_STATE_CHUNKS,
        MAX_SIGNED_STATE_BYTES,
    );
    loop {
        tokio::select! {
            _ = management_check.tick(), if rotation.is_some() => {
                if let Err(error)=receipts.send(&relay,rotation.as_ref().expect("guarded by select condition"),&wireguard).await {
                    tracing::debug!(?error,"configuration receipt deferred");
                }
            }
            _ = rotation_check.tick(), if rotation.is_some() => {
                rotation.as_ref().expect("guarded by select condition")
                    .lock().await.request_if_due(&relay).await?;
            }
            changed = local_candidates.changed() => {
                if changed.is_err() {
                    return Ok(());
                }
                // Candidate coordination is encrypted by the shared runtime;
                // legacy offers must never publish addresses on the Relay control link.
                let candidates = local_candidates.borrow_and_update().clone();
                wireguard.core.lock().await.update_local_paths(candidates.local, candidates.candidates).map_err(core_packet_error)?;
            }
            envelope = controls.recv() => {
                let Some(envelope) = envelope else { return Ok(()); };
                trace_control_state(&envelope);
                let correlation = envelope
                    .correlation_context()
                    .map_err(|error| invalid_control_error("control message", error))?;
                let consumer_span = tracing::info_span!(
                    "peer.control.consume",
                    request_id = tracing::field::Empty,
                    traceparent = tracing::field::Empty,
                    stage = "peer.receive",
                );
                if let Some(context) = correlation {
                    let _ = consumer_span.set_parent(remote_trace_parent(context));
                    consumer_span.record("request_id", context.request_id.to_string());
                    consumer_span.record("traceparent", context.traceparent());
                    tracing::debug!(
                        parent: &consumer_span,
                        request_id = %context.request_id,
                        traceparent = %context.traceparent(),
                        stage = "peer.receive",
                        "Peer accepted correlated control message"
                    );
                }
                match &envelope.message {
                    Some(ControlMessage::PeerManagementResult(result)) => receipts.result(result),
                    Some(ControlMessage::CredentialRenewal(command)) => {
                        if let Some(rotation)=&rotation
                            && let Err(error)=rotation.lock().await.request_from_console(&command.body,&relay).await {
                                tracing::debug!(?error,"credential renewal command rejected or deferred");
                            }
                    },
                    Some(ControlMessage::Keepalive(probe)) => {
                        relay.send_control(ControlEnvelope {
                            trace_context: correlation.map(|context| {
                                peerward_wire::TraceContextV1::from_context(context.child())
                            }),
                            message: Some(ControlMessage::Keepalive(*probe)),
                        }).await?;
                    }
                    Some(ControlMessage::Close(close)) => {
                        if close.body.starts_with(b"PWM1") {
                            let terminal = peerward_credentials::MeshTermination::decode(&close.body)
                                .map_err(|_| PacketPumpError::InvalidControl)?;
                            trust.snapshot().and_then(|trust| trust.verify_termination(&terminal, 0, UnixTime(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs())))
                                .map_err(|_| PacketPumpError::InvalidControl)?;
                            if close.mesh_id != live_policy.mesh_id.as_bytes() { return Err(PacketPumpError::InvalidControl); }
                            if let Some(path) = &live_policy.termination_path {
                                peerward_credentials::private_files::write_private_atomic(path, &close.body)
                                    .map_err(|_| PacketPumpError::InvalidControl)?;
                            }
                        }
                        wireguard.core.lock().await.close();
                        if let Some(observability) = &observability {
                            observability.set_direct_peers(Vec::<PeerId>::new());
                        }
                        return Ok(());
                    }
                    Some(ControlMessage::Opaque(opaque)) => {
                        opaque.validate_for_relay()
                            .map_err(|error| invalid_control_error("control message", error))?;
                        if opaque.mesh_id != live_policy.mesh_id.as_bytes()
                            || opaque.destination_peer != local_peer.as_bytes()
                            || opaque.kind != OpaqueFrameKind::Session as i32
                        {
                            return Err(PacketPumpError::InvalidControl);
                        }
                        let source = PeerId::from_uuid(
                            uuid::Uuid::from_slice(&opaque.source_peer)
                                .map_err(|error| invalid_control_error("control message", error))?,
                        )
                        .map_err(|error| invalid_control_error("control message", error))?;
                        if let Err(error) = wireguard.receive(peerward_peer_core::WireguardIngress::Relay(source), &opaque.opaque).await {
                            tracing::debug!(?error, "relayed WireGuard packet rejected");
                        }
                    }
                    Some(ControlMessage::Services(message)) => {
                        if message.mesh_id != live_policy.mesh_id.as_bytes() {
                            return Err(PacketPumpError::InvalidControl);
                        }
                        let revision = message.revision;
                        let complete = service_chunks.push_redundant(RevisionChunk {
                            mesh_id: live_policy.mesh_id,
                            revision,
                            index: message.index,
                            count: message.count,
                            body: message.body.clone(),
                        }).map_err(|error| invalid_control_error("control message", error))?;
                        let Some(bytes) = complete else { continue; };
                        let table = services.as_ref().ok_or(PacketPumpError::InvalidControl)?;
                        let signed: SignedRemoteServiceSnapshot = serde_json::from_slice(&bytes)
                            .map_err(|error| invalid_control_error("control message", error))?;
                        if signed.snapshot.mesh_id != live_policy.mesh_id
                            || signed.snapshot.revision != revision
                        {
                            return Err(PacketPumpError::InvalidControl);
                        }
                        let mut guard = table.lock().await;
                        let mut candidate = guard.clone();
                        let mut core = wireguard.core.lock().await;
                        for serial in core.revoked_credentials() { candidate.revoke_credential(serial); }
                        candidate.reconcile(&signed).map_err(|error| invalid_control_error("control message", error))?;
                        let canonical = serde_json::to_vec(&signed).map_err(|error| invalid_control_error("services", error))?;
                        core.checkpoint_verified_snapshot(peerward_peer_core::SnapshotKind::Services,
                            revision, &canonical, UnixTime(wall_clock_seconds())).map_err(core_packet_error)?;
                        *guard = candidate;
                        service_chunks.commit(revision)
                            .map_err(|error| invalid_control_error("control message", error))?;
                        if let Some(observability) = &observability {
                            observability.signed_revision(
                                peerward_service::SignedStateFamily::Services,
                                signed.snapshot.revision,
                            );
                        }
                    }
                    Some(ControlMessage::Configuration(message)) => {
                        if message.mesh_id != live_policy.mesh_id.as_bytes() { return Err(PacketPumpError::InvalidControl); }
                        let complete = configuration_chunks.push_redundant(RevisionChunk { mesh_id: live_policy.mesh_id,
                            revision: message.revision, index: message.index, count: message.count, body: message.body.clone() })
                            .map_err(|error| invalid_control_error("configuration", error))?;
                        let Some(bytes) = complete else { continue; };
                        let delivery: peerward_management::ConfigurationDelivery = serde_json::from_slice(&bytes)
                            .map_err(|error| invalid_control_error("configuration", error))?;
                        if delivery.lease.lease.sequence != message.revision { return Err(PacketPumpError::InvalidControl); }
                        wireguard.core.lock().await.install_configuration(delivery, UnixTime(wall_clock_seconds()), std::time::Instant::now())
                            .map_err(core_packet_error)?;
                        configuration_chunks.commit(message.revision).map_err(|error| invalid_control_error("configuration", error))?;
                    }
                    Some(ControlMessage::Policy(message)) => {
                        if message.mesh_id != live_policy.mesh_id.as_bytes() {
                            return Err(PacketPumpError::InvalidControl);
                        }
                        let revision = message.revision;
                        let complete = policy_chunks.push_redundant(RevisionChunk {
                            mesh_id: live_policy.mesh_id,
                            revision,
                            index: message.index,
                            count: message.count,
                            body: message.body.clone(),
                        }).map_err(|error| invalid_control_error("control message", error))?;
                        let Some(bytes) = complete else { continue; };
                        let signed = decode_policy(&bytes)
                            .map_err(|error| invalid_control_error("control message", error))?;
                        if signed.bundle.revision != revision {
                            return Err(PacketPumpError::InvalidControl);
                        }
                        let revision = wireguard.core.lock().await.install_policy(&signed).map_err(core_packet_error)?;
                        policy_chunks.commit(revision)
                            .map_err(|error| invalid_control_error("control message", error))?;
                        if let Some(observability) = &observability {
                            observability.signed_revision(
                                peerward_service::SignedStateFamily::Policy,
                                revision,
                            );
                        }
                    }
                    Some(ControlMessage::Replacement(replacement)) => {
                        rotation.as_ref().ok_or(PacketPumpError::InvalidControl)?
                            .lock().await.accept_replacement(replacement, &relay).await?;
                        if let Some(observability) = &observability {
                            observability.set_direct_peers(Vec::<PeerId>::new());
                        }
                    }
                    Some(ControlMessage::ServiceResult(result)) => {
                        let (service_id, committed) =
                            decode_service_result(live_policy.mesh_id, result)?;
                        let waiter: oneshot::Sender<bool> = service_waiters.remove(&service_id)
                            .ok_or(PacketPumpError::InvalidControl)?;
                        let _ = waiter.send(committed);
                    }
                    Some(ControlMessage::PeerDirectory(chunk)) => {
                        let state = directory.as_ref().ok_or(PacketPumpError::InvalidControl)?;
                        let candidate = state.write()
                            .map_err(|error| invalid_control_error("control message", error))?
                            .prepare_chunk(chunk)?;
                        if let Some(signed) = candidate {
                            wireguard.core.lock().await.install_directory(&signed, UnixTime(wall_clock_seconds())).map_err(core_packet_error)?;
                            state.write().map_err(|error| invalid_control_error("control message", error))?
                                .commit_directory(signed.clone())?;
                            if let Some(rotator) = &rotation
                                && let Some(published) = signed
                                    .directory
                                    .entries
                                    .iter()
                                    .find(|entry| entry.entry.peer_id == local_peer)
                            {
                                rotator.lock().await.commit_if_published(&published.entry)?;
                            }
                            if let Some(observability) = &observability {
                                observability.signed_revision(
                                    peerward_service::SignedStateFamily::Peers,
                                    signed.directory.revision,
                                );
                            }
                        }
                    }
                    Some(ControlMessage::AuthorityDirectory(chunk)) => {
                        if chunk.mesh_id != live_policy.mesh_id.as_bytes() {
                            return Err(PacketPumpError::InvalidControl);
                        }
                        let revision = chunk.revision;
                        let complete = authority_chunks
                            .write()
                            .map_err(|error| invalid_control_error("control message", error))?
                            .push_redundant(RevisionChunk {
                                mesh_id: live_policy.mesh_id,
                                revision,
                                index: chunk.index,
                                count: chunk.count,
                                body: chunk.body.clone(),
                            })
                            .map_err(|error| invalid_control_error("control message", error))?;
                        if let Some(bytes) = complete {
                            let signed = SignedAuthorityBundle::decode(&bytes)
                                .map_err(|error| invalid_control_error("control message", error))?;
                            if signed.bundle.revision != revision {
                                return Err(PacketPumpError::InvalidControl);
                            }
                            wireguard.core.lock().await.authorities(&signed, UnixTime(wall_clock_seconds())).map_err(core_packet_error)?;
                            trust.install_authority_bundle(
                                &signed,
                                UnixTime(wall_clock_seconds()),
                            ).map_err(|error| invalid_control_error("control message", error))?;
                            authority_chunks
                                .write()
                                .map_err(|error| invalid_control_error("control message", error))?
                                .commit(revision)
                                .map_err(|error| invalid_control_error("control message", error))?;
                            if let Some(observability) = &observability {
                                observability.signed_revision(
                                    peerward_service::SignedStateFamily::Authorities,
                                    revision,
                                );
                            }
                        }
                    }
                    Some(ControlMessage::RelayDirectory(chunk)) => {
                        let state = directory.as_ref().ok_or(PacketPumpError::InvalidControl)?;
                        let candidate = state.write()
                            .map_err(|error| invalid_control_error("control message", error))?
                            .prepare_relay_chunk(chunk)?;
                        if let Some(signed) = candidate {
                            let canonical = peerward_directory::encode_relay_directory(&signed)
                                .map_err(|error| invalid_control_error("relay directory", error))?;
                            wireguard.core.lock().await.checkpoint_verified_snapshot(peerward_peer_core::SnapshotKind::Relays,
                                signed.directory.revision, &canonical, UnixTime(wall_clock_seconds())).map_err(core_packet_error)?;
                            state.write().map_err(|error| invalid_control_error("control message", error))?
                                .commit_relay_directory(signed.directory.revision)?;
                            if let Some(observability) = &observability {
                                observability.signed_revision(peerward_service::SignedStateFamily::Relays, signed.directory.revision);
                            }
                        }
                    }
                    Some(ControlMessage::Revocation(revocation)) => {
                        if revocation.mesh_id != live_policy.mesh_id.as_bytes() {
                            return Err(PacketPumpError::InvalidControl);
                        }
                        let revision = revocation.revision;
                        let complete = revocation_chunks.push_redundant(RevisionChunk {
                            mesh_id: live_policy.mesh_id,
                            revision,
                            index: revocation.index,
                            count: revocation.count,
                            body: revocation.body.clone(),
                        }).map_err(|error| invalid_control_error("control message", error))?;
                        let Some(bytes) = complete else { continue; };
                        let decoded_revision = decode_revocations(&bytes)
                            .map_err(|error| invalid_control_error("control message", error))?
                            .bundle
                            .revision;
                        if decoded_revision != revision {
                            return Err(PacketPumpError::InvalidControl);
                        }
                        wireguard.core.lock().await.revoke(&decode_revocations(&bytes).map_err(|_| PacketPumpError::InvalidControl)?, UnixTime(wall_clock_seconds())).map_err(core_packet_error)?;
                        let state = directory.as_ref().ok_or(PacketPumpError::InvalidControl)?;
                        let serials = state
                            .write()
                            .map_err(|error| invalid_control_error("control message", error))?
                            .apply_revocations(&revocation.mesh_id, &bytes)?;
                        revocation_chunks.commit(revision)
                            .map_err(|error| invalid_control_error("control message", error))?;
                        let table = services.as_ref().ok_or(PacketPumpError::InvalidControl)?;
                        let mut table = table.lock().await;
                        for serial in serials {
                            table.revoke_credential(serial);
                        }
                        if let Some(observability) = &observability {
                            observability.signed_revision(
                                peerward_service::SignedStateFamily::Revocations,
                                revision,
                            );
                        }
                    }
                    _ => {}
                }
            }
            change = async {
                match &mut service_changes {
                    Some(changes) => changes.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                let Some(change) = change else {
                    service_changes = None;
                    continue;
                };
                let (service_id, reply, envelope) =
                    encode_service_change(live_policy.mesh_id, change);
                if service_waiters.insert(service_id, reply).is_some() {
                    return Err(PacketPumpError::InvalidControl);
                }
                if let Err(error) = relay.send_control(envelope).await {
                    if let Some(waiter) = service_waiters.remove(&service_id) {
                        let _ = waiter.send(false);
                    }
                    return Err(error);
                }
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() { wireguard.core.lock().await.close(); return Ok(()); }
            }
        }
    }
}
