const AUDIT_FLUSH_SECONDS: u64 = 5;
const AUDIT_CHANNEL_CAPACITY: usize = 256;

struct PeerAuditReporter<C> {
    mesh_id: MeshId,
    peer_id: PeerId,
    recipient_public: [u8; 32],
    identity_file: std::path::PathBuf,
    control: C,
    observability: Option<peerward_service::PeerObservability>,
    last_health_sequence: u64,
}

impl<C: ControlSender> PeerAuditReporter<C> {
    fn current_identity(&self) -> Result<IdentitySigningKey, PacketPumpError> {
        // The rotation journal commits this path only after signed-directory activation.
        // Loading at seal time avoids retaining the old audit signer beyond its overlap.
        let private = zeroize::Zeroizing::new(read_identity_private_key(&self.identity_file)?);
        Ok(IdentitySigningKey::from_bytes(&private))
    }

    async fn run(
        mut self,
        mut events: mpsc::Receiver<peerward_wire::AuditEventV1>,
        mut shutdown: watch::Receiver<bool>,
    ) {
        let mut pending = BTreeMap::<(i32, i32), u32>::new();
        let mut interval = tokio::time::interval(Duration::from_secs(AUDIT_FLUSH_SECONDS));
        let mut health_interval = tokio::time::interval(Duration::from_secs(1));
        let health_epoch = tokio::time::Instant::now();
        let mut health_scheduler = RuntimeScheduler::default();
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        health_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        interval.tick().await;
        loop {
            tokio::select! {
                event = events.recv() => if let Some(event) = event {
                        pending.entry((event.direction,event.reason))
                            .and_modify(|count| *count=count.saturating_add(event.count))
                            .or_insert(event.count);
                    } else {
                        let _ = self.flush(&mut pending).await;
                        return;
                },
                _ = interval.tick() => {
                    if let Err(error) = self.flush(&mut pending).await {
                        tracing::warn!(?error, "encrypted Peer audit batch send deferred");
                    }
                }
                _ = health_interval.tick() => {
                    if let Some(observability) = &self.observability {
                        let report = observability.runtime_report();
                        let now = u64::try_from(health_epoch.elapsed().as_millis())
                            .unwrap_or(u64::MAX);
                        if health_scheduler
                            .poll(now, health_fingerprint(&report))
                            .report_health
                            && self.flush_health(&report).await.is_err()
                        {
                            health_scheduler.retry_health();
                        }
                    }
                }
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        let _ = self.flush(&mut pending).await;
                        return;
                    }
                }
            }
        }
    }

    async fn flush_health(
        &mut self,
        report: &peerward_service::PeerRuntimeReport,
    ) -> Result<(), PacketPumpError> {
        let observed_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| PacketPumpError::InvalidControl)?
            .as_secs();
        let candidate = observed_at
            .saturating_mul(1_000_000)
            .saturating_add(report.generation.min(999_999));
        self.last_health_sequence = candidate.max(self.last_health_sequence.saturating_add(1));
        let batch_id = Uuid::new_v4();
        let batch = peerward_wire::AuditBatchV1 {
            major: PROTOCOL_MAJOR,
            schema_version: 1,
            mesh_id: self.mesh_id.as_bytes().to_vec(),
            source_peer: self.peer_id.as_bytes().to_vec(),
            batch_id: batch_id.as_bytes().to_vec(),
            observed_at,
            events: Vec::new(),
            runtime_health: Some(peerward_wire::RuntimeHealthV1 {
                sequence: self.last_health_sequence,
                direct_path_count: report.direct_path_count,
                relay_packets: report.relay_packets,
                direct_packets: report.direct_packets,
                degraded_reasons: report
                    .degraded_reasons
                    .iter()
                    .map(|reason| match reason {
                        peerward_service::PeerDegradedReason::RelayUnavailable => peerward_wire::RuntimeDegradedReasonV1::RelayUnavailable as i32,
                        peerward_service::PeerDegradedReason::SignedStateIncomplete => peerward_wire::RuntimeDegradedReasonV1::SignedStateIncomplete as i32,
                        peerward_service::PeerDegradedReason::DirectPathUnavailable => peerward_wire::RuntimeDegradedReasonV1::DirectPathUnavailable as i32,
                        peerward_service::PeerDegradedReason::DnsDegraded => peerward_wire::RuntimeDegradedReasonV1::DnsDegraded as i32,
                        peerward_service::PeerDegradedReason::UnderlayUnavailable => peerward_wire::RuntimeDegradedReasonV1::UnderlayUnavailable as i32,
                        peerward_service::PeerDegradedReason::PacketPumpUnavailable => peerward_wire::RuntimeDegradedReasonV1::PacketPumpUnavailable as i32,
                    })
                    .collect(),
                signed_revision: report.signed_revision,
            }),
        };
        let sealed = peerward_wire::seal_audit_batch(
            &batch,
            &self.recipient_public,
            &self.current_identity()?,
            OsRng,
        )?;
        self.control
            .send_control(ControlEnvelope {
                trace_context: None,
                message: Some(ControlMessage::Opaque(RelayEnvelopeV2 {
                    major: PROTOCOL_MAJOR,
                    mesh_id: self.mesh_id.as_bytes().to_vec(),
                    destination_peer: peerward_wire::CONTROL_AUDIT_DESTINATION.to_vec(),
                    source_peer: Vec::new(),
                    kind: OpaqueFrameKind::Audit as i32,
                    opaque: sealed.encode_to_vec(),
                })),
            })
            .await
    }

    async fn flush(
        &self,
        pending: &mut BTreeMap<(i32, i32), u32>,
    ) -> Result<(), PacketPumpError> {
        if pending.is_empty() {
            return Ok(());
        }
        let batch_id = Uuid::new_v4();
        let observed_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| PacketPumpError::InvalidControl)?
            .as_secs();
        let batch = peerward_wire::AuditBatchV1 {
            major: PROTOCOL_MAJOR,
            schema_version: 1,
            mesh_id: self.mesh_id.as_bytes().to_vec(),
            source_peer: self.peer_id.as_bytes().to_vec(),
            batch_id: batch_id.as_bytes().to_vec(),
            observed_at,
            events: pending
                .iter()
                .map(|(&(direction, reason), &count)| peerward_wire::AuditEventV1 {
                    direction,
                    reason,
                    count,
                })
                .collect(),
            runtime_health: None,
        };
        let sealed = peerward_wire::seal_audit_batch(
            &batch,
            &self.recipient_public,
            &self.current_identity()?,
            OsRng,
        )?;
        self.control
            .send_control(ControlEnvelope {
                trace_context: None,
                message: Some(ControlMessage::Opaque(RelayEnvelopeV2 {
                    major: PROTOCOL_MAJOR,
                    mesh_id: self.mesh_id.as_bytes().to_vec(),
                    destination_peer: peerward_wire::CONTROL_AUDIT_DESTINATION.to_vec(),
                    source_peer: Vec::new(),
                    kind: OpaqueFrameKind::Audit as i32,
                    opaque: sealed.encode_to_vec(),
                })),
            })
            .await?;
        pending.clear();
        Ok(())
    }
}

fn health_fingerprint(
    report: &peerward_service::PeerRuntimeReport,
) -> RuntimeHealthFingerprint {
    let degraded_reason_mask = report.degraded_reasons.iter().fold(0_u32, |mask, reason| {
        let bit = match reason {
            peerward_service::PeerDegradedReason::RelayUnavailable => 0,
            peerward_service::PeerDegradedReason::SignedStateIncomplete => 1,
            peerward_service::PeerDegradedReason::DirectPathUnavailable => 2,
            peerward_service::PeerDegradedReason::DnsDegraded => 3,
            peerward_service::PeerDegradedReason::UnderlayUnavailable => 4,
            peerward_service::PeerDegradedReason::PacketPumpUnavailable => 5,
        };
        mask | (1 << bit)
    });
    RuntimeHealthFingerprint {
        state_generation: report.generation,
        primary_relay_authenticated: degraded_reason_mask & 1 == 0,
        standby_relay_count: 0,
        direct_path_count: report.direct_path_count,
        signed_state_complete: degraded_reason_mask & (1 << 1) == 0,
        signed_state_revision: report.signed_revision,
        degraded_reason_mask,
    }
}

fn start_audit_reporter<C: ControlSender + 'static>(
    config: &PeerConfig,
    control: C,
    shutdown: watch::Receiver<bool>,
    observability: Option<peerward_service::PeerObservability>,
) -> Result<
    (
        mpsc::Sender<peerward_wire::AuditEventV1>,
        tokio::task::JoinHandle<()>,
    ),
    PacketPumpError,
> {
    let recipient_public: [u8; 32] = hex::decode(
        config.audit_public_key.as_deref().ok_or(PacketPumpError::InvalidControl)?,
    )
    .map_err(|_| PacketPumpError::InvalidControl)?
    .try_into()
    .map_err(|_| PacketPumpError::InvalidControl)?;
    let private = zeroize::Zeroizing::new(read_identity_private_key(
        &config.identity_private_key_file,
    )?);
    drop(private);
    let reporter = PeerAuditReporter {
        mesh_id: config.mesh_id,
        peer_id: config.peer_id,
        recipient_public,
        identity_file: config.identity_private_key_file.clone(),
        control,
        observability,
        last_health_sequence: 0,
    };
    let (sender, receiver) = mpsc::channel(AUDIT_CHANNEL_CAPACITY);
    let worker = tokio::spawn(reporter.run(receiver, shutdown));
    Ok((sender, worker))
}
