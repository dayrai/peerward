const AUDIT_CLAIM_LIMIT: u32 = 64;
const AUDIT_MAX_ATTEMPTS: u32 = 10;
const AUDIT_MAX_AGE_SECONDS: i64 = 7 * 24 * 60 * 60;

async fn collect_encrypted_audits(
    store: &Store,
    mesh_id: MeshId,
    issuer: &JoinIssuer,
    metrics: &ControlMetrics,
) -> Result<usize, ApiError> {
    let mut processed = 0_usize;
    let claimed = store
        .claim_encrypted_audits(mesh_id, AUDIT_CLAIM_LIMIT)
        .await?;
    for record in claimed {
        let result = verify_encrypted_audit(store, &record, issuer).await;
        match result {
            Ok((batch, events)) => {
                let batch_id = Uuid::from_slice(&batch.batch_id)
                    .map_err(|_| ApiError::invalid("invalid_audit_batch", "invalid batch ID"))?;
                let occurred_at = OffsetDateTime::from_unix_timestamp(
                    i64::try_from(batch.observed_at).map_err(|_| {
                        ApiError::invalid("invalid_audit_time", "invalid audit timestamp")
                    })?,
                )
                .map_err(|_| {
                    ApiError::invalid("invalid_audit_time", "invalid audit timestamp")
                })?;
                let inserted = if let Some(health) = &batch.runtime_health {
                    store
                        .commit_peer_runtime_health(
                            record.id,
                            record.mesh_id,
                            record.source_peer,
                            &PeerRuntimeHealthRecord {
                                sequence: health.sequence,
                                observed_at: occurred_at,
                                direct_path_count: health.direct_path_count,
                                relay_packets: health.relay_packets,
                                direct_packets: health.direct_packets,
                                degraded_reasons: health
                                    .degraded_reasons
                                    .iter()
                                    .map(|reason| runtime_health_reason(*reason).map(str::to_owned))
                                    .collect::<Result<Vec<_>, _>>()
                                    .map_err(|code| {
                                        ApiError::invalid("invalid_runtime_health", code)
                                    })?,
                                signed_revision: health.signed_revision,
                            },
                        )
                        .await?
                } else {
                    store
                        .commit_peer_audit_batch(
                            record.id,
                            record.mesh_id,
                            record.source_peer,
                            batch_id,
                            occurred_at,
                            &events,
                        )
                        .await?
                };
                let counter = if inserted {
                    &metrics.audit_batches_processed
                } else {
                    &metrics.audit_batches_replayed
                };
                counter.fetch_add(1, Ordering::Relaxed);
                processed += usize::from(inserted);
            }
            Err(diagnostic) => {
                metrics
                    .audit_batches_rejected
                    .fetch_add(1, Ordering::Relaxed);
                if record.attempts >= AUDIT_MAX_ATTEMPTS {
                    store.discard_encrypted_audit(record.id).await?;
                } else {
                    store.reject_encrypted_audit(record.id, diagnostic).await?;
                }
            }
        }
    }
    Ok(processed)
}

/// Processes one bounded pass of Relay-forwarded encrypted audit batches.
#[doc(hidden)]
pub async fn collect_peer_audits(
    store: &Store,
    configured: &[JoinIssuerConfig],
) -> Result<usize, ApiError> {
    let issuers = load_join_issuers(configured, None)?;
    let metrics = ControlMetrics::default();
    let mut processed = 0_usize;
    for (mesh_id, candidates) in issuers {
        let issuer = active_issuer(store, mesh_id, &candidates).await?;
        processed += collect_encrypted_audits(store, mesh_id, &issuer, &metrics).await?;
    }
    Ok(processed)
}

async fn verify_encrypted_audit(
    store: &Store,
    record: &peerward_store::EncryptedAuditRecord,
    issuer: &JoinIssuer,
) -> Result<(AuditBatchV1, Vec<PeerAuditEventRecord>), &'static str> {
    let sealed = SealedAuditBatchV1::decode(record.envelope.as_slice())
        .map_err(|_| "malformed_envelope")?;
    sealed.validate().map_err(|_| "invalid_envelope")?;
    if sealed.mesh_id != record.mesh_id.as_bytes()
        || sealed.source_peer != record.source_peer.as_bytes()
    {
        return Err("relay_source_mismatch");
    }
    let identities: Vec<Vec<u8>> = sqlx::query_scalar(
        "SELECT c.identity_public_key FROM peer_credentials c
         JOIN peers p ON p.mesh_id=c.mesh_id AND p.id=c.peer_id
         JOIN meshes m ON m.id=c.mesh_id
         JOIN mesh_authorities a ON a.mesh_id=c.mesh_id AND a.id=c.authority_id
         WHERE c.mesh_id=$1 AND c.peer_id=$2 AND m.lifecycle='active'
           AND p.administrative_state='enabled'
           AND c.lifecycle IN ('active','overlap')
           AND (c.lifecycle='active' OR c.overlap_deadline>clock_timestamp())
           AND c.not_before<=clock_timestamp() AND c.not_after>clock_timestamp()
           AND a.lifecycle IN ('active','overlap')
           AND (a.lifecycle='active' OR a.overlap_deadline>clock_timestamp())
           AND a.not_before<=clock_timestamp() AND a.not_after>clock_timestamp()
         ORDER BY CASE c.lifecycle WHEN 'active' THEN 0 ELSE 1 END,c.created_at DESC",
    )
    .bind(record.mesh_id.into_uuid())
    .bind(record.source_peer.into_uuid())
    .fetch_all(store.pool())
    .await
    .map_err(|_| "identity_lookup_failed")?;
    let batch = identities
        .into_iter()
        .filter_map(|identity| <[u8; 32]>::try_from(identity).ok())
        .find_map(|identity| {
            open_audit_batch(&sealed, &issuer.audit_private_key, &identity).ok()
        })
        .ok_or("identity_verification_failed")?;
    if batch.runtime_health.is_some() && record.envelope.len() > 4 * 1024 {
        return Err("runtime_health_too_large");
    }
    let observed_at = i64::try_from(batch.observed_at).map_err(|_| "invalid_observed_at")?;
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let max_age = if batch.runtime_health.is_some() {
        90
    } else {
        AUDIT_MAX_AGE_SECONDS
    };
    let future_skew = if batch.runtime_health.is_some() { 30 } else { 120 };
    if observed_at > now.saturating_add(future_skew) || observed_at <= now.saturating_sub(max_age)
    {
        return Err("stale_observed_at");
    }
    let events = batch
        .events
        .iter()
        .map(|event| {
            Ok(PeerAuditEventRecord {
                direction: audit_direction(event.direction)?,
                reason: audit_reason(event.reason)?,
                count: event.count,
            })
        })
        .collect::<Result<Vec<_>, &'static str>>()?;
    Ok((batch, events))
}

fn runtime_health_reason(value: i32) -> Result<&'static str, &'static str> {
    match RuntimeDegradedReasonV1::try_from(value).map_err(|_| "invalid degraded reason")? {
        RuntimeDegradedReasonV1::RelayUnavailable => Ok("relay_unavailable"),
        RuntimeDegradedReasonV1::SignedStateIncomplete => Ok("signed_state_incomplete"),
        RuntimeDegradedReasonV1::DirectPathUnavailable => Ok("direct_path_unavailable"),
        RuntimeDegradedReasonV1::DnsDegraded => Ok("dns_degraded"),
        RuntimeDegradedReasonV1::CredentialRotation => Ok("credential_rotation"),
        RuntimeDegradedReasonV1::UnderlayUnavailable => Ok("underlay_unavailable"),
        RuntimeDegradedReasonV1::PacketPumpUnavailable => Ok("packet_pump_unavailable"),
    }
}

fn audit_direction(value: i32) -> Result<&'static str, &'static str> {
    match AuditDirectionV1::try_from(value).map_err(|_| "invalid_direction")? {
        AuditDirectionV1::Egress => Ok("egress"),
        AuditDirectionV1::Ingress => Ok("ingress"),
        AuditDirectionV1::Runtime => Ok("runtime"),
    }
}

fn audit_reason(value: i32) -> Result<&'static str, &'static str> {
    match AuditReasonV1::try_from(value).map_err(|_| "invalid_reason")? {
        AuditReasonV1::PolicyDenied => Ok("policy_denied"),
        AuditReasonV1::MalformedPacket => Ok("malformed_packet"),
        AuditReasonV1::SessionUnavailable => Ok("session_unavailable"),
        AuditReasonV1::ResourceLimited => Ok("resource_limited"),
        AuditReasonV1::SecurityAnomaly => Ok("security_anomaly"),
    }
}
