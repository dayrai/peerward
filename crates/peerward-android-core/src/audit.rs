#[derive(Clone)]
struct PendingMobileAudit {
    sealed: peerward_wire::SealedAuditBatchV1,
    transcript: Vec<u8>,
}

#[derive(Clone)]
struct PendingMobileHealth {
    sealed: peerward_wire::SealedAuditBatchV1,
    transcript: Vec<u8>,
}

impl NativeSession {
    /// Builds the stable Keystore signature transcript for one encrypted, current-only report.
    ///
    /// # Errors
    ///
    /// Returns an error when another report is pending or a field is outside its bound.
    pub fn health_signature_transcript(
        &mut self,
        now: UnixTime,
        health: &MobileRuntimeHealth,
    ) -> Result<Vec<u8>, MobileError> {
        if let Some(pending) = &self.pending_health {
            return Ok(pending.transcript.clone());
        }
        let batch_id = Uuid::new_v4();
        let batch = peerward_wire::AuditBatchV1 {
            major: PROTOCOL_MAJOR,
            schema_version: 1,
            mesh_id: self.trust.mesh_id.as_bytes().to_vec(),
            source_peer: self.local_peer.as_bytes().to_vec(),
            batch_id: batch_id.as_bytes().to_vec(),
            observed_at: now.0,
            events: Vec::new(),
            runtime_health: Some(peerward_wire::RuntimeHealthV1 {
                sequence: health.sequence,
                direct_path_count: health.direct_path_count,
                relay_packets: health.relay_packets,
                direct_packets: health.direct_packets,
                degraded_reasons: health
                    .degraded_reasons
                    .iter()
                    .map(|reason| *reason as i32)
                    .collect(),
                signed_revision: health.signed_revision,
            }),
        };
        let (sealed, transcript) = peerward_wire::prepare_audit_batch(
            &batch,
            &self.trust.audit_recipient(),
            OsRng,
        )?;
        if sealed.encoded_len() > 4 * 1024 {
            return Err(MobileError::InvalidInput);
        }
        self.pending_health = Some(PendingMobileHealth {
            sealed,
            transcript: transcript.clone(),
        });
        Ok(transcript)
    }

    /// Verifies the `AndroidKeyStore` signature and returns a Relay-addressed opaque report.
    ///
    /// # Errors
    ///
    /// Returns an error when no report is pending or the signature is invalid.
    pub fn complete_health(&mut self, signature: [u8; 64]) -> Result<Vec<u8>, MobileError> {
        let pending = self
            .pending_health
            .clone()
            .ok_or(MobileError::InvalidState)?;
        let sealed = peerward_wire::finish_audit_batch(
            pending.sealed,
            &signature,
            &self.current_credential.identity_public_key,
        )?;
        let envelope = ControlEnvelope {
            trace_context: None,
            message: Some(ControlMessage::Opaque(peerward_wire::RelayEnvelopeV2 {
                major: PROTOCOL_MAJOR,
                mesh_id: self.trust.mesh_id.as_bytes().to_vec(),
                destination_peer: peerward_wire::CONTROL_AUDIT_DESTINATION.to_vec(),
                source_peer: Vec::new(),
                kind: peerward_wire::OpaqueFrameKind::Audit as i32,
                opaque: sealed.encode_to_vec(),
            })),
        };
        self.pending_health = None;
        Ok(envelope.encode_to_vec())
    }

    #[cfg(test)]
    fn record_audit(&mut self, direction: peerward_wire::AuditDirectionV1, error: &MobileError) {
        if let Some(owner) = &self.wireguard {
            if let Ok(mut owner) = owner.lock() { accumulate_audit(&mut owner.audit_counts, direction, error); }
        } else {
            accumulate_audit(&mut self.audit_counts, direction, error);
        }
    }

    /// Returns one stable signature transcript for all denials accumulated since the previous
    /// completed batch. An empty vector means there is currently nothing to report.
    ///
    /// # Errors
    ///
    /// Returns an error when the accumulated state or Authority-bound recipient key is invalid.
    pub fn audit_signature_transcript(&mut self, now: UnixTime) -> Result<Vec<u8>, MobileError> {
        if let Some(pending) = &self.pending_audit {
            return Ok(pending.transcript.clone());
        }
        if let Some(owner) = &self.wireguard {
            let mut owner = owner.lock().map_err(|_| MobileError::InvalidState)?;
            for (key, count) in std::mem::take(&mut owner.audit_counts) {
                let total = self.audit_counts.entry(key).or_default();
                *total = total.saturating_add(count);
            }
        }
        if self.audit_counts.is_empty() {
            return Ok(Vec::new());
        }
        let batch_id = Uuid::new_v4();
        let batch = peerward_wire::AuditBatchV1 {
            major: PROTOCOL_MAJOR,
            schema_version: 1,
            mesh_id: self.trust.mesh_id.as_bytes().to_vec(),
            source_peer: self.local_peer.as_bytes().to_vec(),
            batch_id: batch_id.as_bytes().to_vec(),
            observed_at: now.0,
            events: self
                .audit_counts
                .iter()
                .map(|(&(direction, reason), &count)| peerward_wire::AuditEventV1 {
                    direction,
                    reason,
                    count,
                })
                .collect(),
            runtime_health: None,
        };
        let (sealed, transcript) = peerward_wire::prepare_audit_batch(
            &batch,
            &self.trust.audit_recipient(),
            OsRng,
        )?;
        self.pending_audit = Some(PendingMobileAudit {
            sealed,
            transcript: transcript.clone(),
        });
        Ok(transcript)
    }

    /// Verifies a Keystore-backed identity signature and returns a Relay-addressed opaque audit
    /// control envelope. Counts are cleared only after successful signature verification.
    ///
    /// # Errors
    ///
    /// Returns an error when no batch is pending or the supplied identity signature is invalid.
    pub fn complete_audit(&mut self, signature: [u8; 64]) -> Result<Vec<u8>, MobileError> {
        let pending = self
            .pending_audit
            .clone()
            .ok_or(MobileError::InvalidState)?;
        let sealed = peerward_wire::finish_audit_batch(
            pending.sealed,
            &signature,
            &self.current_credential.identity_public_key,
        )?;
        let envelope = ControlEnvelope {
            trace_context: None,
            message: Some(ControlMessage::Opaque(peerward_wire::RelayEnvelopeV2 {
                major: PROTOCOL_MAJOR,
                mesh_id: self.trust.mesh_id.as_bytes().to_vec(),
                destination_peer: peerward_wire::CONTROL_AUDIT_DESTINATION.to_vec(),
                source_peer: Vec::new(),
                kind: peerward_wire::OpaqueFrameKind::Audit as i32,
                opaque: sealed.encode_to_vec(),
            })),
        };
        self.pending_audit = None;
        self.audit_counts.clear();
        Ok(envelope.encode_to_vec())
    }
}

fn accumulate_audit(
    counts: &mut std::collections::BTreeMap<(i32, i32), u32>,
    direction: peerward_wire::AuditDirectionV1, error: &MobileError,
) {
    use peerward_wire::AuditReasonV1;
    let reason = match error {
        MobileError::PolicyDenied | MobileError::Peer(PeerError::PolicyDenied) => AuditReasonV1::PolicyDenied,
        MobileError::Peer(PeerError::QueueFull) => AuditReasonV1::ResourceLimited,
        MobileError::Wire(WireError::RekeyRequired)
        | MobileError::Peer(PeerError::Revoked | PeerError::Closed) => AuditReasonV1::SessionUnavailable,
        _ => AuditReasonV1::SecurityAnomaly,
    };
    counts.entry((direction as i32, reason as i32))
        .and_modify(|count| *count = count.saturating_add(1)).or_insert(1);
}
