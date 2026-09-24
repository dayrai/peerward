impl NativeSession {
    /// Produces a stable receipt or software-evidence transcript for the device to sign.
    /// Evidence renewal remains available while data-plane admission is quarantined.
    pub fn management_transcript(&mut self, now: UnixTime) -> Result<Vec<u8>, MobileError> {
        if matches!(self.state, State::Closed) {
            return Err(MobileError::InvalidState);
        }
        let Some(owner) = &self.wireguard else {
            return Ok(vec![]);
        };
        let mut owner = owner.lock().map_err(|_| MobileError::InvalidState)?;
        let operations = owner.application_receipts(now);
        let receipt = operations.into_iter().find(|operation| {
            !self
                .management_acknowledged
                .contains(&(self.current_credential.serial, operation.clone()))
        });
        let evidence_due = !self.evidence_acknowledged.is_some_and(|(serial, issued_at)| {
            serial == self.current_credential.serial
                && now.0.checked_sub(issued_at).is_some_and(|age| age < 300)
        });
        let operation = evidence_due.then(|| peerward_management::PeerOperation::DeviceEvidence {
                evidence: peerward_management::DeviceEvidence::current(
                    peerward_management::DevicePlatform::Android,
                ),
            }).or(receipt);
        let Some(operation) = operation else {
            self.pending_management = None;
            return Ok(vec![]);
        };
        // Device evidence has a stricter 30-second server freshness window than
        // application receipts. Reserve transit time while retaining exact short retries.
        let retry_age = if matches!(operation, peerward_management::PeerOperation::DeviceEvidence { .. }) { 25 } else { 250 };
        if self.pending_management.as_ref().is_none_or(|command| {
            command.credential_serial != self.current_credential.serial
                || now.0.abs_diff(command.issued_at) > retry_age
                || command.operation != operation
        }) {
            self.pending_management = Some(peerward_management::PeerCommand {
                mesh_id: self.trust.mesh_id,
                peer_id: self.local_peer,
                credential_serial: self.current_credential.serial,
                request_id: uuid::Uuid::new_v4(),
                sequence: owner.core.next_management_sequence()?,
                issued_at: now.0,
                operation,
            });
        }
        self.pending_management
            .as_ref()
            .ok_or(MobileError::InvalidState)?
            .signing_transcript()
            .map_err(|_| MobileError::InvalidInput)
    }

    /// Verifies a protected identity signature without accepting caller-supplied receipt content.
    pub fn complete_management(&mut self, signature: [u8; 64]) -> Result<Vec<u8>, MobileError> {
        if matches!(self.state, State::Closed) {
            return Err(MobileError::InvalidState);
        }
        let command = self
            .pending_management
            .clone()
            .ok_or(MobileError::InvalidState)?;
        let signed = peerward_management::SignedPeerCommand {
            command,
            signature: signature.to_vec(),
        };
        signed
            .verify(
                &self.current_credential.identity_public_key,
                wall_clock_seconds(),
            )
            .map_err(|_| MobileError::InvalidInput)?;
        let body = serde_json::to_vec(&signed).map_err(|_| MobileError::InvalidInput)?;
        Ok(ControlEnvelope {
            trace_context: None,
            message: Some(ControlMessage::PeerManagement(
                peerward_wire::PeerManagement { body },
            )),
        }
        .encode_to_vec())
    }

    fn management_result(&mut self, result: &peerward_wire::PeerManagementResult) {
        let Some(pending) = &self.pending_management else {
            return;
        };
        if result.request_id != pending.request_id.as_bytes() {
            return;
        }
        if result.committed {
            match &pending.operation {
                peerward_management::PeerOperation::Applied { category, .. } => {
                    self.management_acknowledged.retain(|(_, operation)|
                        !matches!(operation, peerward_management::PeerOperation::Applied { category: previous, .. } if previous == category));
                    self.management_acknowledged
                        .push((pending.credential_serial, pending.operation.clone()));
                }
                peerward_management::PeerOperation::DeviceEvidence { .. } => {
                    self.evidence_acknowledged = Some((pending.credential_serial, pending.issued_at));
                }
                _ => {}
            }
        }
        // A newer operation from another attachment may have overtaken this request.
        // Retry with a fresh reserved number after a rejection, never lower the server floor.
        self.pending_management = None;
    }
}
