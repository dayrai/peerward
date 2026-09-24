/// One bounded outstanding receipt. Retries reuse the exact signed command and request ID.
struct ReceiptDelivery {
    acknowledged: Option<(
        CredentialSerial,
        u64,
        peerward_management::ApplicationResult,
    )>,
    pending: Option<PendingReceipt>,
}
struct PendingReceipt {
    signed: peerward_management::SignedPeerCommand,
    lease: u64,
    result: peerward_management::ApplicationResult,
    next_attempt: Instant,
    attempts: u32,
}
impl ReceiptDelivery {
    fn new() -> Self {
        Self {
            acknowledged: None,
            pending: None,
        }
    }
    async fn send<C: ControlSender>(
        &mut self,
        relay: &C,
        rotator: &Arc<Mutex<CredentialRotator>>,
        wireguard: &WireguardPath,
    ) -> Result<(), PacketPumpError> {
        let now = Instant::now();
        let wall = UnixTime(wall_clock_seconds());
        let rotation = rotator.lock().await;
        let mut core = wireguard.core.lock().await;
        let Some(operation) = core.core_management_receipt(wall) else {
            self.pending = None;
            return Ok(());
        };
        let peerward_management::PeerOperation::Applied {
            lease_sequence,
            result,
            ..
        } = &operation
        else {
            return Err(PacketPumpError::InvalidControl);
        };
        let lease = *lease_sequence;
        let result = *result;
        let serial = rotation.current.serial;
        if self.acknowledged == Some((serial, lease, result)) {
            return Ok(());
        }
        if self.pending.as_ref().is_none_or(|pending| {
            pending.lease != lease
                || pending.result != result
                || pending.signed.command.credential_serial != serial
                || wall.0.saturating_sub(pending.signed.command.issued_at) > 250
        }) {
            let command = peerward_management::PeerCommand {
                mesh_id: rotation.mesh_id,
                peer_id: rotation.peer_id,
                credential_serial: serial,
                request_id: uuid::Uuid::new_v4(),
                sequence: core.next_management_sequence().map_err(core_packet_error)?,
                issued_at: wall.0,
                operation,
            };
            let signed = peerward_management::SignedPeerCommand::sign(
                command,
                &IdentitySigningKey::from_bytes(&rotation.current_identity_private_key),
            )
            .map_err(|_| PacketPumpError::InvalidControl)?;
            self.pending = Some(PendingReceipt {
                signed,
                lease,
                result,
                next_attempt: now,
                attempts: 0,
            });
        }
        drop(core);
        drop(rotation);
        let pending = self
            .pending
            .as_mut()
            .ok_or(PacketPumpError::InvalidControl)?;
        if now < pending.next_attempt {
            return Ok(());
        }
        pending.attempts = pending.attempts.saturating_add(1);
        pending.next_attempt =
            now + std::time::Duration::from_secs(2u64.saturating_pow(pending.attempts.min(5)));
        let body =
            serde_json::to_vec(&pending.signed).map_err(|_| PacketPumpError::InvalidControl)?;
        relay
            .send_control(ControlEnvelope {
                trace_context: None,
                message: Some(ControlMessage::PeerManagement(
                    peerward_wire::PeerManagement { body },
                )),
            })
            .await
    }
    fn result(&mut self, result: &peerward_wire::PeerManagementResult) {
        let Some(pending) = &self.pending else {
            return;
        };
        if result.request_id != pending.signed.command.request_id.as_bytes() {
            return;
        }
        if result.committed {
            self.acknowledged = Some((
                pending.signed.command.credential_serial,
                pending.lease,
                pending.result,
            ));
        }
        // A parallel, newer device command may have advanced the replay floor.
        // Re-sign the next attempt with a fresh sequence after an explicit rejection.
        self.pending = None;
    }
}
