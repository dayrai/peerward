impl NativeSession {
    /// Encrypts one canonical link-control record.
    ///
    /// # Errors
    /// Returns an error outside transport state or for an IP link record.
    pub fn encrypt(
        &mut self,
        record: &Record,
        monotonic_seconds: u64,
    ) -> Result<Vec<u8>, MobileError> {
        if !matches!(record, Record::Control(_)) {
            return Err(MobileError::InvalidInput);
        }
        let State::Transport(transport) = &mut self.state else {
            return Err(MobileError::InvalidState);
        };
        if transport.hard_expired(monotonic_seconds) {
            return Err(WireError::RekeyRequired.into());
        }
        Ok(transport.encode(record)?)
    }

    /// Authenticates one link frame. Raw link IP records are rejected; only an
    /// end-to-end `Opaque(Session)` may produce a tunnel packet.
    ///
    /// # Errors
    /// Returns an error on link/session authentication or signed-state failure.
    pub fn decrypt(
        &mut self,
        frame: &[u8],
        monotonic_seconds: u64,
    ) -> Result<(Record, Option<AcceptedUpdate>), MobileError> {
        let State::Transport(transport) = &mut self.state else {
            return Err(MobileError::InvalidState);
        };
        if transport.hard_expired(monotonic_seconds) {
            return Err(WireError::RekeyRequired.into());
        }
        let Record::Control(envelope) = transport.decode(frame)? else {
            return Err(MobileError::InvalidInput);
        };
        if let Some(ControlMessage::Opaque(opaque)) = &envelope.message {
            if let Some(owner) = &self.wireguard {
                if opaque.major != PROTOCOL_MAJOR
                    || opaque.mesh_id != self.trust.mesh_id.as_bytes()
                    || opaque.destination_peer != self.local_peer.as_bytes()
                    || opaque.kind != OpaqueFrameKind::Session as i32 {
                    return Err(MobileError::InvalidInput);
                }
                let source = PeerId::from_uuid(Uuid::from_slice(&opaque.source_peer)
                    .map_err(|_| MobileError::InvalidInput)?)
                    .map_err(|_| MobileError::InvalidInput)?;
                let _ = owner.lock().map_err(|_| MobileError::InvalidState)?.receive(
                    peerward_peer_core::WireguardIngress::Relay(source), &opaque.opaque,
                    UnixTime(wall_clock_seconds()), std::time::Instant::now(),
                );
                // Malformed end-to-end data must not tear down an authenticated Relay link.
                return Ok((Record::Control(envelope), Some(AcceptedUpdate::Control)));
            }
            return Err(MobileError::InvalidState);
        }
        let update = self.apply_control(&envelope)?;
        Ok((Record::Control(envelope), Some(update)))
    }

}
