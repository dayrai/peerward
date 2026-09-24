impl QuicLink {
    pub fn stats(&self) -> DatagramStats {
        self.stats
    }
    pub fn rekey_due(&self) -> bool {
        self.transport.rekey_due(self.now())
    }
    fn now(&self) -> u64 {
        self.epoch.saturating_add(self.started.elapsed().as_secs())
    }
    fn current(&mut self) -> io::Result<()> {
        self.reassembly.expire(Instant::now());
        if self.write_in_progress
            || self.transport.hard_expired(self.now())
            || self.owner.connection.close_reason().is_some()
        {
            self.close();
            return Err(io::Error::from(io::ErrorKind::ConnectionAborted));
        }
        Ok(())
    }
    /// Call immediately on trusted revocation/deletion or failed forwarding fence.
    pub fn close(&mut self) {
        self.owner.connection.close(0_u8.into(), b"admission ended");
        self.reassembly.clear();
    }
    /// Rechecks mesh and source shape. Peer identity binding, leases, ACL and
    /// routed-backbone metadata remain the caller's existing authorization work.
    fn validate_opaque(&self, frame: &RelayEnvelopeV2, outgoing: bool) -> io::Result<()> {
        let from_peer = self.preface.source.is_none()
            && (self.owner.connection.side() == quinn::Side::Client) == outgoing;
        if from_peer {
            frame.validate_from_peer()
        } else {
            frame.validate_for_relay()
        }
        .map_err(io::Error::other)?;
        if frame.mesh_id != self.preface.mesh_id.as_bytes()
            || frame.kind != OpaqueFrameKind::Session as i32
        {
            return Err(invalid(
                "QUIC DATAGRAM requires this Mesh's WireGuard envelope",
            ));
        }
        Ok(())
    }
    /// Non-blocking, whole-frame payload budget check. If capacity runs out
    /// while adding fragment overhead, abandon the remainder; the receiver's
    /// bounded reassembly expires any incomplete frame. Never queues plaintext.
    pub fn send_opaque(&mut self, envelope: &RelayEnvelopeV2) -> io::Result<bool> {
        self.send_datagram_control(&ControlEnvelope {
            trace_context: None,
            message: Some(ControlMessage::Opaque(envelope.clone())),
        })
    }
    pub fn send_datagram_control(&mut self, envelope: &ControlEnvelope) -> io::Result<bool> {
        use futures_util::FutureExt as _;
        self.current()?;
        self.validate_data(envelope, true)?;
        let id = self.next_id;
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or_else(|| invalid("QUIC frame IDs exhausted"))?;
        let limit = self
            .owner
            .connection
            .max_datagram_size()
            .ok_or_else(|| invalid("DATAGRAM unavailable"))?;
        let parts = fragments::split(
            id,
            &envelope.encode_to_vec(),
            limit.saturating_sub(TOKEN_LEN),
        )?;
        let total: usize = parts.iter().map(|part| part.len() + TOKEN_LEN).sum();
        if total > self.owner.connection.datagram_send_buffer_space() {
            self.stats.dropped_frames += 1;
            return Ok(false);
        }
        for part in parts {
            let mut bytes = self.send_token.to_vec();
            bytes.extend_from_slice(&part);
            // Poll the non-evicting API once: never await capacity, and never
            // discard fragments of an older queued frame. quinn-proto 0.11.17's
            // dropping API counts payload space separately from per-datagram
            // memory and double-debits evicted bytes, poisoning the queue.
            match self
                .owner
                .connection
                .send_datagram_wait(Bytes::from(bytes))
                .now_or_never()
            {
                Some(Ok(())) => {}
                None => {
                    self.stats.dropped_frames += 1;
                    return Ok(false);
                }
                Some(Err(error)) => {
                    self.close();
                    return Err(io::Error::other(error));
                }
            }
            self.stats.sent_fragments += 1;
        }
        self.stats.sent_frames += 1;
        Ok(true)
    }
    pub async fn send_control(&mut self, envelope: ControlEnvelope) -> io::Result<()> {
        self.current()?;
        validate_control(&envelope)?;
        self.sent_control = self
            .sent_control
            .checked_add(1)
            .ok_or_else(|| invalid("control sequence exhausted"))?;
        let envelope = wrap_control(self.preface, self.sent_control, &envelope);
        self.write_control_record(envelope).await
    }
    pub fn sent_control(&self) -> u64 {
        self.sent_control
    }
    pub fn received_control(&self) -> u64 {
        self.received_control
    }
    pub async fn acknowledge(&mut self, sequence: u64) -> io::Result<()> {
        self.current()?;
        let mut body = b"quic_receipt_v1\0".to_vec();
        body.extend_from_slice(&sequence.to_be_bytes());
        self.write_control_record(ControlEnvelope {
            trace_context: None,
            message: Some(ControlMessage::Welcome(Welcome {
                mesh_id: self.preface.mesh_id.as_bytes().to_vec(),
                body,
            })),
        })
        .await
    }
    pub async fn heartbeat(&mut self, sequence: u64, response: bool) -> io::Result<()> {
        self.current()?;
        let mut body = if response {
            b"quic_pong_v1\0".to_vec()
        } else {
            b"quic_ping_v1\0".to_vec()
        };
        body.extend_from_slice(&sequence.to_be_bytes());
        self.write_control_record(ControlEnvelope {
            trace_context: None,
            message: Some(ControlMessage::Welcome(Welcome {
                mesh_id: self.preface.mesh_id.as_bytes().to_vec(),
                body,
            })),
        })
        .await
    }
    async fn write_control_record(&mut self, envelope: ControlEnvelope) -> io::Result<()> {
        let frame = match self.transport.encode(&Record::Control(envelope)) {
            Ok(frame) => frame,
            Err(error) => {
                self.close();
                return Err(io::Error::other(error));
            }
        };
        // Cancellation keeps this flag set; the next operation closes the link
        // instead of sending a new Noise record after a partially written one.
        self.write_in_progress = true;
        let result = tokio::time::timeout(IO_TIMEOUT, async {
            self.control.write_all(&frame).await?;
            self.control.flush().await
        })
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))
        .and_then(|value| value);
        if result.is_err() {
            self.close();
        } else {
            self.write_in_progress = false;
        }
        result
    }
    /// Cancellation-safe between select! polls: partial reliable records and
    /// incomplete datagrams remain owned by this link. Controls are never
    /// decoded from DATAGRAM, and missing fragments do not stall this stream.
    pub async fn receive(&mut self) -> io::Result<Received> {
        self.receive_with_data(true).await
    }
    pub(super) async fn receive_with_data(&mut self, datagrams: bool) -> io::Result<Received> {
        let result = self.receive_inner(datagrams).await;
        if result.is_err() {
            self.close();
        }
        result
    }
    async fn receive_inner(&mut self, datagrams: bool) -> io::Result<Received> {
        let mut operations = 0_u8;
        loop {
            // An admitted peer flooding malformed DATAGRAMs must still yield
            // the executor to other Meshes, revocation work and cancellation.
            operations += 1;
            if operations == 32 {
                operations = 0;
                tokio::task::yield_now().await;
            }
            self.current()?;
            tokio::select! {
                read = self.control.read(&mut self.frame[self.frame_read..]) => {
                    let size = read?;
                    if size == 0 { return Err(io::Error::from(io::ErrorKind::UnexpectedEof)); }
                    self.frame_read += size;
                    if self.frame_read != self.frame.len() { continue; }
                    if self.frame.len() == 4 {
                        let length = u32::from_be_bytes(self.frame[..4].try_into().expect("prefix")) as usize;
                        if length == 0 || length > fragments::MAX_FRAME { return Err(invalid("invalid QUIC control record length")); }
                        self.frame.resize(4 + length, 0);
                        continue;
                    }
                    let record = self.transport.decode(&self.frame).map_err(io::Error::other)?;
                    self.frame.resize(4, 0); self.frame_read = 0;
                    let Record::Control(control) = record else { return Err(invalid("raw IP forbidden on Relay link")); };
                    return self.unwrap_control(control);
                }
                bytes = self.owner.connection.read_datagram(), if datagrams => {
                    let bytes = bytes.map_err(io::Error::other)?;
                    self.stats.received_fragments += 1;
                    if bytes.len() <= TOKEN_LEN || bytes[..TOKEN_LEN] != self.receive_token {
                        self.stats.malformed_fragments += 1; continue;
                    }
                    let Ok(complete) = self.reassembly.push(&bytes[TOKEN_LEN..], Instant::now()) else {
                        self.stats.malformed_fragments += 1; continue;
                    };
                    let Some(bytes) = complete else { continue; };
                    let frame = ControlEnvelope::decode(bytes.as_slice()).map_err(io::Error::other)?;
                    if frame.encode_to_vec() != bytes { return Err(invalid("noncanonical QUIC envelope")); }
                    self.validate_data(&frame, false)?;
                    self.stats.received_frames += 1;
                    return Ok(match frame.message {
                        Some(ControlMessage::Opaque(opaque)) if frame.trace_context.is_none() => Received::Opaque(opaque),
                        _ => Received::Datagram(frame),
                    });
                }
                _ = self.sweep.tick() => self.reassembly.expire(Instant::now()),
            }
        }
    }
}
fn validate_control(envelope: &ControlEnvelope) -> io::Result<()> {
    if envelope.message.is_none() || super::quic_data::opaque(envelope)?.is_some() {
        return Err(invalid("WireGuard envelopes must use QUIC DATAGRAM"));
    }
    Ok(())
}

fn wrap_control(
    preface: RelayPreface,
    sequence: u64,
    envelope: &ControlEnvelope,
) -> ControlEnvelope {
    let mut body = b"quic_record_v1\0".to_vec();
    body.extend_from_slice(&sequence.to_be_bytes());
    body.extend_from_slice(&envelope.encode_to_vec());
    ControlEnvelope {
        trace_context: None,
        message: Some(ControlMessage::Welcome(Welcome {
            mesh_id: preface.mesh_id.as_bytes().to_vec(),
            body,
        })),
    }
}
impl QuicLink {
    fn validate_data(&self, control: &ControlEnvelope, outgoing: bool) -> io::Result<()> {
        if matches!(control.message, Some(ControlMessage::Forwarded(_)))
            && self.preface.source.is_none()
        {
            return Err(invalid("Peer may not send backbone datagrams"));
        }
        let frame = super::quic_data::opaque(control)?
            .ok_or_else(|| invalid("control forbidden in QUIC DATAGRAM"))?;
        self.validate_opaque(&frame, outgoing)
    }
    fn unwrap_control(&mut self, control: ControlEnvelope) -> io::Result<Received> {
        let Some(ControlMessage::Welcome(Welcome { mesh_id, body })) = control.message else {
            return Err(invalid("missing QUIC record wrapper"));
        };
        if mesh_id != self.preface.mesh_id.as_bytes() || control.trace_context.is_some() {
            return Err(invalid("invalid QUIC control Mesh"));
        }
        for (prefix, response) in [(b"quic_ping_v1\0", false), (b"quic_pong_v1\0", true)] {
            if let Some(payload) = body.strip_prefix(prefix) {
                let bytes: [u8; 8] = payload
                    .try_into()
                    .map_err(|_| invalid("invalid QUIC heartbeat"))?;
                let sequence = u64::from_be_bytes(bytes);
                if sequence == 0 {
                    return Err(invalid("invalid QUIC heartbeat sequence"));
                }
                return Ok(if response {
                    Received::Pong(sequence)
                } else {
                    Received::Ping(sequence)
                });
            }
        }
        if let Some(body) = body.strip_prefix(b"quic_receipt_v1\0") {
            if body.len() != 8 {
                return Err(invalid("invalid QUIC receipt"));
            }
            let sequence = u64::from_be_bytes(body.try_into().expect("receipt"));
            if sequence <= self.acknowledged_control || sequence > self.sent_control {
                return Err(invalid("unexpected QUIC receipt"));
            }
            self.acknowledged_control = sequence;
            return Ok(Received::Acknowledged(sequence));
        }
        let body = body
            .strip_prefix(b"quic_record_v1\0")
            .ok_or_else(|| invalid("invalid QUIC control kind"))?;
        if body.len() <= 8 {
            return Err(invalid("truncated QUIC control"));
        }
        let sequence = u64::from_be_bytes(body[..8].try_into().expect("control sequence"));
        if self.received_control.checked_add(1) != Some(sequence) {
            return Err(invalid("invalid QUIC control sequence"));
        }
        let control = ControlEnvelope::decode(&body[8..]).map_err(io::Error::other)?;
        if control.encode_to_vec() != body[8..] {
            return Err(invalid("noncanonical QUIC control"));
        }
        validate_control(&control)?;
        self.received_control = sequence;
        Ok(Received::Control(control))
    }
}

impl Drop for QuicLink {
    fn drop(&mut self) {
        tracing::info!(mesh_id = %self.preface.mesh_id, backbone = self.preface.source.is_some(),
            sent_frames = self.stats.sent_frames, received_frames = self.stats.received_frames,
            sent_fragments = self.stats.sent_fragments, received_fragments = self.stats.received_fragments,
            dropped_frames = self.stats.dropped_frames, malformed_fragments = self.stats.malformed_fragments,
            "QUIC DATAGRAM connection retired");
    }
}
