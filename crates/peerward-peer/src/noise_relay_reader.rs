#[async_trait]
impl PacketReceiver for NoiseRelayReceiver {
    async fn receive_packet(&mut self) -> Result<(DataPath, Vec<u8>), PacketPumpError> {
        loop {
            if self.pending_control.is_some() {
                // Reserving capacity leaves the message owned by this receiver if
                // another select! branch wins while the control queue is full.
                let permit = self
                    .controls
                    .reserve()
                    .await
                    .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
                permit.send(
                    self.pending_control
                        .take()
                        .expect("pending control message"),
                );
            }
            while self.frame_read < self.frame.len() {
                // read is cancellation-safe; read_exact/read_u32 lose partial
                // progress when the surrounding receive future is dropped.
                let count = self.reader.read(&mut self.frame[self.frame_read..]).await?;
                if count == 0 {
                    return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
                }
                self.frame_read += count;
            }
            if self.frame.len() == 4 {
                let length =
                    u32::from_be_bytes(self.frame[..4].try_into().expect("complete header"));
                if length == 0 || length > 65_535 {
                    return Err(peerward_wire::WireError::InvalidLength.into());
                }
                self.frame.resize(4 + length as usize, 0);
                continue;
            }
            // Keep the completed frame until the Noise lock is acquired too.
            let record = self.transport.lock().await.decode(&self.frame)?;
            self.frame.resize(4, 0);
            self.frame_read = 0;
            match record {
                Record::Ipv4(_) | Record::Ipv6(_) => return Err(PacketPumpError::InvalidControl),
                Record::Control(control) => self.pending_control = Some(control),
            }
        }
    }
}
