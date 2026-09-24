//! Application record codec. Local mode exists only behind an authenticated
//! QUIC bridge; its frames are process-local and are never accepted from UDP.
use peerward_wire::{
    ControlEnvelope, REKEY_HARD_MESSAGES, REKEY_HARD_SECONDS, REKEY_MESSAGES, REKEY_SECONDS,
    Record, StreamTransport, WireError,
};
use prost::Message;

pub struct RecordTransport {
    noise: Option<Box<StreamTransport>>,
    sent: u64,
    received: u64,
    epoch: u64,
    frame: Vec<u8>,
    frame_read: usize,
}
impl RecordTransport {
    pub fn from_handshake(handshake: snow::HandshakeState, now: u64) -> Result<Self, WireError> {
        Ok(Self::from(StreamTransport::from_handshake(handshake, now)?))
    }
    pub(crate) fn local(now: u64) -> Self {
        Self {
            noise: None,
            sent: 0,
            received: 0,
            epoch: now,
            frame: vec![0; 4],
            frame_read: 0,
        }
    }
    pub(crate) fn into_noise(self) -> Result<StreamTransport, WireError> {
        self.noise
            .map(|noise| *noise)
            .ok_or(WireError::KindMismatch)
    }
    pub fn rekey_due(&self, now: u64) -> bool {
        self.noise.as_ref().map_or_else(
            || {
                self.sent.max(self.received) >= REKEY_MESSAGES
                    || now.saturating_sub(self.epoch) >= REKEY_SECONDS
            },
            |noise| noise.rekey_due(now),
        )
    }
    pub fn hard_expired(&self, now: u64) -> bool {
        self.noise.as_ref().map_or_else(
            || {
                self.sent.max(self.received) >= REKEY_HARD_MESSAGES
                    || now.saturating_sub(self.epoch) >= REKEY_HARD_SECONDS
            },
            |noise| noise.hard_expired(now),
        )
    }
    pub fn encode(&mut self, record: &Record) -> Result<Vec<u8>, WireError> {
        if let Some(noise) = &mut self.noise {
            return noise.encode(record);
        }
        if self.sent >= REKEY_HARD_MESSAGES {
            return Err(WireError::RekeyRequired);
        }
        let frame = encode_local(record)?;
        self.sent += 1;
        Ok(frame)
    }
    pub fn decode(&mut self, frame: &[u8]) -> Result<Record, WireError> {
        if let Some(noise) = &mut self.noise {
            return noise.decode(frame);
        }
        if self.received >= REKEY_HARD_MESSAGES {
            return Err(WireError::RekeyRequired);
        }
        let record = decode_local(frame)?;
        self.received += 1;
        Ok(record)
    }

    /// Keeps prefix/body progress in the connection across select/timeouts.
    /// Decode the returned complete frame synchronously before another await.
    pub async fn read_frame(
        &mut self,
        socket: &mut (impl tokio::io::AsyncRead + Unpin + ?Sized),
    ) -> std::io::Result<Vec<u8>> {
        use tokio::io::AsyncReadExt as _;
        loop {
            if self.frame_read == self.frame.len() {
                if self.frame.len() == 4 {
                    let length =
                        u32::from_be_bytes(self.frame[..4].try_into().expect("prefix")) as usize;
                    if length == 0 || length > 65_535 {
                        return Err(super::invalid("invalid Relay record length"));
                    }
                    self.frame.resize(length + 4, 0);
                } else {
                    self.frame_read = 0;
                    return Ok(std::mem::replace(&mut self.frame, vec![0; 4]));
                }
            }
            let count = socket.read(&mut self.frame[self.frame_read..]).await?;
            if count == 0 {
                return Err(std::io::ErrorKind::UnexpectedEof.into());
            }
            self.frame_read += count;
        }
    }
}
impl From<StreamTransport> for RecordTransport {
    fn from(noise: StreamTransport) -> Self {
        Self {
            noise: Some(Box::new(noise)),
            sent: 0,
            received: 0,
            epoch: 0,
            frame: vec![0; 4],
            frame_read: 0,
        }
    }
}

pub(crate) fn decode_local(frame: &[u8]) -> Result<Record, WireError> {
    if frame.len() < 9 || frame.len() > 65_539 {
        return Err(WireError::InvalidLength);
    }
    let length = u32::from_be_bytes(frame[..4].try_into().expect("checked prefix")) as usize;
    if length + 4 != frame.len() || &frame[4..8] != b"PWLC" {
        return Err(WireError::KindMismatch);
    }
    let envelope = ControlEnvelope::decode(&frame[8..])?;
    if envelope.message.is_none() || envelope.encode_to_vec() != frame[8..] {
        return Err(WireError::KindMismatch);
    }
    Ok(Record::Control(envelope))
}

pub(crate) fn encode_local(record: &Record) -> Result<Vec<u8>, WireError> {
    let Record::Control(envelope) = record else {
        return Err(WireError::KindMismatch);
    };
    let bytes = envelope.encode_to_vec();
    let length = bytes.len() + 4;
    if envelope.message.is_none() || length > 65_535 {
        return Err(WireError::InvalidLength);
    }
    let mut frame = Vec::with_capacity(length + 4);
    frame.extend_from_slice(
        &u32::try_from(length)
            .map_err(|_| WireError::InvalidLength)?
            .to_be_bytes(),
    );
    frame.extend_from_slice(b"PWLC");
    frame.extend_from_slice(&bytes);
    Ok(frame)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt as _;

    #[tokio::test]
    async fn cancelled_prefix_and_body_reads_preserve_every_byte_and_next_record() {
        let record = Record::Control(ControlEnvelope {
            trace_context: None,
            message: Some(peerward_wire::control_envelope::Message::Keepalive(
                peerward_wire::Keepalive {
                    monotonic_timestamp: 123,
                },
            )),
        });
        let encoded = encode_local(&record).unwrap();
        for split in 1..encoded.len() {
            let (mut writer, mut socket) = tokio::io::duplex(128);
            let mut transport = RecordTransport::local(0);
            writer.write_all(&encoded[..split]).await.unwrap();
            assert!(
                tokio::time::timeout(
                    std::time::Duration::from_millis(2),
                    transport.read_frame(&mut socket)
                )
                .await
                .is_err()
            );
            writer.write_all(&encoded[split..]).await.unwrap();
            writer.write_all(&encoded).await.unwrap();
            for _ in 0..2 {
                let frame = transport.read_frame(&mut socket).await.unwrap();
                assert_eq!(frame, encoded);
                assert!(matches!(
                    transport.decode(&frame).unwrap(),
                    Record::Control(_)
                ));
            }
        }
    }
}
