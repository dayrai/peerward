/// Plaintext record before Noise encryption or after Noise authentication.
#[derive(Debug, Clone, PartialEq)]
pub enum Record {
    /// A typed Prost control envelope.
    Control(ControlEnvelope),
    /// One complete IPv4 packet.
    Ipv4(Vec<u8>),
    /// One complete IPv6 packet.
    Ipv6(Vec<u8>),
}

impl Record {
    fn encode_plaintext(&self) -> Result<Vec<u8>, WireError> {
        let body_len = match self {
            Self::Control(envelope) => envelope.encoded_len(),
            Self::Ipv4(packet) | Self::Ipv6(packet) => packet.len(),
        };
        let length = body_len.checked_add(4).ok_or(WireError::InvalidLength)?;
        // Bound allocation before copying a caller-owned body or touching the Noise nonce.
        if length > MAX_CIPHERTEXT_LEN - 16 {
            return Err(WireError::InvalidLength);
        }
        let mut output = Vec::with_capacity(length);
        match self {
            Self::Control(envelope) => {
                output.extend_from_slice(&1_u16.to_be_bytes());
                output.extend_from_slice(&0_u16.to_be_bytes());
                envelope
                    .encode(&mut output)
                    .expect("Vec writes cannot fail");
            }
            Self::Ipv4(packet) => {
                output.extend_from_slice(&2_u16.to_be_bytes());
                output.extend_from_slice(&0_u16.to_be_bytes());
                output.extend_from_slice(packet);
            }
            Self::Ipv6(packet) => {
                output.extend_from_slice(&3_u16.to_be_bytes());
                output.extend_from_slice(&0_u16.to_be_bytes());
                output.extend_from_slice(packet);
            }
        }
        Ok(output)
    }

    fn decode_plaintext(plaintext: &[u8]) -> Result<Self, WireError> {
        if plaintext.len() < 4 {
            return Err(WireError::Truncated);
        }
        let kind = u16::from_be_bytes([plaintext[0], plaintext[1]]);
        let flags = u16::from_be_bytes([plaintext[2], plaintext[3]]);
        if flags != 0 {
            return Err(WireError::Unsupported);
        }
        let payload = &plaintext[4..];
        match kind {
            1 => {
                let envelope = ControlEnvelope::decode(payload)?;
                if envelope.message.is_none() {
                    return Err(WireError::KindMismatch);
                }
                if envelope.encode_to_vec() != payload {
                    return Err(WireError::TrailingBytes);
                }
                Ok(Self::Control(envelope))
            }
            2 if !payload.is_empty() && payload[0] >> 4 == 4 => Ok(Self::Ipv4(payload.to_vec())),
            3 if !payload.is_empty() && payload[0] >> 4 == 6 => Ok(Self::Ipv6(payload.to_vec())),
            2 | 3 => Err(WireError::KindMismatch),
            _ => Err(WireError::Unsupported),
        }
    }
}

/// A post-handshake Noise stream transport.
pub struct StreamTransport {
    noise: TransportState,
    sent: u64,
    received: u64,
    epoch_started: u64,
}

impl StreamTransport {
    /// Wraps a completed Noise handshake.
    pub fn from_handshake(
        handshake: HandshakeState,
        monotonic_seconds: u64,
    ) -> Result<Self, WireError> {
        Ok(Self {
            noise: handshake.into_transport_mode()?,
            sent: 0,
            received: 0,
            epoch_started: monotonic_seconds,
        })
    }

    /// Returns whether the key epoch reached its message or time limit.
    pub fn rekey_due(&self, monotonic_seconds: u64) -> bool {
        self.sent.max(self.received) >= REKEY_MESSAGES
            || monotonic_seconds.saturating_sub(self.epoch_started) >= REKEY_SECONDS
    }

    /// Returns true when this link has reached the non-negotiable hard key bound.
    pub fn hard_expired(&self, monotonic_seconds: u64) -> bool {
        self.sent.max(self.received) >= REKEY_HARD_MESSAGES
            || monotonic_seconds.saturating_sub(self.epoch_started) >= REKEY_HARD_SECONDS
    }

    /// Encrypts and length-prefixes one bounded record.
    pub fn encode(&mut self, record: &Record) -> Result<Vec<u8>, WireError> {
        if self.sent >= REKEY_HARD_MESSAGES {
            return Err(WireError::RekeyRequired);
        }
        let plaintext = record.encode_plaintext()?;
        let mut ciphertext = vec![0; plaintext.len() + 16];
        let count = self.noise.write_message(&plaintext, &mut ciphertext)?;
        ciphertext.truncate(count);
        if ciphertext.is_empty() || ciphertext.len() > MAX_CIPHERTEXT_LEN {
            return Err(WireError::InvalidLength);
        }
        self.sent = self
            .sent
            .checked_add(1)
            .ok_or(WireError::SequenceExhausted)?;
        let mut frame = Vec::with_capacity(4 + ciphertext.len());
        let wire_length = u32::try_from(ciphertext.len()).map_err(|_| WireError::InvalidLength)?;
        frame.extend_from_slice(&wire_length.to_be_bytes());
        frame.extend_from_slice(&ciphertext);
        Ok(frame)
    }

    /// Authenticates and decodes exactly one length-prefixed record.
    pub fn decode(&mut self, frame: &[u8]) -> Result<Record, WireError> {
        if self.received >= REKEY_HARD_MESSAGES {
            return Err(WireError::RekeyRequired);
        }
        if frame.len() < 4 {
            return Err(WireError::Truncated);
        }
        let length = u32::from_be_bytes(frame[..4].try_into().expect("four-byte prefix")) as usize;
        if length == 0 || length > MAX_CIPHERTEXT_LEN {
            return Err(WireError::InvalidLength);
        }
        let expected = 4_usize
            .checked_add(length)
            .ok_or(WireError::InvalidLength)?;
        if frame.len() < expected {
            return Err(WireError::Truncated);
        }
        if frame.len() > expected {
            return Err(WireError::TrailingBytes);
        }
        let mut plaintext = vec![0; length];
        let count = self.noise.read_message(&frame[4..], &mut plaintext)?;
        plaintext.truncate(count);
        self.received = self
            .received
            .checked_add(1)
            .ok_or(WireError::SequenceExhausted)?;
        Record::decode_plaintext(&plaintext)
    }
}
