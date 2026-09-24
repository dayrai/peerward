/// Only Wire major accepted by the current Peerward release.
pub const PROTOCOL_MAJOR: u32 = 5;
/// Retained carrier-format v4 prologue; the authenticated payload independently requires Wire 5.
pub const NOISE_PROLOGUE: &[u8] = b"peerward/noise/v4";
/// Peer-to-relay Noise suite.
pub const IK_SUITE: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
/// Relay-to-relay Noise suite.
pub const KK_SUITE: &str = "Noise_KK_25519_ChaChaPoly_BLAKE2s";
/// Largest encrypted stream record.
pub const MAX_CIPHERTEXT_LEN: usize = 65_535;
/// Soft replacement interval in messages.
pub const REKEY_MESSAGES: u64 = 1 << 19;
/// Hard per-key message limit.
pub const REKEY_HARD_MESSAGES: u64 = 1 << 20;
/// Soft replacement interval in monotonic seconds.
pub const REKEY_SECONDS: u64 = 45 * 60;
/// Hard per-key lifetime in monotonic seconds.
pub const REKEY_HARD_SECONDS: u64 = 60 * 60;

/// Wire-level validation or cryptographic error.
#[derive(Debug, Error)]
pub enum WireError {
    /// Noise state creation or processing failed.
    #[error("noise protocol error")]
    Noise(#[from] snow::Error),
    /// A cryptographic authentication tag failed.
    #[error("datagram authentication failed")]
    Authentication,
    /// A frame is incomplete.
    #[error("truncated record")]
    Truncated,
    /// A frame has bytes beyond its declared boundary.
    #[error("record has trailing bytes")]
    TrailingBytes,
    /// The record length is zero or above the protocol bound.
    #[error("invalid ciphertext length")]
    InvalidLength,
    /// A record kind or flag is not supported.
    #[error("unsupported record kind or critical flag")]
    Unsupported,
    /// Payload does not match its record kind.
    #[error("record payload does not match kind")]
    KindMismatch,
    /// Prost control data is malformed.
    #[error("malformed control envelope")]
    MalformedControl(#[from] prost::DecodeError),
    /// The protocol major version is unsupported.
    #[error("unsupported protocol major")]
    UnsupportedMajor,
    /// The reliable Relay record counter cannot be incremented.
    #[error("packet sequence exhausted")]
    SequenceExhausted,
    /// A fresh authenticated session must replace the current key epoch.
    #[error("authenticated session replacement required")]
    RekeyRequired,
}

/// Handshake application payload mixed into Noise authentication.
#[derive(Clone, PartialEq, Message)]
pub struct HandshakePayload {
    /// Protocol major, exactly [`PROTOCOL_MAJOR`].
    #[prost(uint32, tag = "1")]
    pub major: u32,
    /// Backward-compatible protocol minor.
    #[prost(uint32, tag = "2")]
    pub minor: u32,
    /// Capability bitset.
    #[prost(uint64, tag = "3")]
    pub capabilities: u64,
    /// Typed credential encoded by the credential layer.
    #[prost(bytes = "vec", tag = "4")]
    pub credential: Vec<u8>,
    /// Raw 16-byte attachment UUID.
    #[prost(bytes = "vec", tag = "5")]
    pub attachment_id: Vec<u8>,
}

impl HandshakePayload {
    /// Checks the mandatory Wire 5 fields and computes capability intersection.
    pub fn negotiate(&self, local_capabilities: u64) -> Result<u64, WireError> {
        if self.major != PROTOCOL_MAJOR {
            return Err(WireError::UnsupportedMajor);
        }
        if self.attachment_id.len() != 16 || self.credential.is_empty() {
            return Err(WireError::KindMismatch);
        }
        Ok(self.capabilities & local_capabilities)
    }
}

/// Builds an IK initiator state with the fixed Wire 4 Relay prologue.
pub fn ik_initiator(
    local_private: &[u8; 32],
    remote_public: &[u8; 32],
) -> Result<HandshakeState, WireError> {
    build_handshake(IK_SUITE, true, local_private, Some(remote_public))
}

/// Builds an IK responder state with the fixed Wire 4 Relay prologue.
pub fn ik_responder(local_private: &[u8; 32]) -> Result<HandshakeState, WireError> {
    build_handshake(IK_SUITE, false, local_private, None)
}

/// Builds one side of a KK relay link with both static identities configured.
pub fn kk_handshake(
    initiator: bool,
    local_private: &[u8; 32],
    remote_public: &[u8; 32],
) -> Result<HandshakeState, WireError> {
    build_handshake(KK_SUITE, initiator, local_private, Some(remote_public))
}

fn build_handshake(
    suite: &str,
    initiator: bool,
    local_private: &[u8; 32],
    remote_public: Option<&[u8; 32]>,
) -> Result<HandshakeState, WireError> {
    build_handshake_with_prologue(
        suite,
        initiator,
        local_private,
        remote_public,
        NOISE_PROLOGUE,
    )
}

fn build_handshake_with_prologue(
    suite: &str,
    initiator: bool,
    local_private: &[u8; 32],
    remote_public: Option<&[u8; 32]>,
    prologue: &[u8],
) -> Result<HandshakeState, WireError> {
    let params: NoiseParams = suite.parse().map_err(WireError::Noise)?;
    let mut builder = Builder::new(params)
        .prologue(prologue)?
        .local_private_key(local_private)?;
    if let Some(public) = remote_public {
        builder = builder.remote_public_key(public)?;
    }
    if initiator {
        Ok(builder.build_initiator()?)
    } else {
        Ok(builder.build_responder()?)
    }
}
