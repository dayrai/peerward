/// Maximum opaque body routed by a Relay. The bound includes an end-to-end tag.
pub const MAX_OPAQUE_FRAME_LEN: usize = 65_535;

/// Purpose of an opaque Relay payload. Relays may use this only for resource limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
pub enum OpaqueFrameKind {
    /// An unmodified standard `WireGuard` datagram.
    Session = 1,
    /// HPKE-sealed audit material addressed to Control.
    Audit = 2,
}

/// The only peer payload a Wire 5 Relay routes. IP packets never appear in this envelope.
#[derive(Clone, PartialEq, Message)]
pub struct RelayEnvelopeV2 {
    /// Exact wire major; must be [`PROTOCOL_MAJOR`].
    #[prost(uint32, tag = "1")]
    pub major: u32,
    /// Raw 16-byte Mesh UUID.
    #[prost(bytes = "vec", tag = "2")]
    pub mesh_id: Vec<u8>,
    /// Raw 16-byte destination Peer UUID.
    #[prost(bytes = "vec", tag = "3")]
    pub destination_peer: Vec<u8>,
    /// Raw 16-byte source Peer UUID, overwritten by the authenticated Relay link.
    #[prost(bytes = "vec", tag = "4")]
    pub source_peer: Vec<u8>,
    /// Resource-class hint; it does not reveal the inner protocol.
    #[prost(enumeration = "OpaqueFrameKind", tag = "5")]
    pub kind: i32,
    /// End-to-end encrypted bytes.
    #[prost(bytes = "vec", tag = "6")]
    pub opaque: Vec<u8>,
}

impl RelayEnvelopeV2 {
    /// Validates an unbound envelope received from an authenticated Peer link.
    pub fn validate_from_peer(&self) -> Result<(), WireError> {
        if !self.source_peer.is_empty() {
            return Err(WireError::KindMismatch);
        }
        self.validate_common()
    }

    /// Validates only the routing metadata a Relay is permitted to inspect.
    pub fn validate_for_relay(&self) -> Result<(), WireError> {
        if self.source_peer.len() != 16 {
            return Err(WireError::KindMismatch);
        }
        self.validate_common()
    }

    fn validate_common(&self) -> Result<(), WireError> {
        if self.major != PROTOCOL_MAJOR {
            return Err(WireError::UnsupportedMajor);
        }
        if self.mesh_id.len() != 16 || self.destination_peer.len() != 16 {
            return Err(WireError::KindMismatch);
        }
        if OpaqueFrameKind::try_from(self.kind).is_err()
            || self.opaque.is_empty()
            || self.opaque.len() > MAX_OPAQUE_FRAME_LEN
        {
            return Err(WireError::InvalidLength);
        }
        Ok(())
    }

    /// Replaces caller-controlled source metadata with the authenticated identity.
    pub fn bind_authenticated_source(&mut self, source_peer: [u8; 16]) {
        self.source_peer = source_peer.to_vec();
    }
}
