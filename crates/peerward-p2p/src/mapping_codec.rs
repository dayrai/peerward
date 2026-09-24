/// Fixed-size `PCP` MAP request that can be transported by a platform-owned UDP socket.
#[derive(Debug, Clone)]
pub struct PcpMappingRequest {
    internal: SocketAddr,
    lifetime_seconds: u32,
    nonce: [u8; 12],
    bytes: [u8; 60],
}

impl PcpMappingRequest {
    /// Creates a fresh request, or a renewal/deletion retaining an existing nonce.
    pub fn new(
        internal: SocketAddr,
        lifetime_seconds: u32,
        nonce: Option<[u8; 12]>,
    ) -> Result<Self, P2pError> {
        if internal.port() == 0 || internal.ip().is_unspecified() {
            return Err(P2pError::Mapping);
        }
        let mut nonce = nonce.unwrap_or([0; 12]);
        if nonce.iter().all(|byte| *byte == 0) {
            OsRng.fill_bytes(&mut nonce);
        }
        Ok(Self {
            internal,
            lifetime_seconds,
            nonce,
            bytes: encode_pcp_map(internal, lifetime_seconds, nonce),
        })
    }

    /// Retains the assigned external endpoint during renewal. Deletion does not
    /// request an external endpoint; its mapping identity is internal tuple + nonce.
    #[must_use]
    pub fn suggest_external(mut self, external: SocketAddr) -> Self {
        if self.lifetime_seconds != 0 {
            self.bytes[42..44].copy_from_slice(&external.port().to_be_bytes());
            self.bytes[44..60].copy_from_slice(&ipv6_bytes(external.ip()));
        }
        self
    }

    /// Encoded RFC 6887 request.
    #[must_use]
    pub const fn bytes(&self) -> &[u8; 60] {
        &self.bytes
    }

    /// Request nonce retained across renewals and deletion.
    #[must_use]
    pub const fn nonce(&self) -> [u8; 12] {
        self.nonce
    }

    /// Accepts only the exact nonce, protocol, internal port, and bounded response shape.
    pub fn accept(&self, response: &[u8]) -> Result<MappingLease, P2pError> {
        decode_pcp_map(
            response,
            self.internal,
            self.nonce,
            self.lifetime_seconds == 0,
        )
    }
}

/// Fixed-size `NAT-PMP` UDP mapping request for a platform-owned UDP socket.
#[derive(Debug, Clone)]
pub struct NatPmpMappingRequest {
    internal: SocketAddr,
    lifetime_seconds: u32,
    bytes: [u8; 12],
}

impl NatPmpMappingRequest {
    /// Creates a mapping, renewal, or deletion request for an IPv4 internal endpoint.
    pub fn new(internal: SocketAddr, lifetime_seconds: u32) -> Result<Self, P2pError> {
        if !internal.is_ipv4() || internal.port() == 0 || internal.ip().is_unspecified() {
            return Err(P2pError::Mapping);
        }
        let mut bytes = [0_u8; 12];
        bytes[1] = NAT_PMP_UDP_MAPPING;
        bytes[4..6].copy_from_slice(&internal.port().to_be_bytes());
        if lifetime_seconds != 0 {
            bytes[6..8].copy_from_slice(&internal.port().to_be_bytes());
        }
        bytes[8..12].copy_from_slice(&lifetime_seconds.to_be_bytes());
        Ok(Self {
            internal,
            lifetime_seconds,
            bytes,
        })
    }

    /// Retains the previously assigned port during renewal. Deletion always
    /// sends zero as required by RFC 6886 section 3.4.
    #[must_use]
    pub fn suggest_external_port(mut self, port: u16) -> Self {
        if self.lifetime_seconds != 0 {
            self.bytes[6..8].copy_from_slice(&port.to_be_bytes());
        }
        self
    }

    /// Encoded RFC 6886 UDP mapping request.
    #[must_use]
    pub const fn bytes(&self) -> &[u8; 12] {
        &self.bytes
    }

    /// Accepts only the exact internal port and bounded response shape.
    pub fn accept(&self, response: &[u8], external_ip: Ipv4Addr) -> Result<MappingLease, P2pError> {
        decode_nat_pmp_map(
            response,
            self.internal,
            external_ip,
            self.lifetime_seconds == 0,
        )
    }
}

/// `NAT-PMP` public-address request transported before the mapping request.
pub const NAT_PMP_PUBLIC_ADDRESS_REQUEST: [u8; 2] = [NAT_PMP_VERSION, NAT_PMP_PUBLIC_ADDRESS];

/// Strictly decodes a `NAT-PMP` public address and gateway epoch.
pub fn accept_nat_pmp_public_address(response: &[u8]) -> Result<(Ipv4Addr, u32), P2pError> {
    decode_nat_pmp_public_address(response)
}
