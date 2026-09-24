use thiserror::Error;

/// Direct path setup or datagram failure.
#[derive(Debug, Error)]
pub enum P2pError {
    /// Candidate set is empty, oversized, duplicated, or contains an unsafe endpoint.
    #[error("invalid direct candidate set")]
    Candidate,
    /// STUN framing or response validation failed.
    #[error("invalid STUN message")]
    Stun,
    /// PCP, NAT-PMP, or `UPnP` mapping failed validation or was unavailable.
    #[error("gateway port mapping failed")]
    Mapping,
    /// A PCP or NAT-PMP epoch moved backwards, indicating a gateway restart.
    #[error("gateway mapping epoch restarted")]
    GatewayRestarted,
    /// Socket operation failed.
    #[error("direct socket failed")]
    Io(#[from] std::io::Error),
    /// A discovery or probe operation timed out.
    #[error("direct operation timed out")]
    Timeout,
}
