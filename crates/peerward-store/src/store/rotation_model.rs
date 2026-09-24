/// Durable, authenticated Peer request awaiting online Authority issuance.
#[derive(Debug, Clone)]
pub struct PendingPeerRotation {
    /// Idempotent request identity.
    pub id: RotationId,
    /// Owning mesh.
    pub mesh_id: MeshId,
    /// Peer retaining the private half locally.
    pub peer_id: PeerId,
    /// Credential that authenticated the in-band request.
    pub authenticated_serial: CredentialSerial,
    /// Requested Ed25519 identity verifier.
    pub identity_public_key: [u8; 32],
    /// Requested X25519 session key.
    pub session_public_key: [u8; 32],
    /// Requested independent `WireGuard` data key.
    pub wireguard_public_key: [u8; 32],
    /// Server-generated one-time challenge.
    pub activation_challenge: [u8; 32],
}

/// Issued replacement waiting for first authentication with the new key.
#[derive(Debug, Clone)]
pub struct IssuedPeerRotation {
    /// Original request identity.
    pub id: RotationId,
    /// Replacement credential serial.
    pub serial: CredentialSerial,
    /// Canonically encoded Authority-signed credential.
    pub credential: Vec<u8>,
    /// Server-generated one-time challenge for the new identity.
    pub activation_challenge: [u8; 32],
}
