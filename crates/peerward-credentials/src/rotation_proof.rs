const ROTATION_REQUEST_DOMAIN: &[u8] = b"peerward/credential-rotation/request/v2\0";
const ROTATION_ACTIVATION_DOMAIN: &[u8] = b"peerward/credential-rotation/activate/v1\0";

/// Immutable fields authorized by the currently active Peer identity.
#[derive(Debug, Clone, Copy)]
pub struct RotationRequestProof {
    /// Owning Mesh.
    pub mesh_id: MeshId,
    /// Peer rotating its credential.
    pub peer_id: PeerId,
    /// Idempotent rotation identifier.
    pub rotation_id: peerward_types::RotationId,
    /// Credential used by the current authenticated connection.
    pub current_serial: CredentialSerial,
    /// New Ed25519 verifier.
    pub identity_public_key: [u8; 32],
    /// New X25519 session key.
    pub session_public_key: [u8; 32],
    /// Independent new `WireGuard` data key.
    pub wireguard_public_key: [u8; 32],
}

/// One-time activation fields authorized by the new Peer identity.
#[derive(Debug, Clone, Copy)]
pub struct RotationActivationProof {
    /// Owning Mesh.
    pub mesh_id: MeshId,
    /// Peer rotating its credential.
    pub peer_id: PeerId,
    /// Idempotent rotation identifier.
    pub rotation_id: peerward_types::RotationId,
    /// Newly issued credential serial.
    pub issued_serial: CredentialSerial,
    /// Server-generated one-time challenge.
    pub challenge: [u8; 32],
}

/// Canonical request transcript.
pub fn rotation_request_transcript(proof: &RotationRequestProof) -> Result<Vec<u8>, CredentialError> {
    if proof.identity_public_key.iter().all(|byte| *byte == 0)
        || proof.session_public_key.iter().all(|byte| *byte == 0)
        || !contributory_wireguard_key(&proof.wireguard_public_key)
        || proof.wireguard_public_key == proof.session_public_key
        || proof.wireguard_public_key == proof.identity_public_key
    {
        return Err(CredentialError::InvalidKey);
    }
    let mut bytes = Vec::with_capacity(192);
    bytes.extend_from_slice(ROTATION_REQUEST_DOMAIN);
    bytes.extend_from_slice(proof.mesh_id.as_bytes());
    bytes.extend_from_slice(proof.peer_id.as_bytes());
    bytes.extend_from_slice(proof.rotation_id.as_bytes());
    bytes.extend_from_slice(proof.current_serial.as_bytes());
    bytes.extend_from_slice(&proof.identity_public_key);
    bytes.extend_from_slice(&proof.session_public_key);
    bytes.extend_from_slice(&proof.wireguard_public_key);
    Ok(bytes)
}

/// Signs the rotation request with the current Ed25519 identity.
pub fn sign_rotation_request(
    current_identity_private_key: &[u8; 32],
    proof: &RotationRequestProof,
) -> Result<[u8; 64], CredentialError> {
    Ok(SigningKey::from_bytes(current_identity_private_key)
        .sign(&rotation_request_transcript(proof)?)
        .to_bytes())
}

/// Verifies the rotation request against its currently certified identity.
pub fn verify_rotation_request(
    current_identity_public_key: &[u8; 32],
    proof: &RotationRequestProof,
    signature: &[u8; 64],
) -> Result<(), CredentialError> {
    VerifyingKey::from_bytes(current_identity_public_key)
        .map_err(|_| CredentialError::InvalidKey)?
        .verify(
            &rotation_request_transcript(proof)?,
            &Signature::from_bytes(signature),
        )
        .map_err(|_| CredentialError::InvalidSignature)
}

/// Canonical activation transcript.
pub fn rotation_activation_transcript(proof: &RotationActivationProof) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(128);
    bytes.extend_from_slice(ROTATION_ACTIVATION_DOMAIN);
    bytes.extend_from_slice(proof.mesh_id.as_bytes());
    bytes.extend_from_slice(proof.peer_id.as_bytes());
    bytes.extend_from_slice(proof.rotation_id.as_bytes());
    bytes.extend_from_slice(proof.issued_serial.as_bytes());
    bytes.extend_from_slice(&proof.challenge);
    bytes
}

/// Signs the one-time challenge with the new Ed25519 identity.
pub fn sign_rotation_activation(
    new_identity_private_key: &[u8; 32],
    proof: &RotationActivationProof,
) -> [u8; 64] {
    SigningKey::from_bytes(new_identity_private_key)
        .sign(&rotation_activation_transcript(proof))
        .to_bytes()
}

/// Verifies proof of possession of the new Ed25519 identity.
pub fn verify_rotation_activation(
    new_identity_public_key: &[u8; 32],
    proof: &RotationActivationProof,
    signature: &[u8; 64],
) -> Result<(), CredentialError> {
    VerifyingKey::from_bytes(new_identity_public_key)
        .map_err(|_| CredentialError::InvalidKey)?
        .verify(
            &rotation_activation_transcript(proof),
            &Signature::from_bytes(signature),
        )
        .map_err(|_| CredentialError::InvalidSignature)
}
