const JOIN_CLAIM_DOMAIN: &[u8] = b"peerward/join-claim/v2\0";

/// Canonical, ticket-bound fields authenticated by a joining Peer identity.
#[derive(Debug, Clone, Copy)]
pub struct JoinClaimProof<'a> {
    /// Strict request schema version.
    pub schema_version: u32,
    /// Client-generated idempotency identifier.
    pub claim_id: Uuid,
    /// SHA-256 digest of the secret ticket in the request path.
    pub ticket_digest: [u8; 32],
    /// New Ed25519 identity verifier.
    pub identity_public_key: [u8; 32],
    /// New X25519 static session key.
    pub session_public_key: [u8; 32],
    /// Independent new `WireGuard` data key.
    pub wireguard_public_key: [u8; 32],
    /// Exact client product version.
    pub client_version: &'a str,
    /// Only supported Wire major.
    pub supported_wire_major: u32,
    /// Fresh client nonce.
    pub nonce: &'a [u8],
    /// Human-readable device name.
    pub device_name: &'a str,
    /// Bounded device model.
    pub device_model: &'a str,
    /// Operating-system family.
    pub platform: &'a str,
    /// Operating-system version.
    pub platform_version: &'a str,
}

impl JoinClaimProof<'_> {
    fn validate(&self) -> Result<(), CredentialError> {
        if self.schema_version != 2
            || self.claim_id.get_version_num() != 4
            || self.identity_public_key.iter().all(|byte| *byte == 0)
            || self.session_public_key.iter().all(|byte| *byte == 0)
            || !contributory_wireguard_key(&self.wireguard_public_key)
            || self.wireguard_public_key == self.session_public_key
            || self.wireguard_public_key == self.identity_public_key
            || self.client_version.is_empty()
            || self.client_version.len() > 64
            || self.supported_wire_major == 0
            || !(16..=64).contains(&self.nonce.len())
            || self.device_name.is_empty()
            || self.device_name.len() > 128
            || self.device_model.len() > 128
            || self.platform.is_empty()
            || self.platform.len() > 32
            || self.platform_version.len() > 64
        {
            return Err(CredentialError::Malformed);
        }
        Ok(())
    }
}

/// Produces the canonical Join proof transcript, including the secret ticket binding.
pub fn join_claim_transcript(proof: &JoinClaimProof<'_>) -> Result<Vec<u8>, CredentialError> {
    proof.validate()?;
    let mut bytes = Vec::with_capacity(512);
    bytes.extend_from_slice(JOIN_CLAIM_DOMAIN);
    bytes.extend_from_slice(&proof.schema_version.to_be_bytes());
    bytes.extend_from_slice(proof.claim_id.as_bytes());
    bytes.extend_from_slice(&proof.ticket_digest);
    bytes.extend_from_slice(&proof.identity_public_key);
    bytes.extend_from_slice(&proof.session_public_key);
    bytes.extend_from_slice(&proof.wireguard_public_key);
    bytes.extend_from_slice(&proof.supported_wire_major.to_be_bytes());
    join_claim_bytes(&mut bytes, proof.client_version.as_bytes())?;
    join_claim_bytes(&mut bytes, proof.nonce)?;
    join_claim_bytes(&mut bytes, proof.device_name.as_bytes())?;
    join_claim_bytes(&mut bytes, proof.device_model.as_bytes())?;
    join_claim_bytes(&mut bytes, proof.platform.as_bytes())?;
    join_claim_bytes(&mut bytes, proof.platform_version.as_bytes())?;
    Ok(bytes)
}

/// Signs a Join proof with the new on-device Ed25519 identity.
pub fn sign_join_claim(
    identity_private_key: &[u8; 32],
    proof: &JoinClaimProof<'_>,
) -> Result<[u8; 64], CredentialError> {
    Ok(SigningKey::from_bytes(identity_private_key)
        .sign(&join_claim_transcript(proof)?)
        .to_bytes())
}

/// Verifies that the new identity itself authorized the ticket-bound Join claim.
pub fn verify_join_claim(
    proof: &JoinClaimProof<'_>,
    signature: &[u8; 64],
) -> Result<(), CredentialError> {
    VerifyingKey::from_bytes(&proof.identity_public_key)
        .map_err(|_| CredentialError::InvalidKey)?
        .verify(
            &join_claim_transcript(proof)?,
            &Signature::from_bytes(signature),
        )
        .map_err(|_| CredentialError::InvalidSignature)
}

fn join_claim_bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<(), CredentialError> {
    let length = u32::try_from(value.len()).map_err(|_| CredentialError::Malformed)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}
