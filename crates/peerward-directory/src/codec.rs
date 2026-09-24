/// Serializes a peer directory for chunk transport. JSON is not signed; fixed transcripts are.
pub fn encode_peer_directory(value: &SignedPeerDirectory) -> Result<Vec<u8>, DirectoryError> {
    serde_json::to_vec(value).map_err(|_| DirectoryError::Malformed)
}

/// Parses a transported peer directory before signature verification.
pub fn decode_peer_directory(bytes: &[u8]) -> Result<SignedPeerDirectory, DirectoryError> {
    serde_json::from_slice(bytes).map_err(|_| DirectoryError::Malformed)
}

/// Serializes a signed relay directory for bounded transport chunks.
pub fn encode_relay_directory(value: &SignedRelayDirectory) -> Result<Vec<u8>, DirectoryError> {
    serde_json::to_vec(value).map_err(|_| DirectoryError::Malformed)
}

/// Parses a transported relay directory before verification.
pub fn decode_relay_directory(bytes: &[u8]) -> Result<SignedRelayDirectory, DirectoryError> {
    serde_json::from_slice(bytes).map_err(|_| DirectoryError::Malformed)
}

/// Serializes a separately signed Relay topology revision.
pub fn encode_relay_topology(value: &SignedRelayTopologyV1) -> Result<Vec<u8>, DirectoryError> {
    serde_json::to_vec(value).map_err(|_| DirectoryError::Malformed)
}

/// Parses a transported Relay topology before verification.
pub fn decode_relay_topology(bytes: &[u8]) -> Result<SignedRelayTopologyV1, DirectoryError> {
    serde_json::from_slice(bytes).map_err(|_| DirectoryError::Malformed)
}

/// Serializes a signed policy bundle for its Prost envelope body.
pub fn encode_policy(value: &SignedPolicyBundle) -> Result<Vec<u8>, DirectoryError> {
    serde_json::to_vec(value).map_err(|_| DirectoryError::Malformed)
}

/// Parses a transported policy before signature and revision verification.
pub fn decode_policy(bytes: &[u8]) -> Result<SignedPolicyBundle, DirectoryError> {
    serde_json::from_slice(bytes).map_err(|_| DirectoryError::Malformed)
}

/// Serializes an authenticated exact-revocation bundle.
pub fn encode_revocations(value: &SignedRevocationBundle) -> Result<Vec<u8>, DirectoryError> {
    serde_json::to_vec(value).map_err(|_| DirectoryError::Malformed)
}

/// Parses a transported exact-revocation bundle before signature verification.
pub fn decode_revocations(bytes: &[u8]) -> Result<SignedRevocationBundle, DirectoryError> {
    serde_json::from_slice(bytes).map_err(|_| DirectoryError::Malformed)
}
