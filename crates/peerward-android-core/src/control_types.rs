/// Non-secret material Kotlin needs to prove possession of a staged identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialReplacementUpdate {
    /// Authority-signed staged credential.
    pub credential: Vec<u8>,
    /// Canonical one-time activation transcript to sign with the new identity.
    pub activation_transcript: Vec<u8>,
}

/// Persistable non-secret result of an accepted Authority bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityTrustUpdate {
    /// Monotonic lifecycle revision.
    pub revision: u64,
    /// Current active and overlap Root-signed certificates.
    pub certificates: Vec<Vec<u8>>,
}
