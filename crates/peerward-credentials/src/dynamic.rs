/// Atomically replaceable Root-anchored trust shared by long-running sessions.
#[derive(Clone)]
pub struct DynamicTrust(std::sync::Arc<std::sync::RwLock<TrustSet>>);

impl DynamicTrust {
    /// Wraps an already validated bootstrap trust set.
    pub fn new(trust: TrustSet) -> Self {
        Self(std::sync::Arc::new(std::sync::RwLock::new(trust)))
    }

    /// Verifies one subject against the currently installed Authority lifecycle.
    pub fn verify_subject(
        &self,
        credential: &SubjectCredential,
        now: UnixTime,
    ) -> Result<(), CredentialError> {
        self.0
            .read()
            .map_err(|_| CredentialError::InvalidSignature)?
            .verify_subject(credential, now)
    }

    /// Verifies a distribution certificate against the current Authority lifecycle.
    pub fn verify_distribution(
        &self,
        certificate: &DistributionCertificate,
        now: UnixTime,
    ) -> Result<(), CredentialError> {
        self.0
            .read()
            .map_err(|_| CredentialError::InvalidSignature)?
            .verify_distribution(certificate, now)
    }

    /// Installs only a strictly newer, Root-verified Authority bundle.
    pub fn install_authority_bundle(
        &self,
        signed: &SignedAuthorityBundle,
        now: UnixTime,
    ) -> Result<(), CredentialError> {
        self.0
            .write()
            .map_err(|_| CredentialError::InvalidSignature)?
            .install_authority_bundle(signed, now)
    }

    /// Revokes one exact subject serial without replacing the active Authority set.
    pub fn revoke_subject(&self, serial: CredentialSerial) -> Result<(), CredentialError> {
        self.0
            .write()
            .map_err(|_| CredentialError::InvalidSignature)?
            .revoke_subject(serial);
        Ok(())
    }

    /// Returns the most recently accepted Authority revision.
    pub fn authority_revision(&self) -> Result<Option<u64>, CredentialError> {
        self.0
            .read()
            .map_err(|_| CredentialError::InvalidSignature)
            .map(|trust| trust.authority_revision())
    }

    /// Clones a coherent trust snapshot for an operation that requires a borrowed set.
    pub fn snapshot(&self) -> Result<TrustSet, CredentialError> {
        self.0
            .read()
            .map_err(|_| CredentialError::InvalidSignature)
            .map(|trust| trust.clone())
    }
}
