impl DirectorySigningKey {
    /// Signs a scoped administrative request using the rooted distribution identity.
    pub fn sign_credential_renewal(
        &self,
        command: peerward_management::CredentialRenewalCommand,
    ) -> Result<peerward_management::SignedCredentialRenewal, peerward_management::ManagementError>
    {
        peerward_management::SignedCredentialRenewal::sign(command, &self.0)
    }
}
