/// Irreversible Mesh termination, retained after online secrets are removed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshTermination {
    pub revision: u64,
    pub terminated_at: UnixTime,
    pub authority: AuthorityCertificate,
    pub signature: [u8; 64],
}

const TERMINATION_DOMAIN: &[u8] = b"peerward/mesh-termination/v1\0";

impl TrustSet {
    pub fn verify_termination(
        &self,
        terminal: &MeshTermination,
        previous_revision: u64,
        now: UnixTime,
    ) -> Result<(), CredentialError> {
        if self
            .revoked_authority_serials
            .contains(&terminal.authority.serial)
        {
            return Err(CredentialError::Revoked);
        }
        terminal.verify(self.root, self.mesh_id, previous_revision, now)
    }
}

impl AuthoritySigningKey {
    pub fn terminate_mesh(
        &self,
        authority: AuthorityCertificate,
        revision: u64,
        now: UnixTime,
    ) -> Result<MeshTermination, CredentialError> {
        if revision == 0 || authority.public_key != self.public_key() {
            return Err(CredentialError::InvalidKey);
        }
        validate_time(authority.not_before, authority.not_after, now)?;
        let mut terminal = MeshTermination {
            revision,
            terminated_at: now,
            authority,
            signature: [0; 64],
        };
        terminal.signature = self.0.sign(&terminal.transcript()).to_bytes();
        Ok(terminal)
    }
}

impl MeshTermination {
    fn transcript(&self) -> Vec<u8> {
        let mut bytes = TERMINATION_DOMAIN.to_vec();
        bytes.extend_from_slice(&self.revision.to_be_bytes());
        bytes.extend_from_slice(&self.terminated_at.0.to_be_bytes());
        bytes.extend_from_slice(&self.authority.encode());
        bytes
    }

    /// Validate the immutable proof at signing time, including after expiry.
    /// Runtime callers must use `TrustSet::verify_termination` to also enforce
    /// known Authority revocations before persisting a new termination.
    pub fn verify(
        &self,
        root: RootPublicKey,
        mesh: MeshId,
        previous_revision: u64,
        now: UnixTime,
    ) -> Result<(), CredentialError> {
        if self.revision == 0 || self.revision <= previous_revision {
            return Err(CredentialError::Rollback);
        }
        if self.terminated_at.0 > now.0.saturating_add(60) {
            return Err(CredentialError::OutsideValidity);
        }
        root.verify_authority(&self.authority, mesh, self.terminated_at)?;
        VerifyingKey::from_bytes(&self.authority.public_key)
            .map_err(|_| CredentialError::InvalidKey)?
            .verify_strict(&self.transcript(), &Signature::from_bytes(&self.signature))
            .map_err(|_| CredentialError::InvalidSignature)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = b"PWM1".to_vec();
        bytes.extend_from_slice(&self.revision.to_be_bytes());
        bytes.extend_from_slice(&self.terminated_at.0.to_be_bytes());
        bytes.extend_from_slice(&self.authority.encode());
        bytes.extend_from_slice(&self.signature);
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, CredentialError> {
        if bytes.len() != 228 || &bytes[..4] != b"PWM1" {
            return Err(CredentialError::Malformed);
        }
        Ok(Self {
            revision: u64::from_be_bytes(
                bytes[4..12]
                    .try_into()
                    .map_err(|_| CredentialError::Malformed)?,
            ),
            terminated_at: UnixTime(u64::from_be_bytes(
                bytes[12..20]
                    .try_into()
                    .map_err(|_| CredentialError::Malformed)?,
            )),
            authority: AuthorityCertificate::decode(&bytes[20..164])?,
            signature: bytes[164..]
                .try_into()
                .map_err(|_| CredentialError::Malformed)?,
        })
    }
}

#[cfg(test)]
mod termination_tests {
    use super::*;

    #[test]
    fn known_authority_revocation_rejects_backdated_termination_without_affecting_replacement() {
        let mesh = MeshId::new();
        let root = RootSigningKey::generate();
        let old = AuthoritySigningKey::generate();
        let replacement = AuthoritySigningKey::generate();
        let certificates: Vec<_> = [&old, &replacement]
            .iter()
            .map(|signer| {
                root.certify(UnsignedAuthority {
                    mesh_id: mesh,
                    serial: CredentialSerial::new(),
                    public_key: signer.public_key(),
                    not_before: UnixTime(1),
                    not_after: UnixTime(100),
                })
                .unwrap()
            })
            .collect();
        let mut trust = TrustSet::new(root.public_key(), mesh);
        for certificate in &certificates {
            trust
                .add_authority(certificate.clone(), UnixTime(10))
                .unwrap();
        }
        let terminal = old
            .terminate_mesh(certificates[0].clone(), 2, UnixTime(50))
            .unwrap();
        trust
            .verify_termination(&terminal, 0, UnixTime(500))
            .unwrap();
        trust.revoke_authority(certificates[0].serial);
        // Signed time can be backdated by the revoked signer; it is not proof
        // that this statement was observed before the trusted revocation.
        assert_eq!(
            trust.verify_termination(&terminal, 0, UnixTime(500)),
            Err(CredentialError::Revoked)
        );
        let valid = replacement
            .terminate_mesh(certificates[1].clone(), 3, UnixTime(60))
            .unwrap();
        trust.verify_termination(&valid, 0, UnixTime(500)).unwrap();
    }

    #[test]
    fn termination_is_mesh_bound_permanent_and_monotonic() {
        let mesh = MeshId::new();
        let root = RootSigningKey::generate();
        let signer = AuthoritySigningKey::generate();
        let certificate = root
            .certify(UnsignedAuthority {
                mesh_id: mesh,
                serial: CredentialSerial::new(),
                public_key: signer.public_key(),
                not_before: UnixTime(1),
                not_after: UnixTime(100),
            })
            .unwrap();
        let terminal = signer.terminate_mesh(certificate, 2, UnixTime(50)).unwrap();
        assert_eq!(
            MeshTermination::decode(&terminal.encode()).unwrap(),
            terminal
        );
        terminal
            .verify(root.public_key(), mesh, 1, UnixTime(500))
            .unwrap();
        assert!(
            terminal
                .verify(root.public_key(), MeshId::new(), 0, UnixTime(500))
                .is_err()
        );
        assert!(
            terminal
                .verify(root.public_key(), mesh, 2, UnixTime(500))
                .is_err()
        );
        let mut altered = terminal;
        altered.revision = 3;
        assert!(
            altered
                .verify(root.public_key(), mesh, 0, UnixTime(500))
                .is_err()
        );
    }
}
