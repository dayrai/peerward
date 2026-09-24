const AUTHORITY_DOMAIN: &[u8] = b"peerward/root-authority/v1\0";
const SUBJECT_DOMAIN: &[u8] = b"peerward/subject-credential/v3\0";
const DISTRIBUTION_DOMAIN: &[u8] = b"peerward/distribution-trust/v1\0";
const AUTHORITY_BUNDLE_DOMAIN: &[u8] = b"peerward/authority-bundle/v1\0";

/// Credential validation failure.
#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum CredentialError {
    /// The Ed25519 signature is invalid.
    #[error("signature verification failed")]
    InvalidSignature,
    /// The role-specific Ed25519/X25519 public-key binding is invalid.
    #[error("credential public-key binding is invalid")]
    InvalidKey,
    /// The validity interval is empty or inverted.
    #[error("validity interval is invalid")]
    InvalidInterval,
    /// The credential is not valid at the requested time.
    #[error("credential is outside its validity interval")]
    OutsideValidity,
    /// The credential belongs to a different mesh.
    #[error("credential belongs to a different mesh")]
    WrongMesh,
    /// The exact credential serial is revoked.
    #[error("credential serial is revoked")]
    Revoked,
    /// A transported credential did not have the exact typed binary shape.
    #[error("credential encoding is malformed")]
    Malformed,
    /// A revision is not newer than the already accepted revision.
    #[error("authority bundle revision is not newer")]
    Rollback,
    /// A collection is duplicated, unsorted, or exceeds its bound.
    #[error("credential collection is not canonical")]
    NonCanonical,
}

/// Offline root signing material.
pub struct RootSigningKey(SigningKey);

impl RootSigningKey {
    /// Generates fresh root material using the operating system RNG.
    pub fn generate() -> Self {
        Self::generate_with(&mut OsRng)
    }

    /// Generates root material with a caller-provided CSPRNG.
    pub fn generate_with(rng: &mut (impl CryptoRng + RngCore)) -> Self {
        Self(SigningKey::generate(rng))
    }

    /// Imports exactly 32 private-key bytes.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self(SigningKey::from_bytes(bytes))
    }

    /// Exports private material for an explicit secure-storage operation.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Returns the corresponding public root.
    pub fn public_key(&self) -> RootPublicKey {
        RootPublicKey(self.0.verifying_key())
    }

    /// Certifies one online authority for one mesh.
    pub fn certify(
        &self,
        unsigned: UnsignedAuthority,
    ) -> Result<AuthorityCertificate, CredentialError> {
        validate_interval(unsigned.not_before, unsigned.not_after)?;
        let transcript = authority_transcript(&unsigned);
        Ok(AuthorityCertificate {
            mesh_id: unsigned.mesh_id,
            serial: unsigned.serial,
            public_key: unsigned.public_key,
            not_before: unsigned.not_before,
            not_after: unsigned.not_after,
            signature: self.0.sign(&transcript).to_bytes(),
        })
    }
}

/// Offline root public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RootPublicKey(VerifyingKey);

impl RootPublicKey {
    /// Imports a 32-byte Ed25519 public key.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, CredentialError> {
        VerifyingKey::from_bytes(bytes)
            .map(Self)
            .map_err(|_| CredentialError::InvalidSignature)
    }

    /// Exports the public key.
    pub fn to_bytes(self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Verifies root certification and its validity at `now`.
    pub fn verify_authority(
        &self,
        certificate: &AuthorityCertificate,
        mesh_id: MeshId,
        now: UnixTime,
    ) -> Result<(), CredentialError> {
        if certificate.mesh_id != mesh_id {
            return Err(CredentialError::WrongMesh);
        }
        validate_interval(certificate.not_before, certificate.not_after)?;
        validate_time(certificate.not_before, certificate.not_after, now)?;
        let transcript = authority_transcript(&certificate.unsigned());
        self.0
            .verify(&transcript, &Signature::from_bytes(&certificate.signature))
            .map_err(|_| CredentialError::InvalidSignature)
    }
}

/// Online authority signing material.
pub struct AuthoritySigningKey(SigningKey);

impl AuthoritySigningKey {
    /// Generates fresh authority material.
    pub fn generate() -> Self {
        Self(SigningKey::generate(&mut OsRng))
    }

    /// Imports deterministic 32-byte private material.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self(SigningKey::from_bytes(bytes))
    }

    /// Exports private material for secure persistence.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Returns the online authority public key.
    pub fn public_key(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }

    /// Signs a peer or relay Noise identity.
    pub fn issue(&self, unsigned: UnsignedSubject) -> Result<SubjectCredential, CredentialError> {
        validate_interval(unsigned.not_before, unsigned.not_after)?;
        validate_subject_keys(
            unsigned.subject,
            &unsigned.identity_public_key,
            &unsigned.public_noise_key,
            &unsigned.wireguard_public_key,
        )?;
        let transcript = subject_transcript(&unsigned);
        Ok(SubjectCredential {
            role: unsigned.subject.role(),
            mesh_id: unsigned.mesh_id,
            subject: unsigned.subject,
            identity_public_key: unsigned.identity_public_key,
            public_noise_key: unsigned.public_noise_key,
            wireguard_public_key: unsigned.wireguard_public_key,
            serial: unsigned.serial,
            not_before: unsigned.not_before,
            not_after: unsigned.not_after,
            signature: self.0.sign(&transcript).to_bytes(),
        })
    }

    /// Binds online directory, service, and audit-recipient keys to this rooted authority.
    #[must_use]
    pub fn certify_distribution(
        &self,
        mesh_id: MeshId,
        directory_public_key: [u8; 32],
        service_public_key: [u8; 32],
        audit_public_key: [u8; 32],
    ) -> DistributionCertificate {
        let mut certificate = DistributionCertificate {
            mesh_id,
            authority_public_key: self.public_key(),
            directory_public_key,
            service_public_key,
            audit_public_key,
            signature: [0; 64],
        };
        certificate.signature = self
            .0
            .sign(&distribution_transcript(&certificate))
            .to_bytes();
        certificate
    }

    /// Signs a canonical Root-anchored authority lifecycle bundle.
    pub fn sign_authority_bundle(
        &self,
        mesh_id: MeshId,
        revision: u64,
        active: AuthorityCertificate,
        mut overlap: Vec<AuthorityCertificate>,
        mut revoked: Vec<CredentialSerial>,
    ) -> Result<SignedAuthorityBundle, CredentialError> {
        if active.mesh_id != mesh_id || active.public_key != self.public_key() {
            return Err(CredentialError::WrongMesh);
        }
        overlap.sort_by_key(|certificate| certificate.serial);
        revoked.sort_unstable();
        let bundle = AuthorityBundle {
            mesh_id,
            revision,
            active,
            overlap,
            revoked,
        };
        bundle.validate_shape()?;
        let signature = self.0.sign(&authority_bundle_transcript(&bundle)).to_bytes();
        Ok(SignedAuthorityBundle { bundle, signature })
    }
}

/// Authority-signed binding for online distribution verifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DistributionCertificate {
    /// Mesh isolation boundary.
    pub mesh_id: MeshId,
    /// Root-certified authority that signed this binding.
    pub authority_public_key: [u8; 32],
    /// Peer/relay directory and policy verifier.
    pub directory_public_key: [u8; 32],
    /// Service snapshot verifier.
    pub service_public_key: [u8; 32],
    /// Control X25519 recipient for encrypted Peer security audits.
    pub audit_public_key: [u8; 32],
    /// Authority signature over the fixed transcript.
    pub signature: [u8; 64],
}

impl DistributionCertificate {
    /// Encodes the exact 208-byte enrollment trust shape.
    #[must_use]
    pub fn encode(self) -> [u8; 208] {
        let mut bytes = [0; 208];
        bytes[..16].copy_from_slice(self.mesh_id.as_bytes());
        bytes[16..48].copy_from_slice(&self.authority_public_key);
        bytes[48..80].copy_from_slice(&self.directory_public_key);
        bytes[80..112].copy_from_slice(&self.service_public_key);
        bytes[112..144].copy_from_slice(&self.audit_public_key);
        bytes[144..].copy_from_slice(&self.signature);
        bytes
    }

    /// Decodes only the exact canonical enrollment trust shape.
    pub fn decode(bytes: &[u8]) -> Result<Self, CredentialError> {
        if bytes.len() != 208 {
            return Err(CredentialError::Malformed);
        }
        let mesh = Uuid::from_slice(&bytes[..16]).map_err(|_| CredentialError::Malformed)?;
        Ok(Self {
            mesh_id: MeshId::from_uuid(mesh).map_err(|_| CredentialError::Malformed)?,
            authority_public_key: bytes[16..48]
                .try_into()
                .map_err(|_| CredentialError::Malformed)?,
            directory_public_key: bytes[48..80]
                .try_into()
                .map_err(|_| CredentialError::Malformed)?,
            service_public_key: bytes[80..112]
                .try_into()
                .map_err(|_| CredentialError::Malformed)?,
            audit_public_key: bytes[112..144]
                .try_into()
                .map_err(|_| CredentialError::Malformed)?,
            signature: bytes[144..208]
                .try_into()
                .map_err(|_| CredentialError::Malformed)?,
        })
    }
}

/// Input fields covered by root certification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnsignedAuthority {
    /// Mesh for which this authority may issue credentials.
    pub mesh_id: MeshId,
    /// Authority credential serial.
    pub serial: CredentialSerial,
    /// Authority Ed25519 public key.
    pub public_key: [u8; 32],
    /// Inclusive start of validity.
    pub not_before: UnixTime,
    /// Exclusive end of validity.
    pub not_after: UnixTime,
}

/// Root-signed online authority certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityCertificate {
    /// Mesh for which this authority may issue credentials.
    pub mesh_id: MeshId,
    /// Authority credential serial.
    pub serial: CredentialSerial,
    /// Authority Ed25519 public key.
    pub public_key: [u8; 32],
    /// Inclusive start of validity.
    pub not_before: UnixTime,
    /// Exclusive end of validity.
    pub not_after: UnixTime,
    /// Root Ed25519 signature over the fixed transcript.
    pub signature: [u8; 64],
}

impl AuthorityCertificate {
    fn unsigned(&self) -> UnsignedAuthority {
        UnsignedAuthority {
            mesh_id: self.mesh_id,
            serial: self.serial,
            public_key: self.public_key,
            not_before: self.not_before,
            not_after: self.not_after,
        }
    }

    /// Encodes the exact fixed-width authority certificate transported to clients.
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(144);
        bytes.extend_from_slice(self.mesh_id.as_bytes());
        bytes.extend_from_slice(self.serial.as_bytes());
        bytes.extend_from_slice(&self.public_key);
        bytes.extend_from_slice(&self.not_before.0.to_be_bytes());
        bytes.extend_from_slice(&self.not_after.0.to_be_bytes());
        bytes.extend_from_slice(&self.signature);
        bytes
    }

    /// Decodes only the exact fixed-width authority certificate shape.
    pub fn decode(bytes: &[u8]) -> Result<Self, CredentialError> {
        if bytes.len() != 144 {
            return Err(CredentialError::Malformed);
        }
        let mesh_id = MeshId::from_uuid(
            Uuid::from_slice(&bytes[..16]).map_err(|_| CredentialError::Malformed)?,
        )
        .map_err(|_| CredentialError::Malformed)?;
        let serial = CredentialSerial::from_uuid(
            Uuid::from_slice(&bytes[16..32]).map_err(|_| CredentialError::Malformed)?,
        )
        .map_err(|_| CredentialError::Malformed)?;
        let certificate = Self {
            mesh_id,
            serial,
            public_key: bytes[32..64]
                .try_into()
                .map_err(|_| CredentialError::Malformed)?,
            not_before: UnixTime(u64::from_be_bytes(
                bytes[64..72]
                    .try_into()
                    .map_err(|_| CredentialError::Malformed)?,
            )),
            not_after: UnixTime(u64::from_be_bytes(
                bytes[72..80]
                    .try_into()
                    .map_err(|_| CredentialError::Malformed)?,
            )),
            signature: bytes[80..144]
                .try_into()
                .map_err(|_| CredentialError::Malformed)?,
        };
        validate_interval(certificate.not_before, certificate.not_after)?;
        Ok(certificate)
    }
}
