/// Strongly typed credential subject.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubjectId {
    /// Peer identity.
    Peer(PeerId),
    /// Relay identity.
    Relay(RelayId),
}

impl SubjectId {
    fn role(self) -> SubjectRole {
        match self {
            Self::Peer(_) => SubjectRole::Peer,
            Self::Relay(_) => SubjectRole::Relay,
        }
    }

    fn bytes(self) -> [u8; 16] {
        match self {
            Self::Peer(id) => *id.as_bytes(),
            Self::Relay(id) => *id.as_bytes(),
        }
    }
}

/// Input fields covered by an authority signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnsignedSubject {
    /// Role-bearing subject identity.
    pub subject: SubjectId,
    /// Subject mesh.
    pub mesh_id: MeshId,
    /// Ed25519 identity verifier. Relay credentials use the all-zero reserved value.
    pub identity_public_key: [u8; 32],
    /// X25519 static session public key.
    pub public_noise_key: [u8; 32],
    /// Independent `WireGuard` data key; all zero for Relay credentials.
    pub wireguard_public_key: [u8; 32],
    /// Exact revocation serial.
    pub serial: CredentialSerial,
    /// Inclusive start of validity.
    pub not_before: UnixTime,
    /// Exclusive end of validity.
    pub not_after: UnixTime,
}

/// Authority-signed peer or relay credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectCredential {
    /// Credential role.
    pub role: SubjectRole,
    /// Subject mesh.
    pub mesh_id: MeshId,
    /// Strong subject identity.
    pub subject: SubjectId,
    /// Ed25519 identity verifier. Relay credentials use the all-zero reserved value.
    pub identity_public_key: [u8; 32],
    /// X25519 static session public key.
    pub public_noise_key: [u8; 32],
    /// Independent `WireGuard` data key; all zero for Relay credentials.
    pub wireguard_public_key: [u8; 32],
    /// Exact revocation serial.
    pub serial: CredentialSerial,
    /// Inclusive start of validity.
    pub not_before: UnixTime,
    /// Exclusive end of validity.
    pub not_after: UnixTime,
    /// Authority Ed25519 signature over the fixed transcript.
    pub signature: [u8; 64],
}

impl SubjectCredential {
    fn unsigned(&self) -> UnsignedSubject {
        UnsignedSubject {
            subject: self.subject,
            mesh_id: self.mesh_id,
            identity_public_key: self.identity_public_key,
            public_noise_key: self.public_noise_key,
            wireguard_public_key: self.wireguard_public_key,
            serial: self.serial,
            not_before: self.not_before,
            not_after: self.not_after,
        }
    }

    /// Encodes the typed credential for a Noise handshake payload.
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(225);
        bytes.push(self.role.transcript_tag());
        bytes.extend_from_slice(self.mesh_id.as_bytes());
        bytes.extend_from_slice(&self.subject.bytes());
        bytes.extend_from_slice(&self.identity_public_key);
        bytes.extend_from_slice(&self.public_noise_key);
        bytes.extend_from_slice(&self.wireguard_public_key);
        bytes.extend_from_slice(self.serial.as_bytes());
        bytes.extend_from_slice(&self.not_before.0.to_be_bytes());
        bytes.extend_from_slice(&self.not_after.0.to_be_bytes());
        bytes.extend_from_slice(&self.signature);
        bytes
    }

    /// Decodes the exact role-bearing credential shape used in Noise handshakes.
    pub fn decode(bytes: &[u8]) -> Result<Self, CredentialError> {
        if bytes.len() != 225 {
            return Err(CredentialError::Malformed);
        }
        let role = match bytes[0] {
            1 => SubjectRole::Peer,
            2 => SubjectRole::Relay,
            _ => return Err(CredentialError::Malformed),
        };
        let mesh_uuid = Uuid::from_slice(&bytes[1..17]).map_err(|_| CredentialError::Malformed)?;
        let mesh_id = MeshId::from_uuid(mesh_uuid).map_err(|_| CredentialError::Malformed)?;
        let subject_uuid =
            Uuid::from_slice(&bytes[17..33]).map_err(|_| CredentialError::Malformed)?;
        let subject = match role {
            SubjectRole::Peer => SubjectId::Peer(
                PeerId::from_uuid(subject_uuid).map_err(|_| CredentialError::Malformed)?,
            ),
            SubjectRole::Relay => SubjectId::Relay(
                RelayId::from_uuid(subject_uuid).map_err(|_| CredentialError::Malformed)?,
            ),
        };
        let identity_public_key = bytes[33..65]
            .try_into()
            .map_err(|_| CredentialError::Malformed)?;
        let public_noise_key = bytes[65..97]
            .try_into()
            .map_err(|_| CredentialError::Malformed)?;
        let wireguard_public_key = bytes[97..129]
            .try_into()
            .map_err(|_| CredentialError::Malformed)?;
        let serial_uuid =
            Uuid::from_slice(&bytes[129..145]).map_err(|_| CredentialError::Malformed)?;
        let serial =
            CredentialSerial::from_uuid(serial_uuid).map_err(|_| CredentialError::Malformed)?;
        let not_before = UnixTime(u64::from_be_bytes(
            bytes[145..153]
                .try_into()
                .map_err(|_| CredentialError::Malformed)?,
        ));
        let not_after = UnixTime(u64::from_be_bytes(
            bytes[153..161]
                .try_into()
                .map_err(|_| CredentialError::Malformed)?,
        ));
        let signature = bytes[161..225]
            .try_into()
            .map_err(|_| CredentialError::Malformed)?;
        let credential = Self {
            role,
            mesh_id,
            subject,
            identity_public_key,
            public_noise_key,
            wireguard_public_key,
            serial,
            not_before,
            not_after,
            signature,
        };
        validate_subject_keys(
            credential.subject,
            &credential.identity_public_key,
            &credential.public_noise_key,
            &credential.wireguard_public_key,
        )
        .map_err(|_| CredentialError::Malformed)?;
        validate_interval(credential.not_before, credential.not_after)?;
        Ok(credential)
    }

    /// Verifies this credential with an already authenticated Authority key.
    ///
    /// The caller remains responsible for establishing that the Authority is
    /// Root-certified, belongs to the same mesh, and is not revoked.
    pub fn verify_with_authority(
        &self,
        authority_public_key: &[u8; 32],
        now: UnixTime,
    ) -> Result<(), CredentialError> {
        if self.role != self.subject.role() {
            return Err(CredentialError::InvalidSignature);
        }
        validate_subject_keys(
            self.subject,
            &self.identity_public_key,
            &self.public_noise_key,
            &self.wireguard_public_key,
        )?;
        validate_interval(self.not_before, self.not_after)?;
        validate_time(self.not_before, self.not_after, now)?;
        VerifyingKey::from_bytes(authority_public_key)
            .map_err(|_| CredentialError::InvalidSignature)?
            .verify(
                &subject_transcript(&self.unsigned()),
                &Signature::from_bytes(&self.signature),
            )
            .map_err(|_| CredentialError::InvalidSignature)
    }
}

pub(crate) fn validate_subject_keys(
    subject: SubjectId,
    identity_public_key: &[u8; 32],
    session_public_key: &[u8; 32],
    wireguard_public_key: &[u8; 32],
) -> Result<(), CredentialError> {
    let identity_valid = match subject {
        SubjectId::Peer(_) => {
            identity_public_key.iter().any(|byte| *byte != 0)
                && contributory_wireguard_key(wireguard_public_key)
                && wireguard_public_key != session_public_key
                && wireguard_public_key != identity_public_key
        }
        SubjectId::Relay(_) => {
            identity_public_key.iter().all(|byte| *byte == 0)
                && wireguard_public_key.iter().all(|byte| *byte == 0)
        }
    };
    if identity_valid && session_public_key.iter().any(|byte| *byte != 0) {
        Ok(())
    } else {
        Err(CredentialError::InvalidKey)
    }
}

fn contributory_wireguard_key(key: &[u8; 32]) -> bool {
    // Reject low-order points at enrollment/issuance, before one bad binding
    // can prevent an otherwise valid Mesh directory from being installed.
    x25519_dalek::StaticSecret::from([0x42; 32])
        .diffie_hellman(&x25519_dalek::PublicKey::from(*key))
        .was_contributory()
}

/// Root-anchored active authorities and exact serial revocations.
#[derive(Clone)]
pub struct TrustSet {
    root: RootPublicKey,
    mesh_id: MeshId,
    authorities: Vec<AuthorityCertificate>,
    revoked_authority_serials: BTreeSet<CredentialSerial>,
    revoked_subject_serials: BTreeSet<CredentialSerial>,
    authority_revision: Option<u64>,
    authority_revision_resumed: bool,
}

impl TrustSet {
    /// Mesh identity bound to this trust set.
    pub fn mesh_id(&self) -> MeshId {
        self.mesh_id
    }

    /// Root identity for binding local durable state across credential rotations.
    pub fn root_public_key(&self) -> RootPublicKey {
        self.root
    }

    /// Creates an empty root-anchored authority set.
    pub fn new(root: RootPublicKey, mesh_id: MeshId) -> Self {
        Self {
            root,
            mesh_id,
            authorities: Vec::new(),
            revoked_authority_serials: BTreeSet::new(),
            revoked_subject_serials: BTreeSet::new(),
            authority_revision: None,
            authority_revision_resumed: false,
        }
    }

    /// Restores a persisted Authority revision after all corresponding certificates were verified.
    pub fn resume_authority_revision(&mut self, revision: u64) -> Result<(), CredentialError> {
        if revision == 0 || self.authority_revision.is_some() || self.authorities.is_empty() {
            return Err(CredentialError::NonCanonical);
        }
        self.authority_revision = Some(revision);
        self.authority_revision_resumed = true;
        Ok(())
    }

    /// Adds an authority only after root and mesh validation.
    pub fn add_authority(
        &mut self,
        certificate: AuthorityCertificate,
        now: UnixTime,
    ) -> Result<(), CredentialError> {
        self.root
            .verify_authority(&certificate, self.mesh_id, now)?;
        self.authorities.push(certificate);
        Ok(())
    }

    /// Verifies that distribution keys are signed by a currently valid,
    /// root-certified, non-revoked authority in this mesh.
    pub fn verify_distribution(
        &self,
        certificate: &DistributionCertificate,
        now: UnixTime,
    ) -> Result<(), CredentialError> {
        if certificate.mesh_id != self.mesh_id {
            return Err(CredentialError::WrongMesh);
        }
        let authority = self
            .authorities
            .iter()
            .find(|authority| authority.public_key == certificate.authority_public_key)
            .ok_or(CredentialError::InvalidSignature)?;
        if self.revoked_authority_serials.contains(&authority.serial) {
            return Err(CredentialError::Revoked);
        }
        validate_time(authority.not_before, authority.not_after, now)?;
        VerifyingKey::from_bytes(&certificate.authority_public_key)
            .map_err(|_| CredentialError::InvalidSignature)?
            .verify(
                &distribution_transcript(certificate),
                &Signature::from_bytes(&certificate.signature),
            )
            .map_err(|_| CredentialError::InvalidSignature)
    }

    /// Revokes one exact subject serial without affecting replacements.
    pub fn revoke_subject(&mut self, serial: CredentialSerial) {
        self.revoked_subject_serials.insert(serial);
    }

    /// Revokes one exact authority serial without affecting overlapping replacements.
    pub fn revoke_authority(&mut self, serial: CredentialSerial) {
        self.revoked_authority_serials.insert(serial);
    }

    /// Verifies a subject against any currently valid rooted authority.
    pub fn verify_subject(
        &self,
        credential: &SubjectCredential,
        now: UnixTime,
    ) -> Result<(), CredentialError> {
        self.subject_valid_until(credential, now).map(|_| ())
    }

    /// Verifies a subject and bounds authorization by its authenticating Authority.
    pub fn subject_valid_until(
        &self,
        credential: &SubjectCredential,
        now: UnixTime,
    ) -> Result<UnixTime, CredentialError> {
        if credential.mesh_id != self.mesh_id {
            return Err(CredentialError::WrongMesh);
        }
        if credential.role != credential.subject.role() {
            return Err(CredentialError::InvalidSignature);
        }
        if self.revoked_subject_serials.contains(&credential.serial) {
            return Err(CredentialError::Revoked);
        }
        let mut valid_until = None;
        for authority in &self.authorities {
            if self.revoked_authority_serials.contains(&authority.serial) {
                continue;
            }
            if self
                .root
                .verify_authority(authority, self.mesh_id, now)
                .is_err()
            {
                continue;
            }
            if credential
                .verify_with_authority(&authority.public_key, now)
                .is_ok()
            {
                let until = credential.not_after.min(authority.not_after);
                valid_until =
                    Some(valid_until.map_or(until, |previous: UnixTime| previous.max(until)));
            }
        }
        valid_until.ok_or(CredentialError::InvalidSignature)
    }
}
