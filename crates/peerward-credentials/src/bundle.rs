const MAX_OVERLAP_AUTHORITIES: usize = 8;
const MAX_REVOKED_AUTHORITIES: usize = 65_536;
const AUTHORITY_CERTIFICATE_LENGTH: usize = 144;

/// Monotonic Root-anchored lifecycle view for one mesh's online authorities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityBundle {
    /// Mesh isolation boundary.
    pub mesh_id: MeshId,
    /// Monotonic authority lifecycle revision.
    pub revision: u64,
    /// The only authority allowed to publish new state.
    pub active: AuthorityCertificate,
    /// Still-valid authorities accepted only during bounded rotation overlap.
    pub overlap: Vec<AuthorityCertificate>,
    /// Exact authority serials that must no longer verify subjects.
    pub revoked: Vec<CredentialSerial>,
}

impl AuthorityBundle {
    fn validate_shape(&self) -> Result<(), CredentialError> {
        if self.active.mesh_id != self.mesh_id
            || self.overlap.len() > MAX_OVERLAP_AUTHORITIES
            || self.revoked.len() > MAX_REVOKED_AUTHORITIES
            || self
                .overlap
                .iter()
                .any(|certificate| certificate.mesh_id != self.mesh_id)
            || !strictly_increasing(self.overlap.iter().map(|certificate| certificate.serial))
            || !strictly_increasing(self.revoked.iter().copied())
            || self
                .overlap
                .iter()
                .any(|certificate| certificate.serial == self.active.serial)
            || self.revoked.contains(&self.active.serial)
            || self
                .overlap
                .iter()
                .any(|certificate| self.revoked.contains(&certificate.serial))
        {
            return Err(CredentialError::NonCanonical);
        }
        Ok(())
    }
}

/// Active-Authority-signed authority lifecycle bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedAuthorityBundle {
    /// Canonical lifecycle contents.
    pub bundle: AuthorityBundle,
    /// Signature made by `bundle.active` over the fixed transcript.
    pub signature: [u8; 64],
}

impl SignedAuthorityBundle {
    /// Encodes one strict, bounded transport representation.
    pub fn encode(&self) -> Result<Vec<u8>, CredentialError> {
        self.bundle.validate_shape()?;
        let overlap_count = u32::try_from(self.bundle.overlap.len())
            .map_err(|_| CredentialError::NonCanonical)?;
        let revoked_count = u32::try_from(self.bundle.revoked.len())
            .map_err(|_| CredentialError::NonCanonical)?;
        let mut bytes = Vec::with_capacity(
            16 + 8
                + AUTHORITY_CERTIFICATE_LENGTH
                + 4
                + self.bundle.overlap.len() * AUTHORITY_CERTIFICATE_LENGTH
                + 4
                + self.bundle.revoked.len() * 16
                + 64,
        );
        bytes.extend_from_slice(self.bundle.mesh_id.as_bytes());
        bytes.extend_from_slice(&self.bundle.revision.to_be_bytes());
        bytes.extend_from_slice(&self.bundle.active.encode());
        bytes.extend_from_slice(&overlap_count.to_be_bytes());
        for certificate in &self.bundle.overlap {
            bytes.extend_from_slice(&certificate.encode());
        }
        bytes.extend_from_slice(&revoked_count.to_be_bytes());
        for serial in &self.bundle.revoked {
            bytes.extend_from_slice(serial.as_bytes());
        }
        bytes.extend_from_slice(&self.signature);
        Ok(bytes)
    }

    /// Decodes only the exact canonical transport representation.
    pub fn decode(bytes: &[u8]) -> Result<Self, CredentialError> {
        let minimum = 16 + 8 + AUTHORITY_CERTIFICATE_LENGTH + 4 + 4 + 64;
        if bytes.len() < minimum {
            return Err(CredentialError::Malformed);
        }
        let mesh_id = MeshId::from_uuid(
            Uuid::from_slice(&bytes[..16]).map_err(|_| CredentialError::Malformed)?,
        )
        .map_err(|_| CredentialError::Malformed)?;
        let revision = u64::from_be_bytes(
            bytes[16..24]
                .try_into()
                .map_err(|_| CredentialError::Malformed)?,
        );
        let active_end = 24 + AUTHORITY_CERTIFICATE_LENGTH;
        let active = AuthorityCertificate::decode(&bytes[24..active_end])?;
        let mut cursor = active_end;
        let overlap_count = take_count(bytes, &mut cursor, MAX_OVERLAP_AUTHORITIES)?;
        let overlap_bytes = overlap_count
            .checked_mul(AUTHORITY_CERTIFICATE_LENGTH)
            .ok_or(CredentialError::Malformed)?;
        let overlap_end = cursor
            .checked_add(overlap_bytes)
            .ok_or(CredentialError::Malformed)?;
        if overlap_end > bytes.len() {
            return Err(CredentialError::Malformed);
        }
        let overlap = bytes[cursor..overlap_end]
            .chunks_exact(AUTHORITY_CERTIFICATE_LENGTH)
            .map(AuthorityCertificate::decode)
            .collect::<Result<Vec<_>, _>>()?;
        cursor = overlap_end;
        let revoked_count = take_count(bytes, &mut cursor, MAX_REVOKED_AUTHORITIES)?;
        let revoked_bytes = revoked_count
            .checked_mul(16)
            .ok_or(CredentialError::Malformed)?;
        let revoked_end = cursor
            .checked_add(revoked_bytes)
            .ok_or(CredentialError::Malformed)?;
        let signature_end = revoked_end
            .checked_add(64)
            .ok_or(CredentialError::Malformed)?;
        if signature_end != bytes.len() {
            return Err(CredentialError::Malformed);
        }
        let revoked = bytes[cursor..revoked_end]
            .chunks_exact(16)
            .map(|value| {
                CredentialSerial::from_uuid(
                    Uuid::from_slice(value).map_err(|_| CredentialError::Malformed)?,
                )
                .map_err(|_| CredentialError::Malformed)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let signed = Self {
            bundle: AuthorityBundle {
                mesh_id,
                revision,
                active,
                overlap,
                revoked,
            },
            signature: bytes[revoked_end..signature_end]
                .try_into()
                .map_err(|_| CredentialError::Malformed)?,
        };
        signed.bundle.validate_shape()?;
        Ok(signed)
    }
}

impl RootPublicKey {
    /// Verifies and constructs an atomic trust set from a newer authority bundle.
    pub fn verify_authority_bundle(
        self,
        signed: &SignedAuthorityBundle,
        mesh_id: MeshId,
        accepted_revision: Option<u64>,
        now: UnixTime,
    ) -> Result<TrustSet, CredentialError> {
        let bundle = &signed.bundle;
        bundle.validate_shape()?;
        if bundle.mesh_id != mesh_id {
            return Err(CredentialError::WrongMesh);
        }
        if accepted_revision.is_some_and(|accepted| bundle.revision <= accepted) {
            return Err(CredentialError::Rollback);
        }
        self.verify_authority(&bundle.active, mesh_id, now)?;
        for certificate in &bundle.overlap {
            self.verify_authority(certificate, mesh_id, now)?;
        }
        VerifyingKey::from_bytes(&bundle.active.public_key)
            .map_err(|_| CredentialError::InvalidSignature)?
            .verify(
                &authority_bundle_transcript(bundle),
                &Signature::from_bytes(&signed.signature),
            )
            .map_err(|_| CredentialError::InvalidSignature)?;
        let mut trust = TrustSet::new(self, mesh_id);
        trust.authority_revision = Some(bundle.revision);
        trust.authorities.push(bundle.active.clone());
        trust.authorities.extend(bundle.overlap.iter().cloned());
        trust
            .revoked_authority_serials
            .extend(bundle.revoked.iter().copied());
        Ok(trust)
    }
}

impl TrustSet {
    /// Last atomically accepted authority-bundle revision, if dynamically installed.
    pub const fn authority_revision(&self) -> Option<u64> {
        self.authority_revision
    }

    /// Replaces authority trust atomically while retaining exact subject revocations.
    pub fn install_authority_bundle(
        &mut self,
        signed: &SignedAuthorityBundle,
        now: UnixTime,
    ) -> Result<(), CredentialError> {
        let mut replacement = self.root.verify_authority_bundle(
            signed,
            self.mesh_id,
            self.authority_revision,
            now,
        )?;
        if replacement.authorities.iter().any(|certificate| self.revoked_authority_serials.contains(&certificate.serial)) {
            return Err(CredentialError::Revoked);
        }
        replacement.revoked_authority_serials.extend(self.revoked_authority_serials.iter().copied());
        replacement
            .revoked_subject_serials
            .clone_from(&self.revoked_subject_serials);
        *self = replacement;
        Ok(())
    }

    /// Completes a persisted revision restore from its signed bundle exactly once.
    ///
    /// A persisted client profile contains the already root-verified active/overlap
    /// certificates and their revision, but not the signed bundle's revoked-authority
    /// set. The first live publication at that same revision may therefore complete
    /// restoration only when its signature is valid and its certificate sequence is
    /// byte-for-byte identical. Normal installs and every later duplicate remain
    /// strictly monotonic.
    pub fn install_authority_bundle_after_resume(
        &mut self,
        signed: &SignedAuthorityBundle,
        now: UnixTime,
    ) -> Result<(), CredentialError> {
        if !self.authority_revision_resumed
            || self.authority_revision != Some(signed.bundle.revision)
        {
            return self.install_authority_bundle(signed, now);
        }
        let mut replacement = self.root.verify_authority_bundle(
            signed,
            self.mesh_id,
            None,
            now,
        )?;
        if replacement.authorities != self.authorities {
            return Err(CredentialError::Rollback);
        }
        if replacement.authorities.iter().any(|certificate| self.revoked_authority_serials.contains(&certificate.serial)) {
            return Err(CredentialError::Revoked);
        }
        replacement.revoked_authority_serials.extend(self.revoked_authority_serials.iter().copied());
        replacement
            .revoked_subject_serials
            .clone_from(&self.revoked_subject_serials);
        *self = replacement;
        Ok(())
    }
}

/// Produces the canonical authority-bundle transcript.
pub fn authority_bundle_transcript(bundle: &AuthorityBundle) -> Vec<u8> {
    let mut bytes = Vec::from(AUTHORITY_BUNDLE_DOMAIN);
    bytes.extend_from_slice(bundle.mesh_id.as_bytes());
    bytes.extend_from_slice(&bundle.revision.to_be_bytes());
    bytes.extend_from_slice(&bundle.active.encode());
    put_count(&mut bytes, bundle.overlap.len());
    for certificate in &bundle.overlap {
        bytes.extend_from_slice(&certificate.encode());
    }
    put_count(&mut bytes, bundle.revoked.len());
    for serial in &bundle.revoked {
        bytes.extend_from_slice(serial.as_bytes());
    }
    bytes
}

fn take_count(
    bytes: &[u8],
    cursor: &mut usize,
    maximum: usize,
) -> Result<usize, CredentialError> {
    let end = cursor.checked_add(4).ok_or(CredentialError::Malformed)?;
    let raw = bytes.get(*cursor..end).ok_or(CredentialError::Malformed)?;
    *cursor = end;
    let count = usize::try_from(u32::from_be_bytes(
        raw.try_into().map_err(|_| CredentialError::Malformed)?,
    ))
    .map_err(|_| CredentialError::Malformed)?;
    if count > maximum {
        return Err(CredentialError::NonCanonical);
    }
    Ok(count)
}

fn put_count(bytes: &mut Vec<u8>, value: usize) {
    bytes.extend_from_slice(
        &u32::try_from(value)
            .expect("validated authority collection length")
            .to_be_bytes(),
    );
}

fn strictly_increasing<T: Ord>(values: impl Iterator<Item = T>) -> bool {
    let mut previous = None;
    for value in values {
        if previous.as_ref().is_some_and(|old| old >= &value) {
            return false;
        }
        previous = Some(value);
    }
    true
}
