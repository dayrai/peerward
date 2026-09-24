/// Produces the canonical root-authority transcript.
pub fn authority_transcript(value: &UnsignedAuthority) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(AUTHORITY_DOMAIN.len() + 72);
    bytes.extend_from_slice(AUTHORITY_DOMAIN);
    bytes.extend_from_slice(value.mesh_id.as_bytes());
    bytes.extend_from_slice(value.serial.as_bytes());
    bytes.extend_from_slice(&value.public_key);
    bytes.extend_from_slice(&value.not_before.0.to_be_bytes());
    bytes.extend_from_slice(&value.not_after.0.to_be_bytes());
    bytes
}

/// Produces the canonical authority-subject transcript.
pub fn subject_transcript(value: &UnsignedSubject) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(SUBJECT_DOMAIN.len() + 161);
    bytes.extend_from_slice(SUBJECT_DOMAIN);
    bytes.push(value.subject.role().transcript_tag());
    bytes.extend_from_slice(value.mesh_id.as_bytes());
    bytes.extend_from_slice(&value.subject.bytes());
    bytes.extend_from_slice(&value.identity_public_key);
    bytes.extend_from_slice(&value.public_noise_key);
    bytes.extend_from_slice(&value.wireguard_public_key);
    bytes.extend_from_slice(value.serial.as_bytes());
    bytes.extend_from_slice(&value.not_before.0.to_be_bytes());
    bytes.extend_from_slice(&value.not_after.0.to_be_bytes());
    bytes
}

fn distribution_transcript(value: &DistributionCertificate) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(DISTRIBUTION_DOMAIN.len() + 144);
    bytes.extend_from_slice(DISTRIBUTION_DOMAIN);
    bytes.extend_from_slice(value.mesh_id.as_bytes());
    bytes.extend_from_slice(&value.authority_public_key);
    bytes.extend_from_slice(&value.directory_public_key);
    bytes.extend_from_slice(&value.service_public_key);
    bytes.extend_from_slice(&value.audit_public_key);
    bytes
}

fn validate_interval(start: UnixTime, end: UnixTime) -> Result<(), CredentialError> {
    if start < end {
        Ok(())
    } else {
        Err(CredentialError::InvalidInterval)
    }
}

fn validate_time(start: UnixTime, end: UnixTime, now: UnixTime) -> Result<(), CredentialError> {
    if start <= now && now < end {
        Ok(())
    } else {
        Err(CredentialError::OutsideValidity)
    }
}
