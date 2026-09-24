/// Persists an already Root-verified replacement before its activation signature is sent.
/// With an empty credential, produces a temporary candidate profile WITHOUT writing/committing it.
pub(crate) fn mobile_rotation_recovery(
    blob: &[u8],
    credential: &[u8],
) -> Result<Vec<u8>, MobileError> {
    let mut profile = parse_profile_blob(blob)?;
    if credential.is_empty() {
        let Some(staged) = profile.pending_credential.as_deref() else {
            return Ok(Vec::new());
        };
        let bytes = Zeroizing::new(URL_SAFE_NO_PAD
            .decode(staged)
            .map_err(|_| MobileError::InvalidInput)?);
        return commit_mobile_rotation(blob, &bytes);
    }
    // The commit codec checks Mesh, Peer and all three staged public keys. Discard the
    // resulting temporary profile; durable active identity remains the old generation.
    let _temporary = Zeroizing::new(commit_mobile_rotation(blob, credential)?);
    if profile.pending_device_key_id.is_none() || profile.pending_rotation_id.is_none() {
        return Err(MobileError::InvalidState);
    }
    let encoded = URL_SAFE_NO_PAD.encode(credential);
    if encoded == profile.credential {
        return Err(MobileError::InvalidInput);
    }
    if profile
        .pending_credential
        .as_ref()
        .is_some_and(|previous| previous != &encoded)
    {
        return Err(MobileError::InvalidState);
    }
    profile.pending_credential = Some(encoded);
    encode_profile_document(&profile)
}
