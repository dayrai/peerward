/// Reconstructs rooted Mesh trust from the opaque profile; private material remains transient.
pub(crate) fn mobile_wireguard_from_profile(
    blob: &[u8],
    private: StaticSecret,
    now: UnixTime,
) -> Result<MobileWireguard, MobileError> {
    let profile = parse_profile_blob(blob)?;
    let decode = |value: &str| {
        URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|_| MobileError::InvalidInput)
    };
    let mesh = MeshId::from_uuid(
        Uuid::parse_str(&profile.mesh_id).map_err(|_| MobileError::InvalidInput)?,
    )
    .map_err(|_| MobileError::InvalidInput)?;
    let peer = PeerId::from_uuid(
        Uuid::parse_str(&profile.peer_id).map_err(|_| MobileError::InvalidInput)?,
    )
    .map_err(|_| MobileError::InvalidInput)?;
    let key = |value: &str| decode_32(value).ok_or(MobileError::InvalidInput);
    let mut credentials = TrustSet::new(
        peerward_credentials::RootPublicKey::from_bytes(&key(&profile.root_public_key)?)?,
        mesh,
    );
    for certificate in &profile.authority_certificates {
        credentials.add_authority(
            peerward_credentials::AuthorityCertificate::decode(&decode(certificate)?)?,
            now,
        )?;
    }
    if profile.authority_revision > 0 {
        credentials.resume_authority_revision(profile.authority_revision)?;
    }
    let credential = SubjectCredential::decode(&decode(&profile.credential)?)?;
    if credential.mesh_id != mesh
        || credential.subject != SubjectId::Peer(peer)
        || credential.identity_public_key != key(&profile.local_identity_public)?
        || credential.public_noise_key != key(&profile.local_noise_public)?
        || credential.wireguard_public_key != key(&profile.local_wireguard_public)?
    {
        return Err(MobileError::InvalidInput);
    }
    let trust = MobileTrust::new(
        mesh,
        credentials,
        DirectoryPublicKey::from_bytes(&key(&profile.distribution_public_key)?)?,
        ServiceSnapshotVerifier::from_bytes(&key(&profile.service_public_key)?)?,
        key(&profile.audit_public_key)?,
        &DistributionCertificate::decode(&decode(&profile.distribution_certificate)?)?,
        now,
    )?;
    MobileWireguard::new(&trust, credential, private, usize::from(profile.mtu), now)
}
