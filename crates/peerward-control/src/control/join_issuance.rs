async fn join_enrollment_issuer(
    state: &AppState,
    selected_mesh: MeshId,
    claim: &PublicJoinClaim,
) -> Result<
    impl FnOnce(
        MeshId,
        PeerId,
        std::net::IpAddr,
        std::net::IpAddr,
        Option<u64>,
    ) -> Result<IssuedPeerEnrollment, StoreError>,
    ApiError,
> {
    let selected=sqlx::query("SELECT id AS authority_id FROM mesh_authorities WHERE mesh_id=$1 AND lifecycle='active' AND not_before<=clock_timestamp() AND not_after>clock_timestamp() ORDER BY created_at DESC LIMIT 1")
        .bind(selected_mesh.into_uuid()).fetch_optional(state.store.pool()).await?.ok_or_else(||ApiError::unavailable("active_authority_unavailable","no active Authority is available"))?;
    let selected_authority: Uuid = selected.try_get("authority_id")?;
    let selected_issuer = state
        .join_issuers
        .get(&selected_mesh)
        .and_then(|issuers| {
            issuers
                .iter()
                .find(|issuer| issuer.authority_id == selected_authority)
                .cloned()
        })
        .ok_or_else(|| {
            ApiError::unavailable(
                "active_authority_key_unavailable",
                "active Authority private key is not configured",
            )
        })?;

    let identity_key: [u8; 32] = claim
        .identity_public_key
        .as_slice()
        .try_into()
        .map_err(|_| ApiError::invalid("invalid_identity_key", "stored identity key is invalid"))?;
    let session_key: [u8; 32] =
        claim.public_noise_key.as_slice().try_into().map_err(|_| {
            ApiError::invalid("invalid_session_key", "stored session key is invalid")
        })?;
    let wireguard_key: [u8; 32] = claim
        .wireguard_public_key
        .as_slice()
        .try_into()
        .map_err(|_| ApiError::invalid("invalid_wireguard_key", "stored tunnel key is invalid"))?;
    let response_basis = load_join_response_basis(state, selected_mesh).await?;
    Ok(
        move |mesh_id,
              peer_id,
              address: std::net::IpAddr,
              secondary_address: std::net::IpAddr,
              admission_until: Option<u64>| {
            if mesh_id != selected_mesh {
                return Err(StoreError::Invalid("join issuer mesh"));
            }
            let issuer = selected_issuer;
            let now = OffsetDateTime::now_utc().unix_timestamp();
            let now = u64::try_from(now).map_err(|_| StoreError::Invalid("system clock"))?;
            let not_before = UnixTime(now.saturating_sub(60));
            let not_after = UnixTime(
                now.checked_add(issuer.validity_seconds)
                    .ok_or(StoreError::Invalid("credential validity"))?
                    .min(issuer.authority_certificate.not_after.0)
                    .min(admission_until.unwrap_or(u64::MAX)),
            );
            if not_after.0 <= now.saturating_add(60) {
                return Err(StoreError::Invalid("authority expiry"));
            }
            let serial = CredentialSerial::new();
            let credential = issuer
                .authority
                .issue(UnsignedSubject {
                    subject: SubjectId::Peer(peer_id),
                    mesh_id,
                    identity_public_key: identity_key,
                    public_noise_key: session_key,
                    wireguard_public_key: wireguard_key,
                    serial,
                    not_before,
                    not_after,
                })
                .map_err(|_| StoreError::Invalid("credential issuance"))?;
            let not_before = OffsetDateTime::from_unix_timestamp(
                i64::try_from(not_before.0).map_err(|_| StoreError::Invalid("validity"))?,
            )
            .map_err(|_| StoreError::Invalid("validity"))?;
            let not_after = OffsetDateTime::from_unix_timestamp(
                i64::try_from(not_after.0).map_err(|_| StoreError::Invalid("validity"))?,
            )
            .map_err(|_| StoreError::Invalid("validity"))?;
            let response = JoinResponse {
                profile_id: peer_id,
                mesh_id,
                peer_id,
                mesh_name: response_basis.mesh_name,
                address: format!("{address}/{}", if address.is_ipv4() { 32 } else { 128 }),
                secondary_address: Some(format!(
                    "{secondary_address}/{}",
                    if secondary_address.is_ipv4() { 32 } else { 128 }
                )),
                routes: vec![response_basis.address_cidr, response_basis.secondary_cidr],
                dns_servers: vec![response_basis.gateway],
                mtu: response_basis.mtu,
                stun_servers: issuer
                    .stun_servers
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
                dns_suffix: response_basis.dns_suffix,
                credential: URL_SAFE_NO_PAD.encode(credential.encode()),
                relays: response_basis.relays,
                root_public_key: URL_SAFE_NO_PAD.encode(issuer.root_public_key),
                authority_certificates: response_basis.authority_certificates,
                authority_revision: response_basis.authority_revision,
                distribution_public_key: URL_SAFE_NO_PAD
                    .encode(issuer.directory.public_key().to_bytes()),
                service_public_key: URL_SAFE_NO_PAD.encode(issuer.services.verifier().to_bytes()),
                audit_public_key: URL_SAFE_NO_PAD
                    .encode(audit_recipient_public(&issuer.audit_private_key)),
                distribution_certificate: URL_SAFE_NO_PAD
                    .encode(issuer.distribution_certificate.encode()),
            };
            let response_document =
                serde_json::to_vec(&response).map_err(|_| StoreError::Invalid("join response"))?;
            Ok(IssuedPeerEnrollment {
                credential: IssuedPeerCredential {
                    authority_id: issuer.authority_id,
                    authority_public_key: Some(issuer.authority.public_key().to_vec()),
                    serial,
                    not_before,
                    not_after,
                    signature: credential.signature.to_vec(),
                },
                response_document,
            })
        },
    )
}
