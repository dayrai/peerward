fn publisher_correlation(row: sqlx::postgres::PgRow) -> Result<CorrelationContext, ApiError> {
    CorrelationContext::from_parts(
        row.try_get("request_id")?,
        row.try_get::<Vec<u8>, _>("trace_id")?
            .try_into()
            .map_err(|_| publisher_error())?,
        row.try_get::<Vec<u8>, _>("span_id")?
            .try_into()
            .map_err(|_| publisher_error())?,
        u8::try_from(row.try_get::<i16, _>("trace_flags")?).map_err(|_| publisher_error())?,
    )
    .map_err(|_| publisher_error())
}

fn relay_topology_publication_due(
    previous: &RelayTopologyV1,
    candidate: &RelayTopologyV1,
    published_at: OffsetDateTime,
    now: OffsetDateTime,
) -> bool {
    let structural_change = previous.mode != candidate.mode
        || previous.nodes != candidate.nodes
        || previous.edges.len() != candidate.edges.len()
        || previous
            .edges
            .iter()
            .zip(&candidate.edges)
            .any(|(old, new)| old.left != new.left || old.right != new.right);
    structural_change
        || (previous.edges != candidate.edges && published_at <= now - TimeDuration::seconds(30))
}

async fn issue_pending_peer_rotations(
    store: &Store,
    mesh_id: MeshId,
    issuer: &JoinIssuer,
) -> Result<(), ApiError> {
    let now_seconds =
        u64::try_from(OffsetDateTime::now_utc().unix_timestamp()).map_err(|_| publisher_error())?;
    let not_after = now_seconds
        .saturating_add(issuer.validity_seconds)
        .min(issuer.authority_certificate.not_after.0);
    if not_after <= now_seconds.saturating_add(60) {
        return Err(ApiError::unavailable(
            "rotation_authority_expiring",
            "online Authority validity is too short for credential rotation",
        ));
    }
    for request in store.pending_peer_rotations(mesh_id, 128).await? {
        let deadline: Option<OffsetDateTime> =
            sqlx::query_scalar("SELECT admission_until FROM peers WHERE mesh_id=$1 AND id=$2")
                .bind(mesh_id.into_uuid())
                .bind(request.peer_id.into_uuid())
                .fetch_one(store.pool())
                .await?;
        let not_after = not_after.min(
            deadline
                .map(|value| u64::try_from(value.unix_timestamp()).map_err(|_| publisher_error()))
                .transpose()?
                .unwrap_or(u64::MAX),
        );
        if not_after <= now_seconds.saturating_add(60) {
            continue;
        }

        let credential = issuer
            .authority
            .issue(UnsignedSubject {
                subject: SubjectId::Peer(request.peer_id),
                mesh_id,
                identity_public_key: request.identity_public_key,
                public_noise_key: request.session_public_key,
                wireguard_public_key: request.wireguard_public_key,
                serial: CredentialSerial::new(),
                not_before: UnixTime(now_seconds),
                not_after: UnixTime(not_after),
            })
            .map_err(|_| publisher_error())?;
        let credential_row = IssuedPeerCredential {
            authority_id: issuer.authority_id,
            authority_public_key: Some(issuer.authority.public_key().to_vec()),
            serial: credential.serial,
            not_before: OffsetDateTime::from_unix_timestamp(
                i64::try_from(credential.not_before.0).map_err(|_| publisher_error())?,
            )
            .map_err(|_| publisher_error())?,
            not_after: OffsetDateTime::from_unix_timestamp(
                i64::try_from(credential.not_after.0).map_err(|_| publisher_error())?,
            )
            .map_err(|_| publisher_error())?,
            signature: credential.signature.to_vec(),
        };
        store
            .issue_peer_rotation(&request, &credential_row, &credential.encode())
            .await?;
    }
    Ok(())
}

fn revision(row: &sqlx::postgres::PgRow, column: &str) -> Result<u64, ApiError> {
    u64::try_from(row.try_get::<i64, _>(column)?).map_err(|_| publisher_error())
}

fn publisher_labels(value: &Value) -> Result<BTreeMap<String, String>, ApiError> {
    value
        .as_object()
        .ok_or_else(publisher_error)?
        .iter()
        .map(|(key, value)| {
            value
                .as_str()
                .map(|value| (key.clone(), value.to_owned()))
                .ok_or_else(publisher_error)
        })
        .collect()
}

fn publisher_peer(
    row: sqlx::postgres::PgRow,
    mesh_id: MeshId,
    issuer: &JoinIssuer,
) -> Result<peerward_directory::SignedPeerEntry, ApiError> {
    let id: Uuid = row.try_get("id")?;
    let peer_id = PeerId::from_uuid(id).map_err(|_| publisher_error())?;
    let address = row
        .try_get::<String, _>("address")?
        .parse()
        .map_err(|_| publisher_error())?;
    let mut labels = publisher_labels(&row.try_get::<Value, _>("labels")?)?;
    // DNS is resolved exclusively from authenticated directory state. Keep the
    // resource name authoritative even if an old client stored a conflicting
    // user label under the reserved directory key.
    labels.insert("name".into(), row.try_get("name")?);
    let not_after: OffsetDateTime = row.try_get("not_after")?;
    let not_after = u64::try_from(not_after.unix_timestamp())
        .map(UnixTime)
        .map_err(|_| publisher_error())?;
    let public_key = row
        .try_get::<Vec<u8>, _>("public_key")?
        .try_into()
        .map_err(|_| publisher_error())?;
    let identity_public_key = row
        .try_get::<Vec<u8>, _>("identity_public_key")?
        .try_into()
        .map_err(|_| publisher_error())?;
    let serial = credential_serial(row.try_get("serial")?)?;
    let bindings = row.try_get::<Value, _>("accepted_bindings")?;
    let accepted_credentials = bindings
        .as_array()
        .ok_or_else(publisher_error)?
        .iter()
        .map(publisher_credential_binding)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(issuer.directory.sign_peer(PeerEntry {
        secondary_address: row
            .try_get::<Option<String>, _>("secondary_address")?
            .map(|value| value.parse().map_err(|_| publisher_error()))
            .transpose()?,
        mesh_id,
        peer_id,
        address,
        identity_public_key,
        noise_public_key: public_key,
        credential_serial: serial,
        accepted_credentials,
        enabled: true,
        labels,
        not_after,
    }))
}

fn publisher_relay(row: sqlx::postgres::PgRow) -> Result<RelayEntry, ApiError> {
    let peer_endpoints = publisher_endpoints(row.try_get("peer_endpoints")?)?;
    let backbone_endpoints = publisher_endpoints(row.try_get("backbone_endpoints")?)?;
    Ok(RelayEntry {
        relay_id: RelayId::from_uuid(row.try_get("id")?).map_err(|_| publisher_error())?,
        peer_endpoints,
        backbone_endpoints,
        noise_public_key: row
            .try_get::<Vec<u8>, _>("public_key")?
            .try_into()
            .map_err(|_| publisher_error())?,
        credential_serial: credential_serial(row.try_get("serial")?)?,
    })
}

fn publisher_service(row: sqlx::postgres::PgRow) -> Result<RemoteService, ApiError> {
    let listen_port =
        u16::try_from(row.try_get::<i32, _>("listen_port")?).map_err(|_| publisher_error())?;
    let protocols = row
        .try_get::<Vec<String>, _>("protocols")?
        .into_iter()
        .map(|protocol| match protocol.as_str() {
            "tcp" => Ok(ServiceProtocol::Tcp),
            "udp" => Ok(ServiceProtocol::Udp),
            _ => Err(publisher_error()),
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(RemoteService {
        id: ServiceId::from_uuid(row.try_get("id")?).map_err(|_| publisher_error())?,
        owner: PeerId::from_uuid(row.try_get("peer_id")?).map_err(|_| publisher_error())?,
        credential_serial: credential_serial(row.try_get("serial")?)?,
        virtual_address: row
            .try_get::<String, _>("address")?
            .parse()
            .map_err(|_| publisher_error())?,
        protocols,
        listen_port,
        alias: row.try_get("alias")?,
    })
}

fn publisher_endpoints(values: Vec<String>) -> Result<Vec<NetworkEndpoint>, ApiError> {
    let endpoints = values
        .into_iter()
        .map(|endpoint| endpoint.parse())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| publisher_error())?;
    validate_endpoint_list(&endpoints).map_err(|_| publisher_error())?;
    Ok(endpoints)
}

fn credential_serial(value: Uuid) -> Result<CredentialSerial, ApiError> {
    CredentialSerial::from_uuid(value).map_err(|_| publisher_error())
}

fn publisher_error() -> ApiError {
    ApiError::unavailable(
        "signed_state_unavailable",
        "signed control state could not be built",
    )
}

fn publisher_credential_binding(
    value: &Value,
) -> Result<peerward_directory::PeerCredentialBinding, ApiError> {
    fn key<const N: usize>(value: &Value, field: &str) -> Result<[u8; N], ApiError> {
        hex::decode(value[field].as_str().ok_or_else(publisher_error)?)
            .map_err(|_| publisher_error())?
            .try_into()
            .map_err(|_| publisher_error())
    }
    Ok(peerward_directory::PeerCredentialBinding {
        serial: value["serial"]
            .as_str()
            .ok_or_else(publisher_error)?
            .parse()
            .map_err(|_| publisher_error())?,
        identity_public_key: key(value, "identity_public_key")?,
        noise_public_key: key(value, "noise_public_key")?,
        wireguard_public_key: key(value, "wireguard_public_key")?,
        not_before: UnixTime(value["not_before"].as_u64().ok_or_else(publisher_error)?),
        not_after: UnixTime(value["not_after"].as_u64().ok_or_else(publisher_error)?),
        overlap_until: if value["overlap_until"].is_null() {
            None
        } else {
            Some(UnixTime(
                value["overlap_until"]
                    .as_u64()
                    .ok_or_else(publisher_error)?,
            ))
        },
        signature: key(value, "signature")?,
    })
}
