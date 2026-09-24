use peerward_api::{RelayHostAcknowledgement, RelayHostAssignment, RelayHostAssignments, RelayHostPublicKey, RelayTrustMaterial};

#[derive(Clone, Copy)]
struct RelayHostIdentity(Uuid);

async fn serve_relay_host_api(config: DynamicMeshConfig, state: AppState, ready: tokio::sync::oneshot::Sender<()>) -> Result<(), ApiError> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
    let _ = rustls::crypto::ring::default_provider().install_default();
    let certs = CertificateDer::pem_file_iter(&config.certificate_file).map_err(|_| dynamic_invalid())?
        .collect::<Result<Vec<_>,_>>().map_err(|_| dynamic_invalid())?;
    let private_bytes = Zeroizing::new(read_private(&config.private_key_file, 65_536).map_err(dynamic_io)?);
    let key = PrivateKeyDer::from_pem_slice(&private_bytes).map_err(|_| dynamic_invalid())?;
    let mut roots = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_file_iter(&config.ca_file).map_err(|_| dynamic_invalid())? {
        roots.add(cert.map_err(|_| dynamic_invalid())?).map_err(|_| dynamic_invalid())?;
    }
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots)).build().map_err(|_| dynamic_invalid())?;
    let tls = rustls::ServerConfig::builder().with_client_cert_verifier(verifier).with_single_cert(certs, key).map_err(|_| dynamic_invalid())?;
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
    let listener = TcpListener::bind(config.host_address).await.map_err(dynamic_io)?;
    let router = Router::new()
        .route("/internal/v1/relay-host/assignments", get(relay_host_assignments))
        .route("/internal/v1/relay-host/public-key", post(relay_host_public_key))
        .route("/internal/v1/relay-host/ack", post(relay_host_ack))
        .route("/internal/v1/relay-host/capacity-challenge", get(relay_capacity_challenge))
        .route("/internal/v1/relay-host/capacity", post(relay_capacity_report))
        .layer(DefaultBodyLimit::max(65_536)).with_state(state.clone());
    let limit = Arc::new(Semaphore::new(64));
    let _ = ready.send(());
    let mut connections = tokio::task::JoinSet::new();
    loop {
        let (socket, _) = tokio::select! {
            accepted = listener.accept() => accepted.map_err(dynamic_io)?,
            _ = connections.join_next(), if !connections.is_empty() => continue,
        };
        let Ok(permit) = Arc::clone(&limit).try_acquire_owned() else { continue; };
        let acceptor = acceptor.clone();
        let router = router.clone();
        let store = state.store.clone();
        connections.spawn(async move {
            let _permit = permit;
            let Ok(Ok(tls)) = tokio::time::timeout(Duration::from_secs(5), acceptor.accept(socket)).await else { return; };
            let Some(cert) = tls.get_ref().1.peer_certificates().and_then(|certs| certs.first()) else { return; };
            let fingerprint = Sha256::digest(cert.as_ref()).to_vec();
            let Ok(Some(host)) = sqlx::query_scalar::<_,Uuid>("SELECT id FROM relay_hosts WHERE certificate_sha256=$1 AND enabled")
                .bind(fingerprint).fetch_optional(store.pool()).await else { return; };
            let router = router.layer(Extension(RelayHostIdentity(host)));
            let service = hyper_util::service::TowerToHyperService::new(router);
            let builder = hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
            let _ = tokio::time::timeout(Duration::from_secs(15), builder.serve_connection(hyper_util::rt::TokioIo::new(tls), service)).await;
        });
    }
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RelayAssignmentQuery {
    after: Option<Uuid>,
    revision: Option<i64>,
}

async fn relay_host_assignments(Extension(RelayHostIdentity(host)): Extension<RelayHostIdentity>, State(state): State<AppState>,
    Query(query): Query<RelayAssignmentQuery>) -> Result<Json<RelayHostAssignments>, ApiError> {
    if query.after.is_some() && query.revision.is_none() { return Err(dynamic_invalid()); }
    let mut tx = state.store.begin_mutation().await?;
    // Holding the host row makes this page consistent with its version. Changes
    // between pages cause a conflict and a fresh scan, never a truncated snapshot.
    let row = sqlx::query("UPDATE relay_hosts SET last_seen=clock_timestamp() WHERE id=$1 AND enabled RETURNING revision,peer_endpoints,backbone_endpoints")
        .bind(host).fetch_optional(&mut *tx).await?.ok_or_else(ApiError::not_found)?;
    let revision: i64 = row.try_get("revision")?;
    if query.revision.is_some_and(|expected| expected != revision) {
        return Err(ApiError::conflict("assignment_changed", "Relay configuration changed during pagination"));
    }
    let mut rows = sqlx::query("SELECT a.*,t.termination FROM relay_host_assignments a LEFT JOIN mesh_tombstones t ON t.mesh_id=a.mesh_id WHERE a.host_id=$1 AND ($2::uuid IS NULL OR a.mesh_id>$2) ORDER BY a.mesh_id LIMIT 257")
        .bind(host).bind(query.after).fetch_all(&mut *tx).await?;
    let more = rows.len() > 256;
    rows.truncate(256);
    let next_mesh = if more { rows.last().map(|row| row.try_get::<Uuid,_>("mesh_id")).transpose()? } else { None };
    tx.commit().await?;
    let mut assignments = Vec::with_capacity(rows.len());
    for row in rows {
        let mesh = mesh_id(row.try_get("mesh_id")?)?;
        let credential: Option<Vec<u8>> = row.try_get("credential")?;
        let issuer = state.join_issuers.get(&mesh).and_then(|issuers| issuers.into_iter().find(|issuer| {
            let Some(bytes) = credential.as_ref() else { return false; };
            let Ok(subject) = peerward_credentials::SubjectCredential::decode(bytes) else { return false; };
            subject.verify_with_authority(&issuer.authority_certificate.public_key, UnixTime(current_unix_seconds())).is_ok()
        }));
        let material = issuer.zip(credential).map(|(issuer, credential)| RelayTrustMaterial {
            root_public_key: issuer.root_public_key.to_vec(), authority_certificate: issuer.authority_certificate.encode(),
            distribution_certificate: issuer.distribution_certificate.encode().to_vec(), credential,
        });
        assignments.push(RelayHostAssignment { mesh_id: mesh,
            relay_id: RelayId::from_uuid(row.try_get("relay_id")?).map_err(|_| ApiError::invalid_id())?,
            revision: row.try_get("revision")?, desired: row.try_get("desired")?, material,
            termination: row.try_get("termination")?,
        });
    }
    let endpoints = |field| -> Result<Vec<NetworkEndpoint>, ApiError> {
        row.try_get::<Vec<String>,_>(field)?.into_iter().map(|s| s.parse().map_err(|_| dynamic_invalid())).collect()
    };
    Ok(Json(RelayHostAssignments { host_id: host, revision,
        peer_endpoints: endpoints("peer_endpoints")?, backbone_endpoints: endpoints("backbone_endpoints")?, assignments, next_mesh }))
}

async fn relay_host_public_key(Extension(RelayHostIdentity(host)): Extension<RelayHostIdentity>, State(state): State<AppState>,
    Json(request): Json<RelayHostPublicKey>) -> Result<StatusCode, ApiError> {
    let public: [u8; 32] = request.public_key.as_slice().try_into().map_err(|_| dynamic_invalid())?;
    if public == [0; 32] { return Err(dynamic_invalid()); }
    let mut tx = state.store.begin_mutation().await?;
    let active: Option<String> = sqlx::query_scalar("SELECT lifecycle FROM meshes WHERE id=$1 FOR UPDATE")
        .bind(request.mesh_id.into_uuid()).fetch_optional(&mut *tx).await?;
    if !matches!(active.as_deref(), Some("creating" | "active")) { return Err(ApiError::not_found()); }
    let enabled: bool = sqlx::query_scalar("SELECT enabled FROM relay_hosts WHERE id=$1 FOR SHARE")
        .bind(host).fetch_one(&mut *tx).await?;
    if !enabled { return Err(ApiError::not_found()); }
    let row = sqlx::query("SELECT public_key,credential FROM relay_host_assignments WHERE host_id=$1 AND mesh_id=$2 AND relay_id=$3 AND revision=$4 AND desired='active' FOR UPDATE")
        .bind(host).bind(request.mesh_id.into_uuid()).bind(request.relay_id.into_uuid()).bind(request.revision)
        .fetch_optional(&mut *tx).await?.ok_or_else(ApiError::not_found)?;
    if let Some(existing) = row.try_get::<Option<Vec<u8>>,_>("public_key")? {
        if existing != public { return Err(ApiError::conflict("relay_key_conflict", "Relay identity already has another public key")); }
        if row.try_get::<Option<Vec<u8>>,_>("credential")?.is_some() { return Ok(StatusCode::OK); }
    }
    let candidates = state.join_issuers.get(&request.mesh_id).ok_or_else(dynamic_invalid)?;
    let issuer = active_issuer_with_executor(&mut *tx, request.mesh_id, &candidates).await?;
    let now = current_unix_seconds();
    let credential = issuer.authority.issue(UnsignedSubject { subject: SubjectId::Relay(request.relay_id),
        mesh_id: request.mesh_id, identity_public_key: [0; 32], public_noise_key: public, wireguard_public_key: [0; 32], serial: CredentialSerial::new(),
        not_before: UnixTime(now.saturating_sub(30)), not_after: UnixTime((now + 30 * 86400).min(issuer.authority_certificate.not_after.0)),
    }).map_err(|_| dynamic_invalid())?;
    sqlx::query("INSERT INTO relays(id,mesh_id,name,peer_endpoints,backbone_endpoints)
        SELECT $1,$2,'shared-relay-'||($1::uuid)::text,peer_endpoints,backbone_endpoints FROM relay_hosts WHERE id=$3 ON CONFLICT(id) DO NOTHING")
        .bind(request.relay_id.into_uuid()).bind(request.mesh_id.into_uuid()).bind(host).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO relay_credentials(id,mesh_id,relay_id,authority_id,serial,public_key,not_before,not_after,lifecycle,signature)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,'active',$9)")
        .bind(Uuid::new_v4()).bind(request.mesh_id.into_uuid()).bind(request.relay_id.into_uuid()).bind(issuer.authority_id)
        .bind(credential.serial.into_uuid()).bind(public.to_vec()).bind(timestamp(credential.not_before)?).bind(timestamp(credential.not_after)?)
        .bind(credential.signature.to_vec()).execute(&mut *tx).await?;
    sqlx::query("UPDATE relay_host_assignments SET public_key=$3,credential=$4,updated_at=clock_timestamp() WHERE host_id=$1 AND mesh_id=$2")
        .bind(host).bind(request.mesh_id.into_uuid()).bind(public.to_vec()).bind(credential.encode()).execute(&mut *tx).await?;
    sqlx::query("UPDATE meshes SET relay_revision=relay_revision+1 WHERE id=$1")
        .bind(request.mesh_id.into_uuid()).execute(&mut *tx).await?;
    state.store.commit_mutation(tx, &lifecycle_record(request.mesh_id, "relay-host", "relay.enrolled", "relay.enrolled")).await?;
    Ok(StatusCode::ACCEPTED)
}

async fn relay_host_ack(Extension(RelayHostIdentity(host)): Extension<RelayHostIdentity>, State(state): State<AppState>,
    Json(request): Json<RelayHostAcknowledgement>) -> Result<StatusCode, ApiError> {
    if !matches!(request.state.as_str(), "ready" | "removed" | "failed" | "draining" | "suspended") || request.error_code.as_ref().is_some_and(|s| s.len()>128) || request.active_sessions.is_some_and(|n|n>1_000_000) { return Err(dynamic_invalid()); }
    let result = sqlx::query("UPDATE relay_host_assignments SET applied_revision=$4,state=$5,error_code=$6,updated_at=clock_timestamp(),observed_at=clock_timestamp(),active_sessions=$7
        WHERE host_id=$1 AND mesh_id=$2 AND relay_id=$3 AND revision=$4
          AND EXISTS(SELECT 1 FROM relay_hosts h WHERE h.id=$1 AND h.enabled) AND
          (($5='removed' AND desired='removed') OR ($5='ready' AND desired='active') OR ($5=desired AND desired IN ('draining','suspended')) OR ($5='failed' AND desired<>'removed'))")
        .bind(host).bind(request.mesh_id.into_uuid()).bind(request.relay_id.into_uuid()).bind(request.revision)
        .bind(request.state).bind(request.error_code).bind(request.active_sessions.map(i64::try_from).transpose().map_err(|_|dynamic_invalid())?).execute(state.store.pool()).await?;
    if result.rows_affected()!=1 { return Err(ApiError::conflict("assignment_changed", "Relay assignment changed")); }
    Ok(StatusCode::NO_CONTENT)
}
