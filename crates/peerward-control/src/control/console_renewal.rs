async fn request_console_renewal(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((mesh, peer)): Path<(Uuid, Uuid)>,
    ApiJson(body): ApiJson<peerward_api::ConsoleRenewalRequest>,
) -> Result<Json<peerward_api::ConsoleRenewal>, ApiError> {
    authorize(&context, &headers, Capability::TrustManage, true)?;
    let expected = require_if_match(&headers)?;
    validate_console_reason(&body.reason)?;
    if body.reason.trim().is_empty()
        || !(300..=604_800).contains(&body.valid_for_seconds)
        || body.request_id.get_version_num() != 4
    {
        return Err(ApiError::invalid(
            "invalid_renewal",
            "reason, unique request and a 5 minute to 7 day deadline are required",
        ));
    }
    let digest = declaration_digest(&(expected, &body))?;
    let mut tx = state.store.begin_mutation().await?;
    lock_configuration(&mut tx, mesh).await?;
    let prior:Option<(String,String)>=sqlx::query_as("SELECT actor,request_digest FROM console_credential_renewals WHERE mesh_id=$1 AND peer_id=$2 AND id=$3")
        .bind(mesh).bind(peer).bind(body.request_id).fetch_optional(&mut *tx).await?;
    if let Some((actor, known)) = prior {
        if actor != context.actor || known != digest {
            return Err(ApiError::conflict(
                "request_reused",
                "request identity is bound to different content or authority",
            ));
        }
        tx.rollback().await?;
        return Ok(Json(
            load_console_renewal(&state.store, mesh, peer, body.request_id).await?,
        ));
    }
    lock_resource_version(&mut tx, VersionedFamily::Peer, Some(mesh), peer, expected).await?;
    let valid:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM peer_credentials c JOIN peers p ON p.mesh_id=c.mesh_id AND p.id=c.peer_id
        WHERE c.mesh_id=$1 AND c.peer_id=$2 AND c.serial=$3 AND c.lifecycle='active' AND c.not_after>clock_timestamp() AND c.not_before<=clock_timestamp() AND p.administrative_state='enabled')")
        .bind(mesh).bind(peer).bind(body.current_serial.into_uuid()).fetch_one(&mut *tx).await?;
    if !valid {
        return Err(ApiError::conflict(
            "credential_changed_or_expired",
            "refresh the device; expired credentials require the existing local recovery workflow",
        ));
    }
    let pending:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM console_credential_renewals WHERE mesh_id=$1 AND peer_id=$2 AND current_serial=$3 AND completed_at IS NULL AND expires_at>clock_timestamp())")
        .bind(mesh).bind(peer).bind(body.current_serial.into_uuid()).fetch_one(&mut *tx).await?;
    if pending {
        return Err(ApiError::conflict(
            "renewal_pending",
            "a renewal request is already waiting for this credential",
        ));
    }
    let candidates = state.join_issuers.get(&mesh_id(mesh)?).ok_or_else(|| {
        ApiError::conflict(
            "signer_unavailable",
            "no current online signer is available",
        )
    })?;
    let issuer = active_issuer_with_executor(&mut *tx, mesh_id(mesh)?, &candidates).await?;
    let now = current_unix_seconds();
    let expires = now + u64::from(body.valid_for_seconds);
    if expires > issuer.authority_certificate.not_after.0 {
        return Err(ApiError::conflict(
            "authority_expiring",
            "choose an earlier deadline or renew the issuing authority",
        ));
    }
    let command = issuer
        .directory
        .sign_credential_renewal(peerward_management::CredentialRenewalCommand {
            request_id: body.request_id,
            mesh_id: mesh_id(mesh)?,
            peer_id: peer_id(peer)?,
            current_serial: body.current_serial,
            issued_at: now,
            expires_at: expires,
        })
        .map_err(management_error)?;
    sqlx::query("INSERT INTO console_credential_renewals(mesh_id,peer_id,id,current_serial,actor,reason,request_digest,command,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,to_timestamp($9::double precision))")
        .bind(mesh).bind(peer).bind(body.request_id).bind(body.current_serial.into_uuid()).bind(&context.actor).bind(&body.reason).bind(digest).bind(declaration_value(&command)?).bind(i64::try_from(expires).map_err(|_|publisher_error())?).execute(&mut *tx).await?;
    let mut record = mutation(
        &context,
        Some(mesh_id(mesh)?),
        "credential_renewal.request",
        "credential_renewal.requested",
        "credential_renewal",
        Some(body.request_id),
    );
    record.metadata = json!({"peer_id":peer,"current_serial":body.current_serial,"expires_at":expires,"reason":body.reason,"impact":"device_local_keys_and_authenticated_reconnect"});
    state.store.commit_mutation(tx, &record).await?;
    Ok(Json(
        load_console_renewal(&state.store, mesh, peer, body.request_id).await?,
    ))
}
async fn list_console_renewals(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    Path((mesh, peer)): Path<(Uuid, Uuid)>,
    Query(query): Query<ConsoleQuery>,
) -> Result<Json<ApiPage<peerward_api::ConsoleRenewal>>, ApiError> {
    authorize(&context, &HeaderMap::new(), Capability::ResourceRead, false)?;
    let limit = query.bounded_limit()?;
    let ids:Vec<Uuid>=sqlx::query_scalar("SELECT id FROM console_credential_renewals WHERE mesh_id=$1 AND peer_id=$2 AND ($3::text IS NULL OR (created_at,id)<(SELECT created_at,id FROM console_credential_renewals WHERE mesh_id=$1 AND peer_id=$2 AND id::text=$3)) ORDER BY created_at DESC,id DESC LIMIT $4")
        .bind(mesh).bind(peer).bind(query.cursor).bind(i64::from(limit)+1).fetch_all(state.store.pool()).await?;
    let more = ids.len() > usize::from(limit);
    let mut items = vec![];
    for id in ids.into_iter().take(limit as usize) {
        items.push(load_console_renewal(&state.store, mesh, peer, id).await?);
    }
    let next_cursor = more.then(|| items.last().unwrap().id.to_string());
    Ok(Json(ApiPage { items, next_cursor }))
}
async fn load_console_renewal(
    store: &Store,
    mesh: Uuid,
    peer: Uuid,
    id: Uuid,
) -> Result<peerward_api::ConsoleRenewal, ApiError> {
    let value:Value=sqlx::query_scalar("SELECT jsonb_build_object('id',r.id,'peer_id',r.peer_id,'current_serial',r.current_serial,'created_at',r.created_at,'expires_at',r.expires_at,'delivered_at',r.delivered_at,'completed_at',r.completed_at,'completed_serial',r.completed_serial,
        'state',CASE WHEN r.completed_at IS NOT NULL THEN 'completed'
        WHEN EXISTS(SELECT 1 FROM peer_credential_rotation_requests x WHERE x.mesh_id=r.mesh_id AND x.peer_id=r.peer_id AND x.authenticated_serial=r.current_serial AND x.status='activated') THEN 'awaiting_reconnect'
        WHEN r.expires_at<=clock_timestamp() THEN 'expired'
        WHEN NOT EXISTS(SELECT 1 FROM peer_credentials c WHERE c.mesh_id=r.mesh_id AND c.peer_id=r.peer_id AND c.serial=r.current_serial AND c.lifecycle='active') THEN 'superseded'
        WHEN EXISTS(SELECT 1 FROM peer_credential_rotation_requests x WHERE x.mesh_id=r.mesh_id AND x.peer_id=r.peer_id AND x.authenticated_serial=r.current_serial AND x.status IN ('pending','issued')) THEN 'updating'
        WHEN EXISTS(SELECT 1 FROM console_device_capabilities c WHERE c.mesh_id=r.mesh_id AND c.peer_id=r.peer_id AND c.credential_serial=r.current_serial AND NOT c.credential_renewal) THEN 'upgrade_required'
        WHEN NOT COALESCE((peerward_peer_api_json(p)->>'online')::boolean,false) THEN 'waiting_offline'
        WHEN r.delivered_at IS NOT NULL THEN 'delivered' ELSE 'queued' END)
        FROM console_credential_renewals r JOIN peers p ON p.mesh_id=r.mesh_id AND p.id=r.peer_id WHERE r.mesh_id=$1 AND r.peer_id=$2 AND r.id=$3")
        .bind(mesh).bind(peer).bind(id).fetch_optional(store.pool()).await?.ok_or_else(ApiError::not_found)?;
    serde_json::from_value(value).map_err(|_| publisher_error())
}
