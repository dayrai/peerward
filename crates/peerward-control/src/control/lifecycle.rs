async fn list_authorities(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    Path(mesh): Path<Uuid>,
    Query(query): Query<ListQuery>,
) -> Result<Json<ApiPage<AuthorityResource>>, ApiError> {
    authorize(&context, &HeaderMap::new(), Capability::ResourceRead, false)?;
    mesh_id(mesh)?;
    json_page(
        &state.store,
        "SELECT jsonb_build_object('id',id,'version',version,'serial',serial,'public_key',encode(public_key,'hex'),
         'not_before',not_before,'not_after',not_after,'lifecycle',lifecycle,
         'replacement_id',replacement_id,'overlap_deadline',overlap_deadline) AS item,id,
         created_at AS cursor_time FROM mesh_authorities WHERE mesh_id=$1
         AND ($2::timestamptz IS NULL OR (created_at,id)>($2,$3))
         ORDER BY created_at,id LIMIT $4",
        mesh,
        query.cursor()?,
        query.limit()?,
    )
    .await
}

async fn stage_authority(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(mesh): Path<Uuid>,
    ApiJson(body): ApiJson<AuthorityStageRequest>,
) -> Result<(StatusCode, HeaderMap, Json<AuthorityResource>), ApiError> {
    authorize(&context, &headers, Capability::TrustManage, true)?;
    let mesh_id = mesh_id(mesh)?;
    let issuer = state
        .join_issuers
        .get(&mesh_id)
        .and_then(|issuers| issuers.first().cloned())
        .ok_or_else(|| {
            ApiError::unavailable("authority_trust_unavailable", "mesh root trust is unavailable")
        })?;
    let bytes = URL_SAFE_NO_PAD
        .decode(&body.certificate)
        .map_err(|_| ApiError::invalid("invalid_authority", "certificate is not base64url"))?;
    let certificate = AuthorityCertificate::decode(&bytes)
        .map_err(|_| ApiError::invalid("invalid_authority", "certificate is malformed"))?;
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let now = u64::try_from(now)
        .map(UnixTime)
        .map_err(|_| ApiError::invalid("invalid_clock", "system clock predates Unix time"))?;
    RootPublicKey::from_bytes(&issuer.root_public_key)
        .and_then(|root| root.verify_authority(&certificate, mesh_id, now))
        .map_err(|_| ApiError::invalid("invalid_authority", "certificate is not root anchored"))?;
    let not_before = OffsetDateTime::from_unix_timestamp(
        i64::try_from(certificate.not_before.0)
            .map_err(|_| ApiError::invalid("invalid_authority", "validity is out of range"))?,
    )
    .map_err(|_| ApiError::invalid("invalid_authority", "validity is out of range"))?;
    let not_after = OffsetDateTime::from_unix_timestamp(
        i64::try_from(certificate.not_after.0)
            .map_err(|_| ApiError::invalid("invalid_authority", "validity is out of range"))?,
    )
    .map_err(|_| ApiError::invalid("invalid_authority", "validity is out of range"))?;
    let id = state
        .store
        .stage_authority(
            &NewAuthority {
                mesh_id,
                serial: certificate.serial,
                public_key: certificate.public_key.to_vec(),
                not_before,
                not_after,
                replaces: body.replaces,
                overlap_deadline: None,
                certificate: bytes,
            },
            &context.actor,
        )
        .await?;
    let value: Value = sqlx::query_scalar(
        "SELECT jsonb_build_object('id',id,'version',version,'serial',serial,'public_key',encode(public_key,'hex'),
         'not_before',not_before,'not_after',not_after,'lifecycle',lifecycle,
         'replacement_id',replacement_id,'overlap_deadline',overlap_deadline)
         FROM mesh_authorities WHERE mesh_id=$1 AND id=$2",
    )
    .bind(mesh)
    .bind(id)
    .fetch_one(state.store.pool())
    .await?;
    let resource: AuthorityResource = serde_json::from_value(value)
        .map_err(|_| ApiError::internal("authority_projection", "Authority projection is invalid"))?;
    Ok((StatusCode::CREATED, etag_headers(resource.version)?, Json(resource)))
}

async fn activate_authority(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((mesh, authority)): Path<(Uuid, Uuid)>,
) -> Result<(HeaderMap, StatusCode), ApiError> {
    authorize(&context, &headers, Capability::TrustManage, true)?;
    let expected = require_if_match(&headers)?;
    let mesh_id = mesh_id(mesh)?;
    if !state.join_issuers.get(&mesh_id).is_some_and(|candidates| candidates.iter().any(|issuer| issuer.authority_id == authority)) {
        return Err(ApiError::conflict("authority_key_not_loaded", "Import the online Authority key before activation"));
    }
    let serial = authority_serial(&state.store, mesh, authority).await?;
    state
        .store
        .transition_authority_if_version(mesh_id, authority, expected, serial, Lifecycle::Active, &context.actor)
        .await.map_err(versioned_store_error)?;
    versioned_no_content(&state.store, "mesh_authorities", mesh, authority).await
}

async fn revoke_authority(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((mesh, authority)): Path<(Uuid, Uuid)>,
) -> Result<(HeaderMap, StatusCode), ApiError> {
    authorize(&context, &headers, Capability::TrustManage, true)?;
    let expected = require_if_match(&headers)?;
    let mesh_id = mesh_id(mesh)?;
    let serial = authority_serial(&state.store, mesh, authority).await?;
    state
        .store
        .transition_authority_if_version(mesh_id, authority, expected, serial, Lifecycle::Revoked, &context.actor)
        .await.map_err(versioned_store_error)?;
    versioned_no_content(&state.store, "mesh_authorities", mesh, authority).await
}

async fn list_peer_credentials(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    Path((mesh, peer)): Path<(Uuid, Uuid)>,
    Query(query): Query<ListQuery>,
) -> Result<Json<ApiPage<CredentialResource>>, ApiError> {
    authorize(&context, &HeaderMap::new(), Capability::ResourceRead, false)?;
    mesh_id(mesh)?;
    peer_id(peer)?;
    load_peer(&state.store, mesh, peer).await?;
    credential_page(&state.store, "peer_credentials", "peer_id", mesh, peer, query).await
}

async fn list_relay_credentials(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    Path((mesh, relay)): Path<(Uuid, Uuid)>,
    Query(query): Query<ListQuery>,
) -> Result<Json<ApiPage<CredentialResource>>, ApiError> {
    authorize(&context, &HeaderMap::new(), Capability::ResourceRead, false)?;
    mesh_id(mesh)?;
    relay_id(relay)?;
    credential_page(&state.store, "relay_credentials", "relay_id", mesh, relay, query).await
}

async fn activate_peer_credential(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((mesh, peer, serial)): Path<(Uuid, Uuid, Uuid)>,
) -> Result<(HeaderMap, StatusCode), ApiError> {
    authorize(&context, &headers, Capability::ResourceWrite, true)?;
    let expected = require_if_match(&headers)?;
    let mesh_id = mesh_id(mesh)?;
    peer_id(peer)?;
    state.store.transition_peer_credential_if_version(
        mesh_id,
        peer,
        expected,
        CredentialSerial::from_uuid(serial).map_err(|_| ApiError::invalid_id())?,
        Lifecycle::Active,
        &context.actor,
    ).await.map_err(versioned_store_error)?;
    versioned_no_content(&state.store, "peers", mesh, peer).await
}

async fn revoke_peer_credential(
    Extension(context): Extension<AuthContext>, State(state): State<AppState>, headers: HeaderMap,
    Path((mesh, peer, serial)): Path<(Uuid, Uuid, Uuid)>,
) -> Result<(HeaderMap, StatusCode), ApiError> {
    authorize(&context, &headers, Capability::ResourceWrite, true)?;
    let expected = require_if_match(&headers)?;
    let mesh_id = mesh_id(mesh)?;
    peer_id(peer)?;
    state.store.transition_peer_credential_if_version(
        mesh_id, peer, expected,
        CredentialSerial::from_uuid(serial).map_err(|_| ApiError::invalid_id())?,
        Lifecycle::Revoked, &context.actor,
    ).await.map_err(versioned_store_error)?;
    versioned_no_content(&state.store, "peers", mesh, peer).await
}

async fn activate_relay_credential(
    Extension(context): Extension<AuthContext>, State(state): State<AppState>, headers: HeaderMap,
    Path((mesh, relay, serial)): Path<(Uuid, Uuid, Uuid)>,
) -> Result<(HeaderMap, StatusCode), ApiError> {
    authorize(&context, &headers, Capability::TrustManage, true)?;
    let expected = require_if_match(&headers)?;
    let mesh_id = mesh_id(mesh)?;
    relay_id(relay)?;
    state.store.transition_relay_credential_if_version(
        mesh_id, relay, expected,
        CredentialSerial::from_uuid(serial).map_err(|_| ApiError::invalid_id())?,
        Lifecycle::Active, &context.actor,
    ).await.map_err(versioned_store_error)?;
    versioned_no_content(&state.store, "relays", mesh, relay).await
}

async fn revoke_relay_credential(
    Extension(context): Extension<AuthContext>, State(state): State<AppState>, headers: HeaderMap,
    Path((mesh, relay, serial)): Path<(Uuid, Uuid, Uuid)>,
) -> Result<(HeaderMap, StatusCode), ApiError> {
    authorize(&context, &headers, Capability::TrustManage, true)?;
    let expected = require_if_match(&headers)?;
    let mesh_id = mesh_id(mesh)?;
    relay_id(relay)?;
    state.store.transition_relay_credential_if_version(
        mesh_id, relay, expected,
        CredentialSerial::from_uuid(serial).map_err(|_| ApiError::invalid_id())?,
        Lifecycle::Revoked, &context.actor,
    ).await.map_err(versioned_store_error)?;
    versioned_no_content(&state.store, "relays", mesh, relay).await
}

fn versioned_store_error(error: StoreError) -> ApiError {
    match error {
        StoreError::Conflict => ApiError::conflict(
            "revision_conflict",
            "resource changed after the supplied ETag was read",
        ),
        other => other.into(),
    }
}

async fn versioned_no_content(
    store: &Store,
    table: &str,
    mesh: Uuid,
    subject: Uuid,
) -> Result<(HeaderMap, StatusCode), ApiError> {
    let statement = format!("SELECT version FROM {table} WHERE mesh_id=$1 AND id=$2");
    let version: i64 = sqlx::query_scalar(&statement)
        .bind(mesh)
        .bind(subject)
        .fetch_one(store.pool())
        .await?;
    Ok((
        etag_headers(u64::try_from(version).map_err(|_| {
            ApiError::internal("resource_projection", "resource version is invalid")
        })?)?,
        StatusCode::NO_CONTENT,
    ))
}

async fn authority_serial(store: &Store, mesh: Uuid, authority: Uuid) -> Result<CredentialSerial, ApiError> {
    let serial: Uuid = sqlx::query_scalar("SELECT serial FROM mesh_authorities WHERE mesh_id=$1 AND id=$2")
        .bind(mesh).bind(authority).fetch_optional(store.pool()).await?.ok_or_else(ApiError::not_found)?;
    CredentialSerial::from_uuid(serial).map_err(|_| ApiError::invalid_id())
}

async fn credential_page(
    store: &Store, table: &str, subject_column: &str, mesh: Uuid, subject: Uuid, query: ListQuery,
) -> Result<Json<ApiPage<CredentialResource>>, ApiError> {
    let limit = query.limit()?;
    let statement = format!(
        "SELECT jsonb_build_object('id',id,'serial',serial,'authority_id',authority_id,
         'public_key',encode(public_key,'hex'),'not_before',not_before,'not_after',not_after,
         'lifecycle',lifecycle,'replacement_id',replacement_id,'overlap_deadline',overlap_deadline)
         AS item,id,created_at AS cursor_time FROM {table} WHERE mesh_id=$1 AND {subject_column}=$2
         AND ($3::timestamptz IS NULL OR (created_at,id)>($3,$4))
         ORDER BY created_at,id LIMIT $5"
    );
    let cursor = query.cursor()?;
    let rows = sqlx::query(&statement).bind(mesh).bind(subject)
        .bind(cursor.map(|cursor| cursor.timestamp)).bind(cursor.map(|cursor| cursor.id))
        .bind(i64::from(limit)+1).fetch_all(store.pool()).await?;
    rows_to_page(rows, limit)
}
