fn machine_capabilities(values: &[String]) -> Result<Vec<Capability>, ApiError> {
    if values.is_empty() || values.len() > 3 {
        return Err(ApiError::invalid(
            "invalid_capabilities",
            "choose one to three ordinary capabilities",
        ));
    }
    let mut capabilities = Vec::new();
    for value in values {
        let capability = match value.as_str() {
            "status_audit_read" => Capability::StatusAuditRead,
            "resource_read" => Capability::ResourceRead,
            "resource_write" => Capability::ResourceWrite,
            _ => {
                return Err(ApiError::invalid(
                    "invalid_capabilities",
                    "machine credentials cannot manage trust or other credentials",
                ));
            }
        };
        if capabilities.contains(&capability) {
            return Err(ApiError::invalid(
                "invalid_capabilities",
                "duplicate capability",
            ));
        }
        capabilities.push(capability);
    }
    Ok(capabilities)
}

async fn authenticate_machine(
    state: &AppState,
    token: &str,
    path: &str,
) -> Result<AuthContext, ApiError> {
    let reject = || {
        ApiError::unauthorized(
            "invalid_machine_credential",
            "machine credential is invalid, expired or revoked",
        )
    };
    if token.len() != 55 || !token.starts_with("pw_machine_") {
        return Err(reject());
    }
    let digest = secret_digest(token.as_bytes());
    let row = sqlx::query("SELECT id,mesh_id,capabilities FROM machine_credentials WHERE token_digest=$1 AND revoked_at IS NULL AND expires_at>clock_timestamp()")
        .bind(digest.as_slice()).fetch_optional(state.store.pool()).await?.ok_or_else(reject)?;
    let mesh: Uuid = row.try_get("mesh_id")?;
    let prefix = format!("/api/v1/meshes/{mesh}");
    if path != prefix && !path.starts_with(&(prefix + "/")) {
        return Err(ApiError::forbidden(
            "machine_mesh_scope",
            "this credential is limited to its assigned Mesh",
        ));
    }
    let capabilities = machine_capabilities(&row.try_get::<Vec<String>, _>("capabilities")?)?;
    Ok(AuthContext {
        actor: format!("machine:{}", row.try_get::<Uuid, _>("id")?),
        role: Role::Operator,
        source: AuthSource::Machine(capabilities),
    })
}

async fn list_machine_credentials(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    Path(mesh): Path<Uuid>,
    Query(query): Query<ListQuery>,
) -> Result<Json<ApiPage<Value>>, ApiError> {
    authorize(&context, &HeaderMap::new(), Capability::TrustManage, false)?;
    mesh_id(mesh)?;
    json_page(&state.store,"SELECT to_jsonb(c)-'token_digest' AS item,id,created_at AS cursor_time FROM machine_credentials c WHERE mesh_id=$1 AND ($2::timestamptz IS NULL OR (created_at,id)>($2,$3)) ORDER BY created_at,id LIMIT $4",mesh,query.cursor()?,query.limit()?).await
}
async fn create_machine_credential(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(mesh): Path<Uuid>,
    ApiJson(body): ApiJson<peerward_api::MachineCredentialCreateRequest>,
) -> Result<(StatusCode, HeaderMap, Json<Value>), ApiError> {
    authorize(&context, &headers, Capability::TrustManage, true)?;
    machine_capabilities(&body.capabilities)?;
    if body.id.get_version_num() != 4
        || !peerward_management::name_valid(&body.name)
        || !(300..=7_776_000).contains(&body.ttl_seconds)
    {
        return Err(ApiError::invalid(
            "invalid_machine_credential",
            "use a valid name, UUID and expiry between five minutes and ninety days",
        ));
    }
    let mut tx = state.store.begin_mutation().await?;
    sqlx::query("SELECT id FROM meshes WHERE id=$1 AND lifecycle='active' FOR UPDATE")
        .bind(mesh)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(ApiError::not_found)?;
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM machine_credentials WHERE id=$1)")
            .bind(body.id)
            .fetch_one(&mut *tx)
            .await?;
    if exists {
        return Err(ApiError::conflict(
            "credential_already_issued",
            "secret is displayed once; revoke the previous credential before creating a replacement",
        ));
    }
    let count:i64=sqlx::query_scalar("SELECT count(*) FROM machine_credentials WHERE mesh_id=$1 AND revoked_at IS NULL AND expires_at>clock_timestamp()")
        .bind(mesh).fetch_one(&mut *tx).await?;
    if count >= 100 {
        return Err(ApiError::conflict(
            "credential_capacity",
            "revoke unused credentials before creating another",
        ));
    }
    let mut bytes = Zeroizing::new([0u8; 33]);
    OsRng.fill_bytes(bytes.as_mut());
    let token = Zeroizing::new(format!(
        "pw_machine_{}",
        URL_SAFE_NO_PAD.encode(bytes.as_ref())
    ));
    let digest = secret_digest(token.as_bytes());
    let value:Value=sqlx::query_scalar("INSERT INTO machine_credentials(id,mesh_id,name,token_digest,capabilities,created_at,expires_at) VALUES($1,$2,$3,$4,$5,transaction_timestamp(),transaction_timestamp()+$6*interval '1 second') RETURNING to_jsonb(machine_credentials)-'token_digest'")
        .bind(body.id).bind(mesh).bind(&body.name).bind(digest.as_slice()).bind(&body.capabilities).bind(i64::from(body.ttl_seconds)).fetch_one(&mut *tx).await?;
    state
        .store
        .commit_mutation(
            tx,
            &mutation(
                &context,
                Some(mesh_id(mesh)?),
                "machine_credential.create",
                "machine_credential.created",
                "machine_credential",
                Some(body.id),
            ),
        )
        .await?;
    let mut result_headers = etag_headers(1)?;
    result_headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok((
        StatusCode::CREATED,
        result_headers,
        Json(json!({"credential":value,"token":token.as_str()})),
    ))
}
async fn revoke_machine_credential(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((mesh, id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, ApiError> {
    authorize(&context, &headers, Capability::TrustManage, true)?;
    let expected = require_if_match(&headers)?;
    let mut tx = state.store.begin_mutation().await?;
    let row = sqlx::query(
        "SELECT version,revoked_at FROM machine_credentials WHERE mesh_id=$1 AND id=$2 FOR UPDATE",
    )
    .bind(mesh)
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(ApiError::not_found)?;
    if row
        .try_get::<Option<OffsetDateTime>, _>("revoked_at")?
        .is_some()
    {
        tx.rollback().await?;
        return Ok(StatusCode::NO_CONTENT);
    }
    if row.try_get::<i64, _>("version")? != expected {
        return Err(ApiError::conflict(
            "version_conflict",
            "credential changed; reload before revoking",
        ));
    }
    sqlx::query(
        "UPDATE machine_credentials SET revoked_at=clock_timestamp() WHERE mesh_id=$1 AND id=$2",
    )
    .bind(mesh)
    .bind(id)
    .execute(&mut *tx)
    .await?;
    state
        .store
        .commit_mutation(
            tx,
            &mutation(
                &context,
                Some(mesh_id(mesh)?),
                "machine_credential.revoke",
                "machine_credential.revoked",
                "machine_credential",
                Some(id),
            ),
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
