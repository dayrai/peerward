async fn list_auto_approval_rules(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    Path(mesh): Path<Uuid>,
    Query(query): Query<ListQuery>,
) -> Result<Json<ApiPage<peerward_management::AutoApprovalRule>>, ApiError> {
    authorize(&context, &HeaderMap::new(), Capability::ResourceRead, false)?;
    mesh_id(mesh)?;
    json_page(&state.store,"SELECT jsonb_build_object('id',id,'mesh_id',mesh_id,'version',version,'definition',definition) AS item,id,created_at AS cursor_time FROM auto_approval_rules WHERE mesh_id=$1 AND ($2::timestamptz IS NULL OR (created_at,id)>($2,$3)) ORDER BY created_at,id LIMIT $4",mesh,query.cursor()?,query.limit()?).await
}
async fn load_auto_approval_rule(
    store: &Store,
    mesh: Uuid,
    id: Uuid,
) -> Result<peerward_management::AutoApprovalRule, ApiError> {
    let (version, definition): (i64, Value) = sqlx::query_as(
        "SELECT version,definition FROM auto_approval_rules WHERE mesh_id=$1 AND id=$2",
    )
    .bind(mesh)
    .bind(id)
    .fetch_optional(store.pool())
    .await?
    .ok_or_else(ApiError::not_found)?;
    Ok(peerward_management::AutoApprovalRule {
        id,
        mesh_id: mesh_id(mesh)?,
        version: positive_revision(version)?,
        definition: serde_json::from_value(definition).map_err(|_| publisher_error())?,
    })
}
async fn get_auto_approval_rule(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    Path((mesh, id)): Path<(Uuid, Uuid)>,
) -> Result<(HeaderMap, Json<peerward_management::AutoApprovalRule>), ApiError> {
    authorize(&context, &HeaderMap::new(), Capability::ResourceRead, false)?;
    let rule = load_auto_approval_rule(&state.store, mesh, id).await?;
    Ok((etag_headers(rule.version)?, Json(rule)))
}
async fn save_auto_approval_rule(
    context: AuthContext,
    state: AppState,
    headers: HeaderMap,
    mesh: Uuid,
    id: Uuid,
    definition: peerward_management::AutoApprovalDefinition,
    create: bool,
) -> Result<
    (
        StatusCode,
        HeaderMap,
        Json<peerward_management::AutoApprovalRule>,
    ),
    ApiError,
> {
    authorize(&context, &headers, Capability::ResourceWrite, true)?;
    if id.get_version_num() != 4 {
        return Err(ApiError::invalid_id());
    }
    definition.validate().map_err(management_error)?;
    let expected = if create {
        None
    } else {
        Some(require_if_match(&headers)?)
    };
    let mut tx = state.store.begin_mutation().await?;
    sqlx::query("SELECT id FROM meshes WHERE id=$1 AND lifecycle='active' FOR UPDATE")
        .bind(mesh)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(ApiError::not_found)?;
    let existing: Option<(i64, Value)> = sqlx::query_as(
        "SELECT version,definition FROM auto_approval_rules WHERE mesh_id=$1 AND id=$2 FOR UPDATE",
    )
    .bind(mesh)
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    let document = serde_json::to_value(&definition).map_err(|_| publisher_error())?;
    if let Some((_, current)) = &existing
        && create
    {
        if current != &document {
            return Err(ApiError::conflict(
                "request_reused",
                "automatic rule already has different content",
            ));
        }
        tx.rollback().await?;
        let current = load_auto_approval_rule(&state.store, mesh, id).await?;
        return Ok((
            StatusCode::OK,
            etag_headers(current.version)?,
            Json(current),
        ));
    }
    if !create && existing.as_ref().map(|row| row.0) != expected {
        return Err(ApiError::conflict(
            "version_conflict",
            "automatic rule changed; reload before saving",
        ));
    }
    let valid_collection:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM network_collections WHERE mesh_id=$1 AND id=$2 AND definition->>'kind'='devices')")
        .bind(mesh).bind(definition.device_collection).fetch_one(&mut *tx).await?;
    if !valid_collection {
        return Err(ApiError::invalid(
            "device_collection_required",
            "choose a controlled device collection from this Mesh",
        ));
    }
    let valid_site:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM network_resources WHERE mesh_id=$1 AND definition->'target'->>'site_id'=$2)")
        .bind(mesh).bind(definition.site_id.to_string()).fetch_one(&mut *tx).await?;
    if !valid_site {
        return Err(ApiError::invalid(
            "site_required",
            "create a subnet resource in this site before configuring automatic approval",
        ));
    }
    if create {
        let count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM auto_approval_rules WHERE mesh_id=$1")
                .bind(mesh)
                .fetch_one(&mut *tx)
                .await?;
        if count >= 64 {
            return Err(ApiError::invalid(
                "auto_approval_limit",
                "at most 64 automatic rules per Mesh",
            ));
        }
        let inserted=sqlx::query("INSERT INTO auto_approval_rules(id,mesh_id,definition) VALUES($1,$2,$3) ON CONFLICT(id) DO NOTHING")
            .bind(id).bind(mesh).bind(document).execute(&mut *tx).await?.rows_affected();
        if inserted != 1 {
            return Err(ApiError::conflict(
                "rule_identity",
                "rule identity is already reserved",
            ));
        }
    } else {
        sqlx::query("UPDATE auto_approval_rules SET definition=$3,updated_at=clock_timestamp() WHERE mesh_id=$1 AND id=$2")
            .bind(mesh).bind(id).bind(document).execute(&mut *tx).await?;
    }
    bump_management(&mut tx, mesh).await?;
    state
        .store
        .commit_mutation(
            tx,
            &mutation(
                &context,
                Some(mesh_id(mesh)?),
                if create {
                    "auto_approval_rule.create"
                } else {
                    "auto_approval_rule.update"
                },
                "auto_approval_rule.changed",
                "auto_approval_rule",
                Some(id),
            ),
        )
        .await?;
    let current = load_auto_approval_rule(&state.store, mesh, id).await?;
    Ok((
        if create {
            StatusCode::CREATED
        } else {
            StatusCode::OK
        },
        etag_headers(current.version)?,
        Json(current),
    ))
}
async fn create_auto_approval_rule(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(mesh): Path<Uuid>,
    ApiJson(body): ApiJson<peerward_api::AutoApprovalCreateRequest>,
) -> Result<
    (
        StatusCode,
        HeaderMap,
        Json<peerward_management::AutoApprovalRule>,
    ),
    ApiError,
> {
    save_auto_approval_rule(
        context,
        state,
        headers,
        mesh,
        body.id,
        body.definition,
        true,
    )
    .await
}
async fn update_auto_approval_rule(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((mesh, id)): Path<(Uuid, Uuid)>,
    ApiJson(body): ApiJson<peerward_management::AutoApprovalDefinition>,
) -> Result<
    (
        StatusCode,
        HeaderMap,
        Json<peerward_management::AutoApprovalRule>,
    ),
    ApiError,
> {
    save_auto_approval_rule(context, state, headers, mesh, id, body, false).await
}
async fn delete_auto_approval_rule(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((mesh, id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, ApiError> {
    authorize(&context, &headers, Capability::ResourceWrite, true)?;
    let expected = require_if_match(&headers)?;
    let mut tx = state.store.begin_mutation().await?;
    sqlx::query("SELECT id FROM meshes WHERE id=$1 AND lifecycle='active' FOR UPDATE")
        .bind(mesh)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(ApiError::not_found)?;
    let version: i64 = sqlx::query_scalar(
        "SELECT version FROM auto_approval_rules WHERE mesh_id=$1 AND id=$2 FOR UPDATE",
    )
    .bind(mesh)
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(ApiError::not_found)?;
    if version != expected {
        return Err(ApiError::conflict(
            "version_conflict",
            "automatic rule changed; reload before deleting",
        ));
    }
    sqlx::query("DELETE FROM auto_approval_rules WHERE mesh_id=$1 AND id=$2")
        .bind(mesh)
        .bind(id)
        .execute(&mut *tx)
        .await?;
    bump_management(&mut tx, mesh).await?;
    state
        .store
        .commit_mutation(
            tx,
            &mutation(
                &context,
                Some(mesh_id(mesh)?),
                "auto_approval_rule.delete",
                "auto_approval_rule.deleted",
                "auto_approval_rule",
                Some(id),
            ),
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
async fn request_automatic_gateway_approval(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((mesh, id)): Path<(Uuid, Uuid)>,
    ApiJson(_body): ApiJson<peerward_api::AutomaticGatewayRequest>,
) -> Result<(HeaderMap, Json<peerward_management::GatewayBinding>), ApiError> {
    authorize(&context, &headers, Capability::ResourceWrite, true)?;
    let expected = require_if_match(&headers)?;
    let mut tx = state.store.begin_mutation().await?;
    sqlx::query("SELECT id FROM meshes WHERE id=$1 AND lifecycle='active' FOR UPDATE")
        .bind(mesh)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(ApiError::not_found)?;
    let version: i64 = sqlx::query_scalar(
        "SELECT version FROM gateway_bindings WHERE mesh_id=$1 AND id=$2 FOR UPDATE",
    )
    .bind(mesh)
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(ApiError::not_found)?;
    if version != expected {
        return Err(ApiError::conflict(
            "version_conflict",
            "binding changed; reload before changing approval authority",
        ));
    }
    sqlx::query("UPDATE gateway_bindings SET approved=false,approval_source='{\"kind\":\"manual\"}'::jsonb,updated_at=clock_timestamp() WHERE mesh_id=$1 AND id=$2")
        .bind(mesh).bind(id).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO gateway_auto_eligibility(mesh_id,binding_id) VALUES($1,$2) ON CONFLICT DO NOTHING")
        .bind(mesh).bind(id).execute(&mut *tx).await?;
    bump_management(&mut tx, mesh).await?;
    state
        .store
        .commit_mutation(
            tx,
            &mutation(
                &context,
                Some(mesh_id(mesh)?),
                "gateway_binding.request_auto_approval",
                "gateway_binding.approval_requested",
                "gateway_binding",
                Some(id),
            ),
        )
        .await?;
    let binding = load_gateway_binding(&state.store, mesh, id).await?;
    Ok((etag_headers(binding.version)?, Json(binding)))
}
