async fn list_gateway_bindings(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    Path(mesh): Path<Uuid>,
    Query(query): Query<ListQuery>,
) -> Result<Json<ApiPage<peerward_management::GatewayBinding>>, ApiError> {
    authorize(&context, &HeaderMap::new(), Capability::ResourceRead, false)?;
    mesh_id(mesh)?;
    json_page(&state.store,"SELECT (to_jsonb(b)-'mesh_id'-'created_at'-'updated_at') AS item,id,created_at AS cursor_time
        FROM gateway_bindings b WHERE mesh_id=$1 AND ($2::timestamptz IS NULL OR (created_at,id)>($2,$3)) ORDER BY created_at,id LIMIT $4",
        mesh,query.cursor()?,query.limit()?).await
}

async fn load_gateway_binding(
    store: &Store,
    mesh: Uuid,
    id: Uuid,
) -> Result<peerward_management::GatewayBinding, ApiError> {
    let value: Value = sqlx::query_scalar("SELECT to_jsonb(b)-'mesh_id'-'created_at'-'updated_at' FROM gateway_bindings b WHERE mesh_id=$1 AND id=$2")
        .bind(mesh).bind(id).fetch_optional(store.pool()).await?.ok_or_else(ApiError::not_found)?;
    serde_json::from_value(value).map_err(|_| publisher_error())
}

async fn get_gateway_binding(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    Path((mesh, id)): Path<(Uuid, Uuid)>,
) -> Result<(HeaderMap, Json<peerward_management::GatewayBinding>), ApiError> {
    authorize(&context, &HeaderMap::new(), Capability::ResourceRead, false)?;
    mesh_id(mesh)?;
    let binding = load_gateway_binding(&state.store, mesh, id).await?;
    Ok((etag_headers(binding.version)?, Json(binding)))
}

async fn update_gateway_priority(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((mesh, id)): Path<(Uuid, Uuid)>,
    ApiJson(body): ApiJson<peerward_api::GatewayPriorityRequest>,
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
            "binding changed; reload before changing priority",
        ));
    }
    sqlx::query("UPDATE gateway_bindings SET priority=$3,updated_at=clock_timestamp() WHERE mesh_id=$1 AND id=$2")
        .bind(mesh).bind(id).bind(i64::from(body.priority)).execute(&mut *tx).await?;
    bump_management(&mut tx, mesh).await?;
    state
        .store
        .commit_mutation(
            tx,
            &mutation(
                &context,
                Some(mesh_id(mesh)?),
                "gateway_binding.priority",
                "gateway_binding.priority_changed",
                "gateway_binding",
                Some(id),
            ),
        )
        .await?;
    let binding = load_gateway_binding(&state.store, mesh, id).await?;
    Ok((etag_headers(binding.version)?, Json(binding)))
}

async fn create_gateway_binding(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(mesh): Path<Uuid>,
    ApiJson(body): ApiJson<peerward_api::GatewayBindingCreateRequest>,
) -> Result<
    (
        StatusCode,
        HeaderMap,
        Json<peerward_management::GatewayBinding>,
    ),
    ApiError,
> {
    authorize(&context, &headers, Capability::ResourceWrite, true)?;
    let binding = peerward_management::GatewayBinding {
        id: body.id,
        resource_id: body.resource_id,
        peer_id: body.peer_id,
        version: 1,
        approved: false,
        priority: body.priority,
        forwarding: body.forwarding,
        return_route_confirmed: body.return_route_confirmed,
        approval_source: peerward_management::ApprovalSource::Manual,
    };
    binding.validate().map_err(management_error)?;
    let mut tx = state.store.begin_mutation().await?;
    sqlx::query("SELECT id FROM meshes WHERE id=$1 AND lifecycle='active' FOR UPDATE")
        .bind(mesh)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(ApiError::not_found)?;
    sqlx::query("SELECT id FROM network_resources WHERE mesh_id=$1 AND id=$2 FOR SHARE")
        .bind(mesh)
        .bind(body.resource_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(ApiError::not_found)?;
    sqlx::query("SELECT id FROM peers WHERE mesh_id=$1 AND id=$2 AND administrative_state='enabled' FOR SHARE")
        .bind(mesh).bind(body.peer_id.into_uuid()).fetch_optional(&mut *tx).await?.ok_or_else(ApiError::not_found)?;
    if let Some(value) = sqlx::query_scalar::<_,Value>("SELECT to_jsonb(b)-'mesh_id'-'created_at'-'updated_at' FROM gateway_bindings b WHERE mesh_id=$1 AND id=$2")
        .bind(mesh).bind(body.id).fetch_optional(&mut *tx).await? {
        let existing: peerward_management::GatewayBinding = serde_json::from_value(value).map_err(|_| publisher_error())?;
        if existing.resource_id != binding.resource_id || existing.peer_id != binding.peer_id || existing.priority != binding.priority
            || existing.forwarding != binding.forwarding || existing.return_route_confirmed != binding.return_route_confirmed {
            return Err(ApiError::conflict("request_reused","binding identity already has different content"));
        }
        tx.rollback().await?;
        return Ok((StatusCode::OK,etag_headers(existing.version)?,Json(existing)));
    }
    sqlx::query("INSERT INTO gateway_bindings(id,mesh_id,resource_id,peer_id,priority,forwarding,return_route_confirmed) VALUES($1,$2,$3,$4,$5,$6,$7)")
        .bind(body.id).bind(mesh).bind(body.resource_id).bind(body.peer_id.into_uuid()).bind(i64::from(body.priority))
        .bind(match body.forwarding { peerward_management::ForwardingMode::Snat => "snat", peerward_management::ForwardingMode::PreserveSource => "preserve_source" })
        .bind(body.return_route_confirmed).execute(&mut *tx).await?;
    bump_management(&mut tx, mesh).await?;
    state
        .store
        .commit_mutation(
            tx,
            &mutation(
                &context,
                Some(mesh_id(mesh)?),
                "gateway_binding.create",
                "gateway_binding.created",
                "gateway_binding",
                Some(body.id),
            ),
        )
        .await?;
    let current = load_gateway_binding(&state.store, mesh, body.id).await?;
    Ok((
        StatusCode::CREATED,
        etag_headers(current.version)?,
        Json(current),
    ))
}

async fn set_gateway_approval(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((mesh, id)): Path<(Uuid, Uuid)>,
    ApiJson(body): ApiJson<peerward_api::GatewayApprovalRequest>,
) -> Result<(HeaderMap, Json<peerward_management::GatewayBinding>), ApiError> {
    authorize(&context, &headers, Capability::ResourceWrite, true)?;
    let expected = require_if_match(&headers)?;
    let mut tx = state.store.begin_mutation().await?;
    sqlx::query("SELECT id FROM meshes WHERE id=$1 AND lifecycle='active' FOR UPDATE")
        .bind(mesh)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(ApiError::not_found)?;
    let row = sqlx::query("SELECT b.version,b.forwarding,b.return_route_confirmed,p.administrative_state FROM gateway_bindings b
        JOIN peers p ON p.mesh_id=b.mesh_id AND p.id=b.peer_id WHERE b.mesh_id=$1 AND b.id=$2 FOR UPDATE OF b,p")
        .bind(mesh).bind(id).fetch_optional(&mut *tx).await?.ok_or_else(ApiError::not_found)?;
    if row.try_get::<i64, _>("version")? != expected {
        return Err(ApiError::conflict(
            "version_conflict",
            "binding changed; reload before approving",
        ));
    }
    if body.approved {
        let exit: bool = sqlx::query_scalar("SELECT r.definition->'target'->>'kind'='internet' FROM gateway_bindings b JOIN network_resources r ON r.mesh_id=b.mesh_id AND r.id=b.resource_id WHERE b.mesh_id=$1 AND b.id=$2")
            .bind(mesh).bind(id).fetch_one(&mut *tx).await?;
        if exit {
            if row.try_get::<String, _>("forwarding")? != "snat" {
                return Err(ApiError::invalid(
                    "exit_requires_snat",
                    "Internet exits require source address translation",
                ));
            }
            let ambiguous: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM gateway_bindings current JOIN gateway_bindings other ON other.mesh_id=current.mesh_id AND other.peer_id=current.peer_id AND other.resource_id<>current.resource_id JOIN network_resources r ON r.mesh_id=other.mesh_id AND r.id=other.resource_id WHERE current.mesh_id=$1 AND current.id=$2 AND other.approved AND r.definition->'target'->>'kind'='internet')")
                .bind(mesh).bind(id).fetch_one(&mut *tx).await?;
            if ambiguous {
                return Err(ApiError::conflict(
                    "exit_provider_ambiguous",
                    "A gateway can provide only one approved Internet resource; reuse that resource or withdraw its previous approval",
                ));
            }
        }
        if row.try_get::<String, _>("administrative_state")? != "enabled" {
            return Err(ApiError::conflict(
                "provider_disabled",
                "provider must be enabled",
            ));
        }
        if row.try_get::<String, _>("forwarding")? == "preserve_source"
            && !row.try_get::<bool, _>("return_route_confirmed")?
        {
            return Err(ApiError::invalid(
                "return_route_required",
                "confirm LAN return routing before approving",
            ));
        }
    }
    sqlx::query("DELETE FROM gateway_auto_eligibility WHERE mesh_id=$1 AND binding_id=$2")
        .bind(mesh)
        .bind(id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE gateway_bindings SET approved=$3,approval_source='{\"kind\":\"manual\"}'::jsonb,updated_at=clock_timestamp() WHERE mesh_id=$1 AND id=$2")
        .bind(mesh).bind(id).bind(body.approved).execute(&mut *tx).await?;
    if body.approved {
        // Explicit approval of this exact target releases its shadow in the same audit transaction.
        sqlx::query("DELETE FROM resource_withdrawals w USING network_resources r,gateway_bindings b WHERE w.mesh_id=$1 AND r.mesh_id=w.mesh_id AND b.mesh_id=w.mesh_id AND b.id=$2 AND r.id=b.resource_id AND w.target=r.definition->'target'")
            .bind(mesh).bind(id).execute(&mut *tx).await?;
    }
    bump_management(&mut tx, mesh).await?;
    state
        .store
        .commit_mutation(
            tx,
            &mutation(
                &context,
                Some(mesh_id(mesh)?),
                "gateway_binding.approval",
                "gateway_binding.approval_changed",
                "gateway_binding",
                Some(id),
            ),
        )
        .await?;
    let binding = load_gateway_binding(&state.store, mesh, id).await?;
    Ok((etag_headers(binding.version)?, Json(binding)))
}
