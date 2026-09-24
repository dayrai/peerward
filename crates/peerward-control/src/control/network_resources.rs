async fn list_network_resources(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    Path(mesh): Path<Uuid>,
    Query(query): Query<ListQuery>,
) -> Result<Json<ApiPage<peerward_management::NetworkResource>>, ApiError> {
    authorize(&context, &HeaderMap::new(), Capability::ResourceRead, false)?;
    mesh_id(mesh)?;
    json_page(&state.store, "SELECT jsonb_build_object('id',id,'mesh_id',mesh_id,'version',version,'definition',definition) AS item,id,created_at AS cursor_time
        FROM network_resources WHERE mesh_id=$1 AND ($2::timestamptz IS NULL OR (created_at,id)>($2,$3)) ORDER BY created_at,id LIMIT $4",
        mesh, query.cursor()?, query.limit()?).await
}

async fn get_network_resource(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    Path((mesh, id)): Path<(Uuid, Uuid)>,
) -> Result<(HeaderMap, Json<peerward_management::NetworkResource>), ApiError> {
    authorize(&context, &HeaderMap::new(), Capability::ResourceRead, false)?;
    let resource = load_network_resource(&state.store, mesh, id).await?;
    Ok((etag_headers(resource.version)?, Json(resource)))
}

async fn load_network_resource(
    store: &Store,
    mesh: Uuid,
    id: Uuid,
) -> Result<peerward_management::NetworkResource, ApiError> {
    mesh_id(mesh)?;
    let row =
        sqlx::query("SELECT version,definition FROM network_resources WHERE mesh_id=$1 AND id=$2")
            .bind(mesh)
            .bind(id)
            .fetch_optional(store.pool())
            .await?
            .ok_or_else(ApiError::not_found)?;
    Ok(peerward_management::NetworkResource {
        id,
        mesh_id: mesh_id(mesh)?,
        version: positive_revision(row.try_get("version")?)?,
        definition: serde_json::from_value(row.try_get("definition")?)
            .map_err(|_| publisher_error())?,
    })
}

fn management_error(error: peerward_management::ManagementError) -> ApiError {
    match error {
        peerward_management::ManagementError::Conflict(field) => {
            ApiError::conflict("network_conflict", field)
        }
        peerward_management::ManagementError::Invalid(field) => {
            ApiError::invalid("invalid_network_configuration", field)
        }
        _ => ApiError::invalid(
            "invalid_network_configuration",
            "network state validation failed",
        ),
    }
}

async fn validate_network_target(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    mesh: Uuid,
    id: Uuid,
    definition: &peerward_management::ResourceDefinition,
) -> Result<(), ApiError> {
    definition.validate().map_err(management_error)?;
    // Serialize reference and overlap checks with every resource/grant change in the Mesh.
    let pools: Vec<String> = sqlx::query_scalar(
        "SELECT ARRAY[address_cidr::text,secondary_cidr::text] FROM meshes WHERE id=$1 AND lifecycle='active' FOR UPDATE",
    )
    .bind(mesh)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(ApiError::not_found)?;
    let values: Vec<Value> =
        sqlx::query_scalar("SELECT definition FROM network_resources WHERE mesh_id=$1 AND id<>$2")
            .bind(mesh)
            .bind(id)
            .fetch_all(&mut **tx)
            .await?;
    let resources = values
        .into_iter()
        .map(serde_json::from_value::<peerward_management::ResourceDefinition>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| publisher_error())?;
    if definition.health_probe.is_some()
        && resources
            .iter()
            .filter(|item| item.health_probe.is_some())
            .count()
            >= 64
    {
        return Err(ApiError::invalid(
            "health_probe_limit",
            "at most 64 target probes per Mesh",
        ));
    }
    peerward_management::validate_resource_conflicts(
        &definition.target,
        resources.iter().map(|item| &item.target),
        &pools
            .into_iter()
            .map(|pool| pool.parse().map_err(|_| publisher_error()))
            .collect::<Result<Vec<_>, _>>()?,
    )
    .map_err(management_error)
}

async fn create_network_resource(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(mesh): Path<Uuid>,
    ApiJson(body): ApiJson<peerward_api::NetworkResourceCreateRequest>,
) -> Result<
    (
        StatusCode,
        HeaderMap,
        Json<peerward_management::NetworkResource>,
    ),
    ApiError,
> {
    authorize(&context, &headers, Capability::ResourceWrite, true)?;
    let mesh_id = mesh_id(mesh)?;
    if body.id.get_version_num() != 4 {
        return Err(ApiError::invalid_id());
    }
    let mut tx = state.store.begin_mutation().await?;
    validate_network_target(&mut tx, mesh, body.id, &body.definition).await?;
    let encoded = serde_json::to_value(&body.definition).map_err(|_| publisher_error())?;
    if let Some(existing) = sqlx::query_scalar::<_, Value>(
        "SELECT definition FROM network_resources WHERE mesh_id=$1 AND id=$2",
    )
    .bind(mesh)
    .bind(body.id)
    .fetch_optional(&mut *tx)
    .await?
    {
        if existing != encoded {
            return Err(ApiError::conflict(
                "request_reused",
                "resource identity already has different content",
            ));
        }
        tx.rollback().await?;
        let resource = load_network_resource(&state.store, mesh, body.id).await?;
        return Ok((
            StatusCode::OK,
            etag_headers(resource.version)?,
            Json(resource),
        ));
    }
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM network_resources WHERE mesh_id=$1")
        .bind(mesh)
        .fetch_one(&mut *tx)
        .await?;
    if count >= 4096 {
        return Err(ApiError::invalid(
            "resource_limit",
            "at most 4096 resources per Mesh",
        ));
    }
    sqlx::query("INSERT INTO network_resources(id,mesh_id,definition) VALUES($1,$2,$3)")
        .bind(body.id)
        .bind(mesh)
        .bind(encoded)
        .execute(&mut *tx)
        .await?;
    bump_management(&mut tx, mesh).await?;
    state
        .store
        .commit_mutation(
            tx,
            &mutation(
                &context,
                Some(mesh_id),
                "network_resource.create",
                "network_resource.created",
                "network_resource",
                Some(body.id),
            ),
        )
        .await?;
    let resource = load_network_resource(&state.store, mesh, body.id).await?;
    Ok((
        StatusCode::CREATED,
        etag_headers(resource.version)?,
        Json(resource),
    ))
}

async fn replace_network_resource(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((mesh, id)): Path<(Uuid, Uuid)>,
    ApiJson(body): ApiJson<peerward_management::ResourceDefinition>,
) -> Result<(HeaderMap, Json<peerward_management::NetworkResource>), ApiError> {
    authorize(&context, &headers, Capability::ResourceWrite, true)?;
    let expected = require_if_match(&headers)?;
    let mut tx = state.store.begin_mutation().await?;
    validate_network_target(&mut tx, mesh, id, &body).await?;
    let existing = sqlx::query(
        "SELECT version,definition FROM network_resources WHERE mesh_id=$1 AND id=$2 FOR UPDATE",
    )
    .bind(mesh)
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(ApiError::not_found)?;
    if existing.try_get::<i64, _>("version")? != expected {
        return Err(ApiError::conflict(
            "version_conflict",
            "resource changed; reload before publishing",
        ));
    }
    let previous: peerward_management::ResourceDefinition =
        serde_json::from_value(existing.try_get("definition")?).map_err(|_| publisher_error())?;
    if previous.target != body.target {
        // A grant for the old address/site cannot silently authorize its replacement.
        sqlx::query("DELETE FROM gateway_auto_eligibility e USING gateway_bindings b WHERE e.mesh_id=$1 AND b.mesh_id=e.mesh_id AND b.id=e.binding_id AND b.resource_id=$2")
            .bind(mesh).bind(id).execute(&mut *tx).await?;
        sqlx::query("UPDATE gateway_bindings SET approved=false WHERE mesh_id=$1 AND resource_id=$2 AND approved")
            .bind(mesh).bind(id).execute(&mut *tx).await?;
    }
    sqlx::query("UPDATE network_resources SET definition=$3,updated_at=clock_timestamp() WHERE mesh_id=$1 AND id=$2")
        .bind(mesh).bind(id).bind(serde_json::to_value(body).map_err(|_| publisher_error())?).execute(&mut *tx).await?;
    bump_management(&mut tx, mesh).await?;
    state
        .store
        .commit_mutation(
            tx,
            &mutation(
                &context,
                Some(mesh_id(mesh)?),
                "network_resource.update",
                "network_resource.updated",
                "network_resource",
                Some(id),
            ),
        )
        .await?;
    let resource = load_network_resource(&state.store, mesh, id).await?;
    Ok((etag_headers(resource.version)?, Json(resource)))
}

async fn delete_network_resource(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((mesh, id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, ApiError> {
    authorize(&context, &headers, Capability::ResourceWrite, true)?;
    let expected = require_if_match(&headers)?;
    let mut tx = state.store.begin_mutation().await?;
    sqlx::query("SELECT id FROM meshes WHERE id=$1 FOR UPDATE")
        .bind(mesh)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(ApiError::not_found)?;
    let version: i64 = sqlx::query_scalar(
        "SELECT version FROM network_resources WHERE mesh_id=$1 AND id=$2 FOR UPDATE",
    )
    .bind(mesh)
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(ApiError::not_found)?;
    if version != expected {
        return Err(ApiError::conflict("version_conflict", "resource changed"));
    }
    let referenced: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM resource_rules WHERE mesh_id=$1 AND rule->'resources' @> $2::jsonb)
         OR EXISTS(SELECT 1 FROM resource_policy_history h JOIN meshes m ON m.id=h.mesh_id
           AND m.resource_policy_revision=h.revision
           WHERE h.mesh_id=$1 AND h.document->'tests' @> $3::jsonb)
         OR EXISTS(SELECT 1 FROM network_collections WHERE mesh_id=$1 AND definition->>'kind'='resources' AND definition->'members' @> $2::jsonb)",
    )
    .bind(mesh)
    .bind(json!([id]))
    .bind(json!([{ "resource_id": id }]))
    .fetch_one(&mut *tx)
    .await?;
    if referenced {
        return Err(ApiError::conflict(
            "resource_in_use",
            "remove resource references from current access rules, saved tests and explicit collection members before deleting",
        ));
    }
    sqlx::query("DELETE FROM network_resources WHERE mesh_id=$1 AND id=$2")
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
                "network_resource.delete",
                "network_resource.deleted",
                "network_resource",
                Some(id),
            ),
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn bump_management(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    mesh: Uuid,
) -> Result<(), ApiError> {
    sqlx::query("UPDATE meshes SET management_revision=management_revision+1,updated_at=clock_timestamp() WHERE id=$1")
        .bind(mesh).execute(&mut **tx).await?;
    Ok(())
}

fn positive_revision(version: i64) -> Result<u64, ApiError> {
    u64::try_from(version)
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(publisher_error)
}
