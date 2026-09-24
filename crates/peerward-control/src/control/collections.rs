async fn list_network_collections(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    Path(mesh): Path<Uuid>,
    Query(query): Query<ListQuery>,
) -> Result<Json<ApiPage<peerward_management::Collection>>, ApiError> {
    authorize(&context, &HeaderMap::new(), Capability::ResourceRead, false)?;
    mesh_id(mesh)?;
    json_page(&state.store,"SELECT jsonb_build_object('id',id,'mesh_id',mesh_id,'version',version,'definition',definition) AS item,id,created_at AS cursor_time
        FROM network_collections WHERE mesh_id=$1 AND ($2::timestamptz IS NULL OR (created_at,id)>($2,$3)) ORDER BY created_at,id LIMIT $4",
        mesh,query.cursor()?,query.limit()?).await
}
async fn load_network_collection(
    store: &Store,
    mesh: Uuid,
    id: Uuid,
) -> Result<peerward_management::Collection, ApiError> {
    let (version, definition): (i64, Value) = sqlx::query_as(
        "SELECT version,definition FROM network_collections WHERE mesh_id=$1 AND id=$2",
    )
    .bind(mesh)
    .bind(id)
    .fetch_optional(store.pool())
    .await?
    .ok_or_else(ApiError::not_found)?;
    Ok(peerward_management::Collection {
        id,
        mesh_id: mesh_id(mesh)?,
        version: positive_revision(version)?,
        definition: serde_json::from_value(definition).map_err(|_| publisher_error())?,
    })
}
async fn get_network_collection(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    Path((mesh, id)): Path<(Uuid, Uuid)>,
) -> Result<(HeaderMap, Json<peerward_management::Collection>), ApiError> {
    authorize(&context, &HeaderMap::new(), Capability::ResourceRead, false)?;
    let value = load_network_collection(&state.store, mesh, id).await?;
    Ok((etag_headers(value.version)?, Json(value)))
}
async fn save_network_collection(
    context: AuthContext,
    state: AppState,
    headers: HeaderMap,
    mesh: Uuid,
    id: Uuid,
    definition: peerward_management::CollectionDefinition,
    create: bool,
) -> Result<(StatusCode, HeaderMap, Json<peerward_management::Collection>), ApiError> {
    use peerward_management::CollectionKind;
    authorize(&context, &headers, Capability::ResourceWrite, true)?;
    mesh_id(mesh)?;
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
        "SELECT version,definition FROM network_collections WHERE mesh_id=$1 AND id=$2 FOR UPDATE",
    )
    .bind(mesh)
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    let body = serde_json::to_value(&definition).map_err(|_| publisher_error())?;
    if let Some((_, current)) = &existing
        && create
    {
        if current != &body {
            return Err(ApiError::conflict(
                "request_reused",
                "collection identity has different content",
            ));
        }
        tx.rollback().await?;
        let value = load_network_collection(&state.store, mesh, id).await?;
        return Ok((StatusCode::OK, etag_headers(value.version)?, Json(value)));
    }
    if !create && existing.as_ref().map(|row| row.0) != expected {
        return Err(ApiError::conflict(
            "version_conflict",
            "collection changed; load its current version before saving",
        ));
    }
    if existing
        .as_ref()
        .is_some_and(|(_, old)| old["kind"] != body["kind"])
    {
        return Err(ApiError::conflict(
            "collection_kind",
            "collection kind is immutable; create a separate collection",
        ));
    }
    if create {
        let count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM network_collections WHERE mesh_id=$1")
                .bind(mesh)
                .fetch_one(&mut *tx)
                .await?;
        if count >= 64 {
            return Err(ApiError::invalid(
                "collection_limit",
                "at most 64 collections per Mesh",
            ));
        }
    }
    let query = match definition.kind {
        CollectionKind::Devices => {
            "SELECT id FROM peers WHERE mesh_id=$1 AND administrative_state<>'deleted'"
        }
        CollectionKind::Resources => "SELECT id FROM network_resources WHERE mesh_id=$1",
    };
    let known: Vec<Uuid> = sqlx::query_scalar(query)
        .bind(mesh)
        .fetch_all(&mut *tx)
        .await?;
    let known: BTreeSet<_> = known.into_iter().collect();
    if !definition.members.is_subset(&known) {
        return Err(ApiError::invalid(
            "collection_member",
            "member is missing or belongs to another Mesh or collection kind",
        ));
    }
    let written = sqlx::query("INSERT INTO network_collections(id,mesh_id,definition) VALUES($1,$2,$3) ON CONFLICT(id) DO UPDATE SET definition=EXCLUDED.definition,updated_at=clock_timestamp() WHERE network_collections.mesh_id=EXCLUDED.mesh_id")
        .bind(id).bind(mesh).bind(body).execute(&mut *tx).await?.rows_affected();
    if written != 1 {
        return Err(ApiError::conflict(
            "collection_identity",
            "collection identity is already reserved",
        ));
    }
    // A membership change is a separate authorization mutation. Sign its resolved
    // membership and invalidate existing flows; policy preview remains available.
    resolve_network_collections(&mut tx, mesh).await?;
    bump_management(&mut tx, mesh).await?;
    state
        .store
        .commit_mutation(
            tx,
            &mutation(
                &context,
                Some(mesh_id(mesh)?),
                if create {
                    "collection.create"
                } else {
                    "collection.update"
                },
                "collection.changed",
                "collection",
                Some(id),
            ),
        )
        .await?;
    let value = load_network_collection(&state.store, mesh, id).await?;
    Ok((
        if create {
            StatusCode::CREATED
        } else {
            StatusCode::OK
        },
        etag_headers(value.version)?,
        Json(value),
    ))
}
async fn create_network_collection(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(mesh): Path<Uuid>,
    ApiJson(body): ApiJson<peerward_api::CollectionCreateRequest>,
) -> Result<(StatusCode, HeaderMap, Json<peerward_management::Collection>), ApiError> {
    save_network_collection(
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
async fn replace_network_collection(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((mesh, id)): Path<(Uuid, Uuid)>,
    ApiJson(body): ApiJson<peerward_management::CollectionDefinition>,
) -> Result<(StatusCode, HeaderMap, Json<peerward_management::Collection>), ApiError> {
    save_network_collection(context, state, headers, mesh, id, body, false).await
}
async fn delete_network_collection(
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
        "SELECT version FROM network_collections WHERE mesh_id=$1 AND id=$2 FOR UPDATE",
    )
    .bind(mesh)
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(ApiError::not_found)?;
    if version != expected {
        return Err(ApiError::conflict("version_conflict", "collection changed"));
    }
    let referenced:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM resource_rules WHERE mesh_id=$1 AND (rule->'source_collections' @> $2::jsonb OR rule->'resource_collections' @> $2::jsonb))")
        .bind(mesh).bind(json!([id])).fetch_one(&mut *tx).await?;
    let automatic:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM auto_approval_rules WHERE mesh_id=$1 AND definition->>'device_collection'=$2)")
        .bind(mesh).bind(id.to_string()).fetch_one(&mut *tx).await?;
    if referenced || automatic {
        return Err(ApiError::conflict(
            "collection_in_use",
            "remove collection references from current rules before deleting",
        ));
    }
    sqlx::query("DELETE FROM network_collections WHERE mesh_id=$1 AND id=$2")
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
                "collection.delete",
                "collection.deleted",
                "collection",
                Some(id),
            ),
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
