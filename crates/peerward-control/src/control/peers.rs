async fn list_peers(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    Path(mesh): Path<Uuid>,
    Query(query): Query<ListQuery>,
) -> Result<Json<ApiPage<PeerResource>>, ApiError> {
    authorize(&context, &HeaderMap::new(), Capability::ResourceRead, false)?;
    mesh_id(mesh)?;
    json_page(
        &state.store,
        "SELECT peerward_peer_api_json(p)||jsonb_build_object('version',p.version) AS item,p.id,p.created_at AS cursor_time FROM peers p WHERE p.mesh_id=$1 AND p.administrative_state<>'deleted'
           AND ($2::timestamptz IS NULL OR (p.created_at,p.id)>($2,$3))
           ORDER BY p.created_at,p.id LIMIT $4",
        mesh,
        query.cursor()?,
        query.limit()?,
    )
    .await
}

async fn create_peer(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(mesh): Path<Uuid>,
    ApiJson(body): ApiJson<PeerCreateRequest>,
) -> Result<(StatusCode, HeaderMap, Json<PeerResource>), ApiError> {
    authorize(&context, &headers, Capability::ResourceWrite, true)?;
    if !valid_dns_label(&body.name) {
        return Err(ApiError::invalid(
            "invalid_name",
            "Peer name must be a canonical DNS label",
        ));
    }
    if !peerward_api::valid_labels(&body.labels) {
        return Err(ApiError::invalid(
            "invalid_labels",
            "peer labels are invalid",
        ));
    }
    validate_peer_description(&body.display_name)?;
    validate_peer_description(&body.location)?;
    let mesh_id = mesh_id(mesh)?;
    let peer_id = PeerId::new();
    let mut transaction = state.store.begin_mutation().await?;
    // Serialize new namespace reservations with DNS profile changes and Mesh deletion.
    sqlx::query("SELECT id FROM meshes WHERE id=$1 AND lifecycle='active' FOR UPDATE")
        .bind(mesh)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or_else(ApiError::not_found)?;
    sqlx::query(
        "INSERT INTO peers(id,mesh_id,name,labels,display_name,location) VALUES($1,$2,$3,$4,$5,$6)",
    )
    .bind(peer_id.into_uuid())
    .bind(mesh)
    .bind(&body.name)
    .bind(
        serde_json::to_value(&body.labels)
            .map_err(|_| ApiError::invalid("invalid_labels", "peer labels are invalid"))?,
    )
    .bind(&body.display_name)
    .bind(&body.location)
    .execute(&mut *transaction)
    .await?;
    sqlx::query("UPDATE meshes SET directory_revision=directory_revision+1 WHERE id=$1")
        .bind(mesh)
        .execute(&mut *transaction)
        .await?;
    state
        .store
        .commit_mutation(
            transaction,
            &mutation(
                &context,
                Some(mesh_id),
                "peer.create",
                "peer.created",
                "peer",
                Some(peer_id.into_uuid()),
            ),
        )
        .await?;
    let resource = load_peer(&state.store, mesh, peer_id.into_uuid()).await?;
    Ok((
        StatusCode::CREATED,
        etag_headers(resource.version)?,
        Json(resource),
    ))
}

async fn get_peer(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    Path((mesh, peer)): Path<(Uuid, Uuid)>,
) -> Result<(HeaderMap, Json<PeerResource>), ApiError> {
    authorize(&context, &HeaderMap::new(), Capability::ResourceRead, false)?;
    mesh_id(mesh)?;
    peer_id(peer)?;
    let resource = load_peer(&state.store, mesh, peer).await?;
    Ok((etag_headers(resource.version)?, Json(resource)))
}

async fn patch_peer(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((mesh, peer)): Path<(Uuid, Uuid)>,
    ApiJson(body): ApiJson<PeerPatchRequest>,
) -> Result<(HeaderMap, Json<PeerResource>), ApiError> {
    authorize(&context, &headers, Capability::ResourceWrite, true)?;
    let expected = require_if_match(&headers)?;
    let mesh_id = mesh_id(mesh)?;
    peer_id(peer)?;
    if body
        .name
        .as_deref()
        .is_some_and(|name| !valid_dns_label(name))
    {
        return Err(ApiError::invalid(
            "invalid_name",
            "Peer name must be a canonical DNS label",
        ));
    }
    if body
        .labels
        .as_ref()
        .is_some_and(|labels| !peerward_api::valid_labels(labels))
    {
        return Err(ApiError::invalid(
            "invalid_labels",
            "peer labels are invalid",
        ));
    }
    for value in [body.display_name.as_deref(), body.location.as_deref()]
        .into_iter()
        .flatten()
    {
        validate_peer_description(value)?;
    }
    let mut transaction = state.store.begin_mutation().await?;
    lock_resource_version(
        &mut transaction,
        VersionedFamily::Peer,
        Some(mesh),
        peer,
        expected,
    )
    .await?;
    if body.administrative_state == Some(AdministrativeState::Enabled) {
        let ended: bool = sqlx::query_scalar("SELECT admission_ended_at IS NOT NULL OR COALESCE(admission_until<=clock_timestamp(),false) FROM peers WHERE mesh_id=$1 AND id=$2")
            .bind(mesh).bind(peer).fetch_one(&mut *transaction).await?;
        if ended {
            return Err(ApiError::conflict(
                "device_admission_ended",
                "This device access has ended; create a new invitation to enroll again",
            ));
        }
    }
    let stop_access = body.administrative_state == Some(AdministrativeState::Disabled);
    let changed = sqlx::query(
        "UPDATE peers SET name=COALESCE($1,name), labels=COALESCE($2,labels),
         administrative_state=COALESCE($3,administrative_state),updated_at=clock_timestamp(),
         display_name=COALESCE($6,display_name),location=COALESCE($7,location)
         WHERE mesh_id=$4 AND id=$5",
    )
    .bind(body.name)
    .bind(
        body.labels
            .map(serde_json::to_value)
            .transpose()
            .map_err(|_| ApiError::invalid("invalid_labels", "peer labels are invalid"))?,
    )
    .bind(body.administrative_state.map(administrative_state_name))
    .bind(mesh)
    .bind(peer)
    .bind(body.display_name)
    .bind(body.location)
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    if changed != 1 {
        return Err(ApiError::not_found());
    }
    if stop_access {
        clean_up_peer_access(&mut transaction, mesh, peer).await?;
    }
    sqlx::query("UPDATE meshes SET directory_revision=directory_revision+1 WHERE id=$1")
        .bind(mesh)
        .execute(&mut *transaction)
        .await?;
    state
        .store
        .commit_mutation(
            transaction,
            &mutation(
                &context,
                Some(mesh_id),
                "peer.update",
                "peer.updated",
                "peer",
                Some(peer),
            ),
        )
        .await?;
    let resource = load_peer(&state.store, mesh, peer).await?;
    Ok((etag_headers(resource.version)?, Json(resource)))
}

async fn load_peer(store: &Store, mesh: Uuid, peer: Uuid) -> Result<PeerResource, ApiError> {
    let value: Option<Value> = sqlx::query_scalar(
        "SELECT peerward_peer_api_json(p)||jsonb_build_object('version',p.version) FROM peers p WHERE p.mesh_id=$1 AND p.id=$2 AND p.administrative_state<>'deleted'",
    )
    .bind(mesh)
    .bind(peer)
    .fetch_optional(store.pool())
    .await?;
    serde_json::from_value(value.ok_or_else(ApiError::not_found)?)
        .map_err(|_| ApiError::internal("peer_projection", "Peer projection is invalid"))
}

fn validate_peer_description(value: &str) -> Result<(), ApiError> {
    if value.chars().count() > 128 || value.chars().any(char::is_control) || value.trim() != value {
        return Err(ApiError::invalid(
            "invalid_peer_description",
            "Device name and location must be trimmed text of at most 128 characters without control characters",
        ));
    }
    Ok(())
}

async fn disable_peer(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((mesh, peer)): Path<(Uuid, Uuid)>,
) -> Result<(HeaderMap, StatusCode), ApiError> {
    authorize(&context, &headers, Capability::ResourceWrite, true)?;
    let expected = require_if_match(&headers)?;
    let mesh_id = mesh_id(mesh)?;
    peer_id(peer)?;
    let mut transaction = state.store.begin_mutation().await?;
    lock_resource_version(
        &mut transaction,
        VersionedFamily::Peer,
        Some(mesh),
        peer,
        expected,
    )
    .await?;
    let changed = sqlx::query(
        "UPDATE peers SET administrative_state='disabled', updated_at=clock_timestamp()
         WHERE mesh_id=$1 AND id=$2 AND administrative_state='enabled'",
    )
    .bind(mesh)
    .bind(peer)
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    if changed != 1 {
        return Err(ApiError::not_found());
    }
    clean_up_peer_access(&mut transaction, mesh, peer).await?;
    state
        .store
        .commit_mutation(
            transaction,
            &mutation(
                &context,
                Some(mesh_id),
                "peer.disable",
                "peer.disabled",
                "peer",
                Some(peer),
            ),
        )
        .await?;
    versioned_no_content(&state.store, "peers", mesh, peer).await
}

async fn delete_peer(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((mesh, peer)): Path<(Uuid, Uuid)>,
    ApiJson(body): ApiJson<peerward_api::PeerDeleteRequest>,
) -> Result<(HeaderMap, StatusCode), ApiError> {
    authorize(&context, &headers, Capability::ResourceWrite, true)?;
    let expected = require_if_match(&headers)?;
    let mesh_id = mesh_id(mesh)?;
    peer_id(peer)?;
    let mut transaction = state.store.begin_mutation().await?;
    lock_resource_version(
        &mut transaction,
        VersionedFamily::Peer,
        Some(mesh),
        peer,
        expected,
    )
    .await?;
    let row = sqlx::query("SELECT name,administrative_state FROM peers WHERE mesh_id=$1 AND id=$2")
        .bind(mesh)
        .bind(peer)
        .fetch_one(&mut *transaction)
        .await?;
    if row.try_get::<String, _>("administrative_state")? != "disabled" {
        return Err(ApiError::conflict(
            "peer_must_be_disabled",
            "Disable the Peer before deleting it",
        ));
    }
    if row.try_get::<String, _>("name")? != body.name {
        return Err(ApiError::invalid(
            "confirmation_mismatch",
            "Enter the exact current Peer name to confirm deletion",
        ));
    }
    let version: i64 = sqlx::query_scalar(
        "UPDATE peers SET administrative_state='deleted',updated_at=clock_timestamp() WHERE mesh_id=$1 AND id=$2 RETURNING version",
    ).bind(mesh).bind(peer).fetch_one(&mut *transaction).await?;
    clean_up_peer_access(&mut transaction, mesh, peer).await?;
    sqlx::query("UPDATE peer_credential_rotation_requests SET status='cancelled',cancelled_at=clock_timestamp() WHERE mesh_id=$1 AND peer_id=$2 AND status IN ('pending','issued')")
        .bind(mesh).bind(peer).execute(&mut *transaction).await?;
    sqlx::query("DELETE FROM current_peer_runtime_health WHERE mesh_id=$1 AND peer_id=$2")
        .bind(mesh)
        .bind(peer)
        .execute(&mut *transaction)
        .await?;
    let mut record = mutation(
        &context,
        Some(mesh_id),
        "peer.delete",
        "peer.deleted",
        "peer",
        Some(peer),
    );
    record.metadata = json!({"resource_id":peer,"name":body.name});
    state.store.commit_mutation(transaction, &record).await?;
    Ok((
        etag_headers(
            u64::try_from(version)
                .map_err(|_| ApiError::internal("peer_projection", "Peer version is invalid"))?,
        )?,
        StatusCode::NO_CONTENT,
    ))
}

async fn clean_up_peer_access(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    mesh: Uuid,
    peer: Uuid,
) -> Result<(), ApiError> {
    peerward_store::revoke_peer_access(transaction, mesh, peer).await?;
    Ok(())
}
