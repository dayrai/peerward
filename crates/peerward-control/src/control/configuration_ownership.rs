async fn load_configuration_ownership(
    store: &Store,
    mesh: Uuid,
) -> Result<peerward_api::ConfigurationOwnershipView, ApiError> {
    mesh_id(mesh)?;
    let row=sqlx::query("SELECT o.version,o.owner_machine_id,c.name,COALESCE(c.revoked_at IS NULL AND c.expires_at>clock_timestamp(),false) AS active
        FROM configuration_ownership o LEFT JOIN machine_credentials c ON c.mesh_id=o.mesh_id AND c.id=o.owner_machine_id WHERE o.mesh_id=$1")
        .bind(mesh).fetch_optional(store.pool()).await?.ok_or_else(ApiError::not_found)?;
    Ok(peerward_api::ConfigurationOwnershipView {
        version: positive_revision(row.try_get("version")?)?,
        owner_machine_id: row.try_get("owner_machine_id")?,
        owner_name: row.try_get("name")?,
        owner_active: row.try_get("active")?,
    })
}
async fn get_configuration_ownership(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    Path(mesh): Path<Uuid>,
) -> Result<(HeaderMap, Json<peerward_api::ConfigurationOwnershipView>), ApiError> {
    authorize(&context, &HeaderMap::new(), Capability::ResourceRead, false)?;
    let value = load_configuration_ownership(&state.store, mesh).await?;
    Ok((etag_headers(value.version)?, Json(value)))
}
async fn put_configuration_ownership(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(mesh): Path<Uuid>,
    ApiJson(body): ApiJson<peerward_api::ConfigurationOwnershipRequest>,
) -> Result<(HeaderMap, Json<peerward_api::ConfigurationOwnershipView>), ApiError> {
    authorize(&context, &headers, Capability::TrustManage, true)?;
    let expected = require_if_match(&headers)?;
    if body
        .owner_machine_id
        .is_some_and(|id| id.get_version_num() != 4)
    {
        return Err(ApiError::invalid_id());
    }
    let mut tx = state.store.begin_mutation().await?;
    sqlx::query("SELECT id FROM meshes WHERE id=$1 AND lifecycle='active' FOR UPDATE")
        .bind(mesh)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(ApiError::not_found)?;
    let version: i64 = sqlx::query_scalar(
        "SELECT version FROM configuration_ownership WHERE mesh_id=$1 FOR UPDATE",
    )
    .bind(mesh)
    .fetch_one(&mut *tx)
    .await?;
    if version != expected {
        return Err(ApiError::conflict(
            "version_conflict",
            "configuration changed; reload ownership and review before transferring",
        ));
    }
    if let Some(id) = body.owner_machine_id {
        let valid:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM machine_credentials WHERE mesh_id=$1 AND id=$2 AND revoked_at IS NULL AND expires_at>clock_timestamp() AND capabilities @> ARRAY['resource_read','resource_write']::text[])")
            .bind(mesh).bind(id).fetch_one(&mut *tx).await?;
        if !valid {
            return Err(ApiError::invalid(
                "configuration_owner",
                "choose an active read/write machine credential in this Mesh",
            ));
        }
    }
    sqlx::query("UPDATE configuration_ownership SET owner_machine_id=$2,updated_at=clock_timestamp() WHERE mesh_id=$1")
        .bind(mesh).bind(body.owner_machine_id).execute(&mut *tx).await?;
    let mut record = mutation(
        &context,
        Some(mesh_id(mesh)?),
        "configuration.ownership",
        "configuration.ownership_changed",
        "configuration",
        None,
    );
    record.metadata = json!({"owner_machine_id":body.owner_machine_id});
    state.store.commit_mutation(tx, &record).await?;
    let value = load_configuration_ownership(&state.store, mesh).await?;
    Ok((etag_headers(value.version)?, Json(value)))
}
