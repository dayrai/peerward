fn lifecycle_resource(job: &MeshLifecycleJob) -> Value {
    json!({"id":job.id,"mesh_id":job.mesh_id,"operation":job.operation,"status":job.status,
        "stage":job.stage,"attempt":job.attempt,"error_code":job.error_code})
}

async fn list_mesh_lifecycle(Extension(context): Extension<AuthContext>, State(state): State<AppState>,
    Query(query): Query<ListQuery>) -> Result<Json<ApiPage<Value>>, ApiError> {
    authorize(&context, &HeaderMap::new(), Capability::TrustManage, false)?;
    let page = lifecycle_job_page(&state.store, &query).await?;
    Ok(Json(ApiPage { items: page.items.iter().map(lifecycle_resource).collect(), next_cursor: page.next_cursor }))
}

async fn get_mesh_lifecycle(Extension(context): Extension<AuthContext>, State(state): State<AppState>,
    Path(id): Path<Uuid>) -> Result<Json<Value>, ApiError> {
    authorize(&context, &HeaderMap::new(), Capability::TrustManage, false)?;
    Ok(Json(lifecycle_resource(&state.store.mesh_job(id).await?)))
}

async fn retry_mesh_lifecycle(Extension(context): Extension<AuthContext>, State(state): State<AppState>,
    headers: HeaderMap, Path(id): Path<Uuid>) -> Result<Json<Value>, ApiError> {
    authorize(&context, &headers, Capability::TrustManage, true)?;
    state.store.retry_mesh_job(id, &context.actor).await?;
    Ok(Json(lifecycle_resource(&state.store.mesh_job(id).await?)))
}

/// Public, signed and non-secret: devices with retired credentials must still
/// be able to retrieve a terminal record after normal API authorization ends.
async fn get_mesh_termination(State(state): State<AppState>, Path(id): Path<Uuid>) -> Result<Json<Value>, ApiError> {
    mesh_id(id)?;
    let row = sqlx::query("SELECT root_public_key,termination FROM mesh_tombstones WHERE mesh_id=$1")
        .bind(id).fetch_optional(state.store.pool()).await?.ok_or_else(ApiError::not_found)?;
    Ok(Json(json!({"mesh_id":id,"root_public_key":row.try_get::<Vec<u8>,_>("root_public_key")?,
        "termination":row.try_get::<Vec<u8>,_>("termination")?})))
}

/// Export only the encrypted archive. The offline recipient key is never configured here.
async fn export_mesh_recovery(Extension(context): Extension<AuthContext>, Path(id): Path<Uuid>) -> Result<Response, ApiError> {
    authorize(&context, &HeaderMap::new(), Capability::TrustManage, false)?;
    let mesh = mesh_id(id)?;
    let config = DynamicMeshConfig::from_environment()?.ok_or_else(dynamic_invalid)?;
    let bytes = read_private(&config.recovery_directory.join(format!("{mesh}.recovery")), peerward_wire::ROOT_RECOVERY_LEN as u64).map_err(dynamic_io)?;
    Ok(([(axum::http::header::CONTENT_TYPE, "application/octet-stream"),
         (axum::http::header::CACHE_CONTROL, "no-store")], bytes).into_response())
}

async fn lifecycle_job_page(store: &Store, query: &ListQuery) -> Result<ApiPage<MeshLifecycleJob>, ApiError> {
    let page = store.mesh_jobs(query.cursor()?.map(|cursor| StorePageCursor { timestamp: cursor.timestamp, id: cursor.id }), query.limit()?).await?;
    Ok(ApiPage { items: page.items, next_cursor: page.next_cursor.map(|cursor| encode_page_cursor(ApiPageCursor { timestamp: cursor.timestamp, id: cursor.id })) })
}
