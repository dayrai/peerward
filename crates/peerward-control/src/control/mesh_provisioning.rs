use peerward_api::{MeshProvisioningCreateRequest, MeshProvisioningResource};

async fn provisioning_projection(state: &AppState, job: &MeshLifecycleJob) -> Result<MeshProvisioningResource, ApiError> {
    let row = sqlx::query("SELECT created_at,updated_at FROM mesh_lifecycle_jobs WHERE id=$1")
        .bind(job.id).fetch_one(state.store.pool()).await?;
    let name: Option<String> = sqlx::query_scalar("SELECT name FROM meshes WHERE id=$1 UNION ALL SELECT name FROM mesh_tombstones WHERE mesh_id=$1 LIMIT 1")
        .bind(job.mesh_id.into_uuid()).fetch_optional(state.store.pool()).await?;
    let endpoint: Option<String> = sqlx::query_scalar("SELECT h.peer_endpoints[1] FROM relay_hosts h JOIN relay_host_assignments a ON a.host_id=h.id WHERE a.mesh_id=$1 LIMIT 1")
        .bind(job.mesh_id.into_uuid()).fetch_optional(state.store.pool()).await?;
    Ok(MeshProvisioningResource {
        id: job.id, operation: job.operation.clone(), mesh_id: job.mesh_id, name: name.unwrap_or_default(), existing_mesh: false,
        status: if job.status == "waiting" { "running".into() } else { job.status.clone() },
        stage: job.stage.clone(), error_code: job.error_code.clone(), relay_endpoint: endpoint,
        created_at: row.try_get::<OffsetDateTime,_>("created_at")?.format(&Rfc3339).map_err(|_| dynamic_invalid())?,
        updated_at: row.try_get::<OffsetDateTime,_>("updated_at")?.format(&Rfc3339).map_err(|_| dynamic_invalid())?,
    })
}

async fn list_mesh_provisioning(Extension(context): Extension<AuthContext>, State(state): State<AppState>, Query(query): Query<ListQuery>)
    -> Result<Json<ApiPage<MeshProvisioningResource>>, ApiError> {
    authorize(&context, &HeaderMap::new(), Capability::TrustManage, false)?;
    let mut items = Vec::new();
    let page = lifecycle_job_page(&state.store, &query).await?;
    for job in page.items {
        items.push(provisioning_projection(&state, &job).await?);
    }
    Ok(Json(ApiPage { items, next_cursor: page.next_cursor }))
}

async fn get_mesh_provisioning(Extension(context): Extension<AuthContext>, State(state): State<AppState>, Path(id): Path<Uuid>)
    -> Result<Json<MeshProvisioningResource>, ApiError> {
    authorize(&context, &HeaderMap::new(), Capability::TrustManage, false)?;
    Ok(Json(provisioning_projection(&state, &state.store.mesh_job(id).await?).await?))
}

async fn create_mesh_provisioning(Extension(context): Extension<AuthContext>, State(state): State<AppState>, headers: HeaderMap,
    ApiJson(request): ApiJson<MeshProvisioningCreateRequest>) -> Result<(StatusCode, Json<MeshProvisioningResource>), ApiError> {
    authorize(&context, &headers, Capability::TrustManage, true)?;
    if !valid_display_name(&request.name) || request.request_id.get_version_num()!=4 { return Err(dynamic_invalid()); }
    if request.network_identifier.as_deref().is_some_and(|id| !peerward_api::valid_network_identifier(id))
        || (request.existing_mesh_id.is_some() && request.network_identifier.is_some()) {
        return Err(dynamic_invalid());
    }
    match state.store.mesh_job(request.request_id).await {
        Ok(job) => {
            let resource = provisioning_projection(&state, &job).await?;
            if job.operation!="create" || resource.name != request.name || !provisioning_identifier_matches(&state, &request).await? || request.existing_mesh_id.is_some_and(|mesh| mesh!=job.mesh_id) {
                return Err(ApiError::conflict("request_id_conflict", "Request ID already has different input"));
            }
            return Ok((StatusCode::OK, Json(resource)));
        }
        Err(StoreError::NotFound) => {},
        Err(error) => return Err(error.into()),
    }
    if let Some(mesh) = request.existing_mesh_id {
        let id: Option<Uuid> = sqlx::query_scalar("SELECT id FROM mesh_lifecycle_jobs WHERE mesh_id=$1 AND operation='create'")
            .bind(mesh.into_uuid()).fetch_optional(state.store.pool()).await?;
        if let Some(id) = id { return Ok((StatusCode::OK, Json(provisioning_projection(&state, &state.store.mesh_job(id).await?).await?))); }
        return Err(ApiError::conflict("mesh_not_managed", "Create a new managed Mesh to initialize this installation"));
    }
    // Choose a /24 within the CGNAT range. The store serializes overlap checks
    // with insertion; a concurrent allocation is retried without creating a job.
    for _ in 0..256 {
        let mut random = [0; 2]; OsRng.fill_bytes(&mut random);
        let index = u32::from(u16::from_be_bytes(random)) % 16384;
        let address = std::net::Ipv4Addr::from(u32::from(std::net::Ipv4Addr::new(100,64,0,0)) + index*256);
        let gateway = std::net::Ipv4Addr::from(u32::from(address)+1);
        let mesh = NewMesh { name: request.name.clone(), address_cidr: format!("{address}/24").parse().map_err(|_| dynamic_invalid())?,
            gateway: gateway.into(), dns_suffix: format!("m-{}.peerward.internal", request.request_id.simple()), mtu:1280,
            reserved:Vec::new(), default_policy:DefaultPolicy::Deny, quarantine_seconds:3600, rotation_overlap_seconds:86400 };
        match state.store.create_mesh_with_identifier(&mesh, &context.actor, Some(request.request_id), request.network_identifier.as_deref()).await {
            Ok(_) => return Ok((StatusCode::ACCEPTED, Json(provisioning_projection(&state, &state.store.mesh_job(request.request_id).await?).await?))),
            Err(StoreError::Invalid("mesh prefix overlaps")) => {},
            Err(StoreError::Invalid("network identifier exists")) => return Err(ApiError::conflict("network_identifier_exists", "This network identifier is already in use")),
            Err(StoreError::Conflict) => {
                let job = state.store.mesh_job(request.request_id).await?;
                let resource = provisioning_projection(&state, &job).await?;
                if job.operation != "create" || resource.name != request.name || !provisioning_identifier_matches(&state, &request).await? {
                    return Err(ApiError::conflict("request_id_conflict", "Request ID already has different input"));
                }
                return Ok((StatusCode::OK, Json(resource)));
            },
            Err(error) => return Err(error.into()),
        }
    }
    Err(ApiError::unavailable("address_pool_busy", "Unable to allocate a Mesh prefix"))
}

async fn retry_mesh_provisioning(Extension(context): Extension<AuthContext>, State(state): State<AppState>, headers: HeaderMap, Path(id): Path<Uuid>)
    -> Result<Json<MeshProvisioningResource>, ApiError> {
    authorize(&context, &headers, Capability::TrustManage, true)?;
    state.store.retry_mesh_job(id, &context.actor).await?;
    Ok(Json(provisioning_projection(&state, &state.store.mesh_job(id).await?).await?))
}

async fn provisioning_identifier_matches(state: &AppState, request: &MeshProvisioningCreateRequest) -> Result<bool, ApiError> {
    let identifier: Option<String> = sqlx::query_scalar("SELECT network_identifier FROM mesh_lifecycle_jobs WHERE id=$1")
        .bind(request.request_id).fetch_one(state.store.pool()).await?;
    Ok(identifier == request.network_identifier)
}
