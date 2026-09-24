async fn list_meshes(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
) -> Result<Json<ApiPage<MeshResource>>, ApiError> {
    authorize(&context, &HeaderMap::new(), Capability::ResourceRead, false)?;
    let page = state
        .store
        .list_meshes(
            query.cursor()?.map(|cursor| StorePageCursor {
                timestamp: cursor.timestamp,
                id: cursor.id,
            }),
            query.limit()?,
        )
        .await?;
    Ok(Json(ApiPage {
        items: page.items.into_iter().map(mesh_resource).collect(),
        next_cursor: page.next_cursor.map(|cursor| {
            encode_page_cursor(ApiPageCursor {
                timestamp: cursor.timestamp,
                id: cursor.id,
            })
        }),
    }))
}

async fn create_mesh(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
    ApiJson(request): ApiJson<MeshCreateRequest>,
) -> Result<(StatusCode, HeaderMap, Json<MeshResource>), ApiError> {
    authorize(&context, &headers, Capability::TrustManage, true)?;
    if !valid_display_name(&request.name) {
        return Err(ApiError::invalid(
            "invalid_name",
            "Mesh name must contain at most 128 UTF-8 bytes",
        ));
    }
    if request.reserved.len() > peerward_types::MAX_RESERVED_ADDRESSES {
        return Err(ApiError::invalid(
            "reserved_addresses_too_large",
            "Mesh has too many reserved addresses",
        ));
    }
    let default_policy = match request.default_policy.as_str() {
        "allow" => DefaultPolicy::Allow,
        "deny" => DefaultPolicy::Deny,
        _ => {
            return Err(ApiError::invalid(
                "invalid_default_policy",
                "default policy must be allow or deny",
            ));
        }
    };
    let dns_suffix = normalize_dns_suffix(&request.dns_suffix)?;
    let job_id = request.request_id.unwrap_or_else(Uuid::new_v4);
    let request = NewMesh {
        name: request.name,
        address_cidr: request.address_cidr,
        gateway: request.gateway,
        dns_suffix,
        mtu: request.mtu,
        reserved: request.reserved,
        default_policy,
        quarantine_seconds: request.quarantine_seconds,
        rotation_overlap_seconds: request.rotation_overlap_seconds,
    };
    let mesh = state
        .store
        .create_mesh_with_job(&request, &context.actor, Some(job_id))
        .await?;
    let resource = mesh_resource(mesh);
    Ok((
        StatusCode::ACCEPTED,
        etag_headers(resource.version)?,
        Json(resource),
    ))
}

async fn get_mesh(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    Path(mesh): Path<Uuid>,
) -> Result<(HeaderMap, Json<MeshResource>), ApiError> {
    authorize(&context, &HeaderMap::new(), Capability::ResourceRead, false)?;
    let resource = mesh_resource(state.store.mesh(mesh_id(mesh)?).await?);
    Ok((etag_headers(resource.version)?, Json(resource)))
}

async fn patch_mesh(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(mesh): Path<Uuid>,
    ApiJson(body): ApiJson<MeshPatchRequest>,
) -> Result<(HeaderMap, Json<MeshResource>), ApiError> {
    authorize(&context, &headers, Capability::ResourceWrite, true)?;
    let expected = require_if_match(&headers)?;
    let mesh_id = mesh_id(mesh)?;
    if body.name.is_none() && body.dns_suffix.is_none() && body.lease_seconds.is_none() {
        return Err(ApiError::invalid(
            "empty_patch",
            "patch contains no changes",
        ));
    }
    if body
        .lease_seconds
        .is_some_and(|seconds| ![300, 900, 3600].contains(&seconds))
    {
        return Err(ApiError::invalid(
            "invalid_lease_seconds",
            "authorization duration must be 300, 900 or 3600 seconds",
        ));
    }
    if body
        .name
        .as_ref()
        .is_some_and(|name| !valid_display_name(name))
    {
        return Err(ApiError::invalid(
            "invalid_name",
            "Mesh name is outside its bound",
        ));
    }
    let dns_suffix = body
        .dns_suffix
        .as_deref()
        .map(normalize_dns_suffix)
        .transpose()?;
    let mut transaction = state.store.begin_mutation().await?;
    lock_resource_version(
        &mut transaction,
        VersionedFamily::Mesh,
        None,
        mesh,
        expected,
    )
    .await?;
    if let Some(seconds) = body.lease_seconds {
        let previous: i32 = sqlx::query_scalar("SELECT lease_seconds FROM meshes WHERE id=$1")
            .bind(mesh)
            .fetch_one(&mut *transaction)
            .await?;
        if i64::from(seconds) != i64::from(previous) {
            authorize(&context, &headers, Capability::TrustManage, true)?;
        }
    }
    let changed = sqlx::query(
        "UPDATE meshes SET name=COALESCE($1,name), dns_suffix=COALESCE($2,dns_suffix),
         lease_seconds=COALESCE($4,lease_seconds),
         management_revision=management_revision+CASE WHEN $4::integer IS NOT NULL AND $4<>lease_seconds THEN 1 ELSE 0 END,
         updated_at=clock_timestamp() WHERE id=$3",
    )
    .bind(body.name)
    .bind(dns_suffix)
    .bind(mesh)
    .bind(body.lease_seconds.map(|seconds| i32::try_from(seconds).expect("validated duration")))
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    if changed != 1 {
        return Err(ApiError::not_found());
    }
    state
        .store
        .commit_mutation(
            transaction,
            &mutation(
                &context,
                Some(mesh_id),
                "mesh.update",
                "mesh.updated",
                "mesh",
                Some(mesh),
            ),
        )
        .await?;
    let resource = mesh_resource(state.store.mesh(mesh_id).await?);
    Ok((etag_headers(resource.version)?, Json(resource)))
}

async fn delete_mesh(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(mesh): Path<Uuid>,
    ApiJson(body): ApiJson<MeshDeleteRequest>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    authorize(&context, &headers, Capability::TrustManage, true)?;
    let expected = require_if_match(&headers)?;
    let mesh_id = mesh_id(mesh)?;
    let mut tx = state.store.begin_mutation().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(format!("mesh-lifecycle/{mesh}"))
        .execute(&mut *tx)
        .await?;
    if let Some(row) = sqlx::query(
        "SELECT id,request FROM mesh_lifecycle_jobs WHERE mesh_id=$1 AND operation='delete'",
    )
    .bind(mesh)
    .fetch_optional(&mut *tx)
    .await?
    {
        let request: Value = row.try_get("request")?;
        if request.get("confirmation_name").and_then(Value::as_str)
            != Some(body.confirmation_name.as_str())
        {
            return Err(ApiError::invalid(
                "confirmation_mismatch",
                "Confirmation must match the Mesh name",
            ));
        }
        let job: Uuid = row.try_get("id")?;
        return Ok((
            StatusCode::ACCEPTED,
            Json(json!({"mesh_id":mesh_id,"job_id":job})),
        ));
    }
    lock_resource_version(&mut tx, VersionedFamily::Mesh, None, mesh, expected).await?;
    let name: String = sqlx::query_scalar("SELECT name FROM meshes WHERE id=$1")
        .bind(mesh)
        .fetch_one(&mut *tx)
        .await?;
    if name != body.confirmation_name {
        return Err(ApiError::invalid(
            "confirmation_mismatch",
            "Confirmation must match the Mesh name exactly",
        ));
    }
    let job = Uuid::new_v4();
    sqlx::query("UPDATE meshes SET lifecycle='deleting',lifecycle_revision=lifecycle_revision+1 WHERE id=$1")
        .bind(mesh).execute(&mut *tx).await?;
    sqlx::query("UPDATE mesh_lifecycle_jobs SET status='failed',generation=generation+1,lease_owner=NULL,lease_until=NULL,error_code='mesh_deleted'
        WHERE mesh_id=$1 AND operation='create' AND status<>'succeeded'")
        .bind(mesh).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mesh_lifecycle_jobs(id,mesh_id,operation,request,actor) VALUES($1,$2,'delete',$3,$4)")
        .bind(job).bind(mesh).bind(json!({"confirmation_name":name})).bind(&context.actor).execute(&mut *tx).await?;
    state
        .store
        .commit_mutation(
            tx,
            &mutation(
                &context,
                Some(mesh_id),
                "mesh.delete.request",
                "mesh.deleting",
                "mesh",
                Some(mesh),
            ),
        )
        .await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({"mesh_id":mesh_id,"job_id":job})),
    ))
}

fn mesh_resource(record: MeshRecord) -> MeshResource {
    MeshResource {
        network_identifier: record.network_identifier,
        lease_seconds: record.lease_seconds,
        lifecycle: record.lifecycle,
        lifecycle_job: record.lifecycle_job,
        id: record.id,
        version: record.version,
        name: record.name,
        address_cidr: record.address_cidr,
        secondary_cidr: record.secondary_cidr,
        secondary_gateway: record.secondary_gateway,
        gateway: record.gateway,
        dns_suffix: record.dns_suffix,
        mtu: record.mtu,
        default_policy: match record.default_policy {
            DefaultPolicy::Allow => "allow",
            DefaultPolicy::Deny => "deny",
        }
        .into(),
        policy_revision: record.policy_revision,
        authority_revision: record.authority_revision,
        directory_revision: record.directory_revision,
        relay_revision: record.relay_revision,
        service_revision: record.service_revision,
        revocation_revision: record.revocation_revision,
    }
}
