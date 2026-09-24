async fn list_relays(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    Path(mesh): Path<Uuid>,
    Query(query): Query<ListQuery>,
) -> Result<Json<ApiPage<RelayResource>>, ApiError> {
    authorize(&context, &HeaderMap::new(), Capability::ResourceRead, false)?;
    mesh_id(mesh)?;
    json_page(&state.store,
        "SELECT peerward_relay_api_json(r)||jsonb_build_object('version',r.version) AS item,r.id,r.created_at AS cursor_time FROM relays r WHERE r.mesh_id=$1
         AND ($2::timestamptz IS NULL OR (r.created_at,r.id)>($2,$3))
         ORDER BY r.created_at,r.id LIMIT $4",
        mesh, query.cursor()?, query.limit()?).await
}

async fn get_relay(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    Path((mesh, relay)): Path<(Uuid, Uuid)>,
) -> Result<(HeaderMap, Json<RelayResource>), ApiError> {
    authorize(&context, &HeaderMap::new(), Capability::ResourceRead, false)?;
    mesh_id(mesh)?;
    relay_id(relay)?;
    let resource = load_relay(&state.store, mesh, relay).await?;
    Ok((etag_headers(resource.version)?, Json(resource)))
}

async fn create_relay(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(mesh): Path<Uuid>,
    ApiJson(body): ApiJson<RelayCreateRequest>,
) -> Result<(StatusCode, HeaderMap, Json<RelayResource>), ApiError> {
    authorize(&context, &headers, Capability::ResourceWrite, true)?;
    if !valid_display_name(&body.name) {
        return Err(ApiError::invalid(
            "invalid_name",
            "Relay name must contain at most 128 UTF-8 bytes",
        ));
    }
    validate_endpoint_list(&body.peer_endpoints).map_err(|_| {
        ApiError::invalid("invalid_peer_endpoints", "Relay Peer endpoints are invalid")
    })?;
    validate_endpoint_list(&body.backbone_endpoints).map_err(|_| {
        ApiError::invalid(
            "invalid_backbone_endpoints",
            "Relay backbone endpoints are invalid",
        )
    })?;
    validate_relay_region(&body.region)?;
    validate_routing_weight(body.routing_weight)?;
    let mesh_id = mesh_id(mesh)?;
    let relay_id = RelayId::new();
    let peer_endpoints = endpoint_strings(&body.peer_endpoints);
    let backbone_endpoints = endpoint_strings(&body.backbone_endpoints);
    let mut transaction = state.store.begin_mutation().await?;
    sqlx::query("INSERT INTO relays(id,mesh_id,name,peer_endpoints,backbone_endpoints,region,routing_weight) VALUES($1,$2,$3,$4,$5,$6,$7)")
        .bind(relay_id.into_uuid()).bind(mesh).bind(&body.name).bind(&peer_endpoints)
        .bind(&backbone_endpoints).bind(&body.region).bind(i32::from(body.routing_weight))
        .execute(&mut *transaction).await?;
    sqlx::query("UPDATE meshes SET relay_revision=relay_revision+1 WHERE id=$1")
        .bind(mesh).execute(&mut *transaction).await?;
    state
        .store
        .commit_mutation(
            transaction,
            &mutation(
                &context,
                Some(mesh_id),
                "relay.create",
                "relay.created",
                "relay",
                Some(relay_id.into_uuid()),
            ),
        )
        .await?;
    let resource = load_relay(&state.store, mesh, relay_id.into_uuid()).await?;
    Ok((StatusCode::CREATED, etag_headers(resource.version)?, Json(resource)))
}

async fn patch_relay(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((mesh, relay)): Path<(Uuid, Uuid)>,
    ApiJson(body): ApiJson<RelayPatchRequest>,
) -> Result<(HeaderMap, Json<RelayResource>), ApiError> {
    authorize(&context, &headers, Capability::ResourceWrite, true)?;
    let expected = require_if_match(&headers)?;
    if body
        .name
        .as_deref()
        .is_some_and(|name| !valid_display_name(name))
    {
        return Err(ApiError::invalid(
            "invalid_name",
            "Relay name must contain at most 128 UTF-8 bytes",
        ));
    }
    if let Some(endpoints) = &body.peer_endpoints {
        validate_endpoint_list(endpoints).map_err(|_| {
            ApiError::invalid("invalid_peer_endpoints", "Relay Peer endpoints are invalid")
        })?;
    }
    if let Some(endpoints) = &body.backbone_endpoints {
        validate_endpoint_list(endpoints).map_err(|_| {
            ApiError::invalid(
                "invalid_backbone_endpoints",
                "Relay backbone endpoints are invalid",
            )
        })?;
    }
    if let Some(region) = &body.region {
        validate_relay_region(region)?;
    }
    if let Some(weight) = body.routing_weight {
        validate_routing_weight(weight)?;
    }
    let mesh_id = mesh_id(mesh)?;
    relay_id(relay)?;
    let peer_endpoints = body.peer_endpoints.as_deref().map(endpoint_strings);
    let backbone_endpoints = body.backbone_endpoints.as_deref().map(endpoint_strings);
    let mut transaction = state.store.begin_mutation().await?;
    lock_resource_version(&mut transaction, VersionedFamily::Relay, Some(mesh), relay, expected).await?;
    let changed = sqlx::query(
        "UPDATE relays SET name=COALESCE($1,name),peer_endpoints=COALESCE($2,peer_endpoints),
         backbone_endpoints=COALESCE($3,backbone_endpoints),administrative_state=COALESCE($4,administrative_state),
         region=COALESCE($5,region),routing_weight=COALESCE($6,routing_weight),
         updated_at=clock_timestamp() WHERE mesh_id=$7 AND id=$8",
    ).bind(body.name).bind(peer_endpoints).bind(backbone_endpoints)
      .bind(body.administrative_state.map(administrative_state_name)).bind(body.region)
      .bind(body.routing_weight.map(i32::from)).bind(mesh).bind(relay)
      .execute(&mut *transaction).await?.rows_affected();
    if changed != 1 {
        return Err(ApiError::not_found());
    }
    sqlx::query("UPDATE meshes SET relay_revision=relay_revision+1 WHERE id=$1")
        .bind(mesh).execute(&mut *transaction).await?;
    state
        .store
        .commit_mutation(
            transaction,
            &mutation(
                &context,
                Some(mesh_id),
                "relay.update",
                "relay.updated",
                "relay",
                Some(relay),
            ),
        )
        .await?;
    let resource = load_relay(&state.store, mesh, relay).await?;
    Ok((etag_headers(resource.version)?, Json(resource)))
}

async fn load_relay(store: &Store, mesh: Uuid, relay: Uuid) -> Result<RelayResource, ApiError> {
    let value: Option<Value> = sqlx::query_scalar(
        "SELECT peerward_relay_api_json(r)||jsonb_build_object('version',r.version) FROM relays r WHERE r.mesh_id=$1 AND r.id=$2",
    )
    .bind(mesh)
    .bind(relay)
    .fetch_optional(store.pool())
    .await?;
    serde_json::from_value(value.ok_or_else(ApiError::not_found)?)
        .map_err(|_| ApiError::internal("relay_projection", "Relay projection is invalid"))
}

async fn delete_relay(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((mesh, relay)): Path<(Uuid, Uuid)>,
) -> Result<(HeaderMap, StatusCode), ApiError> {
    authorize(&context, &headers, Capability::ResourceWrite, true)?;
    let expected = require_if_match(&headers)?;
    let mesh_id = mesh_id(mesh)?;
    relay_id(relay)?;
    let mut transaction = state.store.begin_mutation().await?;
    lock_resource_version(&mut transaction, VersionedFamily::Relay, Some(mesh), relay, expected).await?;
    let changed = sqlx::query(
        "UPDATE relays SET administrative_state='disabled', updated_at=clock_timestamp()
         WHERE mesh_id=$1 AND id=$2 AND administrative_state='enabled'",
    )
    .bind(mesh)
    .bind(relay)
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    if changed != 1 {
        return Err(ApiError::not_found());
    }
    sqlx::query("UPDATE relay_credentials SET lifecycle='revoked' WHERE mesh_id=$1 AND relay_id=$2 AND lifecycle<>'revoked'")
        .bind(mesh).bind(relay).execute(&mut *transaction).await?;
    sqlx::query("DELETE FROM relay_presence WHERE mesh_id=$1 AND relay_id=$2")
        .bind(mesh).bind(relay).execute(&mut *transaction).await?;
    sqlx::query("DELETE FROM relay_standby_presence_v1 WHERE mesh_id=$1 AND relay_id=$2")
        .bind(mesh).bind(relay).execute(&mut *transaction).await?;
    sqlx::query("UPDATE meshes SET relay_revision=relay_revision+1,
        directory_revision=directory_revision+1,revocation_revision=revocation_revision+1,
        updated_at=clock_timestamp() WHERE id=$1")
        .bind(mesh).execute(&mut *transaction).await?;
    state.store.commit_mutation(
        transaction,
        &mutation(&context, Some(mesh_id), "relay.disable", "relay.disabled", "relay", Some(relay)),
    ).await?;
    let version: i64 = sqlx::query_scalar("SELECT version FROM relays WHERE mesh_id=$1 AND id=$2")
        .bind(mesh).bind(relay).fetch_one(state.store.pool()).await?;
    Ok((etag_headers(u64::try_from(version).map_err(|_| ApiError::internal("relay_projection", "Relay version is invalid"))?)?, StatusCode::NO_CONTENT))
}

async fn rotate_relay(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((mesh, relay)): Path<(Uuid, Uuid)>,
    ApiJson(body): ApiJson<CredentialRotationRequest>,
) -> Result<(StatusCode, HeaderMap, Json<CredentialResource>), ApiError> {
    authorize(&context, &headers, Capability::ResourceWrite, true)?;
    let expected = require_if_match(&headers)?;
    rotate_subject(&state, &context, mesh_id(mesh)?, relay, &body, false, expected).await
}

fn endpoint_strings(endpoints: &[NetworkEndpoint]) -> Vec<String> {
    endpoints
        .iter()
        .map(ToString::to_string)
        .collect()
}

fn validate_relay_region(region: &str) -> Result<(), ApiError> {
    let valid = !region.is_empty()
        && region.len() <= 32
        && region.as_bytes().iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-'
        })
        && region.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric)
        && region.as_bytes().last().is_some_and(u8::is_ascii_alphanumeric);
    if valid {
        Ok(())
    } else {
        Err(ApiError::invalid(
            "invalid_relay_region",
            "Relay region must be a lowercase DNS-style label of at most 32 bytes",
        ))
    }
}

fn validate_routing_weight(weight: u16) -> Result<(), ApiError> {
    if (1..=1000).contains(&weight) {
        Ok(())
    } else {
        Err(ApiError::invalid(
            "invalid_routing_weight",
            "Relay routing weight must be between 1 and 1000",
        ))
    }
}
