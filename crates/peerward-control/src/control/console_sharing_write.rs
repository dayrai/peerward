fn validate_console_reason(reason: &str) -> Result<(), ApiError> {
    if reason.len() > 512 || reason.chars().any(char::is_control) {
        return Err(ApiError::invalid(
            "invalid_reason",
            "reason must be plain text of at most 512 bytes",
        ));
    }
    Ok(())
}

async fn edit_console_service(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((mesh, id)): Path<(Uuid, Uuid)>,
    ApiJson(body): ApiJson<peerward_api::ConsoleServiceEdit>,
) -> Result<Json<ServiceResource>, ApiError> {
    authorize(&context, &headers, Capability::ResourceWrite, true)?;
    let expected = require_if_match(&headers)?;
    validate_console_reason(&body.reason)?;
    validate_peer_description(&body.display_name)?;
    if body.listen_port == 0
        || !valid_service_protocols(&body.protocols)
        || body.alias.as_deref().is_some_and(|a| !valid_dns_label(a))
    {
        return Err(ApiError::invalid(
            "invalid_service",
            "invalid port, transports or DNS label",
        ));
    }
    let mut tx = state.store.begin_mutation().await?;
    lock_configuration(&mut tx, mesh).await?;
    assert_configuration_owner(&mut tx, mesh, &context.actor).await?;
    lock_resource_version(&mut tx, VersionedFamily::Service, Some(mesh), id, expected).await?;
    let protocols = body
        .protocols
        .iter()
        .map(|p| match p {
            peerward_types::ServiceProtocol::Tcp => "tcp",
            peerward_types::ServiceProtocol::Udp => "udp",
        })
        .collect::<Vec<_>>();
    let changed=sqlx::query("UPDATE services SET display_name=$3,alias=$4,protocols=$5,listen_port=$6,console_paused=$7,updated_at=clock_timestamp()
        WHERE mesh_id=$1 AND id=$2 AND state='enabled'").bind(mesh).bind(id).bind(&body.display_name).bind(&body.alias)
        .bind(protocols).bind(i32::from(body.listen_port)).bind(body.paused).execute(&mut *tx).await?.rows_affected();
    if changed == 0 {
        return Err(ApiError::conflict(
            "service_disabled",
            "a disabled service cannot be reactivated",
        ));
    }
    let mut policy = load_current_policy_from(&mut *tx, mesh).await?;
    policy.revision = policy.revision.checked_add(1).ok_or_else(publisher_error)?;
    stage_peer_policy(&mut tx, mesh, &policy).await?;
    sqlx::query("UPDATE meshes SET service_revision=service_revision+1,directory_revision=directory_revision+1,management_revision=management_revision+1 WHERE id=$1")
        .bind(mesh).execute(&mut *tx).await?;
    let impact = read_console_sharing_impact(&mut tx, mesh, "service", id).await?;
    let mut record = mutation(
        &context,
        Some(mesh_id(mesh)?),
        "service.edit",
        "service.updated",
        "service",
        Some(id),
    );
    record.metadata = json!({"resource_id":id,"paused":body.paused,"reason":body.reason,"endpoint_access_affected":body.paused,"overlapping_resources":impact.overlapping_resources});
    state.store.commit_mutation(tx, &record).await?;
    Ok(Json(load_service(&state.store, mesh, id).await?))
}

async fn set_console_resource_state(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((mesh, id)): Path<(Uuid, Uuid)>,
    ApiJson(body): ApiJson<peerward_api::ConsoleResourceState>,
) -> Result<StatusCode, ApiError> {
    authorize(&context, &headers, Capability::ResourceWrite, true)?;
    validate_console_reason(&body.reason)?;
    let expected = require_if_match(&headers)?;
    let mut tx = state.store.begin_mutation().await?;
    lock_configuration(&mut tx, mesh).await?;
    assert_configuration_owner(&mut tx, mesh, &context.actor).await?;
    let version: i64 = sqlx::query_scalar(
        "SELECT version FROM network_resources WHERE mesh_id=$1 AND id=$2 FOR UPDATE",
    )
    .bind(mesh)
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(ApiError::not_found)?;
    if version != expected {
        return Err(ApiError::conflict(
            "version_conflict",
            "resource changed; review again",
        ));
    }
    sqlx::query("UPDATE network_resources SET console_paused=$3,updated_at=clock_timestamp() WHERE mesh_id=$1 AND id=$2")
        .bind(mesh).bind(id).bind(body.paused).execute(&mut *tx).await?;
    read_resource_configuration(&mut tx, mesh_id(mesh)?)
        .await?
        .validate()
        .map_err(management_error)?;
    let impact = read_console_sharing_impact(&mut tx, mesh, "lan", id).await?;
    bump_management(&mut tx, mesh).await?;
    let mut record = mutation(
        &context,
        Some(mesh_id(mesh)?),
        "network_resource.state",
        "network_resource.updated",
        "network_resource",
        Some(id),
    );
    record.metadata = json!({"resource_id":id,"paused":body.paused,"reason":body.reason,"grants_preserved":true,"overlapping_resources":impact.overlapping_resources});
    state.store.commit_mutation(tx, &record).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn console_sharing_impact(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    Path((mesh, kind, id)): Path<(Uuid, String, Uuid)>,
) -> Result<Json<peerward_api::ConsoleSharingImpact>, ApiError> {
    authorize(&context, &HeaderMap::new(), Capability::ResourceRead, false)?;
    let mut tx = state.store.begin_mutation().await?;
    lock_configuration(&mut tx, mesh).await?;
    let result = read_console_sharing_impact(&mut tx, mesh, &kind, id).await?;
    tx.rollback().await?;
    Ok(Json(result))
}
async fn read_console_sharing_impact(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    mesh: Uuid,
    kind: &str,
    id: Uuid,
) -> Result<peerward_api::ConsoleSharingImpact, ApiError> {
    let (version, name, overlapping_resources) = if kind == "service" {
        let row:(i64,String,Uuid,i32,Vec<String>)=sqlx::query_as("SELECT version,COALESCE(NULLIF(display_name,''),alias,id::text),peer_id,listen_port,protocols FROM services WHERE mesh_id=$1 AND id=$2")
            .bind(mesh).bind(id).fetch_optional(&mut **tx).await?.ok_or_else(ApiError::not_found)?;
        let overlaps=sqlx::query_scalar("SELECT COALESCE(NULLIF(display_name,''),alias,id::text) FROM services WHERE mesh_id=$1 AND id<>$2 AND peer_id=$3 AND listen_port=$4 AND protocols && $5::text[] AND state='enabled' ORDER BY id")
            .bind(mesh).bind(id).bind(row.2).bind(row.3).bind(&row.4).fetch_all(&mut **tx).await?;
        (positive_revision(row.0)?, row.1, overlaps)
    } else if matches!(kind, "lan" | "internet") {
        let resources:Vec<peerward_management::NetworkResource>=configuration_rows(tx,mesh_id(mesh)?,"SELECT jsonb_build_object('id',id,'mesh_id',mesh_id,'version',version,'definition',definition) FROM network_resources WHERE mesh_id=$1 ORDER BY id").await?;
        let resource = resources
            .iter()
            .find(|r| r.id == id)
            .ok_or_else(ApiError::not_found)?;
        let overlaps = resources
            .iter()
            .filter(|r| {
                r.id != id
                    && match (&r.definition.target, &resource.definition.target) {
                        (
                            peerward_management::ResourceTarget::Subnet { prefix: a, .. },
                            peerward_management::ResourceTarget::Subnet { prefix: b, .. },
                        ) => a.contains(&b.network()) || b.contains(&a.network()),
                        (
                            peerward_management::ResourceTarget::Internet { ipv4: a, ipv6: b },
                            peerward_management::ResourceTarget::Internet { ipv4: c, ipv6: d },
                        ) => (*a && *c) || (*b && *d),
                        _ => false,
                    }
            })
            .map(|r| r.definition.name.clone())
            .collect();
        (resource.version, resource.definition.name.clone(), overlaps)
    } else {
        return Err(ApiError::not_found());
    };
    Ok(peerward_api::ConsoleSharingImpact {
        version,
        resource_name: name,
        overlapping_resources,
    })
}

async fn retire_console_device(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((mesh, peer)): Path<(Uuid, Uuid)>,
    ApiJson(body): ApiJson<peerward_api::ConsoleDeviceRetire>,
) -> Result<StatusCode, ApiError> {
    authorize(&context, &headers, Capability::ResourceWrite, true)?;
    let expected = require_if_match(&headers)?;
    validate_console_reason(&body.reason)?;
    if body.reason.trim().is_empty() {
        return Err(ApiError::invalid(
            "reason_required",
            "provide a retirement reason",
        ));
    }
    let mut tx = state.store.begin_mutation().await?;
    lock_resource_version(&mut tx, VersionedFamily::Peer, Some(mesh), peer, expected).await?;
    let (name, enabled): (String, bool) = sqlx::query_as(
        "SELECT name,administrative_state='enabled' FROM peers WHERE mesh_id=$1 AND id=$2",
    )
    .bind(mesh)
    .bind(peer)
    .fetch_one(&mut *tx)
    .await?;
    if name != body.name {
        return Err(ApiError::invalid(
            "confirmation_mismatch",
            "enter the exact device network name",
        ));
    }
    if !enabled {
        return Err(ApiError::conflict(
            "device_disabled",
            "device is already retired",
        ));
    }
    let services: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM services WHERE mesh_id=$1 AND peer_id=$2 AND state='enabled'",
    )
    .bind(mesh)
    .bind(peer)
    .fetch_one(&mut *tx)
    .await?;
    let bindings: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM gateway_bindings WHERE mesh_id=$1 AND peer_id=$2 AND approved",
    )
    .bind(mesh)
    .bind(peer)
    .fetch_one(&mut *tx)
    .await?;
    sqlx::query("UPDATE peers SET administrative_state='disabled',updated_at=clock_timestamp() WHERE mesh_id=$1 AND id=$2").bind(mesh).bind(peer).execute(&mut *tx).await?;
    clean_up_peer_access(&mut tx, mesh, peer).await?;
    let mut record = mutation(
        &context,
        Some(mesh_id(mesh)?),
        "peer.retire",
        "peer.disabled",
        "peer",
        Some(peer),
    );
    record.metadata = json!({"name":name,"reason":body.reason,"services_affected":services,"gateway_bindings_affected":bindings,"credentials_revoked":true});
    state.store.commit_mutation(tx, &record).await?;
    Ok(StatusCode::NO_CONTENT)
}
