async fn stage_console_network_edit(
    state: &AppState,
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    mesh: Uuid,
    id: Uuid,
    version: u64,
    draft: &peerward_api::ConsoleNetworkEdit,
) -> Result<peerward_api::ConsoleNetworkEditPreview, ApiError> {
    if draft.request_id.get_version_num() != 4 {
        return Err(ApiError::invalid_id());
    }
    validate_console_reason(&draft.reason)?;
    if draft.reason.trim().is_empty() {
        return Err(ApiError::invalid(
            "reason_required",
            "provide a change reason",
        ));
    }
    let current: i64 = sqlx::query_scalar(
        "SELECT version FROM network_resources WHERE mesh_id=$1 AND id=$2 FOR UPDATE",
    )
    .bind(mesh)
    .bind(id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(ApiError::not_found)?;
    if positive_revision(current)? != draft.resource_version {
        return Err(ApiError::conflict(
            "version_conflict",
            "resource changed; reload its current definition",
        ));
    }
    let old = read_configuration_document(tx, mesh).await?;
    let mut new = old.clone();
    let resource = new
        .resources
        .iter_mut()
        .find(|r| r.id == id)
        .ok_or_else(ApiError::not_found)?;
    let previous_target = resource.definition.target.clone();
    // Changing resource families belongs to explicit creation with separate approval.
    if std::mem::discriminant(&previous_target) != std::mem::discriminant(&draft.definition.target)
    {
        return Err(ApiError::invalid(
            "resource_kind_changed",
            "create a separate resource to change its kind",
        ));
    }
    let target_changed = previous_target != draft.definition.target;
    resource.definition = draft.definition.clone();
    let mut gateways_requiring_approval = 0;
    if target_changed {
        if !draft.gateways.is_empty() {
            return Err(ApiError::invalid(
                "target_requires_review",
                "save the new target before reviewing gateway approvals",
            ));
        }
        // A previous grant must not silently authorize a different destination, even
        // when an automatic approval rule happens to cover both destinations.
        for binding in new.bindings.iter_mut().filter(|b| b.resource_id == id) {
            binding.approval = peerward_api::ConfigurationApproval::Manual { approved: false };
            gateways_requiring_approval += 1;
        }
    }
    if draft.gateways.len() > 100 {
        return Err(ApiError::invalid(
            "gateway_limit",
            "at most 100 gateway changes per request",
        ));
    }
    let mut changed = std::collections::BTreeSet::new();
    for change in &draft.gateways {
        if !changed.insert(change.id) {
            return Err(ApiError::invalid(
                "duplicate_gateway",
                "gateway occurs more than once",
            ));
        }
        let binding_version: i64 = sqlx::query_scalar("SELECT version FROM gateway_bindings WHERE mesh_id=$1 AND resource_id=$2 AND id=$3 FOR UPDATE")
            .bind(mesh).bind(id).bind(change.id).fetch_optional(&mut **tx).await?.ok_or_else(ApiError::not_found)?;
        if positive_revision(binding_version)? != change.version {
            return Err(ApiError::conflict(
                "version_conflict",
                "gateway changed; review its current approval",
            ));
        }
        let binding = new
            .bindings
            .iter_mut()
            .find(|b| b.id == change.id)
            .ok_or_else(ApiError::not_found)?;
        binding.priority = change.priority;
        binding.approval = peerward_api::ConfigurationApproval::Manual {
            approved: change.approved,
        };
    }
    normalize_configuration(&mut new, mesh)?;
    let failed = stage_configuration(&state.store, tx, mesh, &old, &new).await?;
    if !failed.is_empty() {
        return Err(ApiError::conflict(
            "policy_tests_failed",
            "saved policy assertions failed; review before changing this target",
        ));
    }
    let impact = read_console_sharing_impact(tx, mesh, "lan", id).await?;
    let digest = declaration_digest(&(
        "console_network_edit_v1",
        version,
        id,
        draft,
        &previous_target,
        gateways_requiring_approval,
        &impact.overlapping_resources,
    ))?;
    Ok(peerward_api::ConsoleNetworkEditPreview {
        version,
        digest,
        resource_id: id,
        previous_target,
        target_changed,
        gateways_requiring_approval,
        gateways_changed: draft.gateways.len() as u64,
        overlapping_resources: impact.overlapping_resources,
        applied: false,
    })
}

async fn console_network_gateways(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    Path((mesh, id)): Path<(Uuid, Uuid)>,
    Query(query): Query<ConsoleQuery>,
) -> Result<Json<ApiPage<peerward_api::ConsoleGateway>>, ApiError> {
    authorize(&context, &HeaderMap::new(), Capability::ResourceRead, false)?;
    let limit = query.bounded_limit()?;
    let cursor = query
        .cursor
        .map(|s| s.parse::<Uuid>())
        .transpose()
        .map_err(|_| ApiError::invalid("invalid_cursor", "expected gateway cursor"))?;
    load_network_resource(&state.store, mesh, id).await?;
    let rows: Vec<Value> = sqlx::query_scalar("SELECT jsonb_build_object('binding',to_jsonb(b)-'mesh_id'-'created_at'-'updated_at','peer_name',COALESCE(NULLIF(p.display_name,''),p.name),'online',(peerward_peer_api_json(p)->>'online')::boolean)
        FROM gateway_bindings b JOIN peers p ON p.mesh_id=b.mesh_id AND p.id=b.peer_id WHERE b.mesh_id=$1 AND b.resource_id=$2 AND ($3::uuid IS NULL OR b.id>$3) ORDER BY b.id LIMIT $4")
        .bind(mesh).bind(id).bind(cursor).bind(i64::from(limit)+1).fetch_all(state.store.pool()).await?;
    let more = rows.len() > usize::from(limit);
    let items: Vec<peerward_api::ConsoleGateway> = rows
        .into_iter()
        .take(usize::from(limit))
        .map(|row| serde_json::from_value(row).map_err(|_| publisher_error()))
        .collect::<Result<_, _>>()?;
    let next_cursor = more.then(|| items.last().unwrap().binding.id.to_string());
    Ok(Json(ApiPage { items, next_cursor }))
}

async fn preview_console_network_edit(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((mesh, id)): Path<(Uuid, Uuid)>,
    ApiJson(draft): ApiJson<peerward_api::ConsoleNetworkEdit>,
) -> Result<Json<peerward_api::ConsoleNetworkEditPreview>, ApiError> {
    authorize(&context, &headers, Capability::ResourceWrite, true)?;
    let mut tx = state.store.begin_mutation().await?;
    let version = lock_configuration(&mut tx, mesh).await?;
    assert_configuration_owner(&mut tx, mesh, &context.actor).await?;
    let preview = stage_console_network_edit(&state, &mut tx, mesh, id, version, &draft).await?;
    tx.rollback().await?;
    Ok(Json(preview))
}

async fn apply_console_network_edit(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((mesh, id)): Path<(Uuid, Uuid)>,
    ApiJson(body): ApiJson<peerward_api::ConsoleNetworkEditApply>,
) -> Result<Json<peerward_api::ConsoleNetworkEditPreview>, ApiError> {
    authorize(&context, &headers, Capability::ResourceWrite, true)?;
    let expected = require_if_match(&headers)?;
    let digest = declaration_digest(&("console_network_edit_v1", mesh, id, expected, &body))?;
    let mut tx = state.store.begin_mutation().await?;
    let version = lock_configuration(&mut tx, mesh).await?;
    assert_configuration_owner(&mut tx, mesh, &context.actor).await?;
    let prior: Option<(String,String,Value)> = sqlx::query_as("SELECT actor,digest,response FROM console_sharing_requests WHERE mesh_id=$1 AND request_id=$2")
        .bind(mesh).bind(body.draft.request_id).fetch_optional(&mut *tx).await?;
    if let Some((actor, known, response)) = prior {
        if actor != context.actor || digest != known {
            return Err(ApiError::conflict(
                "request_reused",
                "request identity is bound to a different change",
            ));
        }
        tx.rollback().await?;
        return Ok(Json(
            serde_json::from_value(response).map_err(|_| publisher_error())?,
        ));
    }
    check_configuration_version(version, expected)?;
    let mut preview =
        stage_console_network_edit(&state, &mut tx, mesh, id, version, &body.draft).await?;
    if preview.digest != body.preview_digest {
        return Err(ApiError::conflict(
            "preview_changed",
            "change impact changed; preview again",
        ));
    }
    bump_management(&mut tx, mesh).await?;
    preview.applied = true;
    sqlx::query("INSERT INTO console_sharing_requests(mesh_id,request_id,actor,digest,response) VALUES($1,$2,$3,$4,$5)")
        .bind(mesh).bind(body.draft.request_id).bind(&context.actor).bind(digest).bind(declaration_value(&preview)?).execute(&mut *tx).await?;
    let mut record = mutation(
        &context,
        Some(mesh_id(mesh)?),
        "network_resource.edit",
        "network_resource.updated",
        "network_resource",
        Some(id),
    );
    record.metadata = json!({"reason":body.draft.reason,"impact":preview,"grants_preserved":true});
    state.store.commit_mutation(tx, &record).await?;
    Ok(Json(preview))
}
