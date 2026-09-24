async fn stage_console_grant(
    store: &Store,
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    mesh: Uuid,
    version: u64,
    draft: &peerward_api::ConsoleGrantDraft,
) -> Result<peerward_api::ConsoleSharingPreview, ApiError> {
    if draft.request_id.get_version_num() != 4
        || matches!(draft.source, peerward_api::ConsoleGrantSource::None)
    {
        return Err(ApiError::invalid(
            "source_required",
            "select a device or device collection",
        ));
    }
    validate_console_reason(&draft.reason)?;
    let (source, groups, count) = console_grant_source(tx, mesh, &draft.source).await?;
    let impact = read_console_sharing_impact(
        tx,
        mesh,
        if draft.service { "service" } else { "lan" },
        draft.resource_id,
    )
    .await?;
    if draft.service {
        let enabled: bool =
            sqlx::query_scalar("SELECT state='enabled' FROM services WHERE mesh_id=$1 AND id=$2")
                .bind(mesh)
                .bind(draft.resource_id)
                .fetch_one(&mut **tx)
                .await?;
        if !enabled {
            return Err(ApiError::conflict(
                "service_disabled",
                "disabled service cannot receive a grant",
            ));
        }
        sqlx::query("INSERT INTO console_service_grants(mesh_id,id,service_id,source,source_collections) VALUES($1,$2,$3,$4,$5)")
            .bind(mesh).bind(draft.request_id).bind(draft.resource_id).bind(declaration_value(&source)?).bind(groups.iter().copied().collect::<Vec<_>>()).execute(&mut **tx).await?;
        let mut policy = load_current_policy_from(&mut **tx, mesh).await?;
        policy.revision = policy.revision.checked_add(1).ok_or_else(publisher_error)?;
        stage_peer_policy(tx, mesh, &policy).await?;
    } else {
        if draft.protocol != 0 {
            validate_packet_predicate(draft.protocol, draft.port)?;
        } else if draft.port.is_some() {
            return Err(ApiError::invalid(
                "invalid_port",
                "all protocols cannot specify a port",
            ));
        }
        let old = read_configuration_document(tx, mesh).await?;
        let mut new = old.clone();
        new.resource_policy
            .rules
            .push(peerward_management::ResourceRule {
                id: draft.request_id,
                priority: 1000,
                enabled: true,
                action: peerward_management::ResourceAction::Allow,
                source,
                source_collections: groups,
                resources: [draft.resource_id].into(),
                resource_collections: std::collections::BTreeSet::new(),
                providers: std::collections::BTreeSet::new(),
                protocol: draft.protocol,
                destination_ports: draft.port.map(|p| vec![(p, p)]).unwrap_or_default(),
                not_after: None,
            });
        normalize_configuration(&mut new, mesh)?;
        if !stage_configuration(store, tx, mesh, &old, &new)
            .await?
            .is_empty()
        {
            return Err(ApiError::conflict(
                "policy_tests_failed",
                "saved assertions failed; review advanced tests",
            ));
        }
    }
    let warnings = vec![
        "existing_rule_order_and_denies_preserved".to_owned(),
        "policy_simulation_is_not_connectivity_evidence".into(),
    ];
    let digest = declaration_digest(&(version, draft, count, &impact))?;
    Ok(peerward_api::ConsoleSharingPreview {
        version,
        digest,
        resource_id: draft.resource_id,
        affected_sources: count,
        overlapping_resources: impact.overlapping_resources,
        warnings,
        applied: false,
    })
}
async fn preview_console_grant(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(mesh): Path<Uuid>,
    ApiJson(draft): ApiJson<peerward_api::ConsoleGrantDraft>,
) -> Result<Json<peerward_api::ConsoleSharingPreview>, ApiError> {
    authorize(&context, &headers, Capability::ResourceWrite, true)?;
    let mut tx = state.store.begin_mutation().await?;
    let version = lock_configuration(&mut tx, mesh).await?;
    assert_configuration_owner(&mut tx, mesh, &context.actor).await?;
    let result = stage_console_grant(&state.store, &mut tx, mesh, version, &draft).await?;
    tx.rollback().await?;
    Ok(Json(result))
}
async fn apply_console_grant(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(mesh): Path<Uuid>,
    ApiJson(body): ApiJson<peerward_api::ConsoleGrantApply>,
) -> Result<Json<peerward_api::ConsoleSharingPreview>, ApiError> {
    authorize(&context, &headers, Capability::ResourceWrite, true)?;
    let expected = require_if_match(&headers)?;
    let digest = declaration_digest(&(expected, &body))?;
    let mut tx = state.store.begin_mutation().await?;
    let version = lock_configuration(&mut tx, mesh).await?;
    assert_configuration_owner(&mut tx, mesh, &context.actor).await?;
    let prior:Option<(String,String,Value)>=sqlx::query_as("SELECT actor,digest,response FROM console_sharing_requests WHERE mesh_id=$1 AND request_id=$2")
        .bind(mesh).bind(body.draft.request_id).fetch_optional(&mut *tx).await?;
    if let Some((actor, known, response)) = prior {
        if actor != context.actor || known != digest {
            return Err(ApiError::conflict(
                "request_reused",
                "request identity is bound to different content or authority",
            ));
        }
        tx.rollback().await?;
        return Ok(Json(
            serde_json::from_value(response).map_err(|_| publisher_error())?,
        ));
    }
    check_configuration_version(version, expected)?;
    let mut preview =
        stage_console_grant(&state.store, &mut tx, mesh, version, &body.draft).await?;
    if preview.digest != body.preview_digest {
        return Err(ApiError::conflict(
            "preview_changed",
            "dependencies changed; preview again",
        ));
    }
    bump_management(&mut tx, mesh).await?;
    preview.applied = true;
    sqlx::query("INSERT INTO console_sharing_requests(mesh_id,request_id,actor,digest,response) VALUES($1,$2,$3,$4,$5)")
        .bind(mesh).bind(body.draft.request_id).bind(&context.actor).bind(digest).bind(declaration_value(&preview)?).execute(&mut *tx).await?;
    let mut record = mutation(
        &context,
        Some(mesh_id(mesh)?),
        "sharing.grant",
        "sharing.updated",
        "sharing",
        Some(body.draft.resource_id),
    );
    record.metadata = json!({"grant_id":body.draft.request_id,"reason":body.draft.reason,"affected_sources":preview.affected_sources,"overlapping_resources":preview.overlapping_resources});
    state.store.commit_mutation(tx, &record).await?;
    Ok(Json(preview))
}

async fn list_console_service_grants(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    Path((mesh, service)): Path<(Uuid, Uuid)>,
    Query(query): Query<ConsoleQuery>,
) -> Result<Json<ApiPage<peerward_api::ConsoleServiceGrant>>, ApiError> {
    authorize(&context, &HeaderMap::new(), Capability::ResourceRead, false)?;
    let limit = query.bounded_limit()?;
    let rows:Vec<Value>=sqlx::query_scalar("SELECT jsonb_build_object('id',g.id,'version',g.version,'enabled',g.enabled,'source',g.source,'source_collections',g.source_collections,
        'source_names',COALESCE((SELECT jsonb_agg(COALESCE(NULLIF(p.display_name,''),p.name) ORDER BY p.id) FROM peers p WHERE p.mesh_id=g.mesh_id AND p.id::text IN (SELECT jsonb_array_elements_text(g.source->'peers'))),'[]'::jsonb) ||
        COALESCE((SELECT jsonb_agg(c.definition->>'name' ORDER BY c.id) FROM network_collections c WHERE c.mesh_id=g.mesh_id AND c.id=ANY(g.source_collections)),'[]'::jsonb))
        FROM console_service_grants g WHERE g.mesh_id=$1 AND g.service_id=$2 AND ($3::text IS NULL OR g.id::text>$3) ORDER BY g.id LIMIT $4")
        .bind(mesh).bind(service).bind(query.cursor).bind(i64::from(limit)+1).fetch_all(state.store.pool()).await?;
    let more = rows.len() > limit as usize;
    let items: Vec<peerward_api::ConsoleServiceGrant> = rows
        .into_iter()
        .take(limit as usize)
        .map(|v| serde_json::from_value(v).map_err(|_| publisher_error()))
        .collect::<Result<_, _>>()?;
    let next_cursor = more.then(|| items.last().unwrap().id.to_string());
    Ok(Json(ApiPage { items, next_cursor }))
}
async fn set_console_service_grant(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((mesh, service, id)): Path<(Uuid, Uuid, Uuid)>,
    ApiJson(body): ApiJson<peerward_api::ConsoleServiceGrantState>,
) -> Result<StatusCode, ApiError> {
    authorize(&context, &headers, Capability::ResourceWrite, true)?;
    let expected = require_if_match(&headers)?;
    validate_console_reason(&body.reason)?;
    if body.reason.trim().is_empty() {
        return Err(ApiError::invalid(
            "reason_required",
            "provide a reason for changing access",
        ));
    }
    let mut tx = state.store.begin_mutation().await?;
    lock_configuration(&mut tx, mesh).await?;
    assert_configuration_owner(&mut tx, mesh, &context.actor).await?;
    let (version,source,groups):(i64,Value,Vec<Uuid>)=sqlx::query_as("SELECT version,source,source_collections FROM console_service_grants WHERE mesh_id=$1 AND service_id=$2 AND id=$3 FOR UPDATE")
        .bind(mesh).bind(service).bind(id).fetch_optional(&mut *tx).await?.ok_or_else(ApiError::not_found)?;
    if version != expected {
        return Err(ApiError::conflict(
            "version_conflict",
            "grant changed; refresh and review again",
        ));
    }
    let impact = read_console_sharing_impact(&mut tx, mesh, "service", service).await?;
    sqlx::query(
        "UPDATE console_service_grants SET enabled=$4 WHERE mesh_id=$1 AND service_id=$2 AND id=$3",
    )
    .bind(mesh)
    .bind(service)
    .bind(id)
    .bind(body.enabled)
    .execute(&mut *tx)
    .await?;
    let mut policy = load_current_policy_from(&mut *tx, mesh).await?;
    policy.revision = policy.revision.checked_add(1).ok_or_else(publisher_error)?;
    stage_peer_policy(&mut tx, mesh, &policy).await?;
    bump_management(&mut tx, mesh).await?;
    let mut record = mutation(
        &context,
        Some(mesh_id(mesh)?),
        "sharing.grant.state",
        "sharing.updated",
        "sharing",
        Some(service),
    );
    record.metadata = json!({"grant_id":id,"enabled":body.enabled,"reason":body.reason,"source":source,"source_collections":groups,"overlapping_resources":impact.overlapping_resources});
    state.store.commit_mutation(tx, &record).await?;
    Ok(StatusCode::NO_CONTENT)
}
