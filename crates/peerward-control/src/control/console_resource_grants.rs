// A simple action can only change one source's allow rule for one resource.
// Advanced predicates and rules spanning resources remain in the policy editor.
fn console_simple_resource_grant(rule: &peerward_management::ResourceRule, resource: Uuid) -> bool {
    rule.action == peerward_management::ResourceAction::Allow
        && rule.resources == [resource].into()
        && rule.resource_collections.is_empty()
        && rule.providers.is_empty()
        && rule.not_after.is_none()
        && rule.source.labels.is_empty()
        && rule.source.cidrs.is_empty()
        && rule.source.peers.len() + rule.source_collections.len() == 1
        && rule.destination_ports.len() <= 1
        && rule
            .destination_ports
            .iter()
            .all(|(first, last)| first == last)
}

async fn list_console_resource_grants(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    Path((mesh, resource)): Path<(Uuid, Uuid)>,
    Query(query): Query<ConsoleQuery>,
) -> Result<Json<ApiPage<peerward_api::ConsoleServiceGrant>>, ApiError> {
    authorize(&context, &HeaderMap::new(), Capability::ResourceRead, false)?;
    let limit = usize::from(query.bounded_limit()?);
    let mut tx = state.store.begin_mutation().await?;
    let version = lock_configuration(&mut tx, mesh).await?;
    let configuration = read_resource_configuration(&mut tx, mesh_id(mesh)?).await?;
    if !configuration.resources.iter().any(|r| r.id == resource) {
        return Err(ApiError::not_found());
    }
    let mut rules: Vec<_> = configuration
        .rules
        .iter()
        .filter(|r| {
            r.resources.contains(&resource)
                || peerward_management::collection_contains(
                    &configuration.collections,
                    &r.resource_collections,
                    peerward_management::CollectionKind::Resources,
                    resource,
                )
        })
        .filter(|r| query.cursor.as_ref().is_none_or(|c| r.id.to_string() > *c))
        .collect();
    rules.sort_by_key(|r| r.id);
    let more = rules.len() > limit;
    let mut items = Vec::new();
    for rule in rules.into_iter().take(limit) {
        let peers: Vec<Uuid> = rule.source.peers.iter().map(|id| id.into_uuid()).collect();
        let groups: Vec<Uuid> = rule.source_collections.iter().copied().collect();
        let source_names: Vec<String> = sqlx::query_scalar("SELECT name FROM (
            SELECT id,COALESCE(NULLIF(display_name,''),name) AS name FROM peers WHERE mesh_id=$1 AND id=ANY($2)
            UNION ALL SELECT id,definition->>'name' FROM network_collections WHERE mesh_id=$1 AND id=ANY($3)
            ) s ORDER BY id")
            .bind(mesh).bind(peers).bind(&groups).fetch_all(&mut *tx).await?;
        items.push(peerward_api::ConsoleServiceGrant {
            id: rule.id,
            version,
            enabled: rule.enabled,
            source: rule.source.clone(),
            source_collections: groups,
            source_names,
            protocol: rule.protocol,
            destination_ports: rule.destination_ports.clone(),
            advanced: !console_simple_resource_grant(rule, resource),
        });
    }
    tx.rollback().await?;
    let next_cursor = more.then(|| items.last().unwrap().id.to_string());
    Ok(Json(ApiPage { items, next_cursor }))
}

async fn set_console_resource_grant(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((mesh, resource, grant)): Path<(Uuid, Uuid, Uuid)>,
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
    let version = lock_configuration(&mut tx, mesh).await?;
    assert_configuration_owner(&mut tx, mesh, &context.actor).await?;
    check_configuration_version(version, expected)?;
    let impact = read_console_sharing_impact(&mut tx, mesh, "lan", resource).await?;
    let old = read_configuration_document(&mut tx, mesh).await?;
    let mut new = old.clone();
    let rule = new
        .resource_policy
        .rules
        .iter_mut()
        .find(|r| r.id == grant)
        .ok_or_else(ApiError::not_found)?;
    if !console_simple_resource_grant(rule, resource) {
        return Err(ApiError::conflict(
            "advanced_grant_required",
            "review this rule in the advanced policy editor",
        ));
    }
    let before = rule.clone();
    rule.enabled = body.enabled;
    let after = rule.clone();
    if !stage_configuration(&state.store, &mut tx, mesh, &old, &new)
        .await?
        .is_empty()
    {
        return Err(ApiError::conflict(
            "policy_tests_failed",
            "saved assertions failed; review advanced tests",
        ));
    }
    bump_management(&mut tx, mesh).await?;
    let mut record = mutation(
        &context,
        Some(mesh_id(mesh)?),
        "sharing.grant.state",
        "sharing.updated",
        "sharing",
        Some(resource),
    );
    record.metadata = json!({"grant_id":grant,"enabled":body.enabled,"reason":body.reason,"before":before,"after":after,"overlapping_resources":impact.overlapping_resources});
    state.store.commit_mutation(tx, &record).await?;
    Ok(StatusCode::NO_CONTENT)
}
