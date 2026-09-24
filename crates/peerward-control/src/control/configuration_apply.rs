async fn validate_configuration(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    Path(mesh): Path<Uuid>,
    ApiJson(mut document): ApiJson<peerward_api::ConfigurationDocument>,
) -> Result<Json<peerward_api::ConfigurationPreview>, ApiError> {
    authorize(
        &context,
        &HeaderMap::new(),
        Capability::ResourceWrite,
        false,
    )?;
    normalize_configuration(&mut document, mesh)?;
    let mut tx = state.store.begin_mutation().await?;
    let version = lock_configuration(&mut tx, mesh).await?;
    let preview =
        prepare_configuration_preview(&state.store, &mut tx, mesh, version, &document).await?;
    tx.rollback().await?;
    Ok(Json(preview))
}

async fn preview_configuration(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(mesh): Path<Uuid>,
    ApiJson(mut document): ApiJson<peerward_api::ConfigurationDocument>,
) -> Result<Json<peerward_api::ConfigurationPreview>, ApiError> {
    authorize(&context, &headers, Capability::ResourceWrite, false)?;
    let expected = require_if_match(&headers)?;
    normalize_configuration(&mut document, mesh)?;
    let mut tx = state.store.begin_mutation().await?;
    let version = lock_configuration(&mut tx, mesh).await?;
    check_configuration_version(version, expected)?;
    let preview =
        prepare_configuration_preview(&state.store, &mut tx, mesh, version, &document).await?;
    tx.rollback().await?;
    Ok(Json(preview))
}

fn check_configuration_version(version: u64, expected: i64) -> Result<(), ApiError> {
    if i64::try_from(version).ok() != Some(expected) {
        return Err(ApiError::conflict(
            "version_conflict",
            "configuration or its dependencies changed; export and preview again",
        ));
    }
    Ok(())
}

async fn assert_configuration_owner(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    mesh: Uuid,
    actor: &str,
) -> Result<(), ApiError> {
    let owner: Option<Uuid> =
        sqlx::query_scalar("SELECT owner_machine_id FROM configuration_ownership WHERE mesh_id=$1")
            .bind(mesh)
            .fetch_one(&mut **tx)
            .await?;
    let permitted = match owner {
        Some(id) => actor == format!("machine:{id}"),
        None => !actor.starts_with("machine:"),
    };
    if !permitted {
        return Err(StoreError::ConfigurationOwned.into());
    }
    Ok(())
}

async fn apply_configuration(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(mesh): Path<Uuid>,
    ApiJson(mut body): ApiJson<peerward_api::ConfigurationApplyRequest>,
) -> Result<(HeaderMap, Json<peerward_api::ConfigurationPreview>), ApiError> {
    authorize(&context, &headers, Capability::ResourceWrite, true)?;
    let expected = require_if_match(&headers)?;
    if body.request_id.get_version_num() != 4 {
        return Err(ApiError::invalid_id());
    }
    normalize_configuration(&mut body.document, mesh)?;
    if body.preview_digest.len() != 64
        || !body.preview_digest.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(ApiError::invalid(
            "preview_digest",
            "preview this exact document before applying",
        ));
    }
    let digest = declaration_digest(&(expected, &body))?;
    let mut tx = state.store.begin_mutation().await?;
    let version = lock_configuration(&mut tx, mesh).await?;
    assert_configuration_owner(&mut tx, mesh, &context.actor).await?;
    let prior:Option<(String,Vec<u8>,Option<Value>)>=sqlx::query_as("SELECT actor,request_digest,response FROM configuration_applications WHERE mesh_id=$1 AND request_id=$2")
        .bind(mesh).bind(body.request_id).fetch_optional(&mut *tx).await?;
    if let Some((actor, known, response)) = prior {
        if actor != context.actor || hex::encode(known) != digest {
            return Err(ApiError::conflict(
                "request_reused",
                "request identity is bound to different content or authority",
            ));
        }
        let response = response.ok_or_else(|| ApiError::new(
            StatusCode::GONE,
            "configuration_response_archived",
            "original response retention ended; export and preview current configuration with a new request identity",
        ))?;
        let response: peerward_api::ConfigurationPreview =
            serde_json::from_value(response).map_err(|_| publisher_error())?;
        tx.rollback().await?;
        return Ok((etag_headers(response.version)?, Json(response)));
    }
    check_configuration_version(version, expected)?;
    let mut preview =
        prepare_configuration_preview(&state.store, &mut tx, mesh, version, &body.document).await?;
    if preview.preview_digest != body.preview_digest {
        return Err(ApiError::conflict(
            "preview_changed",
            "preview differs from current dependencies; review a new preview",
        ));
    }
    if !preview.can_apply {
        return Err(ApiError::conflict(
            "policy_tests_failed",
            "saved assertions failed; correct the declaration or its tests",
        ));
    }
    let changed = !preview.changes.is_empty();
    if changed {
        bump_management(&mut tx, mesh).await?;
        preview.version = version.checked_add(1).ok_or_else(publisher_error)?;
    }
    preview.applied = true;
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM configuration_applications WHERE mesh_id=$1 AND response IS NOT NULL",
    )
    .bind(mesh)
    .fetch_one(&mut *tx)
    .await?;
    if count >= 10000 {
        return Err(ApiError::conflict(
            "configuration_history_full",
            "retained response capacity reached; maintenance archives responses older than 30 days",
        ));
    }
    sqlx::query("INSERT INTO configuration_applications(mesh_id,request_id,actor,request_digest,response) VALUES($1,$2,$3,$4,$5)")
        .bind(mesh).bind(body.request_id).bind(&context.actor).bind(hex::decode(&digest).map_err(|_|publisher_error())?).bind(declaration_value(&preview)?).execute(&mut *tx).await?;
    let mut record = mutation(
        &context,
        Some(mesh_id(mesh)?),
        if changed {
            "configuration.apply"
        } else {
            "configuration.apply_noop"
        },
        "configuration.applied",
        "configuration",
        Some(body.request_id),
    );
    record.metadata = json!({"version":preview.version,"document_digest":preview.document_digest,"changes":preview.changes,"failed_tests":preview.failed_tests});
    state.store.commit_mutation(tx, &record).await?;
    Ok((etag_headers(preview.version)?, Json(preview)))
}

async fn prepare_configuration_preview(
    store: &Store,
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    mesh: Uuid,
    version: u64,
    new: &peerward_api::ConfigurationDocument,
) -> Result<peerward_api::ConfigurationPreview, ApiError> {
    let old = read_configuration_document(tx, mesh).await?;
    let before:Vec<Value>=configuration_rows(tx,mesh_id(mesh)?,"SELECT jsonb_build_object('id',id,'approved',approved,'approval_source',approval_source) FROM gateway_bindings WHERE mesh_id=$1 ORDER BY id").await?;
    let mut changes = configuration_changes(&old, new)?;
    let failed_tests = stage_configuration(store, tx, mesh, &old, new).await?;
    let after:Vec<Value>=configuration_rows(tx,mesh_id(mesh)?,"SELECT jsonb_build_object('id',id,'approved',approved,'approval_source',approval_source) FROM gateway_bindings WHERE mesh_id=$1 ORDER BY id").await?;
    for value in after {
        if !before.contains(&value) {
            changes.push(peerward_api::ConfigurationChange {
                kind: "effective_approval".into(),
                id: serde_json::from_value(value["id"].clone()).map_err(|_| publisher_error())?,
                change: if value["approved"] == true {
                    "approved"
                } else {
                    "withdrawn"
                }
                .into(),
            });
        }
    }
    let only_removes_grants = configuration_only_removes(&old, new)?;
    let can_apply = failed_tests.is_empty()
        || (only_removes_grants
            && failed_tests.iter().all(|id| {
                new.resource_policy.tests.iter().any(|test| {
                    test.id == *id && test.expected == peerward_management::ResourceAction::Allow
                })
            }));
    let document_digest = declaration_digest(new)?;
    let preview_digest = declaration_digest(&(
        version,
        &document_digest,
        &changes,
        &failed_tests,
        only_removes_grants,
        can_apply,
    ))?;
    Ok(peerward_api::ConfigurationPreview {
        version,
        document_digest,
        preview_digest,
        changes,
        failed_tests,
        only_removes_grants,
        can_apply,
        applied: false,
    })
}

fn configuration_changes(
    old: &peerward_api::ConfigurationDocument,
    new: &peerward_api::ConfigurationDocument,
) -> Result<Vec<peerward_api::ConfigurationChange>, ApiError> {
    let old = declaration_value(old)?;
    let new = declaration_value(new)?;
    let mesh: Uuid =
        serde_json::from_value(new["mesh_id"].clone()).map_err(|_| publisher_error())?;
    let mut changes = Vec::new();
    for kind in [
        "resources",
        "bindings",
        "collections",
        "auto_approval_rules",
        "dns_profiles",
    ] {
        let previous = old[kind].as_array().ok_or_else(publisher_error)?;
        let next = new[kind].as_array().ok_or_else(publisher_error)?;
        for item in previous {
            if !next.iter().any(|v| v["id"] == item["id"]) {
                changes.push(peerward_api::ConfigurationChange {
                    kind: kind.into(),
                    id: serde_json::from_value(item["id"].clone())
                        .map_err(|_| publisher_error())?,
                    change: "removed".into(),
                });
            }
        }
        for item in next {
            let prior = previous.iter().find(|v| v["id"] == item["id"]);
            if prior != Some(item) {
                changes.push(peerward_api::ConfigurationChange {
                    kind: kind.into(),
                    id: serde_json::from_value(item["id"].clone())
                        .map_err(|_| publisher_error())?,
                    change: if prior.is_some() {
                        "updated"
                    } else {
                        "created"
                    }
                    .into(),
                });
            }
        }
    }
    for kind in ["peer_policy", "resource_policy", "device_conditions"] {
        if old[kind] != new[kind] {
            changes.push(peerward_api::ConfigurationChange {
                kind: kind.into(),
                id: mesh,
                change: "updated".into(),
            });
        }
    }
    Ok(changes)
}

fn configuration_only_removes(
    old: &peerward_api::ConfigurationDocument,
    new: &peerward_api::ConfigurationDocument,
) -> Result<bool, ApiError> {
    if !new.device_conditions.only_restricts(&old.device_conditions) {
        return Ok(false);
    }
    let old_value = declaration_value(old)?;
    let new_value = declaration_value(new)?;
    let old_resources = old_value["resources"]
        .as_array()
        .ok_or_else(publisher_error)?;
    if !new_value["resources"]
        .as_array()
        .ok_or_else(publisher_error)?
        .iter()
        .all(|resource| old_resources.contains(resource))
    {
        return Ok(false);
    }
    if !configuration_collections_only_restrict(old, new) {
        return Ok(false);
    }
    for rule in &new.auto_approval_rules {
        if !rule.definition.enabled {
            continue;
        }
        let Some(previous) = old
            .auto_approval_rules
            .iter()
            .find(|value| value.id == rule.id)
        else {
            return Ok(false);
        };
        if !previous.definition.enabled
            || previous.definition.device_collection != rule.definition.device_collection
            || previous.definition.site_id != rule.definition.site_id
            || !rule.definition.prefixes.iter().all(|prefix| {
                previous.definition.prefixes.iter().any(|prior| {
                    prior.prefix_len() <= prefix.prefix_len() && prior.contains(&prefix.network())
                })
            })
        {
            return Ok(false);
        }
    }
    if old.dns_profiles != new.dns_profiles
        || !only_removes_resource_grants(&old.resource_policy, &new.resource_policy)
    {
        return Ok(false);
    }
    for binding in &new.bindings {
        if matches!(
            binding.approval,
            peerward_api::ConfigurationApproval::Manual { approved: false }
        ) {
            continue;
        }
        let value = declaration_value(binding)?;
        if !old_value["bindings"]
            .as_array()
            .ok_or_else(publisher_error)?
            .contains(&value)
        {
            return Ok(false);
        }
    }
    Ok((new.peer_policy.default_action == "deny"
        || new.peer_policy.default_action == old.peer_policy.default_action)
        && new
            .peer_policy
            .rules
            .iter()
            .filter(|r| r.enabled && r.action == "allow")
            .all(|r| old.peer_policy.rules.contains(r))
        && old
            .peer_policy
            .rules
            .iter()
            .filter(|r| r.enabled && r.action == "deny")
            .all(|r| new.peer_policy.rules.contains(r)))
}
