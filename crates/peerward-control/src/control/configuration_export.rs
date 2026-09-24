async fn export_configuration(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    Path(mesh): Path<Uuid>,
) -> Result<(HeaderMap, Json<peerward_api::ConfigurationSnapshot>), ApiError> {
    authorize(&context, &HeaderMap::new(), Capability::ResourceRead, false)?;
    let mut tx = state.store.begin_mutation().await?;
    let version = lock_configuration(&mut tx, mesh).await?;
    let document = read_configuration_document(&mut tx, mesh).await?;
    tx.rollback().await?;
    Ok((
        etag_headers(version)?,
        Json(peerward_api::ConfigurationSnapshot { version, document }),
    ))
}

async fn lock_configuration(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    mesh: Uuid,
) -> Result<u64, ApiError> {
    mesh_id(mesh)?;
    sqlx::query("SELECT id FROM meshes WHERE id=$1 AND lifecycle='active' FOR UPDATE")
        .bind(mesh)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or_else(ApiError::not_found)?;
    let version: i64 = sqlx::query_scalar(
        "SELECT version FROM configuration_ownership WHERE mesh_id=$1 FOR UPDATE",
    )
    .bind(mesh)
    .fetch_one(&mut **tx)
    .await?;
    positive_revision(version)
}

async fn read_configuration_document(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    mesh: Uuid,
) -> Result<peerward_api::ConfigurationDocument, ApiError> {
    let id = mesh_id(mesh)?;
    let policy = load_current_policy_from(&mut **tx, mesh).await?;
    let resource_policy: Value = sqlx::query_scalar("SELECT h.document FROM resource_policy_history h JOIN meshes m ON m.id=h.mesh_id AND m.resource_policy_revision=h.revision WHERE m.id=$1")
        .bind(mesh).fetch_one(&mut **tx).await?;
    let mut document = peerward_api::ConfigurationDocument {
        schema_version: 4, wire_version: 5, mesh_id: mesh,
        resources: configuration_rows(tx,id,"SELECT jsonb_build_object('id',id,'definition',definition) FROM network_resources WHERE mesh_id=$1 ORDER BY id").await?,
        collections: configuration_rows(tx,id,"SELECT jsonb_build_object('id',id,'definition',definition) FROM network_collections WHERE mesh_id=$1 ORDER BY id").await?,
        auto_approval_rules: configuration_rows(tx,id,"SELECT jsonb_build_object('id',id,'definition',definition) FROM auto_approval_rules WHERE mesh_id=$1 ORDER BY id").await?,
        bindings: configuration_rows(tx,id,"SELECT jsonb_build_object('id',b.id,'resource_id',b.resource_id,'peer_id',b.peer_id,'priority',b.priority,'forwarding',b.forwarding,'return_route_confirmed',b.return_route_confirmed,'approval',CASE WHEN e.binding_id IS NOT NULL AND NOT (b.approved AND b.approval_source->>'kind'='manual') THEN jsonb_build_object('kind','automatic') ELSE jsonb_build_object('kind','manual','approved',b.approved) END) FROM gateway_bindings b LEFT JOIN gateway_auto_eligibility e ON e.mesh_id=b.mesh_id AND e.binding_id=b.id WHERE b.mesh_id=$1 ORDER BY b.id").await?,
        device_conditions: read_device_conditions(tx,mesh).await?.1,
        dns_profiles: configuration_rows(tx,id,"SELECT profile FROM dns_profiles WHERE mesh_id=$1 ORDER BY id").await?,
        peer_policy: peerward_api::ConfigurationPeerPolicy { default_action: policy.default_action, rules: policy.rules },
        resource_policy: serde_json::from_value(resource_policy).map_err(|_| publisher_error())?,
    };
    normalize_configuration(&mut document, mesh)?;
    Ok(document)
}

fn normalize_configuration(
    document: &mut peerward_api::ConfigurationDocument,
    mesh: Uuid,
) -> Result<(), ApiError> {
    if document.mesh_id != mesh || document.schema_version != 4 || document.wire_version != 5 {
        return Err(ApiError::invalid(
            "configuration_format",
            "expected Schema 4 / Wire 5 and this Mesh identity",
        ));
    }
    document.device_conditions.validate().map_err(management_error)?;
    validate_declaration_ids(document.resources.iter().map(|x| x.id), 4096)?;
    if document
        .resources
        .iter()
        .filter(|x| x.definition.health_probe.is_some())
        .count()
        > 64
    {
        return Err(ApiError::invalid(
            "health_probe_limit",
            "at most 64 target probes per Mesh",
        ));
    }
    for resource in &document.resources {
        resource.definition.validate().map_err(management_error)?;
    }
    validate_declaration_ids(document.bindings.iter().map(|x| x.id), 8192)?;
    validate_declaration_ids(document.collections.iter().map(|x| x.id), 64)?;
    validate_declaration_ids(document.auto_approval_rules.iter().map(|x| x.id), 64)?;
    validate_declaration_ids(document.dns_profiles.iter().map(|x| x.id), 64)?;
    if !document.dns_profiles.iter().any(|x| x.id == mesh) {
        return Err(ApiError::invalid(
            "default_dns_required",
            "the Mesh default DNS profile must remain in the declaration",
        ));
    }
    let policy = PolicyPutRequest {
        revision: 1,
        default_action: document.peer_policy.default_action.clone(),
        rules: document.peer_policy.rules.clone(),
    };
    if !policy.within_limits() {
        return Err(ApiError::invalid(
            "policy_too_large",
            "policy exceeds collection limits",
        ));
    }
    canonical_policy_document(&policy)?;
    document.resources.sort_by_key(|x| x.id);
    document.bindings.sort_by_key(|x| x.id);
    document.collections.sort_by_key(|x| x.id);
    document.auto_approval_rules.sort_by_key(|x| x.id);
    document.dns_profiles.sort_by_key(|x| x.id);
    document
        .peer_policy
        .rules
        .sort_by_key(|x| (x.priority, x.action != "deny", x.id));
    document
        .resource_policy
        .rules
        .sort_by_key(|x| (x.priority, x.action, x.id));
    document.resource_policy.tests.sort_by_key(|x| x.id);
    Ok(())
}

fn declaration_value<T: serde::Serialize>(value: &T) -> Result<Value, ApiError> {
    serde_json::to_value(value).map_err(|_| publisher_error())
}

fn declaration_digest<T: serde::Serialize>(value: &T) -> Result<String, ApiError> {
    peerward_management::content_digest(value)
        .map(hex::encode)
        .map_err(management_error)
}

fn validate_declaration_ids(
    values: impl Iterator<Item = Uuid>,
    bound: usize,
) -> Result<(), ApiError> {
    let mut known = BTreeSet::new();
    for id in values {
        if id.get_version_num() != 4 || !known.insert(id) || known.len() > bound {
            return Err(ApiError::invalid(
                "configuration_identity",
                "duplicate, invalid or excessive declaration identities",
            ));
        }
    }
    Ok(())
}
