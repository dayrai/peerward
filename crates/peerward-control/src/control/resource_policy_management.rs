use std::collections::BTreeSet;
async fn load_resource_policy(
    store: &Store,
    mesh: Uuid,
    revision: Option<u64>,
) -> Result<peerward_api::ResourcePolicyResponse, ApiError> {
    mesh_id(mesh)?;
    let version = revision
        .map(i64::try_from)
        .transpose()
        .map_err(|_| ApiError::invalid("revision", "invalid revision"))?;
    let (version,document):(i64,Value)=sqlx::query_as("SELECT h.revision,h.document FROM resource_policy_history h JOIN meshes m ON h.mesh_id=m.id
        WHERE h.mesh_id=$1 AND h.revision=COALESCE($2,m.resource_policy_revision)")
        .bind(mesh).bind(version).fetch_optional(store.pool()).await?.ok_or_else(ApiError::not_found)?;
    Ok(peerward_api::ResourcePolicyResponse {
        version: positive_revision(version)?,
        document: serde_json::from_value(document).map_err(|_| publisher_error())?,
        failed_tests: vec![],
        tests_evaluated: false,
    })
}

async fn get_resource_policy(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    Path(mesh): Path<Uuid>,
) -> Result<(HeaderMap, Json<peerward_api::ResourcePolicyResponse>), ApiError> {
    authorize(&context, &HeaderMap::new(), Capability::ResourceRead, false)?;
    let policy = load_resource_policy(&state.store, mesh, None).await?;
    Ok((etag_headers(policy.version)?, Json(policy)))
}

async fn get_resource_policy_history(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    Path((mesh, revision)): Path<(Uuid, u64)>,
) -> Result<Json<peerward_api::ResourcePolicyResponse>, ApiError> {
    authorize(&context, &HeaderMap::new(), Capability::ResourceRead, false)?;
    Ok(Json(
        load_resource_policy(&state.store, mesh, Some(revision)).await?,
    ))
}

async fn validate_resource_policy_document(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    mesh: Uuid,
    document: &peerward_api::ResourcePolicyDocument,
) -> Result<Vec<Uuid>, ApiError> {
    use peerward_management::{ResourceAccess, ResourceAction, decide_resource_aliases};
    if document.rules.len() > 4096 || document.tests.len() > 256 {
        return Err(ApiError::invalid(
            "policy_too_large",
            "resource policy exceeds limits",
        ));
    }
    let configuration = read_resource_configuration(tx, mesh_id(mesh)?).await?;
    let resources = &configuration.resources;
    let peer_ids: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM peers WHERE mesh_id=$1")
        .bind(mesh)
        .fetch_all(&mut **tx)
        .await?;
    let peer_ids: BTreeSet<_> = peer_ids.into_iter().collect();
    let resource_ids: BTreeSet<_> = resources.iter().map(|resource| resource.id).collect();
    let collections = &configuration.collections;
    let mut ids = BTreeSet::new();
    for rule in &document.rules {
        rule.validate().map_err(management_error)?;
        validate_rule_collections(rule, collections)?;
        if !ids.insert(rule.id)
            || !rule.resources.is_subset(&resource_ids)
            || rule
                .source
                .peers
                .iter()
                .chain(rule.providers.iter())
                .any(|peer| !peer_ids.contains(&peer.into_uuid()))
        {
            return Err(ApiError::invalid(
                "policy_reference",
                "duplicate rule or reference outside this Mesh",
            ));
        }
    }
    let mut failed = Vec::new();
    ids.clear();
    for test in &document.tests {
        if test.id.is_nil()
            || !ids.insert(test.id)
            || test.name.trim().is_empty()
            || test.name.len() > 128
            || test.name.chars().any(char::is_control)
            || !peer_ids.contains(&test.source_peer_id.into_uuid())
            || !peer_ids.contains(&test.provider_peer_id.into_uuid())
        {
            return Err(ApiError::invalid(
                "policy_test",
                "invalid assertion or device reference",
            ));
        }
        validate_packet_predicate(test.protocol, test.destination_port)?;
        let target = resources
            .iter()
            .find(|resource| resource.id == test.resource_id)
            .ok_or_else(|| {
                ApiError::invalid("policy_test_resource", "assertion target does not exist")
            })?;
        if !target.definition.target.contains(test.address) {
            return Err(ApiError::invalid(
                "policy_test_address",
                "assertion address is outside the resource",
            ));
        }
        let source:Option<(String,Value)>=sqlx::query_as("SELECT host(a.address),p.labels FROM peers p JOIN peer_addresses a ON a.mesh_id=p.mesh_id AND a.peer_id=p.id
            WHERE p.mesh_id=$1 AND p.id=$2 AND p.administrative_state='enabled' AND a.state='active' AND family(a.address)=$3")
            .bind(mesh).bind(test.source_peer_id.into_uuid()).bind(if test.address.is_ipv4(){4i32}else{6}).fetch_optional(&mut **tx).await?;
        let exit = matches!(
            target.definition.target,
            peerward_management::ResourceTarget::Internet { .. }
        )
        .then_some(test.resource_id);
        let aliases = peerward_management::packet_resource_aliases(resources, test.address, exit);
        let shadowed = configuration.withdrawals.iter().any(|withdrawal| {
            matches!(
                withdrawal.target,
                peerward_management::ResourceTarget::Subnet { .. }
            ) && withdrawal.target.contains(test.address)
                && resources
                    .iter()
                    .filter(|r| aliases.contains(&r.id))
                    .all(|r| withdrawal.target.specificity() >= r.definition.target.specificity())
        });
        let action = if let Some((address, labels)) = source
            && !shadowed
            && configuration.admission.permits(test.source_peer_id,current_unix_seconds())
            && configuration.admission.permits(test.provider_peer_id,current_unix_seconds())
        {
            decide_resource_aliases(
                &document.rules,
                collections,
                &aliases,
                &configuration.bindings,
                &ResourceAccess {
                    source_peer: test.source_peer_id,
                    source_address: address.parse().map_err(|_| publisher_error())?,
                    source_labels: &serde_json::from_value(labels)
                        .map_err(|_| publisher_error())?,
                    resource: test.resource_id,
                    provider: test.provider_peer_id,
                    protocol: test.protocol,
                    destination_port: test.destination_port,
                    now: current_unix_seconds(),
                },
            )
            .0
        } else {
            ResourceAction::Deny
        };
        if action != test.expected {
            failed.push(test.id);
        }
    }
    Ok(failed)
}

fn only_removes_resource_grants(
    old: &peerward_api::ResourcePolicyDocument,
    new: &peerward_api::ResourcePolicyDocument,
) -> bool {
    use peerward_management::ResourceAction;
    // Conservative proof: remaining allows must be byte-for-byte identical, and every old
    // enabled deny must remain. This prevents removing a deny from masquerading as revocation.
    new.rules
        .iter()
        .filter(|rule| rule.enabled && rule.action == ResourceAction::Allow)
        .all(|rule| old.rules.contains(rule))
        && old
            .rules
            .iter()
            .filter(|rule| rule.enabled && rule.action == ResourceAction::Deny)
            .all(|rule| new.rules.contains(rule))
}

async fn put_resource_policy(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(mesh): Path<Uuid>,
    ApiJson(mut document): ApiJson<peerward_api::ResourcePolicyDocument>,
) -> Result<(HeaderMap, Json<peerward_api::ResourcePolicyResponse>), ApiError> {
    authorize(&context, &headers, Capability::ResourceWrite, true)?;
    let expected = require_if_match(&headers)?;
    let mut tx = state.store.begin_mutation().await?;
    let version: i64 = sqlx::query_scalar(
        "SELECT resource_policy_revision FROM meshes WHERE id=$1 AND lifecycle='active' FOR UPDATE",
    )
    .bind(mesh)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(ApiError::not_found)?;
    if version != expected {
        return Err(ApiError::conflict(
            "version_conflict",
            "policy changed; reload before publishing",
        ));
    }
    document
        .rules
        .sort_by_key(|rule| (rule.priority, rule.action, rule.id));
    document.tests.sort_by_key(|test| test.id);
    let failed_tests = validate_resource_policy_document(&mut tx, mesh, &document).await?;
    let old: Value = sqlx::query_scalar(
        "SELECT document FROM resource_policy_history WHERE mesh_id=$1 AND revision=$2",
    )
    .bind(mesh)
    .bind(version)
    .fetch_one(&mut *tx)
    .await?;
    let old = serde_json::from_value(old).map_err(|_| publisher_error())?;
    if !failed_tests.is_empty() && !only_removes_resource_grants(&old, &document) {
        return Err(ApiError::conflict(
            "policy_tests_failed",
            "saved assertions failed; run preview and correct the policy or assertions",
        ));
    }
    sqlx::query("DELETE FROM resource_rules WHERE mesh_id=$1")
        .bind(mesh)
        .execute(&mut *tx)
        .await?;
    for rule in &document.rules {
        sqlx::query("INSERT INTO resource_rules(id,mesh_id,rule) VALUES($1,$2,$3)")
            .bind(rule.id)
            .bind(mesh)
            .bind(serde_json::to_value(rule).map_err(|_| publisher_error())?)
            .execute(&mut *tx)
            .await?;
    }
    let next = version.checked_add(1).ok_or_else(publisher_error)?;
    sqlx::query("INSERT INTO resource_policy_history(mesh_id,revision,document) VALUES($1,$2,$3)")
        .bind(mesh)
        .bind(next)
        .bind(serde_json::to_value(&document).map_err(|_| publisher_error())?)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE meshes SET resource_policy_revision=$2 WHERE id=$1")
        .bind(mesh)
        .bind(next)
        .execute(&mut *tx)
        .await?;
    bump_management(&mut tx, mesh).await?;
    state
        .store
        .commit_mutation(
            tx,
            &mutation(
                &context,
                Some(mesh_id(mesh)?),
                "resource_policy.publish",
                "resource_policy.published",
                "resource_policy",
                None,
            ),
        )
        .await?;
    let version = positive_revision(next)?;
    Ok((
        etag_headers(version)?,
        Json(peerward_api::ResourcePolicyResponse {
            version,
            document,
            failed_tests,
            tests_evaluated: true,
        }),
    ))
}

async fn preview_resource_policy(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    Path(mesh): Path<Uuid>,
    ApiJson(document): ApiJson<peerward_api::ResourcePolicyDocument>,
) -> Result<Json<Value>, ApiError> {
    authorize(
        &context,
        &HeaderMap::new(),
        Capability::ResourceWrite,
        false,
    )?;
    let mut tx = state.store.begin_mutation().await?;
    sqlx::query("SELECT id FROM meshes WHERE id=$1 FOR SHARE")
        .bind(mesh)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(ApiError::not_found)?;
    let failed = validate_resource_policy_document(&mut tx, mesh, &document).await?;
    let previous = load_resource_policy(&state.store, mesh, None).await?;
    let added: Vec<_> = document
        .rules
        .iter()
        .filter(|rule| !previous.document.rules.contains(rule))
        .map(|rule| rule.id)
        .collect();
    let removed: Vec<_> = previous
        .document
        .rules
        .iter()
        .filter(|rule| !document.rules.contains(rule))
        .map(|rule| rule.id)
        .collect();
    Ok(Json(
        json!({"version":previous.version,"failed_tests":failed,"added_or_changed_rules":added,"removed_or_changed_rules":removed,
        "only_removes_grants":only_removes_resource_grants(&previous.document,&document),"connectivity":"unknown"}),
    ))
}
