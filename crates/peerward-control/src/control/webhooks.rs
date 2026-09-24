const WEBHOOK_EVENTS: &[&str] = &[
    "peer.created",
    "peer.updated",
    "peer.disabled",
    "peer.deleted",
    "policy.replaced",
    "network_resource.created",
    "network_resource.updated",
    "network_resource.deleted",
    "gateway_binding.created",
    "gateway_binding.approval_changed",
    "gateway_binding.priority_changed",
    "resource_policy.published",
    "dns_profile.changed",
    "dns_profile.deleted",
    "configuration.applied",
    "configuration.ownership_changed",
    "join.application.pending",
    "join.application.rejected",
];
const WEBHOOK_PROJECTION: &str = "SELECT w.id,w.mesh_id,w.created_at,jsonb_build_object(
    'id',w.id,'mesh_id',w.mesh_id,'version',w.version,'name',w.name,'endpoint',w.endpoint,'enabled',w.enabled,
    'event_types',w.event_types,'signing_public_key',NULL,'dropped_events',w.dropped_events,'created_at',w.created_at,
    'pending_deliveries',(SELECT count(*) FROM webhook_deliveries d WHERE d.mesh_id=w.mesh_id AND d.webhook_id=w.id AND d.status IN ('queued','sending')),
    'dead_deliveries',(SELECT count(*) FROM webhook_deliveries d WHERE d.mesh_id=w.mesh_id AND d.webhook_id=w.id AND d.status='failed')) AS item FROM webhooks w";

fn webhook_url(endpoint: &str) -> Result<Url, ApiError> {
    let invalid = || {
        ApiError::invalid(
            "webhook_endpoint",
            "use an HTTPS endpoint on port 443 without credentials, query or fragment; private addresses are forbidden",
        )
    };
    let url = Url::parse(endpoint).map_err(|_| invalid())?;
    if endpoint.len() > 2048
        || url.scheme() != "https"
        || url.port_or_known_default() != Some(443)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.host_str().is_none()
    {
        return Err(invalid());
    }
    match url.host().ok_or_else(invalid)? {
        url::Host::Ipv4(ip) if !peerward_management::internet_destination(ip.into()) => {
            return Err(invalid());
        }
        url::Host::Ipv6(ip) if !peerward_management::internet_destination(ip.into()) => {
            return Err(invalid());
        }
        url::Host::Domain(host)
            if !host.contains('.')
                || host.ends_with('.')
                || [
                    ".localhost",
                    ".local",
                    ".internal",
                    ".home.arpa",
                    ".test",
                    ".invalid",
                ]
                .iter()
                .any(|suffix| host.ends_with(suffix)) =>
        {
            return Err(invalid());
        }
        _ => {}
    }
    Ok(url)
}
fn validate_webhook(body: &mut peerward_api::WebhookUpdateRequest) -> Result<(), ApiError> {
    if !valid_display_name(&body.name) {
        return Err(ApiError::invalid("name", "provide a bounded webhook name"));
    }
    body.endpoint = webhook_url(&body.endpoint)?.to_string();
    if body.event_types.is_empty()
        || body.event_types.len() > 32
        || body
            .event_types
            .iter()
            .any(|event| !WEBHOOK_EVENTS.contains(&event.as_str()))
    {
        return Err(ApiError::invalid(
            "event_types",
            "choose supported exact management event names",
        ));
    }
    body.event_types.sort();
    body.event_types.dedup();
    Ok(())
}
async fn webhook_issuer(
    store: &Store,
    registry: &IssuerRegistry,
    mesh: Uuid,
) -> Result<Option<Arc<JoinIssuer>>, ApiError> {
    let active:Option<Uuid>=sqlx::query_scalar("SELECT id FROM mesh_authorities WHERE mesh_id=$1 AND lifecycle='active' AND not_before<=clock_timestamp() AND not_after>clock_timestamp()")
        .bind(mesh).fetch_optional(store.pool()).await?;
    Ok(registry.get(&mesh_id(mesh)?).and_then(|issuers| {
        issuers
            .into_iter()
            .find(|issuer| Some(issuer.authority_id) == active)
    }))
}
async fn load_webhook(
    state: &AppState,
    mesh: Uuid,
    id: Uuid,
) -> Result<peerward_api::WebhookResource, ApiError> {
    let value: Value = sqlx::query_scalar(&format!(
        "SELECT item FROM ({WEBHOOK_PROJECTION}) w WHERE mesh_id=$1 AND id=$2"
    ))
    .bind(mesh)
    .bind(id)
    .fetch_optional(state.store.pool())
    .await?
    .ok_or_else(ApiError::not_found)?;
    let mut hook: peerward_api::WebhookResource =
        serde_json::from_value(value).map_err(|_| publisher_error())?;
    hook.signing_public_key = webhook_issuer(&state.store, &state.join_issuers, mesh)
        .await?
        .map(|issuer| hex::encode(issuer.directory.public_key().to_bytes()));
    Ok(hook)
}
async fn list_webhooks(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    Path(mesh): Path<Uuid>,
    Query(query): Query<ListQuery>,
) -> Result<Json<ApiPage<peerward_api::WebhookResource>>, ApiError> {
    authorize(&context, &HeaderMap::new(), Capability::ResourceRead, false)?;
    mesh_id(mesh)?;
    let mut page:Json<ApiPage<peerward_api::WebhookResource>>=json_page(&state.store,&format!("SELECT item,id,created_at AS cursor_time FROM ({WEBHOOK_PROJECTION}) w WHERE mesh_id=$1 AND ($2::timestamptz IS NULL OR (created_at,id)>($2,$3)) ORDER BY created_at,id LIMIT $4"),mesh,query.cursor()?,query.limit()?).await?;
    let key = webhook_issuer(&state.store, &state.join_issuers, mesh)
        .await?
        .map(|issuer| hex::encode(issuer.directory.public_key().to_bytes()));
    for hook in &mut page.items {
        hook.signing_public_key.clone_from(&key);
    }
    Ok(page)
}
async fn get_webhook(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    Path((mesh, id)): Path<(Uuid, Uuid)>,
) -> Result<(HeaderMap, Json<peerward_api::WebhookResource>), ApiError> {
    authorize(&context, &HeaderMap::new(), Capability::ResourceRead, false)?;
    let hook = load_webhook(&state, mesh, id).await?;
    Ok((etag_headers(hook.version)?, Json(hook)))
}
async fn create_webhook(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(mesh): Path<Uuid>,
    ApiJson(body): ApiJson<peerward_api::WebhookCreateRequest>,
) -> Result<(StatusCode, HeaderMap, Json<peerward_api::WebhookResource>), ApiError> {
    save_webhook(
        context,
        state,
        headers,
        mesh,
        body.id,
        peerward_api::WebhookUpdateRequest {
            name: body.name,
            endpoint: body.endpoint,
            enabled: body.enabled,
            event_types: body.event_types,
        },
        true,
    )
    .await
}
async fn update_webhook(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((mesh, id)): Path<(Uuid, Uuid)>,
    ApiJson(body): ApiJson<peerward_api::WebhookUpdateRequest>,
) -> Result<(StatusCode, HeaderMap, Json<peerward_api::WebhookResource>), ApiError> {
    save_webhook(context, state, headers, mesh, id, body, false).await
}
async fn save_webhook(
    context: AuthContext,
    state: AppState,
    headers: HeaderMap,
    mesh: Uuid,
    id: Uuid,
    mut body: peerward_api::WebhookUpdateRequest,
    create: bool,
) -> Result<(StatusCode, HeaderMap, Json<peerward_api::WebhookResource>), ApiError> {
    authorize(&context, &headers, Capability::TrustManage, true)?;
    if id.get_version_num() != 4 {
        return Err(ApiError::invalid_id());
    }
    validate_webhook(&mut body)?;
    let expected = if create {
        None
    } else {
        Some(require_if_match(&headers)?)
    };
    if body.enabled
        && webhook_issuer(&state.store, &state.join_issuers, mesh)
            .await?
            .is_none()
    {
        return Err(ApiError::unavailable(
            "webhook_signer_unavailable",
            "configure the active distribution signer before enabling notifications",
        ));
    }
    let mut tx = state.store.begin_mutation().await?;
    sqlx::query("SELECT id FROM meshes WHERE id=$1 AND lifecycle='active' FOR UPDATE")
        .bind(mesh)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(ApiError::not_found)?;
    let existing:Option<(i64,Value)>=sqlx::query_as("SELECT version,jsonb_build_object('name',name,'endpoint',endpoint,'enabled',enabled,'event_types',event_types) FROM webhooks WHERE mesh_id=$1 AND id=$2 FOR UPDATE")
        .bind(mesh).bind(id).fetch_optional(&mut *tx).await?;
    if create && let Some((_, value)) = &existing {
        if value != &serde_json::to_value(&body).map_err(|_| publisher_error())? {
            return Err(ApiError::conflict(
                "request_reused",
                "webhook identity already has different content",
            ));
        }
        tx.rollback().await?;
        let hook = load_webhook(&state, mesh, id).await?;
        return Ok((StatusCode::OK, etag_headers(hook.version)?, Json(hook)));
    }
    if !create && existing.as_ref().map(|row| row.0) != expected {
        return Err(ApiError::conflict(
            "version_conflict",
            "reload the webhook before saving",
        ));
    }
    if create {
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM webhooks WHERE mesh_id=$1")
            .bind(mesh)
            .fetch_one(&mut *tx)
            .await?;
        if count >= 16 {
            return Err(ApiError::invalid(
                "webhook_limit",
                "at most 16 webhooks per Mesh",
            ));
        }
        sqlx::query("INSERT INTO webhooks(mesh_id,id,name,endpoint,enabled,event_types) VALUES($1,$2,$3,$4,$5,$6)")
            .bind(mesh).bind(id).bind(&body.name).bind(&body.endpoint).bind(body.enabled).bind(&body.event_types).execute(&mut *tx).await?;
    } else {
        sqlx::query("UPDATE webhooks SET version=version+1,name=$3,endpoint=$4,enabled=$5,event_types=$6 WHERE mesh_id=$1 AND id=$2")
            .bind(mesh).bind(id).bind(&body.name).bind(&body.endpoint).bind(body.enabled).bind(&body.event_types).execute(&mut *tx).await?;
        sqlx::query("UPDATE webhook_deliveries SET status='cancelled',completed_at=clock_timestamp(),result_code='webhook_changed',lease_owner=NULL,lease_until=NULL WHERE mesh_id=$1 AND webhook_id=$2 AND status IN ('queued','sending')")
            .bind(mesh).bind(id).execute(&mut *tx).await?;
    }
    let mut record = mutation(
        &context,
        Some(mesh_id(mesh)?),
        "webhook.save",
        "webhook.saved",
        "webhook",
        Some(id),
    );
    record.metadata = json!({"enabled":body.enabled,"event_types":body.event_types});
    state.store.commit_mutation(tx, &record).await?;
    let hook = load_webhook(&state, mesh, id).await?;
    Ok((
        if create {
            StatusCode::CREATED
        } else {
            StatusCode::OK
        },
        etag_headers(hook.version)?,
        Json(hook),
    ))
}
async fn delete_webhook(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((mesh, id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, ApiError> {
    authorize(&context, &headers, Capability::TrustManage, true)?;
    let expected = require_if_match(&headers)?;
    let mut tx = state.store.begin_mutation().await?;
    sqlx::query("SELECT id FROM meshes WHERE id=$1 FOR UPDATE")
        .bind(mesh)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(ApiError::not_found)?;
    let removed = sqlx::query("DELETE FROM webhooks WHERE mesh_id=$1 AND id=$2 AND version=$3")
        .bind(mesh)
        .bind(id)
        .bind(expected)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if removed != 1 {
        return Err(ApiError::conflict(
            "version_conflict",
            "webhook changed or was deleted; reload before deleting",
        ));
    }
    state
        .store
        .commit_mutation(
            tx,
            &mutation(
                &context,
                Some(mesh_id(mesh)?),
                "webhook.delete",
                "webhook.deleted",
                "webhook",
                Some(id),
            ),
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
