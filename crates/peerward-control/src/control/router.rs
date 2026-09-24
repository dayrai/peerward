fn router_with_loaded_join_issuers(
    store: Store,
    auth_config: AuthConfig,
    join_issuers: impl Into<IssuerRegistry>,
) -> Router {
    let (_sender, event_signal) = watch::channel(0);
    application_router(application_state(
        store,
        auth_config,
        join_issuers,
        Arc::new(ControlMetrics::default()),
        event_signal,
    ))
}

fn routers_with_loaded_join_issuers(
    store: Store,
    auth_config: AuthConfig,
    join_issuers: impl Into<IssuerRegistry>,
    metrics: Arc<ControlMetrics>,
    event_signal: watch::Receiver<u64>,
    public_url: Option<Url>,
) -> (Router, Router) {
    let mut state = application_state(store, auth_config, join_issuers, metrics, event_signal);
    state.public_url = public_url;
    (
        application_router(state.clone()),
        management_router_with_state(state),
    )
}

fn application_state(
    store: Store,
    auth_config: AuthConfig,
    join_issuers: impl Into<IssuerRegistry>,
    metrics: Arc<ControlMetrics>,
    event_signal: watch::Receiver<u64>,
) -> AppState {
    AppState {
        store,
        public_url: None,
        auth: AuthState {
            oidc: auth_config.oidc.clone(),
            development_digest: auth_config
                .development_bearer_token
                .as_deref()
                .map(|token| secret_digest(token.as_bytes())),
            bootstrap_digest: auth_config
                .bootstrap_token
                .as_deref()
                .map(|token| secret_digest(token.as_bytes())),
        },
        join_issuers: join_issuers.into(),
        metrics,
        event_signal,
        sse_connections: Arc::new(Semaphore::new(256)),
    }
}

fn application_router(state: AppState) -> Router {
    let protected = Router::new()
        .merge(console_routes())
        .route(
            "/api/v1/deployment-runners",
            get(list_deployment_runners).post(create_deployment_runner),
        )
        .route(
            "/api/v1/deployment-runners/{id}",
            axum::routing::delete(revoke_deployment_runner),
        )
        .route(
            "/api/v1/deployment-runners/{id}/exchange",
            post(deployment_exchange),
        )
        .route(
            "/api/v1/deployment-tasks",
            get(list_deployment_tasks).post(create_deployment_task),
        )
        .route("/api/v1/deployment-tasks/{id}", get(get_deployment_task))
        .route(
            "/api/v1/deployment-tasks/{id}/cancel",
            post(cancel_deployment_task),
        )
        .route(
            "/api/v1/deployment-tasks/{id}/recover",
            post(recover_deployment_task),
        )
        .route(
            "/api/v1/meshes/{mesh_id}/webhook-event-types",
            get(list_webhook_events),
        )
        .route(
            "/api/v1/meshes/{mesh_id}/webhooks/{id}/deliveries",
            get(list_webhook_deliveries),
        )
        .route(
            "/api/v1/meshes/{mesh_id}/webhooks/{id}/deliveries/{delivery}/retry",
            post(retry_webhook_delivery),
        )
        .route(
            "/api/v1/meshes/{mesh_id}/webhooks",
            get(list_webhooks).post(create_webhook),
        )
        .route(
            "/api/v1/meshes/{mesh_id}/webhooks/{id}",
            get(get_webhook).put(update_webhook).delete(delete_webhook),
        )
        .route(
            "/api/v1/meshes/{mesh_id}/configuration/ownership",
            get(get_configuration_ownership).put(put_configuration_ownership),
        )
        .route(
            "/api/v1/meshes/{mesh_id}/device-conditions",
            get(get_device_conditions).put(put_device_conditions),
        )
        .route(
            "/api/v1/meshes/{mesh_id}/peers/{peer_id}/device-condition",
            get(get_peer_device_condition),
        )
        .route(
            "/api/v1/meshes/{mesh_id}/configuration/export",
            get(export_configuration),
        )
        .route(
            "/api/v1/meshes/{mesh_id}/configuration/validate",
            post(validate_configuration),
        )
        .route(
            "/api/v1/meshes/{mesh_id}/configuration/preview",
            post(preview_configuration),
        )
        .route(
            "/api/v1/meshes/{mesh_id}/configuration/apply",
            post(apply_configuration),
        )
        .route(
            "/api/v1/meshes/{mesh_id}/auto-approval-rules",
            get(list_auto_approval_rules).post(create_auto_approval_rule),
        )
        .route(
            "/api/v1/meshes/{mesh_id}/auto-approval-rules/{id}",
            get(get_auto_approval_rule)
                .put(update_auto_approval_rule)
                .delete(delete_auto_approval_rule),
        )
        .route(
            "/api/v1/meshes/{mesh_id}/gateway-bindings/{id}/automatic-approval",
            post(request_automatic_gateway_approval),
        )
        .route(
            "/api/v1/meshes/{mesh_id}/machine-credentials",
            get(list_machine_credentials).post(create_machine_credential),
        )
        .route(
            "/api/v1/meshes/{mesh_id}/machine-credentials/{id}",
            delete(revoke_machine_credential),
        )
        .route("/api/v1/relay-hosts", get(list_relay_hosts))
        .route(
            "/api/v1/relay-hosts/{host_id}/capacity",
            get(get_relay_capacity),
        )
        .route("/api/v1/operations/status", get(operations_status))
        .route(
            "/api/v1/maintenance-tasks",
            get(list_maintenance_tasks).post(create_maintenance_task),
        )
        .route(
            "/api/v1/maintenance-tasks/preview",
            post(maintenance_preview),
        )
        .route("/api/v1/maintenance-tasks/{id}", get(get_maintenance_task))
        .route(
            "/api/v1/maintenance-tasks/{id}/retry",
            post(retry_maintenance_task),
        )
        .route(
            "/api/v1/meshes/{mesh_id}/relay-hosts",
            post(assign_relay_host),
        )
        .route("/api/v1/mesh-recovery/{id}", get(export_mesh_recovery))
        .route("/api/v1/mesh-lifecycle", get(list_mesh_lifecycle))
        .route("/api/v1/mesh-lifecycle/{id}", get(get_mesh_lifecycle))
        .route(
            "/api/v1/mesh-lifecycle/{id}/retry",
            post(retry_mesh_lifecycle),
        )
        .route("/api/v1/status", get(status))
        .route(
            "/api/v1/mesh-provisioning",
            get(list_mesh_provisioning).post(create_mesh_provisioning),
        )
        .route("/api/v1/mesh-provisioning/{id}", get(get_mesh_provisioning))
        .route(
            "/api/v1/mesh-provisioning/{id}/retry",
            post(retry_mesh_provisioning),
        )
        .route("/api/v1/meshes", get(list_meshes).post(create_mesh))
        .route(
            "/api/v1/meshes/{mesh_id}",
            get(get_mesh).patch(patch_mesh).delete(delete_mesh),
        )
        .route("/api/v1/meshes/{mesh_id}/topology", get(get_topology))
        .route(
            "/api/v1/meshes/{mesh_id}/topology/summary",
            get(get_topology_summary),
        )
        .route(
            "/api/v1/meshes/{mesh_id}/topology/nodes",
            get(get_topology_nodes),
        )
        .route(
            "/api/v1/meshes/{mesh_id}/topology/edges",
            get(get_topology_edges),
        )
        .route("/api/v1/meshes/{mesh_id}/bulk/preview", post(preview_bulk))
        .route("/api/v1/meshes/{mesh_id}/bulk/commit", post(commit_bulk))
        .route(
            "/api/v1/meshes/{mesh_id}/authorities",
            get(list_authorities).post(stage_authority),
        )
        .route(
            "/api/v1/meshes/{mesh_id}/authorities/{authority_id}",
            delete(revoke_authority),
        )
        .route(
            "/api/v1/meshes/{mesh_id}/authorities/{authority_id}/activate",
            post(activate_authority),
        )
        .route(
            "/api/v1/meshes/{mesh_id}/peers",
            get(list_peers).post(create_peer),
        )
        .route(
            "/api/v1/meshes/{mesh_id}/peers/{peer_id}",
            get(get_peer).patch(patch_peer).delete(disable_peer),
        )
        .route(
            "/api/v1/meshes/{mesh_id}/peers/{peer_id}/delete",
            post(delete_peer),
        )
        .route(
            "/api/v1/meshes/{mesh_id}/peers/{peer_id}/credentials",
            get(list_peer_credentials),
        )
        .route(
            "/api/v1/meshes/{mesh_id}/peers/{peer_id}/credentials/{credential_serial}",
            post(activate_peer_credential).delete(revoke_peer_credential),
        )
        .route(
            "/api/v1/meshes/{mesh_id}/relays",
            get(list_relays).post(create_relay),
        )
        .route(
            "/api/v1/meshes/{mesh_id}/relays/{relay_id}",
            get(get_relay).patch(patch_relay).delete(delete_relay),
        )
        .route(
            "/api/v1/meshes/{mesh_id}/relays/{relay_id}/credentials/rotate",
            post(rotate_relay),
        )
        .route(
            "/api/v1/meshes/{mesh_id}/relays/{relay_id}/credentials",
            get(list_relay_credentials),
        )
        .route(
            "/api/v1/meshes/{mesh_id}/relays/{relay_id}/credentials/{credential_serial}",
            post(activate_relay_credential).delete(revoke_relay_credential),
        )
        .route(
            "/api/v1/meshes/{mesh_id}/join-applications",
            get(list_join_applications),
        )
        .route(
            "/api/v1/meshes/{mesh_id}/join-applications/{id}",
            get(get_join_application),
        )
        .route(
            "/api/v1/meshes/{mesh_id}/join-applications/{id}/approve",
            post(approve_join_application),
        )
        .route(
            "/api/v1/meshes/{mesh_id}/join-applications/{id}/reject",
            post(reject_join_application),
        )
        .route(
            "/api/v1/meshes/{mesh_id}/join-tickets",
            get(list_tickets).post(create_ticket),
        )
        .route(
            "/api/v1/meshes/{mesh_id}/join-tickets/{ticket_id}",
            get(get_ticket).delete(delete_ticket),
        )
        .route(
            "/api/v1/meshes/{mesh_id}/policy",
            get(get_policy).put(put_policy),
        )
        .route(
            "/api/v1/meshes/{mesh_id}/policy/validate",
            post(validate_policy),
        )
        .route(
            "/api/v1/meshes/{mesh_id}/policy/simulate",
            post(simulate_policy_extended),
        )
        .route(
            "/api/v1/meshes/{mesh_id}/services",
            get(list_services).post(create_service),
        )
        .route(
            "/api/v1/meshes/{mesh_id}/services/{service_id}",
            get(get_service).delete(delete_service),
        )
        .route("/api/v1/meshes/{mesh_id}/audit", get(list_audit))
        .route(
            "/api/v1/meshes/{mesh_id}/peers/{peer_id}/configuration-receipts",
            get(get_peer_configuration_receipts),
        )
        .route(
            "/api/v1/meshes/{mesh_id}/resource-policy",
            get(get_resource_policy).put(put_resource_policy),
        )
        .route(
            "/api/v1/meshes/{mesh_id}/resource-policy/preview",
            post(preview_resource_policy),
        )
        .route(
            "/api/v1/meshes/{mesh_id}/resource-policy/history/{revision}",
            get(get_resource_policy_history),
        )
        .route(
            "/api/v1/meshes/{mesh_id}/dns-profiles",
            get(list_dns_profiles).post(create_dns_profile),
        )
        .route(
            "/api/v1/meshes/{mesh_id}/dns-profiles/{profile_id}",
            get(get_dns_profile)
                .put(replace_dns_profile)
                .delete(delete_dns_profile),
        )
        .route("/api/v1/meshes/{mesh_id}/dns/preview", post(preview_dns))
        .route(
            "/api/v1/meshes/{mesh_id}/collections",
            get(list_network_collections).post(create_network_collection),
        )
        .route(
            "/api/v1/meshes/{mesh_id}/collections/{collection_id}",
            get(get_network_collection)
                .put(replace_network_collection)
                .delete(delete_network_collection),
        )
        .route(
            "/api/v1/meshes/{mesh_id}/network-resources",
            get(list_network_resources).post(create_network_resource),
        )
        .route(
            "/api/v1/meshes/{mesh_id}/network-resources/{resource_id}/health",
            get(get_target_health),
        )
        .route(
            "/api/v1/meshes/{mesh_id}/network-resources/{resource_id}",
            get(get_network_resource)
                .put(replace_network_resource)
                .delete(delete_network_resource),
        )
        .route(
            "/api/v1/meshes/{mesh_id}/gateway-bindings",
            get(list_gateway_bindings).post(create_gateway_binding),
        )
        .route(
            "/api/v1/meshes/{mesh_id}/gateway-bindings/{binding_id}",
            get(get_gateway_binding).patch(update_gateway_priority),
        )
        .route(
            "/api/v1/meshes/{mesh_id}/gateway-bindings/{binding_id}/approval",
            axum::routing::put(set_gateway_approval),
        )
        .route("/api/v1/audit", get(list_global_audit))
        .route("/api/v1/events", get(events))
        .route("/auth/session", get(auth_session))
        .route("/auth/logout", post(logout))
        .route_layer(middleware::from_fn_with_state(state.clone(), authenticate));

    Router::new()
        .route(
            "/api/v1/meshes/{mesh_id}/termination",
            get(get_mesh_termination),
        )
        .route("/api/v1/join/{token}/claim", post(claim_join))
        .route("/api/v1/auth/login", get(auth_login))
        .route("/auth/callback", get(auth_callback))
        .route("/api/v1/auth/bootstrap", post(auth_bootstrap))
        .merge(protected)
        .fallback(route_not_found)
        .method_not_allowed_fallback(method_not_allowed)
        .layer(DefaultBodyLimit::max(peerward_api::MAX_REQUEST_BYTES))
        .layer(middleware::from_fn(request_context))
        .with_state(state)
}

async fn route_not_found() -> ApiError {
    ApiError::not_found()
}

async fn method_not_allowed() -> ApiError {
    ApiError::new(
        StatusCode::METHOD_NOT_ALLOWED,
        "method_not_allowed",
        "HTTP method is not allowed for this resource",
    )
}

fn management_router_with_state(state: AppState) -> Router {
    Router::new()
        .route("/livez", get(live))
        .route("/readyz", get(ready))
        .route("/metrics", get(metrics))
        .layer(middleware::from_fn(request_context))
        .with_state(state)
}

include!("request_context.rs");
async fn authenticate(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    state
        .metrics
        .protected_requests
        .fetch_add(1, Ordering::Relaxed);
    let headers = request.headers();
    if let Some(token) = bearer_token(headers) {
        if token.starts_with("pw_runner_") {
            let context = authenticate_deployment_runner(
                &state,
                token,
                request.method(),
                request.uri().path(),
            )
            .await
            .map_err(|error| auth_rejection(&state, error))?;
            request.extensions_mut().insert(context);
            return Ok(next.run(request).await);
        }
        if token.starts_with("pw_machine_") {
            let context = authenticate_machine(&state, token, request.uri().path())
                .await
                .map_err(|error| auth_rejection(&state, error))?;
            request.extensions_mut().insert(context);
            guard_mesh_mutation(&state, request.method(), request.uri().path()).await?;
            return Ok(next.run(request).await);
        }
        if state.auth.oidc.is_some() {
            return Err(auth_rejection(
                &state,
                ApiError::unauthorized(
                    "development_bearer_disabled",
                    "development bearer authentication is disabled",
                ),
            ));
        }
        let expected = state.auth.development_digest.ok_or_else(|| {
            auth_rejection(
                &state,
                ApiError::unauthorized("missing_credentials", "authentication required"),
            )
        })?;
        if !constant_time_digest_eq(secret_digest(token.as_bytes()), expected) {
            return Err(auth_rejection(
                &state,
                ApiError::unauthorized("invalid_bearer", "invalid bearer token"),
            ));
        }
        request.extensions_mut().insert(AuthContext {
            actor: "development-bearer".into(),
            role: Role::Admin,
            source: AuthSource::Bearer,
        });
        guard_mesh_mutation(&state, request.method(), request.uri().path()).await?;
        return Ok(next.run(request).await);
    }
    let token = cookie_value(headers, "peerward_session").ok_or_else(|| {
        auth_rejection(
            &state,
            ApiError::unauthorized("missing_credentials", "authentication required"),
        )
    })?;
    let session = state
        .store
        .session(token)
        .await
        .map_err(|error| match error {
            StoreError::NotFound => auth_rejection(
                &state,
                ApiError::unauthorized("invalid_session", "session is invalid"),
            ),
            other => ApiError::from(other),
        })?;
    request.extensions_mut().insert(AuthContext {
        // Keep authenticated actor namespaces disjoint: an OIDC subject may
        // literally be "machine:<uuid>" and must never impersonate that token.
        actor: format!("oidc:{}", session.subject),
        role: session.role,
        source: AuthSource::Session(session.csrf_digest),
    });
    guard_mesh_mutation(&state, request.method(), request.uri().path()).await?;
    Ok(next.run(request).await)
}

fn auth_rejection(state: &AppState, error: ApiError) -> ApiError {
    state
        .metrics
        .auth_rejections
        .fetch_add(1, Ordering::Relaxed);
    error
}

#[derive(Clone)]
struct AuthContext {
    actor: String,
    role: Role,
    source: AuthSource,
}

#[derive(Clone)]
enum AuthSource {
    Bearer,
    DeploymentRunner(Uuid),
    Machine(Vec<Capability>),
    Session([u8; 32]),
}

fn context_allows(context: &AuthContext, required: Capability) -> bool {
    context.role.allows(required)
        && !matches!(context.source, AuthSource::DeploymentRunner(_))
        && !matches!(&context.source, AuthSource::Machine(allowed) if !allowed.contains(&required))
}

fn authorize(
    context: &AuthContext,
    headers: &HeaderMap,
    required: Capability,
    mutation: bool,
) -> Result<(), ApiError> {
    if !context_allows(context, required) {
        return Err(ApiError::forbidden(
            "insufficient_role",
            "insufficient role",
        ));
    }
    if mutation && let AuthSource::Session(expected) = context.source {
        let supplied = headers
            .get("x-csrf-token")
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| ApiError::forbidden("csrf_required", "CSRF token required"))?;
        if !constant_time_digest_eq(secret_digest(supplied.as_bytes()), expected) {
            return Err(ApiError::forbidden("csrf_invalid", "CSRF token invalid"));
        }
    }
    Ok(())
}

include!("health_routes.rs");

async fn guard_mesh_mutation(
    state: &AppState,
    method: &axum::http::Method,
    path: &str,
) -> Result<(), ApiError> {
    if matches!(
        *method,
        axum::http::Method::GET | axum::http::Method::HEAD | axum::http::Method::OPTIONS
    ) {
        return Ok(());
    }
    let Some(tail) = path.strip_prefix("/api/v1/meshes/") else {
        return Ok(());
    };
    if method == axum::http::Method::DELETE && !tail.contains('/') {
        return Ok(());
    }
    let Some(mesh) = tail
        .split('/')
        .next()
        .and_then(|id| Uuid::parse_str(id).ok())
    else {
        return Ok(());
    };
    let lifecycle: Option<String> = sqlx::query_scalar("SELECT lifecycle FROM meshes WHERE id=$1")
        .bind(mesh)
        .fetch_optional(state.store.pool())
        .await?;
    if lifecycle.as_deref() != Some("active") {
        return Err(ApiError::conflict("mesh_not_active", "Mesh is not active"));
    }
    Ok(())
}
