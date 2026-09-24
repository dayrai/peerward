async fn live() -> Json<Value> {
    Json(json!({"status":"live"}))
}

async fn ready(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    if !state.store.ready().await {
        return Err(ApiError::unavailable(
            "database_unready",
            "database is unavailable",
        ));
    }
    if !state.join_issuers.is_empty() {
        let now = current_unix_seconds();
        let last_success = state.metrics.publisher_last_success.load(Ordering::Relaxed);
        if last_success == 0 || now.saturating_sub(last_success) > 5 {
            return Err(ApiError::unavailable(
                "publisher_unready",
                "signed-state publisher has no recent successful pass",
            ));
        }
        for mesh_id in state.join_issuers.keys() {
            let mesh = state.store.mesh(mesh_id).await?;
            if mesh.lifecycle != "active" {
                continue;
            }
            let states = state.store.latest_signed_states(mesh_id).await?;
            if states
                .iter()
                .filter(|state| state.kind != SignedStateKind::RelayTopology)
                .count()
                != 7
                || states.iter().any(|signed| {
                    expected_signed_revision(&mesh, signed.kind)
                        .is_some_and(|expected| signed.revision != expected)
                })
            {
                return Err(ApiError::unavailable(
                    "signed_state_unready",
                    "signed state is incomplete or behind authoritative revisions",
                ));
            }
        }
    }
    Ok(Json(json!({"status":"ready"})))
}

async fn metrics(State(state): State<AppState>) -> impl IntoResponse {
    let _ = sample_audit_capacity(&state).await;
    let protected_requests = state.metrics.protected_requests.load(Ordering::Relaxed);
    let auth_rejections = state.metrics.auth_rejections.load(Ordering::Relaxed);
    let join_claims = state.metrics.join_claims.load(Ordering::Relaxed);
    let join_replays = state.metrics.join_replays.load(Ordering::Relaxed);
    let join_completions = state.metrics.join_completions.load(Ordering::Relaxed);
    let policy_validations = state.metrics.policy_validations.load(Ordering::Relaxed);
    let policy_validation_failures = state
        .metrics
        .policy_validation_failures
        .load(Ordering::Relaxed);
    let publisher_last_success = state.metrics.publisher_last_success.load(Ordering::Relaxed);
    let publisher_failures = state.metrics.publisher_failures.load(Ordering::Relaxed);
    let publisher_builds = state.metrics.publisher_builds.load(Ordering::Relaxed);
    let publisher_skips = state.metrics.publisher_skips.load(Ordering::Relaxed);
    let lifecycle_expirations = state.metrics.lifecycle_expirations.load(Ordering::Relaxed);
    let audit_batches_processed = state
        .metrics
        .audit_batches_processed
        .load(Ordering::Relaxed);
    let audit_batches_replayed = state.metrics.audit_batches_replayed.load(Ordering::Relaxed);
    let audit_batches_rejected = state.metrics.audit_batches_rejected.load(Ordering::Relaxed);
    let maintenance_last_success = state
        .metrics
        .maintenance_last_success
        .load(Ordering::Relaxed);
    let maintenance_failures = state.metrics.maintenance_failures.load(Ordering::Relaxed);
    let maintenance_deleted_rows = state
        .metrics
        .maintenance_deleted_rows
        .load(Ordering::Relaxed);
    let maintenance_backlog_tables = state
        .metrics
        .maintenance_backlog_tables
        .load(Ordering::Relaxed);
    let sse_connections = 256_u64
        .saturating_sub(u64::try_from(state.sse_connections.available_permits()).unwrap_or(256));
    let sse_capacity_rejections = state
        .metrics
        .sse_capacity_rejections
        .load(Ordering::Relaxed);
    let sse_cursor_resets = state.metrics.sse_cursor_resets.load(Ordering::Relaxed);
    let audit_storage_available=state.metrics.audit_storage_available.load(Ordering::Relaxed);
    let audit_growth_available=state.metrics.audit_growth_available.load(Ordering::Relaxed);
    let audit_sample_at=state.metrics.audit_log_last_sample_seconds.load(Ordering::Relaxed);
    let audit_log_rows = state.metrics.audit_log_rows.load(Ordering::Relaxed);
    let audit_log_bytes = state.metrics.audit_log_bytes.load(Ordering::Relaxed);
    let audit_log_growth_rows_per_hour = state
        .metrics
        .audit_log_growth_rows_per_hour
        .load(Ordering::Relaxed);
    (
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        format!(
            "# HELP peerward_control_live Control process liveness.\n# TYPE peerward_control_live gauge\npeerward_control_live 1\n# HELP peerward_control_protected_requests_total Protected API requests observed.\n# TYPE peerward_control_protected_requests_total counter\npeerward_control_protected_requests_total {protected_requests}\n# HELP peerward_control_auth_rejections_total Authentication rejections.\n# TYPE peerward_control_auth_rejections_total counter\npeerward_control_auth_rejections_total {auth_rejections}\n# HELP peerward_control_join_claims_total Signed Join claims received.\n# TYPE peerward_control_join_claims_total counter\npeerward_control_join_claims_total {join_claims}\n# HELP peerward_control_join_replays_total Idempotent Join response replays.\n# TYPE peerward_control_join_replays_total counter\npeerward_control_join_replays_total {join_replays}\n# HELP peerward_control_join_completions_total Join claims completed or replayed.\n# TYPE peerward_control_join_completions_total counter\npeerward_control_join_completions_total {join_completions}\n# HELP peerward_control_policy_validations_total Side-effect-free policy validations.\n# TYPE peerward_control_policy_validations_total counter\npeerward_control_policy_validations_total {policy_validations}\n# HELP peerward_control_policy_validation_failures_total Policy documents rejected by validation.\n# TYPE peerward_control_policy_validation_failures_total counter\npeerward_control_policy_validation_failures_total {policy_validation_failures}\n# HELP peerward_control_publisher_last_success_seconds Unix timestamp of the last complete signed-state publication pass.\n# TYPE peerward_control_publisher_last_success_seconds gauge\npeerward_control_publisher_last_success_seconds {publisher_last_success}\n# HELP peerward_control_publisher_failures_total Signed-state publication failures.\n# TYPE peerward_control_publisher_failures_total counter\npeerward_control_publisher_failures_total {publisher_failures}\n# HELP peerward_control_publisher_builds_total Signed-state passes that built changed revisions.\n# TYPE peerward_control_publisher_builds_total counter\npeerward_control_publisher_builds_total {publisher_builds}\n# HELP peerward_control_publisher_skips_total Signed-state passes skipped because revisions were unchanged.\n# TYPE peerward_control_publisher_skips_total counter\npeerward_control_publisher_skips_total {publisher_skips}\n# HELP peerward_control_lifecycle_expirations_total Credential overlaps revoked after their bounded acceptance deadline.\n# TYPE peerward_control_lifecycle_expirations_total counter\npeerward_control_lifecycle_expirations_total {lifecycle_expirations}\n# HELP peerward_control_audit_batches_processed_total Verified encrypted Peer audit batches.\n# TYPE peerward_control_audit_batches_processed_total counter\npeerward_control_audit_batches_processed_total {audit_batches_processed}\n# HELP peerward_control_audit_batches_replayed_total Deduplicated Peer audit batches.\n# TYPE peerward_control_audit_batches_replayed_total counter\npeerward_control_audit_batches_replayed_total {audit_batches_replayed}\n# HELP peerward_control_audit_batches_rejected_total Audit verification failures.\n# TYPE peerward_control_audit_batches_rejected_total counter\npeerward_control_audit_batches_rejected_total {audit_batches_rejected}\n# HELP peerward_control_maintenance_last_success_seconds Last successful elected cleanup pass.\n# TYPE peerward_control_maintenance_last_success_seconds gauge\npeerward_control_maintenance_last_success_seconds {maintenance_last_success}\n# HELP peerward_control_maintenance_failures_total Maintenance failures.\n# TYPE peerward_control_maintenance_failures_total counter\npeerward_control_maintenance_failures_total {maintenance_failures}\n# HELP peerward_control_maintenance_deleted_rows_total Operational rows removed by bounded maintenance.\n# TYPE peerward_control_maintenance_deleted_rows_total counter\npeerward_control_maintenance_deleted_rows_total {maintenance_deleted_rows}\n# HELP peerward_control_maintenance_backlog_tables Tables that saturated their bounded cleanup batch.\n# TYPE peerward_control_maintenance_backlog_tables gauge\npeerward_control_maintenance_backlog_tables {maintenance_backlog_tables}\n# HELP peerward_control_sse_connections Current SSE connection count.\n# TYPE peerward_control_sse_connections gauge\npeerward_control_sse_connections {sse_connections}\n# HELP peerward_control_sse_capacity_rejections_total SSE connections rejected at capacity.\n# TYPE peerward_control_sse_capacity_rejections_total counter\npeerward_control_sse_capacity_rejections_total {sse_capacity_rejections}\n# HELP peerward_control_sse_cursor_resets_total Expired SSE cursors requiring a snapshot reset.\n# TYPE peerward_control_sse_cursor_resets_total counter\npeerward_control_sse_cursor_resets_total {sse_cursor_resets}\n# TYPE peerward_control_audit_storage_available gauge\npeerward_control_audit_storage_available {audit_storage_available}\n# TYPE peerward_control_audit_growth_available gauge\npeerward_control_audit_growth_available {audit_growth_available}\n# TYPE peerward_control_audit_sample_seconds gauge\npeerward_control_audit_sample_seconds {audit_sample_at}\n# HELP peerward_control_audit_log_rows Approximate immutable audit row count.\n# TYPE peerward_control_audit_log_rows gauge\npeerward_control_audit_log_rows {audit_log_rows}\n# HELP peerward_control_audit_log_bytes Total audit table storage including indexes and TOAST.\n# TYPE peerward_control_audit_log_bytes gauge\npeerward_control_audit_log_bytes {audit_log_bytes}\n# HELP peerward_control_audit_log_growth_rows_per_hour PostgreSQL statistics insertion estimate; check growth availability and statistics resets.\n# TYPE peerward_control_audit_log_growth_rows_per_hour gauge\npeerward_control_audit_log_growth_rows_per_hour {audit_log_growth_rows_per_hour}\n"
        ),
    )
}

const fn expected_signed_revision(mesh: &MeshRecord, kind: SignedStateKind) -> Option<u64> {
    Some(match kind {
        SignedStateKind::Authorities => mesh.authority_revision,
        SignedStateKind::Peers => mesh.directory_revision,
        SignedStateKind::Relays => mesh.relay_revision,
        SignedStateKind::Policy => mesh.policy_revision,
        SignedStateKind::Services => mesh.service_revision,
        SignedStateKind::Revocations => mesh.revocation_revision,
        SignedStateKind::RelayTopology | SignedStateKind::Configuration => return None,
    })
}

async fn status(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
) -> Result<Json<Value>, ApiError> {
    authorize(
        &context,
        &HeaderMap::new(),
        Capability::StatusAuditRead,
        false,
    )?;
    Ok(Json(
        json!({"database_ready":state.store.ready().await,"version":env!("CARGO_PKG_VERSION")}),
    ))
}

#[derive(Deserialize)]
struct ListQuery {
    cursor: Option<String>,
    limit: Option<u16>,
}

impl ListQuery {
    fn cursor(&self) -> Result<Option<ApiPageCursor>, ApiError> {
        match self.cursor.as_deref() {
            None => Ok(None),
            Some(cursor) => decode_page_cursor(cursor)
                .map(Some)
                .ok_or_else(|| ApiError::invalid("invalid_cursor", "cursor is invalid")),
        }
    }

    fn limit(&self) -> Result<u16, ApiError> {
        let value = self.limit.unwrap_or(100);
        if (1..=500).contains(&value) {
            Ok(value)
        } else {
            Err(ApiError::invalid(
                "invalid_limit",
                "limit must be between 1 and 500",
            ))
        }
    }
}
