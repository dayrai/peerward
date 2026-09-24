#[derive(Default)]
struct AuditCapacityState {
    attempted_at: Option<std::time::Instant>,
    previous: Option<(peerward_store::AuditStorageStats, std::time::Instant)>,
    value: Value,
}

async fn sample_audit_capacity(state: &AppState) -> Value {
    // The sample and its baseline are one unit. Parallel scrapes must not pair
    // one request's timestamp with another request's PostgreSQL counters.
    let mut cached = state.metrics.audit_capacity.lock().await;
    if cached
        .attempted_at
        .is_some_and(|time| time.elapsed() < Duration::from_secs(15))
    {
        return cached.value.clone();
    }
    cached.attempted_at = Some(std::time::Instant::now());
    let Ok(Ok(sample)) =
        tokio::time::timeout(Duration::from_secs(2), state.store.audit_storage_stats()).await
    else {
        state
            .metrics
            .audit_storage_available
            .store(0, Ordering::Relaxed);
        cached.value["fresh"] = json!(false);
        return cached.value.clone();
    };
    let now = std::time::Instant::now();
    let sampled_at = current_unix_seconds();
    let growth = cached.previous.as_ref().and_then(|(previous, time)| {
        let elapsed = time.elapsed().as_millis();
        if elapsed == 0
            || previous.stats_reset != sample.stats_reset
            || sample.inserted_rows < previous.inserted_rows
        {
            return None;
        }
        u64::try_from(
            u128::from(sample.inserted_rows - previous.inserted_rows) * 3_600_000 / elapsed,
        )
        .ok()
    });
    state
        .metrics
        .audit_log_rows
        .store(sample.estimated_rows, Ordering::Relaxed);
    state
        .metrics
        .audit_log_bytes
        .store(sample.total_bytes, Ordering::Relaxed);
    state
        .metrics
        .audit_log_growth_rows_per_hour
        .store(growth.unwrap_or(0), Ordering::Relaxed);
    state
        .metrics
        .audit_storage_available
        .store(1, Ordering::Relaxed);
    state
        .metrics
        .audit_growth_available
        .store(u64::from(growth.is_some()), Ordering::Relaxed);
    state
        .metrics
        .audit_log_last_sample_seconds
        .store(sampled_at, Ordering::Relaxed);
    cached.previous = Some((sample, now));
    cached.value = json!({"fresh":true,"sampled_at":sampled_at,"estimated_rows":sample.estimated_rows,
        "storage_bytes":sample.total_bytes,"estimated_growth_rows_per_hour":growth});
    cached.value.clone()
}

async fn operations_status(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<Value>, ApiError> {
    authorize(&auth, &HeaderMap::new(), Capability::TrustManage, false)?;
    let audit = sample_audit_capacity(&state).await;
    let missing:i64=sqlx::query_scalar("SELECT count(*) FROM relay_hosts h LEFT JOIN relay_host_capacity c ON c.host_id=h.id
        WHERE h.enabled AND (c.observed_at IS NULL OR c.observed_at<=clock_timestamp()-interval '30 seconds')")
        .fetch_one(state.store.pool()).await?;
    let maintenance_failed: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM maintenance_tasks WHERE status='failed')")
            .fetch_one(state.store.pool())
            .await?;
    let recovery_required: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM deployment_tasks WHERE status='recovery_required')",
    )
    .fetch_one(state.store.pool())
    .await?;
    let latest:Option<Value>=sqlx::query_scalar("SELECT jsonb_build_object('id',id,'status',status,'stage',stage,'reported_at',reported_at,'updated_at',updated_at)
        FROM deployment_tasks WHERE operation='installation_backup' ORDER BY created_at DESC,id DESC LIMIT 1").fetch_optional(state.store.pool()).await?;
    let successful: Option<Value> = sqlx::query_scalar(
        "SELECT jsonb_build_object('id',id,'reported_at',reported_at,'artifact',report->'artifact')
        FROM deployment_tasks WHERE operation='installation_backup' AND status='succeeded' ORDER BY created_at DESC,id DESC LIMIT 1",
    )
    .fetch_optional(state.store.pool())
    .await?;
    let mut alerts = Vec::new();
    if audit["fresh"] != true {
        alerts.push("audit_observation_unknown");
    }
    if missing > 0 {
        alerts.push("relay_observation_unknown");
    }
    if maintenance_failed {
        alerts.push("relay_maintenance_failed");
    }
    if recovery_required {
        alerts.push("installation_recovery_required");
    }
    if latest
        .as_ref()
        .is_some_and(|task| task["status"] == "failed")
    {
        alerts.push("latest_backup_failed");
    }
    Ok(Json(
        json!({"observed_at":current_unix_seconds(),"audit":audit,"unobserved_relay_hosts":missing,
        "latest_backup_task":latest,"latest_successful_backup":successful,"alerts":alerts}),
    ))
}
