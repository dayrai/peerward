/// Builds and persists one complete signed state set for every configured mesh issuer.
pub async fn publish_enrollment_state(
    store: &Store,
    configured: &[JoinIssuerConfig],
) -> Result<usize, ApiError> {
    store.expire_device_admissions(500).await?;
    store.expire_credentials(500).await?;
    let issuers = load_join_issuers(configured, None)?;
    let mut published = 0_usize;
    for (mesh_id, candidates) in &issuers {
        let issuer = active_issuer(store, *mesh_id, candidates).await?;
        published += publish_mesh_state(store, *mesh_id, &issuer).await?;
        published += publish_configuration(store, *mesh_id, &issuer).await?;
    }
    Ok(published)
}

async fn run_publisher(
    store: Store,
    issuers: IssuerRegistry,
    metrics: Arc<ControlMetrics>,
    mut event_signal: watch::Receiver<u64>,
) {
    let observer = Uuid::new_v4();
    let mut observations = std::collections::BTreeMap::<MeshId, std::time::Instant>::new();
    let mut interval = tokio::time::interval(Duration::from_secs(5));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = interval.tick() => {}
            changed = event_signal.changed() => {
                if changed.is_err() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
                let _ = event_signal.borrow_and_update();
            }
        }
        let mut pass_succeeded = true;
        let reconciled = async {
            let admissions = store.expire_device_admissions(500).await?;
            store
                .expire_credentials(500)
                .await
                .map(|count| count + admissions)
        }
        .await;
        match reconciled {
            Ok(expired) => {
                metrics
                    .lifecycle_expirations
                    .fetch_add(expired, Ordering::Relaxed);
            }
            Err(error) => {
                pass_succeeded = false;
                metrics.publisher_failures.fetch_add(1, Ordering::Relaxed);
                tracing::error!(?error, "Control credential expiry reconciliation failed");
            }
        }
        if !pass_succeeded {
            observations.clear();
            continue;
        }
        for (mesh_id, candidates) in &issuers.snapshot() {
            let live = sqlx::query_scalar::<_, bool>(
                "SELECT lifecycle IN ('creating','active') FROM meshes WHERE id=$1",
            )
            .bind(mesh_id.into_uuid())
            .fetch_optional(store.pool())
            .await;
            match live {
                Ok(Some(true)) => {}
                Ok(Some(false) | None) => {
                    observations.remove(mesh_id);
                    continue;
                }
                Err(error) => {
                    observations.remove(mesh_id);
                    pass_succeeded = false;
                    metrics.publisher_failures.fetch_add(1, Ordering::Relaxed);
                    tracing::error!(%mesh_id, ?error, "Control publisher Mesh lookup failed");
                    continue;
                }
            }

            let result = async {
                let issuer = active_issuer(&store, *mesh_id, candidates).await?;
                let states = publish_mesh_state(&store, *mesh_id, &issuer).await?;
                let count = publish_configuration(&store, *mesh_id, &issuer).await?;
                let elapsed = observations.get(mesh_id).map(std::time::Instant::elapsed);
                store
                    .observe_ephemeral_peers(*mesh_id, observer, elapsed)
                    .await?;
                observations.insert(*mesh_id, std::time::Instant::now());
                Ok::<_, ApiError>(count + states)
            }
            .await;
            match result {
                Ok(0) => {
                    metrics.publisher_skips.fetch_add(1, Ordering::Relaxed);
                }
                Ok(_) => {
                    metrics.publisher_builds.fetch_add(1, Ordering::Relaxed);
                }
                Err(error) => {
                    observations.remove(mesh_id);
                    pass_succeeded = false;
                    metrics.publisher_failures.fetch_add(1, Ordering::Relaxed);
                    tracing::error!(%mesh_id, ?error, "Control signed-state publisher failed");
                }
            }
        }
        if pass_succeeded {
            metrics
                .publisher_last_success
                .store(current_unix_seconds(), Ordering::Relaxed);
        }
    }
}

async fn run_audit_collector(store: Store, issuers: IssuerRegistry, metrics: Arc<ControlMetrics>) {
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        for (mesh_id, candidates) in &issuers.snapshot() {
            let live = sqlx::query_scalar::<_, bool>(
                "SELECT lifecycle IN ('creating','active') FROM meshes WHERE id=$1",
            )
            .bind(mesh_id.into_uuid())
            .fetch_optional(store.pool())
            .await;
            if !matches!(live, Ok(Some(true))) {
                continue;
            }

            let result = async {
                let issuer = active_issuer(&store, *mesh_id, candidates).await?;
                collect_encrypted_audits(&store, *mesh_id, &issuer, &metrics).await
            }
            .await;
            if let Err(error) = result {
                tracing::warn!(%mesh_id, ?error, "Control audit collector pass failed");
            }
        }
    }
}

async fn active_issuer(
    store: &Store,
    mesh_id: MeshId,
    candidates: &[Arc<JoinIssuer>],
) -> Result<Arc<JoinIssuer>, ApiError> {
    active_issuer_with_executor(store.pool(), mesh_id, candidates).await
}

async fn active_issuer_with_executor<'e>(
    executor: impl sqlx::Executor<'e, Database = sqlx::Postgres>,
    mesh_id: MeshId,
    candidates: &[Arc<JoinIssuer>],
) -> Result<Arc<JoinIssuer>, ApiError> {
    let active: Uuid = sqlx::query_scalar(
        "SELECT id FROM mesh_authorities WHERE mesh_id=$1 AND lifecycle='active'
         AND not_before<=clock_timestamp() AND not_after>clock_timestamp()",
    )
    .bind(mesh_id.into_uuid())
    .fetch_optional(executor)
    .await?
    .ok_or_else(|| {
        ApiError::unavailable(
            "active_authority_unavailable",
            "mesh has no active Authority",
        )
    })?;
    candidates
        .iter()
        .find(|issuer| issuer.authority_id == active)
        .cloned()
        .ok_or_else(|| {
            ApiError::unavailable(
                "active_authority_key_unavailable",
                "active Authority private key is not configured",
            )
        })
}

include!("publisher_build.rs");
include!("publisher_configuration.rs");
