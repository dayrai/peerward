async fn run_maintenance(
    store: Store,
    config: MaintenanceConfig,
    metrics: Arc<ControlMetrics>,
) {
    let policy = peerward_store::MaintenancePolicy {
        batch_size: config.batch_size,
        event_retention_seconds: config.event_retention_seconds,
        event_max_rows: config.event_max_rows,
        signed_state_versions: config.signed_state_versions,
        terminal_retention_seconds: config.terminal_retention_seconds,
    };
    let mut interval = tokio::time::interval(Duration::from_secs(config.interval_seconds));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        match store.maintain(policy).await {
            Ok(report) if report.elected => {
                metrics
                    .maintenance_deleted_rows
                    .fetch_add(report.deleted_rows, Ordering::Relaxed);
                metrics.maintenance_backlog_tables.store(
                    u64::from(report.backlog_tables),
                    Ordering::Relaxed,
                );
                metrics
                    .maintenance_last_success
                    .store(current_unix_seconds(), Ordering::Relaxed);
                if report.deleted_rows > 0 {
                    tracing::info!(
                        deleted_rows = report.deleted_rows,
                        "Control maintenance removed expired operational state"
                    );
                }
            }
            Ok(_) => {}
            Err(error) => {
                metrics
                    .maintenance_failures
                    .fetch_add(1, Ordering::Relaxed);
                tracing::error!(?error, "Control maintenance pass failed");
            }
        }
    }
}
