/// Runs the HTTP control service until shutdown.
pub async fn serve(config: ControlConfig, auth: AuthConfig) -> Result<(), ApiError> {
    let database_url = config
        .database_url
        .as_deref()
        .ok_or_else(|| ApiError::invalid("missing_database_url", "database URL is required"))?;
    let store = Store::connect(database_url, config.max_connections)
        .await
        .map_err(ApiError::from)?;
    store.migrate().await.map_err(ApiError::from)?;
    let issuers = load_startup_join_issuers(&config)?;
    validate_authority_configuration(&store, &issuers).await?;
    if config.http_address == config.management_address {
        return Err(ApiError::invalid(
            "listener_collision",
            "public and management listeners must use different addresses",
        ));
    }
    let listener = TcpListener::bind(config.http_address)
        .await
        .map_err(|_| ApiError::unavailable("listen_failed", "HTTP listener unavailable"))?;
    let management_listener = TcpListener::bind(config.management_address)
        .await
        .map_err(|_| {
            ApiError::unavailable(
                "management_listen_failed",
                "management listener unavailable",
            )
        })?;
    tracing::info!(address = %config.http_address, "Control HTTP listener ready");
    tracing::info!(address = %config.management_address, "Control management listener ready");
    let metrics = Arc::new(ControlMetrics::default());
    let (event_sender, event_signal) = watch::channel(0_u64);
    let event_notifications = tokio::spawn(run_event_notifications(
        store.clone(),
        database_url.to_owned(),
        event_sender,
    ));
    let publisher_issuers = IssuerRegistry::from(issuers);
    let dynamic = DynamicMeshConfig::from_environment()?;
    let (mut lifecycle, mut host_api) = if let Some(dynamic) = dynamic {
        register_initial_hosts(&dynamic, &store).await?;
        reload_managed_issuers(&dynamic, &store, &publisher_issuers).await?;
        let host_state = application_state(store.clone(), auth.clone(), publisher_issuers.clone(), metrics.clone(), event_signal.clone());
        let host_config = dynamic.clone();
        let (ready, waiting) = tokio::sync::oneshot::channel();
        let host = tokio::spawn(async move { serve_relay_host_api(host_config, host_state, ready).await });
        if !matches!(tokio::time::timeout(Duration::from_secs(5), waiting).await, Ok(Ok(()))) {
            host.abort();
            return Err(ApiError::unavailable("host_management_start_failed", "Relay host management listener could not start"));
        }
        (Some(tokio::spawn(run_mesh_lifecycle(dynamic, store.clone(), publisher_issuers.clone()))), Some(host))
    } else { (None, None) };
    let publisher = tokio::spawn(run_publisher(
        store.clone(),
        publisher_issuers.clone(),
        Arc::clone(&metrics),
        event_signal.clone(),
    ));
    let audit_collector = tokio::spawn(run_audit_collector(
        store.clone(),
        publisher_issuers.clone(),
        Arc::clone(&metrics),
    ));
    let webhooks = tokio::spawn(run_webhooks(store.clone(), publisher_issuers.clone()));
    let maintenance_tasks = tokio::spawn(run_maintenance_tasks(store.clone()));
    let maintenance = tokio::spawn(run_maintenance(
        store.clone(),
        config.maintenance.clone(),
        Arc::clone(&metrics),
    ));
    let (application, management) =
        routers_with_loaded_join_issuers(store, auth, publisher_issuers, metrics, event_signal, config.public_url);
    let result = tokio::select! {
        result = async { tokio::try_join!(
            axum::serve(listener, application).with_graceful_shutdown(shutdown_signal()),
            axum::serve(management_listener, management).with_graceful_shutdown(shutdown_signal()),
        ) } => result.map(|_| ()).map_err(|_| ApiError::unavailable("server_failed", "HTTP server failed")),
        () = async { match host_api.as_mut() {
            Some(task) => { let _ = task.await; }, None => std::future::pending().await,
        } } => Err(ApiError::unavailable("host_management_stopped", "Relay host management listener stopped")),
        () = async { match lifecycle.as_mut() {
            Some(task) => { let _ = task.await; }, None => std::future::pending().await,
        } } => Err(ApiError::unavailable("lifecycle_stopped", "Mesh lifecycle worker stopped")),
    };
    if let Some(task) = lifecycle { task.abort(); }
    if let Some(task) = host_api { task.abort(); }
    publisher.abort();
    audit_collector.abort();
    maintenance.abort();
    maintenance_tasks.abort();
    webhooks.abort();
    event_notifications.abort();
    result
}

async fn shutdown_signal() {
    let _ = peerward_service::shutdown_signal().await;
}
