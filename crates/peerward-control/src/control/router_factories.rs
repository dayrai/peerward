/// Builds the public v1 application router.
pub fn router(store: Store, auth_config: AuthConfig) -> Router {
    router_with_loaded_join_issuers(store, auth_config, HashMap::new())
}

/// Builds the private management router for a dedicated listener.
pub fn management_router(store: Store, auth_config: AuthConfig) -> Router {
    let (_sender, event_signal) = watch::channel(0);
    management_router_with_state(application_state(
        store,
        auth_config,
        HashMap::new(),
        Arc::new(ControlMetrics::default()),
        event_signal,
    ))
}

/// Builds the v1 router with validated online enrollment issuers.
pub fn router_with_enrollment(
    store: Store,
    auth_config: AuthConfig,
    configured: &[JoinIssuerConfig],
) -> Result<Router, ApiError> {
    Ok(router_with_loaded_join_issuers(
        store,
        auth_config,
        load_join_issuers(configured, None)?,
    ))
}
