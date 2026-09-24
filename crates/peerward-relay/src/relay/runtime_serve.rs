/// Binds relay listeners, verifies durable signed state, and runs fenced sessions.
pub async fn serve(
    config: RelayConfig,
    local_private: [u8; 32],
    local_credential: Vec<u8>,
    distribution: DistributionCertificate,
    credential_gate: Arc<CredentialGate>,
    store: Store,
    shutdown: watch::Receiver<bool>,
) -> Result<(), RelayError> {
    serve_with_database_policy(
        config,
        local_private,
        local_credential,
        distribution,
        credential_gate,
        store,
        shutdown,
        RelayDatabasePolicy::production(),
    )
    .await
}

/// Runs the production Relay with accelerated database timeouts for fault injection.
#[doc(hidden)]
#[allow(clippy::too_many_arguments)]
pub async fn serve_with_database_policy(
    config: RelayConfig,
    local_private: [u8; 32],
    local_credential: Vec<u8>,
    distribution: DistributionCertificate,
    credential_gate: Arc<CredentialGate>,
    store: Store,
    mut shutdown: watch::Receiver<bool>,
    database_policy: RelayDatabasePolicy,
) -> Result<(), RelayError> {
    let runtime = initialize_mesh_runtime(
        config.clone(),
        local_private,
        local_credential,
        distribution,
        credential_gate,
        store,
        shutdown.clone(),
        database_policy,
        true,
        Arc::new(TrafficCounters::default()),
    )
    .await?;
    let shared = Arc::clone(&runtime.shared);
    let private = Arc::clone(&shared.local_private);
    let directory_verifier = runtime.directory_verifier;
    let instance_id = runtime.instance_id;
    let runtime_generation = runtime.runtime_generation;
    let serving = async {
        let database_url = config
            .database_url
            .as_deref()
            .ok_or(RelayError::InvalidConfig)?
            .to_owned();
        let mut dispatcher = shared.store.dispatcher(&database_url).await?;
        let peers = TcpListener::bind(config.peer_address).await?;
        let backbone = TcpListener::bind(config.backbone_address).await?;
        tracing::info!(
            mesh_id = %config.mesh_id,
            relay_id = %config.relay_id,
            peer_address = %config.peer_address,
            backbone_address = %config.backbone_address,
            "Relay listeners ready"
        );
        let health = if let Some(address) = config.health_address {
            let listener = TcpListener::bind(address).await?;
            let state = Arc::clone(&shared);
            let health_shutdown = shutdown.clone();
            Some(spawn_mesh_task(&shared, async move {
                run_health_server(listener, state, health_shutdown).await;
            }))
        } else {
            None
        };
        reconcile_backbones(&shared).await;
        let mut refresh = tokio::time::interval(Duration::from_secs(5));
        refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut heartbeat = tokio::time::interval(Duration::from_secs(15));
        heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        heartbeat.tick().await;
        loop {
            tokio::select! {
                accepted = peers.accept() => {
                    let (socket, remote) = accepted?;
                    let Ok(session_permit) = Arc::clone(&shared.peer_sessions).try_acquire_owned() else {
                        shared.queue_full.fetch_add(1, Ordering::Relaxed);
                        tracing::warn!(%remote, "Relay Peer session limit reached");
                        continue;
                    };
                    let Some(ip_permit) = shared.ip_handshakes.try_acquire(remote.ip()) else {
                        shared.queue_full.fetch_add(1, Ordering::Relaxed);
                        tracing::warn!(%remote, "Relay per-IP handshake limit reached");
                        continue;
                    };
                    let key = Arc::clone(&private);
                    let state = Arc::clone(&shared);
                    spawn_mesh_task(&shared, async move {
                        let _session_permit = session_permit;
                        if let Err(error) = run_peer_session(socket, key, Arc::clone(&state), ip_permit, None, None).await {
                            record_forwarding_error(&state, &error);
                            tracing::warn!(%remote, ?error, "Relay Peer session ended");
                        }
                    });
                }
                accepted = backbone.accept() => {
                    let (socket, remote) = accepted?;
                    let state = Arc::clone(&shared);
                    spawn_mesh_task(&shared, async move {
                        if let Err(error) = run_incoming_backbone(socket, Arc::clone(&state)).await {
                            record_forwarding_error(&state, &error);
                            tracing::warn!(%remote, ?error, "Relay backbone session ended");
                        }
                    });
                }
                _ = refresh.tick() => {
                    match catch_up_state(&shared, directory_verifier).await {
                        Ok(()) => reconcile_backbones(&shared).await,
                        Err(error) => {
                            if !database_allows_existing_sessions(&shared) {
                                return Err(error);
                            }
                        }
                    }
                }
                notified = dispatcher.next_cursor() => {
                    match notified {
                        Ok(_) => {
                            if let Err(error) = catch_up_state(&shared, directory_verifier).await {
                                tracing::warn!(?error, "Relay durable event catch-up failed");
                            } else {
                                reconcile_backbones(&shared).await;
                            }
                        }
                        Err(error) => {
                            tracing::warn!(?error, "Relay event notification listener failed; reconnecting");
                            tokio::time::sleep(Duration::from_secs(1)).await;
                            match tokio::time::timeout(
                                Duration::from_secs(1),
                                shared.store.dispatcher(&database_url),
                            ).await {
                                Ok(Ok(reconnected)) => dispatcher = reconnected,
                                Ok(Err(error)) => tracing::debug!(?error, "Relay event notification reconnect deferred"),
                                Err(_) => tracing::debug!("Relay event notification reconnect timed out"),
                            }
                        }
                    }
                }
                _ = heartbeat.tick() => {
                    let neighbor_health = shared
                        .backbone_health
                        .lock()
                        .await
                        .values()
                        .cloned()
                        .collect::<Vec<_>>();
                    match shared.store.renew_relay_runtime_with_health(
                        config.mesh_id,
                        config.relay_id,
                        instance_id,
                        runtime_generation,
                        OffsetDateTime::now_utc() + time::Duration::seconds(30),
                        &neighbor_health,
                    ).await {
                        Ok(()) => shared.last_database_success.store(unix_time().0, Ordering::Relaxed),
                        Err(StoreError::Conflict | StoreError::SignedStateConflict { .. }) => {
                            return Err(RelayError::StaleFence);
                        }
                        Err(error) => {
                            if !database_allows_existing_sessions(&shared) {
                                return Err(RelayError::Store(error));
                            }
                        }
                    }
                }
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
            }
        }
        shared
            .store
            .release_relay_runtime(
                config.mesh_id,
                config.relay_id,
                instance_id,
                runtime_generation,
            )
            .await?;
        if let Some(task) = health {
            task.abort();
        }
        runtime.stop().await;
        Ok(())
    };
    tokio::select! {
        biased;
        () = shared.cancel.cancelled() => Err(RelayError::NoRoute),
        result = serving => result,
    }
}
