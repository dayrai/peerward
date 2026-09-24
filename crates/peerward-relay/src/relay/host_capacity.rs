async fn observe_host_capacity(
    config: RelayHostConfig,
    client: reqwest::Client,
    registry: Registry,
    traffic: Arc<TrafficCounters>,
    mut stop: watch::Receiver<bool>,
) {
    let process_id = uuid::Uuid::new_v4();
    let started = std::time::Instant::now();
    let mut interval = tokio::time::interval(Duration::from_secs(10));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = stop.changed() => { if *stop.borrow() { return; } }
            _ = interval.tick() => {},
        }
        let observation = async {
            let base = format!(
                "{}/internal/v1/relay-host",
                config.control_url.trim_end_matches('/')
            );
            let challenge = client
                .get(format!("{base}/capacity-challenge"))
                .send()
                .await?
                .error_for_status()?
                .json::<peerward_api::RelayObservationChallenge>()
                .await?;
            let runtimes = registry.read().await.values().cloned().collect::<Vec<_>>();
            let queues = queue_totals(&runtimes).await;
            let report = peerward_api::RelayCapacityReport {
                nonce: challenge.nonce,
                process_id,
                uptime_millis: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                received_bytes: traffic.received_bytes.load(Ordering::Relaxed),
                accepted_bytes: traffic.accepted_bytes.load(Ordering::Relaxed),
                authenticated_peer_sessions: traffic.authenticated_peers.load(Ordering::Relaxed),
                authenticated_backbone_sessions: traffic.authenticated_backbones.load(Ordering::Relaxed),
                session_limit: u64::try_from(config.max_peer_sessions).unwrap_or(u64::MAX),
                mesh_contexts: u64::try_from(runtimes.len()).unwrap_or(u64::MAX),
                router_queued_messages: queues.messages,
                router_queued_encoded_bytes: queues.encoded_bytes,
                backbone_pending_slots: queues.backbone_pending,
                audit_pending_slots: queues.audit_pending,
                no_route_total: traffic.no_route.load(Ordering::Relaxed),
                queue_full_total: traffic.queue_full.load(Ordering::Relaxed),
                invalid_forwarded_frames_total: traffic
                    .invalid_forwarded_frames
                    .load(Ordering::Relaxed),
                audit_queued_total: traffic.audit_queued.load(Ordering::Relaxed),
                audit_dropped_total: traffic.audit_dropped.load(Ordering::Relaxed),
            };
            client
                .post(format!("{base}/capacity"))
                .json(&report)
                .send()
                .await?
                .error_for_status()?;
            Ok::<(), reqwest::Error>(())
        };
        // Telemetry failure never delays state synchronization, revocation or stop.
        tokio::select! {
            _ = stop.changed() => { if *stop.borrow() { return; } }
            result = tokio::time::timeout(Duration::from_secs(5), observation) => {
                if !matches!(result, Ok(Ok(()))) { tracing::debug!("Relay capacity observation deferred"); }
            }
        }
    }
}
