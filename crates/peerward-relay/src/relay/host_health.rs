async fn respond_host_health(
    mut socket: TcpStream,
    registry: &Registry,
    store: &Store,
    sync_ok: &AtomicU64,
    traffic: &TrafficCounters,
) -> Result<(), RelayError> {
    let mut request = [0; 1024];
    let count = tokio::time::timeout(Duration::from_secs(1), socket.read(&mut request))
        .await
        .map_err(|_| RelayError::NoRoute)??;
    let line = std::str::from_utf8(&request[..count]).unwrap_or_default();
    let mut parts = line.lines().next().unwrap_or_default().split_whitespace();
    let method = parts.next().unwrap_or_default();
    let path = parts.next().unwrap_or_default();
    let meshes = registry.read().await.len();
    let (status, content_type, body) = match (method, path) {
        ("GET", "/metrics") => {
            use std::fmt::Write as _;
            let mut body = traffic_metrics(traffic);
            let runtimes = registry.read().await.values().cloned().collect::<Vec<_>>();
            let queues = queue_totals(&runtimes).await;
            body.push_str(&queues.metrics());
            let ready = host_ready(store, sync_ok).await;
            let stale = runtimes
                .iter()
                .map(|state| database_stale_for(state))
                .max()
                .unwrap_or(0);
            let _ = write!(
                body,
                "# TYPE peerward_relay_ready gauge\npeerward_relay_ready {}\n# TYPE peerward_relay_database_stale_seconds gauge\npeerward_relay_database_stale_seconds {stale}\n",
                u8::from(ready)
            );
            let mut samples = 0u64;
            let mut loss = 0u64;
            let mut rtt = 0u64;
            let mut links = 0u64;
            for runtime in &runtimes {
                for link in runtime.backbone_health.lock().await.values() {
                    samples = samples.saturating_add(u64::from(link.samples));
                    loss = loss.saturating_add(u64::from(link.loss_permyriad));
                    rtt = rtt.saturating_add(u64::from(link.rtt_millis));
                    links += 1;
                }
            }
            let loss = loss.checked_div(links).unwrap_or(0);
            let rtt = rtt.checked_div(links).unwrap_or(0);
            let _ = write!(
                body,
                "# TYPE peerward_relay_backbone_health_samples gauge\npeerward_relay_backbone_health_samples {samples}\n# TYPE peerward_relay_backbone_loss_permyriad gauge\npeerward_relay_backbone_loss_permyriad {loss}\n# TYPE peerward_relay_backbone_rtt_milliseconds gauge\npeerward_relay_backbone_rtt_milliseconds {rtt}\n"
            );
            let _ = write!(
                body,
                "# TYPE peerward_relay_mesh_contexts gauge\npeerward_relay_mesh_contexts {meshes}\n"
            );
            ("200 OK", "text/plain; version=0.0.4", body)
        }
        ("GET", "/livez") => (
            "200 OK",
            "application/json",
            format!("{{\"status\":\"live\",\"mesh_count\":{meshes}}}"),
        ),
        ("GET", "/readyz") => {
            let ready = host_ready(store, sync_ok).await;
            (
                if ready {
                    "200 OK"
                } else {
                    "503 Service Unavailable"
                },
                "application/json",
                format!(
                    "{{\"status\":\"{}\",\"mesh_count\":{meshes}}}",
                    if ready { "ready" } else { "unready" }
                ),
            )
        }
        _ => (
            "404 Not Found",
            "application/json",
            "{\"error\":\"not_found\"}".into(),
        ),
    };
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    socket.write_all(response.as_bytes()).await?;
    socket.shutdown().await?;
    Ok(())
}

async fn host_ready(store: &Store, sync_ok: &AtomicU64) -> bool {
    let synchronized = sync_ok.load(Ordering::Relaxed);
    synchronized != 0
        && unix_time().0.saturating_sub(synchronized) <= 30
        && tokio::time::timeout(Duration::from_secs(2), store.ready())
            .await
            .unwrap_or(false)
}
