async fn run_audit_ingress(
    shared: Arc<RelayShared>,
    mut receiver: mpsc::Receiver<RelayAuditIngress>,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        let ingress = tokio::select! {
            item = receiver.recv() => item,
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() { None } else { continue; }
            }
        };
        let Some(ingress) = ingress else { break };
        loop {
            let stored = tokio::time::timeout(
                Duration::from_secs(1),
                shared.store.queue_encrypted_audit(
                    shared.config.mesh_id,
                    ingress.source_peer,
                    &ingress.envelope,
                ),
            )
            .await;
            match stored {
                Ok(Ok(_)) => {
                    shared
                        .last_database_success
                        .store(unix_time().0, Ordering::Relaxed);
                    break;
                }
                Ok(Err(error)) => {
                    tracing::warn!(?error, "Relay encrypted audit persistence deferred");
                }
                Err(_) => tracing::warn!("Relay encrypted audit persistence timed out"),
            }
            tokio::select! {
                () = tokio::time::sleep(Duration::from_millis(250)) => {}
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() { return; }
                }
            }
        }
    }
}
