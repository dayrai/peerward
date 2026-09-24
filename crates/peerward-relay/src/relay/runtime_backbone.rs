async fn reconcile_backbones(shared: &Arc<RelayShared>) {
    let relays = shared
        .distributions
        .read()
        .await
        .relays
        .as_ref()
        .map(|directory| directory.directory.entries.clone())
        .unwrap_or_default();
    let desired = desired_backbone_neighbors(shared, &relays).await;
    shared
        .backbones
        .lock()
        .await
        .retain(|relay, _| desired.contains(relay));
    shared
        .backbone_health
        .lock()
        .await
        .retain(|relay, _| desired.contains(relay));
    for remote in relays {
        if !desired.contains(&remote.relay_id)
            || !should_initiate(shared.config.relay_id, remote.relay_id)
        {
            continue;
        }
        let mut registry = shared.backbones.lock().await;
        if registry.contains_key(&remote.relay_id) {
            continue;
        }
        let (sender, receiver) = mpsc::channel(shared.config.queue_capacity);
        registry.insert(remote.relay_id, sender);
        drop(registry);
        let state = Arc::clone(shared);
        let remote_id = remote.relay_id;
        spawn_mesh_task(shared, async move {
            run_outgoing_backbone(state, remote_id, receiver).await;
        });
    }
}

async fn desired_backbone_neighbors(
    shared: &RelayShared,
    relays: &[RelayEntry],
) -> BTreeSet<RelayId> {
    let distributions = shared.distributions.read().await;
    if let Some(mut desired) = distributions
        .topology
        .as_ref()
        .and_then(|signed| topology_neighbors(&signed.topology, shared.config.relay_id))
    {
        if let Some((deadline, previous)) = &distributions.previous_topology
            && *deadline > tokio::time::Instant::now()
            && let Some(previous) = topology_neighbors(&previous.topology, shared.config.relay_id)
        {
            desired.extend(previous);
        }
        return desired;
    }
    relays
        .iter()
        .filter_map(|relay| (relay.relay_id != shared.config.relay_id).then_some(relay.relay_id))
        .collect()
}

async fn is_backbone_neighbor(shared: &RelayShared, remote: RelayId) -> bool {
    let relays = shared
        .distributions
        .read()
        .await
        .relays
        .as_ref()
        .map(|directory| directory.directory.entries.clone())
        .unwrap_or_default();
    desired_backbone_neighbors(shared, &relays)
        .await
        .contains(&remote)
}

async fn sparse_topology(shared: &RelayShared) -> Option<peerward_directory::RelayTopologyV1> {
    shared
        .distributions
        .read()
        .await
        .topology
        .as_ref()
        .map(|signed| signed.topology.clone())
        .filter(|topology| {
            topology.mode == peerward_directory::RelayTopologyMode::Sparse
                && topology
                    .nodes
                    .iter()
                    .any(|node| node.relay_id == shared.config.relay_id)
        })
}

async fn topology_for_revision(
    shared: &RelayShared,
    revision: u64,
) -> Option<peerward_directory::RelayTopologyV1> {
    let distributions = shared.distributions.read().await;
    if let Some(current) = &distributions.topology
        && current.topology.revision == revision
    {
        return Some(current.topology.clone());
    }
    distributions
        .previous_topology
        .as_ref()
        .filter(|(deadline, topology)| {
            *deadline > tokio::time::Instant::now() && topology.topology.revision == revision
        })
        .map(|(_, topology)| topology.topology.clone())
}

async fn validate_sparse_route(
    shared: &RelayShared,
    remote: RelayId,
    route: &BackboneRoute,
) -> Result<peerward_directory::RelayTopologyV1, RelayError> {
    if route.hop_limit == 0 {
        shared.backbone_ttl_drops.fetch_add(1, Ordering::Relaxed);
        return Err(RelayError::NoRoute);
    }
    if route.visited.contains(&shared.config.relay_id) {
        shared.backbone_loop_drops.fetch_add(1, Ordering::Relaxed);
        return Err(RelayError::NoRoute);
    }
    if route.visited.is_empty() || route.visited.len() > 4 || route.visited.last() != Some(&remote)
    {
        return Err(RelayError::NoRoute);
    }
    let topology = topology_for_revision(shared, route.topology_revision)
        .await
        .ok_or(RelayError::NoRoute)?;
    let adjacent = topology
        .edges
        .iter()
        .any(|edge| edge.other(shared.config.relay_id) == Some(remote));
    if topology.mode != peerward_directory::RelayTopologyMode::Sparse || !adjacent {
        return Err(RelayError::NoRoute);
    }
    Ok(topology)
}

async fn forward_sparse_presence(
    shared: &RelayShared,
    topology: &peerward_directory::RelayTopologyV1,
    update: PresenceAnnouncement,
    mut route: BackboneRoute,
) -> Result<(), RelayError> {
    if route.hop_limit <= 1 || route.visited.len() >= 4 {
        shared.backbone_ttl_drops.fetch_add(1, Ordering::Relaxed);
        return Ok(());
    }
    route.hop_limit -= 1;
    route.visited.push(shared.config.relay_id);
    let senders = shared.backbones.lock().await.clone();
    for next in topology
        .edges
        .iter()
        .filter_map(|edge| edge.other(shared.config.relay_id))
        .filter(|relay| !route.visited.contains(relay))
    {
        if let Some(sender) = senders.get(&next) {
            match sender.try_send(BackbonePayload::RoutedPresence(update, route.clone())) {
                Ok(()) => {
                    shared
                        .backbone_forwarded_hops
                        .fetch_add(1, Ordering::Relaxed);
                }
                Err(mpsc::error::TrySendError::Full(_)) => return Err(RelayError::QueueFull),
                Err(mpsc::error::TrySendError::Closed(_)) => {}
            }
        }
    }
    Ok(())
}

async fn cached_presence_owner(
    shared: &RelayShared,
    peer: PeerId,
) -> Result<peerward_store::PresenceOwner, RelayError> {
    let stale_for = database_stale_for(shared);
    shared.presence.lock().await.primary_owner(
        peer,
        OffsetDateTime::now_utc(),
        stale_for > shared.config.lease_seconds && database_allows_existing_sessions(shared),
    )
}

async fn cached_presence_source(
    shared: &RelayShared,
    peer: PeerId,
    relay: RelayId,
    generation: i64,
) -> bool {
    let stale_for = database_stale_for(shared);
    shared.presence.lock().await.authenticates_source(
        peer,
        relay,
        generation,
        OffsetDateTime::now_utc(),
        stale_for > shared.config.lease_seconds && database_allows_existing_sessions(shared),
    )
}

async fn broadcast_presence(shared: &RelayShared, update: PresenceAnnouncement) {
    let topology = sparse_topology(shared).await;
    let senders = shared.backbones.lock().await.clone();
    let payload = topology.as_ref().map(|topology| {
        BackbonePayload::RoutedPresence(
            update,
            BackboneRoute {
                origin: shared.config.relay_id,
                destination: None,
                topology_revision: topology.revision,
                hop_limit: 4,
                visited: vec![shared.config.relay_id],
            },
        )
    });
    for sender in senders.values() {
        let payload = payload.clone().unwrap_or(BackbonePayload::Presence(update));
        if sender.try_send(payload).is_err() {
            tracing::warn!(peer_id = %update.entry.peer_id, "Relay presence broadcast queue unavailable");
        }
    }
}

include!("runtime_backbone_sessions.rs");
