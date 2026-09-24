async fn discover_direct_candidates(
    config: &PeerConfig,
    demux: UdpDemuxHandle,
    mapped: Option<SocketAddr>,
    observability: Option<&peerward_service::PeerObservability>,
    prediction: &mut peerward_p2p::SymmetricNatPredictionGate,
    underlay: Arc<dyn UnderlayNetwork>,
) -> Result<Vec<SocketAddr>, PeerError> {
    let (mut endpoints, mut candidates) = base_direct_candidates(config, &demux.socket)?;
    if let Some(endpoint) = mapped
        && endpoints.insert(endpoint)
    {
        candidates.push(DirectCandidate {
            endpoint,
            kind: CandidateKind::Mapped,
            priority: 25_000,
        });
    }
    let mut observations = Vec::new();
    let ipv4 = demux.socket.local_addr()?.is_ipv4();
    let resolved = peerward_p2p::resolve_stun_servers_with(
        &config.stun_servers,
        ipv4,
        Duration::from_secs(1),
        move |server| {
            let underlay = Arc::clone(&underlay);
            async move {
                underlay
                    .resolve_host(&server.host(), server.port())
                    .await
                    .unwrap_or_default()
            }
        },
    )
    .await;
    let mut servers = resolved.into_iter().enumerate();
    let mut tasks = tokio::task::JoinSet::new();
    // Port deltas describe allocation order, not the order in a config file.
    // Parallel STUN is useful for ordinary discovery but cannot be used as
    // evidence of sequential NAT allocation when prediction is enabled.
    let predict_this_round =
        config.symmetric_nat_prediction && prediction.begin_round(monotonic_seconds());
    let concurrency = if predict_this_round { 1 } else { 4 };
    let deadline = tokio::time::sleep(std::time::Duration::from_secs(2));
    tokio::pin!(deadline);
    loop {
        while tasks.len() < concurrency {
            let Some((index, server)) = servers.next() else {
                break;
            };
            let demux = demux.clone();
            tasks.spawn(async move {
                demux
                    .discover_mapping(server, std::time::Duration::from_secs(2))
                    .await
                    .map(|endpoint| (index, server, endpoint))
            });
        }
        if tasks.is_empty() {
            break;
        }
        tokio::select! {
            result = tasks.join_next() => {
                match result {
                    Some(Ok(Ok((index, server, endpoint)))) => {
                        if let Some(observability) = observability {
                            observability.record_stun_result(true);
                        }
                        observations.push((index, server, endpoint));
                        if endpoints.insert(endpoint) {
                            candidates.push(DirectCandidate {
                                endpoint,
                                kind: CandidateKind::ServerReflexive,
                                priority: 20_000_u32
                                    .saturating_sub(u32::try_from(index).unwrap_or(u32::MAX)),
                            });
                        }
                    }
                    Some(Ok(Err(_)) | Err(_)) => {
                        if let Some(observability) = observability {
                            observability.record_stun_result(false);
                        }
                    }
                    None => break,
                }
            }
            () = &mut deadline => {
                if let Some(observability) = observability {
                    for _ in 0..tasks.len() {
                        observability.record_stun_result(false);
                    }
                }
                tasks.abort_all();
                break;
            }
        }
    }
    if predict_this_round {
        let observations = ordered_prediction_observations(observations);
        let predicted = peerward_p2p::predicted_ports(&observations);
        prediction.complete_round(monotonic_seconds(), !predicted.is_empty());
        if let Some(observability) = observability {
            observability.record_nat_prediction(!predicted.is_empty());
        }
        if let Some(address) = observations.last().map(SocketAddr::ip) {
            for (index, port) in predicted.into_iter().enumerate() {
                let endpoint = SocketAddr::new(address, port);
                if endpoints.insert(endpoint) {
                    candidates.push(DirectCandidate {
                        endpoint,
                        kind: CandidateKind::Predicted,
                        priority: 15_000_u32
                            .saturating_sub(u32::try_from(index).unwrap_or(u32::MAX)),
                    });
                }
            }
        }
    }
    candidates.sort_by_key(|candidate| std::cmp::Reverse(candidate.priority));
    Ok(wireguard_candidates(candidates))
}

fn ordered_prediction_observations(
    mut observations: Vec<(usize, SocketAddr, SocketAddr)>,
) -> Vec<SocketAddr> {
    observations.sort_by_key(|(index, _, _)| *index);
    let mut servers = BTreeSet::new();
    observations
        .into_iter()
        .filter_map(|(_, server, endpoint)| servers.insert(server).then_some(endpoint))
        .collect()
}

fn base_direct_candidates(
    config: &PeerConfig,
    socket: &UdpSocket,
) -> Result<(BTreeSet<SocketAddr>, Vec<DirectCandidate>), PeerError> {
    let mut endpoints = BTreeSet::new();
    let mut candidates = Vec::new();
    let local = socket.local_addr()?;
    for (index, endpoint) in config
        .p2p_endpoints
        .iter()
        .copied()
        .filter(|endpoint| endpoint.is_ipv4() == local.is_ipv4())
        .enumerate()
    {
        if endpoints.insert(endpoint) {
            candidates.push(DirectCandidate {
                endpoint,
                kind: CandidateKind::Static,
                priority: 30_000_u32.saturating_sub(u32::try_from(index).unwrap_or(u32::MAX)),
            });
        }
    }
    if !local.ip().is_unspecified() && endpoints.insert(local) {
        candidates.push(DirectCandidate {
            endpoint: local,
            kind: CandidateKind::Host,
            priority: 10_000,
        });
    }
    Ok((endpoints, candidates))
}

fn wireguard_candidates(candidates: Vec<DirectCandidate>) -> Vec<SocketAddr> {
    peerward_peer_core::filter_wireguard_candidates(
        candidates.into_iter().map(|candidate| candidate.endpoint),
    )
}
