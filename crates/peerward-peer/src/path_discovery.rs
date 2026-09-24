async fn run_path_discovery(
    config: PeerConfig,
    demux: UdpDemuxHandle,
    address: peerward_platform::UnderlayAddress,
    instance: u64,
    discovered: mpsc::Sender<(u64, Vec<SocketAddr>)>,
    mut stop: watch::Receiver<bool>,
    observed: Option<peerward_service::PeerObservability>,
    underlay: Arc<dyn UnderlayNetwork>,
) {
    let Ok(internal) = demux.socket.local_addr() else {
        return;
    };
    let mut leases = GatewayMappings::default();
    let mut prediction = peerward_p2p::SymmetricNatPredictionGate::default();
    loop {
        // Each path's STUN, mappings and data use the same actual bound internal endpoint.
        let gateways = if config.nat_mapping == crate::NatMappingMode::Auto {
            peerward_platform::linux_gateways(&address.interface, internal.is_ipv4())
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        let mapping = leases.refresh(&gateways, internal, observed.as_ref(), &demux);
        let candidates = discover_direct_candidates(
            &config,
            demux.clone(),
            None,
            observed.as_ref(),
            &mut prediction,
            Arc::clone(&underlay),
        );
        let result = tokio::select! {
            result = async { tokio::join!(mapping, candidates) } => Some(result),
            _ = stop.changed() => None,
        };
        let Some(((), candidates)) = result else {
            break;
        };
        let mut candidates = candidates.unwrap_or_else(|_| vec![internal]);
        for endpoint in leases.candidates() {
            if !candidates.contains(&endpoint) {
                candidates.insert(0, endpoint);
            }
        }
        candidates.truncate(32);
        if discovered.send((instance, candidates)).await.is_err() {
            break;
        }
        let refresh_delay =
            leases
                .next_refresh()
                .min(Duration::from_secs(if config.symmetric_nat_prediction {
                    25
                } else {
                    60
                }));
        tokio::select! {
            () = tokio::time::sleep(refresh_delay) => (),
            _ = stop.changed() => break,
        }
    }
    leases.close(&demux).await;
}
