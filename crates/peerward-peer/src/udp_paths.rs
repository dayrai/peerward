type UdpPathRuntime = (
    watch::Receiver<LocalPaths>,
    mpsc::Receiver<(SocketAddr, SocketAddr, Vec<u8>)>,
    tokio::task::JoinHandle<()>,
);

/// Actual bound sockets, shared with the synchronous ciphertext writer.
type UdpSockets = Arc<StdRwLock<BTreeMap<SocketAddr, Arc<UdpSocket>>>>;

#[derive(Clone, Default, PartialEq, Eq)]
struct LocalPaths {
    local: Vec<SocketAddr>,
    candidates: Vec<SocketAddr>,
}

struct BoundUdpPath {
    interface: String,
    interface_index: u32,
    local: SocketAddr,
    stop: watch::Sender<bool>,
    discovery: tokio::task::JoinHandle<()>,
    receiver: tokio::task::JoinHandle<()>,
    candidates: Vec<SocketAddr>,
    instance: u64,
}
impl Drop for BoundUdpPath {
    fn drop(&mut self) {
        self.stop.send_replace(true);
        self.receiver.abort();
        // Discovery owns best-effort lease deletion and exits through its stop receiver.
    }
}

fn start_udp_paths(
    config: PeerConfig,
    underlay: Arc<dyn UnderlayNetwork>,
    sockets: UdpSockets,
    mut shutdown: watch::Receiver<bool>,
    observed: Option<peerward_service::PeerObservability>,
) -> UdpPathRuntime {
    let (snapshot, snapshots) = watch::channel(LocalPaths::default());
    let (datagrams, incoming) = mpsc::channel(config.packet_queue_capacity);
    let task = tokio::spawn(async move {
        let mut network_events = underlay.network_changes();
        let (discovered, mut discoveries) = mpsc::channel::<(u64, Vec<SocketAddr>)>(32);
        let mut active: Vec<BoundUdpPath> = Vec::new();
        let mut instance = 0_u64;
        let mut refresh = true;
        let mut topology = Vec::new();
        let mut retry = tokio::time::interval(Duration::from_secs(15));
        retry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            if refresh {
                let mut invalidate = false;
                if let Ok(addresses) = peerward_platform::linux_underlay_addresses().await {
                    let addresses = select_underlay_addresses(addresses);
                    let current: Vec<_> = addresses
                        .iter()
                        .map(|address| {
                            (
                                address.index,
                                address.address,
                                address.mtu,
                                peerward_platform::linux_gateways(
                                    &address.interface,
                                    address.address.is_ipv4(),
                                )
                                .unwrap_or_default(),
                            )
                        })
                        .collect();
                    invalidate = current != topology;
                    topology = current;
                    active.retain(|path| {
                        addresses.iter().any(|address| {
                            address.interface == path.interface
                                && address.index == path.interface_index
                                && address.address == path.local.ip()
                        })
                    });
                    for address in addresses {
                        if active.iter().any(|path| {
                            path.interface == address.interface
                                && path.interface_index == address.index
                                && path.local.ip() == address.address
                        }) {
                            continue;
                        }
                        let port = config
                            .p2p_endpoints
                            .iter()
                            .find(|endpoint| endpoint.is_ipv4() == address.address.is_ipv4())
                            .map_or(0, SocketAddr::port);
                        let socket = match underlay
                            .bind_udp_on(SocketAddr::new(address.address, port), &address.interface)
                            .await
                        {
                            Ok(socket) => Arc::new(socket),
                            Err(error) => {
                                tracing::debug!(?error, "underlay UDP bind unavailable");
                                continue;
                            }
                        };
                        if peerward_peer_core::configure_wireguard_udp(
                            socket.as_ref(),
                            address.address.is_ipv6(),
                        )
                        .is_err()
                        {
                            continue;
                        }
                        let Ok(local) = socket.local_addr() else {
                            continue;
                        };
                        let (stop, stopped) = watch::channel(false);
                        let (mut demux, mut received) = UdpDemuxHandle::spawn(
                            Arc::clone(&socket),
                            config.packet_queue_capacity,
                            stopped.clone(),
                            observed.clone(),
                        );
                        demux.interface_index = address.index;
                        instance = instance.saturating_add(1);
                        let identifier = instance;
                        let sender = datagrams.clone();
                        let forwarder = tokio::spawn(async move {
                            while let Some((source, packet)) = received.recv().await {
                                let _ = sender.try_send((local, source, packet));
                            }
                        });
                        let discovered = discovered.clone();
                        let config = config.clone();
                        let observed = observed.clone();
                        let interface = address.interface.clone();
                        let interface_index = address.index;
                        let discovery_underlay = Arc::clone(&underlay);
                        let discovery = tokio::spawn(async move {
                            run_path_discovery(
                                config,
                                demux,
                                address,
                                identifier,
                                discovered,
                                stopped,
                                observed,
                                discovery_underlay,
                            )
                            .await;
                        });
                        sockets
                            .write()
                            .expect("UDP socket set")
                            .insert(local, socket);
                        active.push(BoundUdpPath {
                            interface,
                            interface_index,
                            local,
                            stop,
                            discovery,
                            receiver: forwarder,
                            candidates: vec![local],
                            instance: identifier,
                        });
                    }
                    sockets
                        .write()
                        .expect("UDP socket set")
                        .retain(|local, _| active.iter().any(|path| path.local == *local));
                }
                publish_local_paths(&active, &snapshot, invalidate);
                refresh = false;
            }
            tokio::select! {
                changed = shutdown.changed() => { if changed.is_err() || *shutdown.borrow() { break; } }
                changed = network_events.changed() => { if changed.is_err() { break; } refresh = true; }
                _ = retry.tick() => { refresh = true; }
                update = discoveries.recv() => {
                    if let Some((id, candidates)) = update {
                        if let Some(path) = active.iter_mut().find(|path| path.instance == id) { path.candidates = candidates; }
                        publish_local_paths(&active, &snapshot, false);
                    }
                }
            }
        }
        sockets.write().expect("UDP socket set").clear();
        for path in &active {
            path.stop.send_replace(true);
        }
        for mut path in active {
            if tokio::time::timeout(Duration::from_secs(3), &mut path.discovery)
                .await
                .is_err()
            {
                path.discovery.abort();
            }
        }
    });
    (snapshots, incoming, task)
}

fn publish_local_paths(
    active: &[BoundUdpPath],
    output: &watch::Sender<LocalPaths>,
    invalidate: bool,
) {
    let mut snapshot = LocalPaths {
        local: active.iter().map(|path| path.local).collect(),
        candidates: Vec::new(),
    };
    for index in 0..32 {
        for path in active {
            if let Some(candidate) = path.candidates.get(index)
                && !snapshot.candidates.contains(candidate)
            {
                snapshot.candidates.push(*candidate);
            }
        }
        if snapshot.candidates.len() >= 32 {
            snapshot.candidates.truncate(32);
            break;
        }
    }
    if invalidate || *output.borrow() != snapshot {
        output.send_replace(snapshot);
    }
}

fn select_underlay_addresses(
    mut addresses: Vec<peerward_platform::UnderlayAddress>,
) -> Vec<peerward_platform::UnderlayAddress> {
    // Prefer interfaces with a default route, while reserving opportunities for each family.
    addresses.retain(|address| address.mtu >= 1280);
    addresses.sort_by_key(|address| {
        (
            !peerward_platform::linux_gateways(&address.interface, address.address.is_ipv4())
                .is_ok_and(|v| !v.is_empty()),
            address.index,
        )
    });
    let mut v4 = addresses.iter().filter(|a| a.address.is_ipv4());
    let mut v6 = addresses.iter().filter(|a| a.address.is_ipv6());
    let mut selected = Vec::new();
    while selected.len() < 8 {
        let next = if selected.len() % 2 == 0 {
            v4.next().or_else(|| v6.next())
        } else {
            v6.next().or_else(|| v4.next())
        };
        let Some(next) = next else {
            break;
        };
        selected.push(next.clone());
    }
    selected
}
