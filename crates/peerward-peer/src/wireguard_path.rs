/// Linux I/O adapter. All cryptographic and IP authorization state is in the shared core.
#[derive(Clone)]
struct WireguardPath {
    core: Arc<Mutex<peerward_peer_core::WireguardRuntime>>,
    relay: RelayPoolSender,
    sockets: UdpSockets,
    incoming: mpsc::Sender<peerward_peer_core::WireguardOutput>,
    audit: mpsc::Sender<peerward_wire::AuditEventV1>,
    observability: Option<peerward_service::PeerObservability>,
    counters: Arc<CounterSet>,
    mesh: MeshId,
}

impl WireguardPath {
    async fn dispatch(
        &self,
        events: Vec<peerward_peer_core::WireguardOutput>,
    ) -> Result<DataPath, PacketPumpError> {
        use peerward_peer_core::{WireguardIngress, WireguardOutput};
        let mut path = DataPath::Relay;
        let mut failure = None;
        for event in events {
            match event {
                WireguardOutput::Network {
                    peer,
                    packet,
                    reply_to,
                    path_probe,
                    authorization,
                    expires,
                    ..
                } => {
                    let guard = WireguardSendGuard {
                        core: Arc::downgrade(&self.core),
                        authorization,
                        expires,
                    };
                    if !guard.current().await {
                        continue;
                    }
                    match reply_to {
                        Some(
                            route @ (WireguardIngress::Direct(_)
                            | WireguardIngress::DirectPath { .. }),
                        ) => {
                            let (local, endpoint) = match route {
                                WireguardIngress::Direct(endpoint) => (None, endpoint),
                                WireguardIngress::DirectPath { local, remote } => {
                                    (Some(local), remote)
                                }
                                WireguardIngress::Relay(_) => unreachable!(),
                            };
                            let result = {
                                // Recheck authorization under the same lock as the actual writer.
                                let mut core = self.core.lock().await;
                                if Instant::now() >= expires
                                    || !core.delivery_current(
                                        authorization,
                                        UnixTime(wall_clock_seconds()),
                                    )
                                {
                                    continue;
                                }
                                let sockets =
                                    self.sockets.read().map_err(|_| PacketPumpError::NoRoute)?;
                                let socket = if let Some(local) = local {
                                    sockets.get(&local)
                                } else {
                                    sockets
                                        .iter()
                                        .find(|(local, _)| local.is_ipv4() == endpoint.is_ipv4())
                                        .map(|(_, socket)| socket)
                                };
                                socket.map_or_else(
                                    || Err(io::Error::from(io::ErrorKind::AddrNotAvailable)),
                                    |socket| socket.try_send_to(&packet, endpoint),
                                )
                            };
                            match result {
                                Ok(_) => path = DataPath::Direct,
                                Err(_) => {
                                    if !path_probe
                                        && let Some(peer) = peer
                                        && let Err(error) = self
                                            .relay
                                            .try_wireguard(self.mesh, peer, &packet, guard)
                                            .await
                                    {
                                        failure = Some(error);
                                    }
                                }
                            }
                        }
                        reply => {
                            let destination = peer
                                .or(match reply {
                                    Some(WireguardIngress::Relay(peer)) => Some(peer),
                                    _ => None,
                                })
                                .ok_or(PacketPumpError::NoRoute)?;
                            if let Err(error) = self
                                .relay
                                .try_wireguard(self.mesh, destination, &packet, guard)
                                .await
                            {
                                failure = Some(error);
                            }
                        }
                    }
                }
                event @ WireguardOutput::Tunnel { .. } => {
                    if let Err(error) = self.incoming.try_send(event) {
                        if let WireguardOutput::Tunnel { packet, .. } = error.into_inner() {
                            self.record_drop(true, packet.len(), &PeerError::QueueFull);
                        }
                        failure = Some(PacketPumpError::QueueFull);
                    }
                }
            }
        }
        failure.map_or(Ok(path), Err)
    }

    async fn receive(
        &self,
        ingress: peerward_peer_core::WireguardIngress,
        bytes: &[u8],
    ) -> Result<(), PacketPumpError> {
        let received = self.core.lock().await.receive(
            ingress,
            bytes,
            UnixTime(wall_clock_seconds()),
            Instant::now(),
        );
        let output = match received {
            Ok(output) => output,
            Err(error) => {
                self.record_drop(true, bytes.len(), &error);
                return Err(core_packet_error(error));
            }
        };
        self.dispatch(output).await.map(|_| ())
    }

    async fn tick(&self) -> Result<(), PacketPumpError> {
        let mut core = self.core.lock().await;
        let wall = UnixTime(wall_clock_seconds());
        let now = Instant::now();
        let output = core.tick(wall, now).map_err(core_packet_error)?;
        if let Some(observability) = &self.observability {
            observability.set_direct_peers(core.direct_peers(wall, now));
        }
        drop(core);
        self.dispatch(output).await.map(|_| ())
    }
}

fn core_packet_error(error: PeerError) -> PacketPumpError {
    match error {
        PeerError::QueueFull => PacketPumpError::QueueFull,
        PeerError::NoRoute | PeerError::Revoked => PacketPumpError::NoRoute,
        _ => PacketPumpError::InvalidPacket,
    }
}
