const MAX_PENDING_STUN: usize = 32;

type StunKey = (SocketAddr, [u8; 12]);

/// Cloneable sender and STUN registry paired with the single UDP receive owner.
#[derive(Clone)]
struct UdpDemuxHandle {
    socket: Arc<UdpSocket>,
    interface_index: u32,
    pending_stun: Arc<Mutex<BTreeMap<StunKey, oneshot::Sender<Vec<u8>>>>>,
    pending_gateway: Arc<Mutex<BTreeMap<SocketAddr, GatewayWaiter>>>,
}

impl UdpDemuxHandle {
    fn spawn(
        socket: Arc<UdpSocket>,
        capacity: usize,
        mut shutdown: watch::Receiver<bool>,
        observability: Option<peerward_service::PeerObservability>,
    ) -> (Self, mpsc::Receiver<(SocketAddr, Vec<u8>)>) {
        let pending_stun = Arc::new(Mutex::new(
            BTreeMap::<StunKey, oneshot::Sender<Vec<u8>>>::new(),
        ));
        let pending_gateway = Arc::new(Mutex::new(BTreeMap::<SocketAddr, GatewayWaiter>::new()));
        let handle = Self {
            socket: Arc::clone(&socket),
            interface_index: 0,
            pending_gateway: Arc::clone(&pending_gateway),
            pending_stun: Arc::clone(&pending_stun),
        };
        let (direct_tx, direct_rx) = mpsc::channel(capacity.max(1));
        tokio::spawn(async move {
            let mut datagram = vec![0_u8; 65_535];
            loop {
                tokio::select! {
                    received = socket.recv_from(&mut datagram) => {
                        let Ok((length, source)) = received else { break };
                        let bytes = &datagram[..length];
                        if matches!(bytes.first(), Some(0 | 2)) && bytes.get(1).is_some_and(|opcode| opcode & 0x80 != 0) {
                            let mut pending = pending_gateway.lock().await;
                            if pending.get(&source).is_some_and(|waiter| gateway_response_matches(&waiter.request, bytes))
                                && let Some(waiter) = pending.remove(&source) { let _ = waiter.reply.send(bytes.to_vec()); }
                            continue;
                        }
                        if let Some(transaction) = stun_transaction(bytes) {
                            if peerward_p2p::StunRequest::from_transaction(transaction)
                                .parse_response(bytes).is_err()
                            {
                                continue;
                            }
                            let waiter = pending_stun.lock().await.remove(&(source, transaction));
                            if waiter.is_none_or(|waiter| waiter.send(bytes.to_vec()).is_err())
                                && let Some(observability) = &observability
                            {
                                observability.record_stun_unmatched_response();
                            }
                            continue;
                        }
                        let wireguard = match bytes.get(..4) {
                            Some([1, 0, 0, 0]) => bytes.len() == 148,
                            Some([2, 0, 0, 0]) => bytes.len() == 92,
                            Some([3, 0, 0, 0]) => bytes.len() == 64,
                            Some([4, 0, 0, 0]) => bytes.len() >= 32,
                            _ => false,
                        };
                        if wireguard {
                            if direct_tx.try_send((source, bytes.to_vec())).is_err()
                                && let Some(observability) = &observability
                            {
                                observability.record_udp_direct_queue_drop();
                            }
                        } else if let Some(observability) = &observability {
                            observability.record_udp_unrecognized_datagram();
                        }
                    }
                    changed = shutdown.changed() => {
                        if changed.is_err() || *shutdown.borrow() {
                            break;
                        }
                    }
                }
            }
        });
        (handle, direct_rx)
    }

    async fn discover_mapping(
        &self,
        server: SocketAddr,
        timeout: Duration,
    ) -> Result<SocketAddr, peerward_p2p::P2pError> {
        let request = peerward_p2p::StunRequest::random();
        let key = (server, request.transaction);
        let (sender, mut receiver) = oneshot::channel();
        {
            let mut pending = self.pending_stun.lock().await;
            // Cancelled discovery tasks drop their receiver. Reclaim registrations
            // before applying the global bound, including after a network change.
            pending.retain(|_, waiter| !waiter.is_closed());
            if pending.len() >= MAX_PENDING_STUN || pending.insert(key, sender).is_some() {
                return Err(peerward_p2p::P2pError::Candidate);
            }
        }
        let deadline = tokio::time::Instant::now() + timeout;
        let mut retry = tokio::time::Instant::now();
        let mut backoff = Duration::from_millis(250);
        let result = loop {
            tokio::select! {
                biased;
                () = tokio::time::sleep_until(deadline) => break Err(peerward_p2p::P2pError::Timeout),
                () = tokio::time::sleep_until(retry) => {
                    if let Err(error) = self.socket.send_to(&request.bytes, server).await {
                        break Err(error.into());
                    }
                    retry = tokio::time::Instant::now() + backoff;
                    backoff = (backoff * 2).min(Duration::from_secs(1));
                }
                response = &mut receiver => {
                    break match response {
                        Ok(response) => request.parse_response(&response),
                        Err(_) => Err(peerward_p2p::P2pError::Stun),
                    };
                }
            }
        };
        self.pending_stun.lock().await.remove(&key);
        result
    }
}

fn stun_transaction(bytes: &[u8]) -> Option<[u8; 12]> {
    if bytes.len() < 20 || bytes[4..8] != peerward_p2p::STUN_MAGIC.to_be_bytes() {
        return None;
    }
    bytes[8..20].try_into().ok()
}
