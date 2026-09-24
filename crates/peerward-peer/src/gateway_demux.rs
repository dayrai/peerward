struct GatewayWaiter {
    request: Vec<u8>,
    reply: oneshot::Sender<Vec<u8>>,
}

#[async_trait]
impl peerward_p2p::MappingTransport for UdpDemuxHandle {
    async fn exchange(
        &self,
        mut server: SocketAddr,
        request: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, peerward_p2p::P2pError> {
        if request.len() > 60 {
            return Err(peerward_p2p::P2pError::Mapping);
        }
        if let SocketAddr::V6(address) = &mut server
            && address.ip().is_unicast_link_local()
        {
            if self.interface_index == 0 {
                return Err(peerward_p2p::P2pError::Mapping);
            }
            address.set_scope_id(self.interface_index);
        }
        let (reply, mut response) = oneshot::channel();
        {
            let mut pending = self.pending_gateway.lock().await;
            pending.retain(|_, waiter| !waiter.reply.is_closed());
            if pending.len() >= 8 || pending.contains_key(&server) {
                return Err(peerward_p2p::P2pError::Mapping);
            }
            pending.insert(
                server,
                GatewayWaiter {
                    request: request.to_vec(),
                    reply,
                },
            );
        }
        let deadline = tokio::time::Instant::now() + timeout;
        let mut retry = tokio::time::Instant::now();
        let mut interval = Duration::from_millis(250);
        let result = loop {
            tokio::select! {
                biased;
                () = tokio::time::sleep_until(deadline) => break Err(peerward_p2p::P2pError::Timeout),
                response = &mut response => break response.map_err(|_| peerward_p2p::P2pError::Mapping),
                () = tokio::time::sleep_until(retry) => {
                    if let Err(error) = self.socket.send_to(request, server).await { break Err(error.into()); }
                    retry = tokio::time::Instant::now() + interval;
                    interval = (interval * 2).min(Duration::from_secs(1));
                }
            }
        };
        self.pending_gateway.lock().await.remove(&server);
        result
    }
}

fn gateway_response_matches(request: &[u8], response: &[u8]) -> bool {
    if response.len() > 1024
        || request.len() < 2
        || response.len() < 8
        || response[0] != request[0]
        || response[1] != request[1] | 0x80
    {
        return false;
    }
    match request[0] {
        2 if request.len() == 60 && response.len() >= 24 => {
            response[3] != 0 || (response.len() == 60 && request[24..42] == response[24..42])
        }
        0 if response[2..4] != [0, 0] => true,
        0 if request.len() == 2 => response.len() == 12,
        0 if request.len() == 12 => response.len() == 16 && request[4..6] == response[8..10],
        _ => false,
    }
}
