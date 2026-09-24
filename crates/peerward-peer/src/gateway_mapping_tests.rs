use super::*;

fn pcp_reply(request: &[u8], port: u16, epoch: u32) -> Vec<u8> {
    let mut response = request.to_vec();
    response[1] = 0x81;
    response[8..24].fill(0);
    response[8..12].copy_from_slice(&epoch.to_be_bytes());
    response[42..44].copy_from_slice(&port.to_be_bytes());
    response[44..60].copy_from_slice(
        &std::net::Ipv4Addr::new(203, 0, 113, 7)
            .to_ipv6_mapped()
            .octets(),
    );
    response
}

#[tokio::test]
async fn gateway_requests_use_the_wireguard_data_port_and_ignore_wrong_nonce() {
    use peerward_p2p::MappingTransport as _;
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let local = socket.local_addr().unwrap();
    let (shutdown, stopped) = watch::channel(false);
    let (demux, _incoming) = UdpDemuxHandle::spawn(socket, 4, stopped, None);
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = server.local_addr().unwrap();
    let responder = tokio::spawn(async move {
        let mut buffer = [0; 128];
        let (_, first) = server.recv_from(&mut buffer).await.unwrap();
        assert_eq!(first, local);
        // Drop the first request to exercise the bounded retransmission schedule.
        let (size, second) = server.recv_from(&mut buffer).await.unwrap();
        assert_eq!(second, local);
        let response = pcp_reply(&buffer[..size], 42000, 10);
        let mut wrong = response.clone();
        wrong[24] ^= 1;
        server.send_to(&wrong, second).await.unwrap();
        server.send_to(&response, second).await.unwrap();
    });
    let request = peerward_p2p::PcpMappingRequest::new(local, 600, Some([7; 12])).unwrap();
    let response = demux
        .exchange(address, request.bytes(), Duration::from_secs(2))
        .await
        .unwrap();
    assert_eq!(request.accept(&response).unwrap().external.port(), 42000);
    assert!(demux.pending_gateway.lock().await.is_empty());
    responder.await.unwrap();
    shutdown.send_replace(true);
}

#[derive(Default)]
struct Gateways {
    requests: std::sync::Mutex<Vec<(SocketAddr, u32)>>,
    port: std::sync::atomic::AtomicU16,
}
#[async_trait]
impl peerward_p2p::MappingTransport for Gateways {
    async fn exchange(
        &self,
        server: SocketAddr,
        request: &[u8],
        _timeout: Duration,
    ) -> Result<Vec<u8>, peerward_p2p::P2pError> {
        let lifetime = u32::from_be_bytes(request[4..8].try_into().unwrap());
        self.requests.lock().unwrap().push((server, lifetime));
        Ok(pcp_reply(request, self.port.load(Ordering::Relaxed), 10))
    }
}

#[tokio::test]
async fn gateway_leases_renew_independently_and_retiring_one_preserves_the_other() {
    let first: IpAddr = "192.0.2.1".parse().unwrap();
    let second: IpAddr = "192.0.2.2".parse().unwrap();
    let internal = "192.0.2.10:41000".parse().unwrap();
    let gateways = Gateways::default();
    gateways.port.store(42000, Ordering::Relaxed);
    let mut leases = GatewayMappings::default();
    leases
        .refresh(&[first, second], internal, None, &gateways)
        .await;
    assert_eq!(leases.leases.len(), 2);
    assert_eq!(leases.candidates().len(), 2);
    gateways.port.store(43000, Ordering::Relaxed);
    leases.leases.get_mut(&first).unwrap().renew_at = Instant::now();
    leases
        .refresh(&[first, second], internal, None, &gateways)
        .await;
    assert_eq!(leases.leases[&first].lease.external.port(), 43000);
    assert_eq!(leases.leases[&second].lease.external.port(), 42000);
    assert!(
        gateways
            .requests
            .lock()
            .unwrap()
            .iter()
            .all(|(_, lifetime)| *lifetime != 0)
    );
    leases.refresh(&[second], internal, None, &gateways).await;
    assert_eq!(leases.leases.len(), 1);
    let requests = gateways.requests.lock().unwrap().clone();
    assert!(
        requests
            .iter()
            .any(|(server, lifetime)| server.ip() == first && *lifetime == 0)
    );
    assert!(
        !requests
            .iter()
            .any(|(server, lifetime)| server.ip() == second && *lifetime == 0)
    );
    leases.close(&gateways).await;
    assert!(leases.leases.is_empty());
}
