use super::*;

#[tokio::test]
async fn cancelled_stun_transactions_do_not_exhaust_the_shared_socket() {
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let (shutdown, changes) = watch::channel(false);
    let (demux, _data) = UdpDemuxHandle::spawn(socket, 8, changes, None);
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = server.local_addr().unwrap();
    for _ in 0..40 {
        let request = demux.clone();
        let pending = tokio::spawn(async move {
            request
                .discover_mapping(address, Duration::from_secs(2))
                .await
        });
        let mut buffer = [0; 1024];
        tokio::time::timeout(Duration::from_secs(1), server.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        pending.abort();
        assert!(pending.await.unwrap_err().is_cancelled());
    }
    let request = demux.clone();
    let pending = tokio::spawn(async move {
        request
            .discover_mapping(address, Duration::from_secs(2))
            .await
    });
    let mut buffer = [0; 1024];
    let (size, source) = server.recv_from(&mut buffer).await.unwrap();
    let response = peerward_p2p::stun_binding_response(&buffer[..size], source).unwrap();
    server.send_to(&response, source).await.unwrap();
    assert_eq!(
        pending.await.unwrap().unwrap(),
        demux.socket.local_addr().unwrap()
    );
    assert!(demux.pending_stun.lock().await.is_empty());
    shutdown.send(true).unwrap();
}

#[tokio::test]
async fn demux_retries_loss_and_ignores_malformed_matching_responses() {
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let local = socket.local_addr().unwrap();
    let (shutdown, changes) = watch::channel(false);
    let (demux, _data) = UdpDemuxHandle::spawn(socket, 8, changes, None);
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let destination = format!("localhost:{}", server.local_addr().unwrap().port())
        .parse()
        .unwrap();
    let resolved = peerward_p2p::resolve_stun_servers(&[destination], true).await;
    let address = *resolved
        .iter()
        .find(|address| **address == server.local_addr().unwrap())
        .unwrap();
    let pending = tokio::spawn(async move {
        demux
            .discover_mapping(address, Duration::from_secs(2))
            .await
    });
    let mut buffer = [0; 1024];
    let (size, source) = server.recv_from(&mut buffer).await.unwrap();
    let original = buffer[..size].to_vec();
    let mut malformed = peerward_p2p::stun_binding_response(&original, source).unwrap();
    malformed[3] = 0;
    server.send_to(&malformed, source).await.unwrap();
    let (size, source) =
        tokio::time::timeout(Duration::from_secs(1), server.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
    assert_eq!(&buffer[..size], original);
    server
        .send_to(
            &peerward_p2p::stun_binding_response(&original, source).unwrap(),
            source,
        )
        .await
        .unwrap();
    assert_eq!(pending.await.unwrap().unwrap(), local);
    shutdown.send(true).unwrap();
}
