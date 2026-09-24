use super::*;

#[tokio::test]
async fn queue_pressure_keeps_live_association_and_drops_only_the_new_datagram() {
    let remote = "127.0.0.1:1234".parse().unwrap();
    let (sender, mut receiver) = mpsc::channel(1);
    let mut associations = HashMap::from([(remote, sender)]);
    enqueue_udp_request(&mut associations, remote, b"first");
    enqueue_udp_request(&mut associations, remote, b"discarded");
    assert_eq!(associations.len(), 1);
    assert_eq!(receiver.recv().await.unwrap(), b"first");
    assert!(receiver.try_recv().is_err());
    enqueue_udp_request(&mut associations, remote, b"next");
    assert_eq!(receiver.recv().await.unwrap(), b"next");
    drop(receiver);
    enqueue_udp_request(&mut associations, remote, b"closed");
    assert!(associations.is_empty());
}

#[tokio::test]
async fn udp_forwarder_observes_shutdown_already_requested_before_start() {
    let mesh = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (_shutdown, receiver) = watch::channel(true);
    tokio::time::timeout(
        Duration::from_secs(1),
        forward_udp(
            mesh,
            "127.0.0.1:53".parse().unwrap(),
            1,
            Duration::from_mins(1),
            receiver,
        ),
    )
    .await
    .unwrap()
    .unwrap();
}

#[tokio::test]
async fn management_client_rejects_oversized_request_before_connecting() {
    let request = Request::Publish {
        listen_port: 80,
        target: "127.0.0.1:80".parse().unwrap(),
        protocols: vec![ServiceProtocol::Tcp],
        alias: Some("a".repeat(LOCAL_MESSAGE_LIMIT)),
    };
    assert!(matches!(
        client(Path::new(""), &request).await,
        Err(ServiceError::Invalid)
    ));
}

#[test]
fn udp_association_deadline_saturates_without_wrapping() {
    let mut associations = UdpAssociations::new(1, 10).unwrap();
    associations
        .touch("127.0.0.1:1234".parse().unwrap(), u64::MAX - 5)
        .unwrap();
    associations.expire(u64::MAX - 1);
    assert_eq!(associations.len(), 1);
    associations.expire(u64::MAX);
    assert!(associations.is_empty());
}

#[tokio::test]
async fn udp_forwarding_supports_both_loopback_families() {
    for ingress in ["127.0.0.1:0", "[::1]:0"] {
        for destination in ["127.0.0.1:0", "[::1]:0"] {
            let target = UdpSocket::bind(destination).await.unwrap();
            let target_address = target.local_addr().unwrap();
            let mesh = UdpSocket::bind(ingress).await.unwrap();
            let mesh_address = mesh.local_addr().unwrap();
            let client = UdpSocket::bind(ingress).await.unwrap();
            let (shutdown, receiver) = watch::channel(false);
            let proxy = tokio::spawn(forward_udp(
                mesh,
                target_address,
                1,
                Duration::from_secs(10),
                receiver,
            ));
            let exchange = tokio::time::timeout(Duration::from_secs(2), async {
                client.send_to(b"request", mesh_address).await.unwrap();
                let mut bytes = [0; 32];
                let (length, source) = target.recv_from(&mut bytes).await.unwrap();
                assert_eq!(&bytes[..length], b"request");
                assert_eq!(source.is_ipv6(), target_address.is_ipv6());
                assert!(source.ip().is_loopback());
                target.send_to(b"response", source).await.unwrap();
                let (length, _) = client.recv_from(&mut bytes).await.unwrap();
                assert_eq!(&bytes[..length], b"response");
            })
            .await;
            let _ = shutdown.send(true);
            let result = proxy.await.unwrap();
            result.unwrap();
            exchange.unwrap();
        }
    }
}

#[tokio::test]
async fn management_client_rejects_oversized_response_without_waiting_for_newline() {
    let directory = std::env::temp_dir().join(format!("peerward-client-{}", ServiceId::new()));
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("peer.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let (release, wait) = oneshot::channel();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let (reader, mut writer) = stream.into_split();
        let mut request = String::new();
        BufReader::new(reader)
            .read_line(&mut request)
            .await
            .unwrap();
        writer.write_all(&vec![b' '; 65_537]).await.unwrap();
        let _ = wait.await;
    });
    let result = tokio::time::timeout(Duration::from_secs(2), client(&path, &Request::List)).await;
    let _ = release.send(());
    server.await.unwrap();
    std::fs::remove_dir_all(directory).unwrap();
    assert!(matches!(result, Ok(Err(ServiceError::Invalid))));
}

#[tokio::test]
async fn management_client_accepts_the_exact_response_size_limit() {
    let directory = std::env::temp_dir().join(format!("peerward-client-{}", ServiceId::new()));
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("peer.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let (reader, mut writer) = stream.into_split();
        let mut request = String::new();
        BufReader::new(reader)
            .read_line(&mut request)
            .await
            .unwrap();
        let mut bytes = serde_json::to_vec(&Response::success()).unwrap();
        bytes.resize(LOCAL_MESSAGE_LIMIT - 1, b' ');
        bytes.push(b'\n');
        writer.write_all(&bytes).await.unwrap();
    });
    let result = client(&path, &Request::List).await;
    server.await.unwrap();
    std::fs::remove_dir_all(directory).unwrap();
    assert!(result.unwrap().ok);
}
