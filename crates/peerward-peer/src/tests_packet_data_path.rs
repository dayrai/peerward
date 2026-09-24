fn reverse_udp(packet: &[u8]) -> Vec<u8> {
    let mut opposite = packet.to_vec();
    opposite[12..16].copy_from_slice(&packet[16..20]);
    opposite[16..20].copy_from_slice(&packet[12..16]);
    opposite[20..22].copy_from_slice(&packet[22..24]);
    opposite[22..24].copy_from_slice(&packet[20..22]);
    opposite[10..12].fill(0);
    let mut sum = 0_u32;
    for pair in opposite[..20].chunks_exact(2) {
        sum += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let folded = u16::try_from(sum).unwrap();
    opposite[10..12].copy_from_slice(&(!folded).to_be_bytes());
    opposite
}

#[tokio::test]
async fn noise_relay_rejects_plaintext_packets_and_carries_only_opaque_frames() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client_socket = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (server_socket, _) = listener.accept().await.unwrap();
    let (client_transport, server_transport) = stream_transport_pair();
    let (client_controls, _) = mpsc::channel(4);
    let (server_controls, mut server_control_rx) = mpsc::channel(4);
    let (client_relay_sender, _client_relay_receiver) =
        split_noise_relay(client_socket, client_transport, client_controls);
    let (_, mut server_relay_receiver) =
        split_noise_relay(server_socket, server_transport, server_controls);
    let mut client_relay_sender = client_relay_sender;
    let packet = udp_packet();
    assert!(client_relay_sender.send_packet(&packet, 1).await.is_err());
    let mesh = MeshId::new();
    let destination = PeerId::new();
    client_relay_sender
        .send_opaque(mesh, destination, b"end-to-end-ciphertext")
        .await
        .unwrap();
    let receive = tokio::spawn(async move { server_relay_receiver.receive_packet().await });
    let control = server_control_rx.recv().await.unwrap();
    let Some(ControlMessage::Opaque(opaque)) = control.message else {
        panic!("expected opaque Relay envelope")
    };
    assert_eq!(opaque.mesh_id, mesh.as_bytes());
    assert_eq!(opaque.destination_peer, destination.as_bytes());
    assert_eq!(opaque.opaque, b"end-to-end-ciphertext");
    assert!(
        !opaque
            .opaque
            .windows(packet.len())
            .any(|window| window == packet)
    );
    receive.abort();
}

#[tokio::test]
async fn udp_demux_keeps_parallel_stun_and_real_session_datagrams_separate() {
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let local = socket.local_addr().unwrap();
    let (shutdown, shutdown_rx) = watch::channel(false);
    let observability = peerward_service::PeerObservability::default();
    let (demux, mut datagrams) = UdpDemuxHandle::spawn(
        Arc::clone(&socket),
        1,
        shutdown_rx,
        Some(observability.clone()),
    );
    let first = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let second = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let first_address = first.local_addr().unwrap();
    let second_address = second.local_addr().unwrap();
    let first_task = tokio::spawn(async move {
        let mut request = [0_u8; 64];
        let (length, client) = first.recv_from(&mut request).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        let mapped = std::net::SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 1), 40_001);
        first
            .send_to(&stun_response(&request[..length], mapped), client)
            .await
            .unwrap();
    });
    let second_task = tokio::spawn(async move {
        let mut request = [0_u8; 64];
        let (length, client) = second.recv_from(&mut request).await.unwrap();
        let mapped = std::net::SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 2), 40_002);
        second
            .send_to(&stun_response(&request[..length], mapped), client)
            .await
            .unwrap();
    });
    let wireguard_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let remote =
        x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from([8; 32])).to_bytes();
    let mut sender = peerward_wireguard::Engine::new(
        x25519_dalek::StaticSecret::from([7; 32]),
        peerward_wireguard::Limits::default(),
    )
    .unwrap();
    sender.install(remote).unwrap();
    let peerward_wireguard::Event::Network {
        packet: session_frame,
        ..
    } = sender.initiate(&remote).unwrap().remove(0)
    else {
        panic!("WG initiation must emit a datagram")
    };
    wireguard_socket
        .send_to(&session_frame, local)
        .await
        .unwrap();
    wireguard_socket
        .send_to(&session_frame, local)
        .await
        .unwrap();
    let (first_mapping, second_mapping) = tokio::join!(
        demux.discover_mapping(first_address, Duration::from_secs(1)),
        demux.discover_mapping(second_address, Duration::from_secs(1)),
    );
    assert_eq!(first_mapping.unwrap(), "203.0.113.1:40001".parse().unwrap());
    assert_eq!(
        second_mapping.unwrap(),
        "203.0.113.2:40002".parse().unwrap()
    );
    let (_, frame) = tokio::time::timeout(Duration::from_secs(1), datagrams.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(frame, session_frame);
    let unmatched = peerward_p2p::StunRequest::random();
    wireguard_socket
        .send_to(
            &stun_response(
                &unmatched.bytes,
                std::net::SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9),
            ),
            local,
        )
        .await
        .unwrap();
    wireguard_socket
        .send_to(b"PWD2-legacy-datagram", local)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    let metrics = observability.metrics_json();
    assert_eq!(metrics["peerward_peer_stun_unmatched_responses_total"], 1);
    assert_eq!(metrics["peerward_peer_udp_unrecognized_datagrams_total"], 1);
    assert_eq!(metrics["peerward_peer_udp_direct_queue_drops_total"], 1);
    first_task.await.unwrap();
    second_task.await.unwrap();
    shutdown.send(true).unwrap();
}

#[test]
fn symmetric_nat_prediction_is_rate_limited_and_cools_after_three_failures() {
    let mut gate = peerward_p2p::SymmetricNatPredictionGate::default();
    assert!(gate.begin_round(100));
    gate.complete_round(100, false);
    assert!(!gate.begin_round(129));
    assert!(gate.begin_round(130));
    gate.complete_round(130, false);
    assert!(gate.begin_round(160));
    gate.complete_round(160, false);
    assert!(!gate.begin_round(759));
    assert!(gate.begin_round(760));
    gate.complete_round(760, true);
    assert!(gate.begin_round(790));
}

#[test]
fn prediction_observations_follow_config_order_and_require_distinct_servers() {
    let first_server = "192.0.2.1:3478".parse().unwrap();
    let second_server = "192.0.2.2:3478".parse().unwrap();
    let observations = ordered_prediction_observations(vec![
        (2, first_server, "203.0.113.1:40002".parse().unwrap()),
        (1, second_server, "203.0.113.1:40001".parse().unwrap()),
        (0, first_server, "203.0.113.1:40000".parse().unwrap()),
    ]);
    assert_eq!(
        observations,
        vec![
            "203.0.113.1:40000".parse().unwrap(),
            "203.0.113.1:40001".parse().unwrap(),
        ]
    );
    assert!(peerward_p2p::predicted_ports(&observations).is_empty());
}

#[path = "packet_directory_tests.rs"]
mod directory_tests;
