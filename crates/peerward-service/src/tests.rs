use std::net::{Ipv4Addr, SocketAddrV4};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

use super::*;

#[test]
fn udp_associations_expire_and_are_bounded() {
    let mut mappings = UdpAssociations::new(2, 10).unwrap();
    let a = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1).into();
    let b = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 2).into();
    let c = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 3).into();
    mappings.touch(a, 0).unwrap();
    mappings.touch(b, 0).unwrap();
    assert!(matches!(mappings.touch(c, 1), Err(ServiceError::Capacity)));
    mappings.expire(10);
    assert!(mappings.is_empty());
    mappings.touch(c, 10).unwrap();
}

#[tokio::test]
async fn tcp_proxy_preserves_client_half_close() {
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_address = target.local_addr().unwrap();
    let target_task = tokio::spawn(async move {
        let (mut stream, _) = target.accept().await.unwrap();
        let mut request = Vec::new();
        stream.read_to_end(&mut request).await.unwrap();
        assert_eq!(request, b"request");
        stream.write_all(b"response-after-eof").await.unwrap();
    });
    let ingress = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ingress_address = ingress.local_addr().unwrap();
    let proxy = tokio::spawn(async move {
        let (stream, _) = ingress.accept().await.unwrap();
        forward_tcp(stream, target_address).await.unwrap();
    });
    let mut client = TcpStream::connect(ingress_address).await.unwrap();
    client.write_all(b"request").await.unwrap();
    client.shutdown().await.unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    assert_eq!(response, b"response-after-eof");
    proxy.await.unwrap();
    target_task.await.unwrap();
}

#[tokio::test]
async fn tcp_publication_bounds_connections_and_cancels_them_on_shutdown() {
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_address = target.local_addr().unwrap();
    let ingress = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ingress_address = ingress.local_addr().unwrap();
    let metrics = Arc::new(Metrics::default());
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let publication_metrics = Arc::clone(&metrics);
    let publication = tokio::spawn(async move {
        run_tcp_publication(ingress, target_address, 1, publication_metrics, shutdown_rx).await;
    });

    let mut first = TcpStream::connect(ingress_address).await.unwrap();
    let (mut accepted, _) = tokio::time::timeout(Duration::from_secs(1), target.accept())
        .await
        .unwrap()
        .unwrap();
    let mut second = TcpStream::connect(ingress_address).await.unwrap();
    let mut byte = [0_u8; 1];
    let rejected = tokio::time::timeout(Duration::from_secs(1), second.read(&mut byte))
        .await
        .expect("connection above the publication capacity must be closed");
    assert!(matches!(rejected, Ok(0) | Err(_)));
    assert_eq!(metrics.tcp_connections.load(Ordering::Relaxed), 1);

    shutdown_tx.send(true).unwrap();
    publication.await.unwrap();
    let target_closed = tokio::time::timeout(Duration::from_secs(1), accepted.read(&mut byte))
        .await
        .expect("publication shutdown must close target connections");
    assert!(matches!(target_closed, Ok(0) | Err(_)));
    let client_closed = tokio::time::timeout(Duration::from_secs(1), first.read(&mut byte))
        .await
        .expect("publication shutdown must close mesh connections");
    assert!(matches!(client_closed, Ok(0) | Err(_)));
}

#[tokio::test]
async fn udp_proxy_forwards_only_to_loopback_and_stops_cleanly() {
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target_address = target.local_addr().unwrap();
    let echo = tokio::spawn(async move {
        let mut bytes = [0_u8; 32];
        let (length, source) = target.recv_from(&mut bytes).await.unwrap();
        target.send_to(&bytes[..length], source).await.unwrap();
    });
    let mesh = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mesh_address = mesh.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let proxy = tokio::spawn(async move {
        forward_udp(mesh, target_address, 4, Duration::from_secs(1), shutdown_rx).await
    });
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.send_to(b"datagram", mesh_address).await.unwrap();
    let mut response = [0_u8; 32];
    let (length, _) = tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&response[..length], b"datagram");
    shutdown_tx.send(true).unwrap();
    proxy.await.unwrap().unwrap();
    echo.await.unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn protected_socket_mutations_are_durable() {
    let directory = std::env::temp_dir().join(format!("peerward-service-{}", ServiceId::new()));
    std::fs::create_dir_all(&directory).unwrap();
    let socket = directory.join("peer.sock");
    let state = directory.join("services.json");
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let socket_clone = socket.clone();
    let server = tokio::spawn(async move { serve(&socket_clone, state, shutdown_rx).await });
    for _ in 0..100 {
        if socket.exists() {
            break;
        }
        tokio::task::yield_now().await;
    }
    let published = client(
        &socket,
        &Request::Publish {
            listen_port: 8080,
            target: "127.0.0.1:8080".parse().unwrap(),
            protocols: vec![ServiceProtocol::Tcp],
            alias: Some("web".into()),
        },
    )
    .await
    .unwrap();
    assert!(published.ok);
    let listed = client(&socket, &Request::List).await.unwrap();
    assert_eq!(listed.services.len(), 1);
    let removed = client(
        &socket,
        &Request::Remove {
            service_id: published.service.unwrap().id,
        },
    )
    .await
    .unwrap();
    assert!(removed.ok);
    shutdown_tx.send(true).unwrap();
    server.await.unwrap().unwrap();
    std::fs::remove_dir_all(directory).unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn protected_socket_shutdown_cancels_an_idle_client() {
    let directory =
        std::env::temp_dir().join(format!("peerward-service-idle-{}", ServiceId::new()));
    std::fs::create_dir_all(&directory).unwrap();
    let socket = directory.join("peer.sock");
    let state = directory.join("services.json");
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let socket_clone = socket.clone();
    let server = tokio::spawn(async move { serve(&socket_clone, state, shutdown_rx).await });
    for _ in 0..100 {
        if socket.exists() {
            break;
        }
        tokio::task::yield_now().await;
    }

    let mut idle = UnixStream::connect(&socket).await.unwrap();
    idle.write_all(b"{").await.unwrap();
    tokio::task::yield_now().await;
    shutdown_tx.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(1), server)
        .await
        .expect("management shutdown must not wait for an idle client")
        .unwrap()
        .unwrap();
    let mut byte = [0_u8; 1];
    let closed = tokio::time::timeout(Duration::from_secs(1), idle.read(&mut byte))
        .await
        .expect("management shutdown must close an idle client");
    assert!(matches!(closed, Ok(0) | Err(_)));
    std::fs::remove_dir_all(directory).unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn protected_socket_startup_failure_removes_the_bound_socket() {
    let directory =
        std::env::temp_dir().join(format!("peerward-service-invalid-{}", ServiceId::new()));
    std::fs::create_dir_all(&directory).unwrap();
    let socket = directory.join("peer.sock");
    let state = directory.join("services.json");
    std::fs::write(&state, b"not valid state").unwrap();
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);

    assert!(serve(&socket, state, shutdown_rx).await.is_err());
    assert!(
        !socket.exists(),
        "failed startup must not leave a stale socket"
    );
    std::fs::remove_dir_all(directory).unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn protected_publish_activates_and_removes_mesh_tcp_listener() {
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_address = target.local_addr().unwrap();
    let port = target_address.port();
    let target_task = tokio::spawn(async move {
        let (mut stream, _) = target.accept().await.unwrap();
        let mut request = Vec::new();
        stream.read_to_end(&mut request).await.unwrap();
        assert_eq!(request, b"mesh-request");
        stream.write_all(b"loopback-response").await.unwrap();
    });
    let directory =
        std::env::temp_dir().join(format!("peerward-service-active-{}", ServiceId::new()));
    std::fs::create_dir_all(&directory).unwrap();
    let socket = directory.join("peer.sock");
    let state = directory.join("services.json");
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server_socket = socket.clone();
    let server = tokio::spawn(async move {
        serve_with_address(
            &server_socket,
            state,
            "127.0.0.2".parse().unwrap(),
            shutdown_rx,
        )
        .await
    });
    for _ in 0..100 {
        if socket.exists() {
            break;
        }
        tokio::task::yield_now().await;
    }
    let published = client(
        &socket,
        &Request::Publish {
            listen_port: port,
            target: target_address,
            protocols: vec![ServiceProtocol::Tcp],
            alias: Some("active".into()),
        },
    )
    .await
    .unwrap();
    assert!(published.ok);
    let id = published.service.unwrap().id;
    let mut mesh_client = TcpStream::connect((Ipv4Addr::new(127, 0, 0, 2), port))
        .await
        .unwrap();
    mesh_client.write_all(b"mesh-request").await.unwrap();
    mesh_client.shutdown().await.unwrap();
    let mut response = Vec::new();
    mesh_client.read_to_end(&mut response).await.unwrap();
    assert_eq!(response, b"loopback-response");
    target_task.await.unwrap();
    assert!(
        client(&socket, &Request::Remove { service_id: id })
            .await
            .unwrap()
            .ok
    );
    assert!(
        TcpStream::connect((Ipv4Addr::new(127, 0, 0, 2), port))
            .await
            .is_err()
    );
    shutdown_tx.send(true).unwrap();
    server.await.unwrap().unwrap();
    std::fs::remove_dir_all(directory).unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn both_protocol_publish_rolls_back_when_one_bind_fails() {
    let blocker = UdpSocket::bind("127.0.0.2:0").await.unwrap();
    let listen_port = blocker.local_addr().unwrap().port();
    let directory =
        std::env::temp_dir().join(format!("peerward-service-atomic-{}", ServiceId::new()));
    std::fs::create_dir_all(&directory).unwrap();
    let socket = directory.join("peer.sock");
    let state = directory.join("services.json");
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server_socket = socket.clone();
    let server = tokio::spawn(async move {
        serve_with_address(
            &server_socket,
            state,
            "127.0.0.2".parse().unwrap(),
            shutdown_rx,
        )
        .await
    });
    for _ in 0..100 {
        if socket.exists() {
            break;
        }
        tokio::task::yield_now().await;
    }
    let failed = client(
        &socket,
        &Request::Publish {
            listen_port,
            target: "127.0.0.1:9000".parse().unwrap(),
            protocols: vec![ServiceProtocol::Tcp, ServiceProtocol::Udp],
            alias: None,
        },
    )
    .await
    .unwrap();
    assert!(!failed.ok);
    assert_eq!(failed.error.as_deref(), Some("service_bind_failed"));
    assert!(
        client(&socket, &Request::List)
            .await
            .unwrap()
            .services
            .is_empty()
    );
    assert!(
        TcpStream::connect((Ipv4Addr::new(127, 0, 0, 2), listen_port))
            .await
            .is_err()
    );
    shutdown_tx.send(true).unwrap();
    server.await.unwrap().unwrap();
    drop(blocker);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn pre_one_zero_service_state_is_rejected_without_rewrite() {
    let directory =
        std::env::temp_dir().join(format!("peerward-service-upgrade-{}", ServiceId::new()));
    std::fs::create_dir_all(&directory).unwrap();
    let state = directory.join("services.json");
    let id = ServiceId::new();
    std::fs::write(
        &state,
        serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "services": [{
                "id": id,
                "protocol": "tcp",
                "target": "127.0.0.1:9443",
                "alias": null
            }]
        }))
        .unwrap(),
    )
    .unwrap();
    assert!(matches!(
        Registry::load(state.clone()),
        Err(ServiceError::Invalid)
    ));
    let persisted: serde_json::Value =
        serde_json::from_slice(&std::fs::read(state).unwrap()).unwrap();
    assert_eq!(persisted["schema_version"], 1);
    assert_eq!(persisted["services"][0]["protocol"], "tcp");
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn peer_observability_requires_live_tasks_relay_and_all_signed_state() {
    let state = PeerObservability::default();
    state.initialize("mesh", "peer", &["relay-a".into(), "relay-b".into()]);
    state.set_tun(true);
    state.set_task(PeerTask::Packet, true);
    state.set_task(PeerTask::Control, true);
    state.set_task(PeerTask::Dns, true);
    state.set_relay(1, true);
    for (family, revision) in [
        (SignedStateFamily::Authorities, 1),
        (SignedStateFamily::Peers, 2),
        (SignedStateFamily::Relays, 3),
        (SignedStateFamily::Policy, 4),
        (SignedStateFamily::Services, 5),
        (SignedStateFamily::Revocations, 6),
    ] {
        state.signed_revision(family, revision);
    }
    state.record_egress(128, true, false);
    state.record_ingress(64, false);
    state.record_dns_query();
    state.record_rekey();
    state.record_invalid_packet();
    state.record_no_route();
    state.record_queue_full();
    state.record_stun_result(true);
    state.record_stun_result(false);

    assert_eq!(state.health_json()["status"], "ok");
    assert_eq!(
        state.status_json()["relay_attachments"][1]["role"],
        "standby"
    );
    assert_eq!(
        state.metrics_json()["peerward_peer_egress_bytes_total"],
        128
    );
    assert_eq!(state.metrics_json()["peerward_peer_acl_denied_total"], 1);
    assert_eq!(state.metrics_json()["peerward_peer_relay_rekeys_total"], 1);
    assert_eq!(
        state.metrics_json()["peerward_peer_invalid_packets_total"],
        1
    );
    assert_eq!(state.metrics_json()["peerward_peer_no_route_total"], 1);
    assert_eq!(state.metrics_json()["peerward_peer_queue_full_total"], 1);
    assert_eq!(
        state.metrics_json()["peerward_peer_stun_successes_total"],
        1
    );
    assert_eq!(state.metrics_json()["peerward_peer_stun_failures_total"], 1);
    assert!(
        state.status_json()["diagnostics"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    state.set_direct_peers(["remote-peer"]);
    state.set_direct_peers(std::iter::empty::<&str>());
    assert_eq!(
        state.runtime_report().degraded_reasons,
        vec![PeerDegradedReason::DirectPathUnavailable]
    );
    // A periodic healthy Relay observation must not hide the direct-path fallback.
    state.set_relay(1, true);
    let diagnostic = &state.status_json()["diagnostics"][0];
    assert_eq!(diagnostic["code"], "direct_path_unavailable");
    assert_eq!(diagnostic["retry_hint"], "check_udp_or_use_relay");
    assert!(diagnostic["observed_at"].as_u64().unwrap() > 0);
    state.set_direct_peers(["remote-peer"]);
    assert!(state.runtime_report().degraded_reasons.is_empty());
    // A live DNS listener cannot hide a failed host resolver transaction.
    state.set_dns_host_ready(false);
    assert_eq!(state.health_json()["status"], "degraded");
    assert_eq!(
        state.status_json()["diagnostics"][0]["code"],
        "dns_degraded"
    );
    state.set_dns_host_ready(true);
    assert_eq!(state.health_json()["status"], "ok");
    assert!(state.runtime_report().degraded_reasons.is_empty());
    state.set_task(PeerTask::Dns, false);
    assert_eq!(
        state.status_json()["diagnostics"][0]["code"],
        "dns_degraded"
    );
}
