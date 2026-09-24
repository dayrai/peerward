use super::*;
use crate::StunRequest;

#[test]
fn binding_round_trip_dual_stack_and_ipv4_mapped_ipv6() {
    let request = StunRequest::from_transaction([19; 12]);
    for (source, expected) in [
        ("203.0.113.1:45000", "203.0.113.1:45000"),
        ("[2001:db8::1234]:45000", "[2001:db8::1234]:45000"),
        ("[::ffff:203.0.113.1]:45000", "203.0.113.1:45000"),
    ] {
        let response = stun_binding_response(&request.bytes, source.parse().unwrap()).unwrap();
        assert_eq!(
            request.parse_response(&response).unwrap(),
            expected.parse().unwrap()
        );
        assert!(response.len() <= 44);
    }
}

#[test]
fn parser_rejects_duplicate_mapping_and_malformed_trailing_attributes() {
    let request = StunRequest::random();
    let response =
        stun_binding_response(&request.bytes, "203.0.113.1:1234".parse().unwrap()).unwrap();
    let mut duplicate = response.clone();
    duplicate.extend_from_slice(&response[20..]);
    duplicate[2..4].copy_from_slice(&24_u16.to_be_bytes());
    assert!(request.parse_response(&duplicate).is_err());
    let mut trailing = response;
    trailing.extend_from_slice(&[0, 9, 0, 8]);
    trailing[2..4].copy_from_slice(&16_u16.to_be_bytes());
    assert!(request.parse_response(&trailing).is_err());
    assert!(stun_binding_response(&trailing, "203.0.113.1:1234".parse().unwrap()).is_none());
}

#[test]
fn server_limits_are_bounded_and_ipv6_prefix_scoped() {
    let now = Instant::now();
    let mut limits = StunLimits::new(now);
    for _ in 0..10 {
        assert!(limits.allow("2001:db8::1".parse().unwrap(), now));
    }
    assert!(!limits.allow("2001:db8::2".parse().unwrap(), now));
    assert!(limits.allow("2001:db8::2".parse().unwrap(), now + Duration::from_secs(1)));
    for i in 0..MAX_PER_SECOND - 1 {
        assert!(limits.allow(
            IpAddr::V4((0xc000_0200 + i).into()),
            now + Duration::from_secs(1)
        ));
    }
    assert!(!limits.allow(
        "198.51.100.1".parse().unwrap(),
        now + Duration::from_secs(1)
    ));
    assert!(limits.clients.len() <= MAX_CLIENTS);
}

#[tokio::test]
async fn client_retransmits_same_transaction_after_dropped_request() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = server.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut buffer = [0; 1024];
        let (size, source) = server.recv_from(&mut buffer).await.unwrap();
        let initial = buffer[..size].to_vec();
        let (size, retry_source) = server.recv_from(&mut buffer).await.unwrap();
        assert_eq!(retry_source, source);
        assert_eq!(&buffer[..size], initial);
        server
            .send_to(&stun_binding_response(&initial, source).unwrap(), source)
            .await
            .unwrap();
    });
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let observed = crate::discover_mapping(&client, address, Duration::from_secs(2))
        .await
        .unwrap();
    assert_eq!(observed, client.local_addr().unwrap());
    task.await.unwrap();
}

#[tokio::test]
async fn shared_service_stops_when_shutdown_sender_disappears() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let (shutdown, changes) = watch::channel(false);
    let worker = tokio::spawn(serve_stun(socket, changes));
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    assert_eq!(
        crate::discover_mapping(&client, address, Duration::from_secs(1))
            .await
            .unwrap(),
        client.local_addr().unwrap()
    );
    drop(shutdown);
    tokio::time::timeout(Duration::from_secs(1), worker)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}
