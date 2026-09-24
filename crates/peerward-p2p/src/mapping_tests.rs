use super::*;

#[test]
fn pcp_map_codec_is_fixed_length_and_rejects_wrong_nonce() {
    let internal: SocketAddr = "192.0.2.10:41000".parse().unwrap();
    let nonce = [7_u8; 12];
    let request = encode_pcp_map(internal, 3_600, nonce);
    assert_eq!(request.len(), 60);
    assert_eq!(&request[..2], &[2, 1]);
    assert_eq!(&request[40..42], &41_000_u16.to_be_bytes());
    let mut response = request;
    response[1] = 0x81;
    response[3] = 0;
    response[8..12].copy_from_slice(&99_u32.to_be_bytes());
    response[12..24].fill(0);
    response[42..44].copy_from_slice(&42_000_u16.to_be_bytes());
    response[44..60].copy_from_slice(&Ipv4Addr::new(203, 0, 113, 9).to_ipv6_mapped().octets());
    let lease = decode_pcp_map(&response, internal, nonce, false).unwrap();
    assert_eq!(lease.external, "203.0.113.9:42000".parse().unwrap());
    assert_eq!(lease.epoch, Some(99));
    assert!(decode_pcp_map(&response, internal, [8; 12], false).is_err());
}

#[test]
fn platform_owned_mapping_requests_reuse_the_exact_internal_port() {
    let internal: SocketAddr = "192.0.2.10:41000".parse().unwrap();
    let pcp = PcpMappingRequest::new(internal, 600, Some([9; 12])).unwrap();
    assert_eq!(&pcp.bytes()[40..42], &41_000_u16.to_be_bytes());
    assert_eq!(pcp.nonce(), [9; 12]);
    let nat = NatPmpMappingRequest::new(internal, 600).unwrap();
    assert_eq!(&nat.bytes()[4..8], &[0xa0, 0x28, 0xa0, 0x28]);
    assert_eq!(NAT_PMP_PUBLIC_ADDRESS_REQUEST, [0, 0]);

    let mut public = [0_u8; 12];
    public[1] = 128;
    public[4..8].copy_from_slice(&77_u32.to_be_bytes());
    public[8..12].copy_from_slice(&[203, 0, 113, 6]);
    assert_eq!(
        accept_nat_pmp_public_address(&public).unwrap(),
        (Ipv4Addr::new(203, 0, 113, 6), 77)
    );
    public[2] = 1;
    assert!(accept_nat_pmp_public_address(&public).is_err());
}

#[test]
fn nat_pmp_response_and_prediction_are_strictly_bounded() {
    let internal: SocketAddr = "192.0.2.10:41000".parse().unwrap();
    let mut response = [0_u8; 16];
    response[1] = 129;
    response[4..8].copy_from_slice(&100_u32.to_be_bytes());
    response[8..10].copy_from_slice(&41_000_u16.to_be_bytes());
    response[10..12].copy_from_slice(&42_000_u16.to_be_bytes());
    response[12..16].copy_from_slice(&3_600_u32.to_be_bytes());
    let lease =
        decode_nat_pmp_map(&response, internal, Ipv4Addr::new(203, 0, 113, 10), false).unwrap();
    assert_eq!(lease.external, "203.0.113.10:42000".parse().unwrap());
    let observations = [
        "203.0.113.20:40000".parse().unwrap(),
        "203.0.113.20:40002".parse().unwrap(),
        "203.0.113.20:40004".parse().unwrap(),
    ];
    assert_eq!(
        predicted_ports(&observations),
        vec![40_004, 40_005, 40_006, 40_007, 40_008]
    );
    assert!(predicted_ports(&observations[..2]).is_empty());
}

#[test]
fn mapping_epoch_detects_restart_but_allows_serial_wrap() {
    assert!(gateway_epoch_restarted(Some(10_000), Some(3)));
    assert!(!gateway_epoch_restarted(Some(10_000), Some(10_001)));
    assert!(!gateway_epoch_restarted(Some(u32::MAX - 2), Some(2)));
    assert!(!gateway_epoch_restarted(None, Some(2)));
    assert!(!gateway_epoch_restarted(Some(2), None));
}

#[test]
fn renewed_mapping_survives_external_port_changes_and_protocol_fallback() {
    let old = MappingLease {
        protocol: MappingProtocol::Pcp,
        internal: "192.0.2.10:41000".parse().unwrap(),
        external: "203.0.113.10:42000".parse().unwrap(),
        lifetime_seconds: 600,
        epoch: Some(100),
        nonce: Some([7; 12]),
    };
    for protocol in [MappingProtocol::Pcp, MappingProtocol::NatPmp] {
        let old = MappingLease {
            protocol,
            ..old.clone()
        };
        for replacement_protocol in [
            MappingProtocol::Pcp,
            MappingProtocol::NatPmp,
            MappingProtocol::Upnp,
        ] {
            let renewed = MappingLease {
                protocol: replacement_protocol,
                external: "203.0.113.11:43000".parse().unwrap(),
                epoch: Some(1),
                nonce: Some([8; 12]),
                ..old.clone()
            };
            assert!(!old.independently_deletable(&renewed));
            let unrelated = MappingLease {
                internal: "192.0.2.10:41001".parse().unwrap(),
                ..renewed
            };
            assert!(old.independently_deletable(&unrelated));
        }
    }
    let old = MappingLease {
        protocol: MappingProtocol::Upnp,
        ..old
    };
    let mut renewed = old.clone();
    renewed.external.set_ip("203.0.113.11".parse().unwrap());
    assert!(!old.independently_deletable(&renewed));
    renewed.external.set_port(43000);
    assert!(old.independently_deletable(&renewed));
}

#[test]
fn nat_pmp_renewal_retains_assigned_port_and_deletion_sends_zero() {
    let internal = "192.0.2.10:41000".parse().unwrap();
    let renew = NatPmpMappingRequest::new(internal, 600)
        .unwrap()
        .suggest_external_port(42000);
    assert_eq!(&renew.bytes()[6..8], &42000_u16.to_be_bytes());
    let delete = NatPmpMappingRequest::new(internal, 0)
        .unwrap()
        .suggest_external_port(42000);
    assert_eq!(&delete.bytes()[4..6], &41000_u16.to_be_bytes());
    assert_eq!(&delete.bytes()[6..12], &[0; 6]);
}

#[test]
fn prediction_gate_rate_limits_and_cools_after_three_failures() {
    let mut gate = SymmetricNatPredictionGate::default();
    assert!(gate.begin_round(100));
    gate.complete_round(100, false);
    assert!(!gate.begin_round(129));
    assert!(gate.begin_round(130));
    gate.complete_round(130, false);
    assert!(gate.begin_round(160));
    gate.complete_round(160, false);
    assert!(!gate.begin_round(759));
    assert!(gate.begin_round(760));
}

#[tokio::test]
async fn pcp_exchange_uses_nonce_internal_port_and_granted_lifetime() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_address = server.local_addr().unwrap();
    let responder = tokio::spawn(async move {
        let mut request = [0_u8; 60];
        let (length, client) = server.recv_from(&mut request).await.unwrap();
        assert_eq!(length, request.len());
        let mut response = request;
        response[1] = 0x81;
        response[3] = 0;
        response[4..8].copy_from_slice(&900_u32.to_be_bytes());
        response[8..12].copy_from_slice(&55_u32.to_be_bytes());
        response[12..24].fill(0);
        response[42..44].copy_from_slice(&42_000_u16.to_be_bytes());
        response[44..60].copy_from_slice(&Ipv4Addr::new(203, 0, 113, 5).to_ipv6_mapped().octets());
        server.send_to(&response, client).await.unwrap();
    });
    let lease = pcp_map_at(
        server_address,
        "127.0.0.1:41000".parse().unwrap(),
        600,
        Duration::from_secs(1),
        Some([9; 12]),
        None,
        None,
    )
    .await
    .unwrap();
    responder.await.unwrap();
    assert_eq!(lease.protocol, MappingProtocol::Pcp);
    assert_eq!(lease.external, "203.0.113.5:42000".parse().unwrap());
    assert_eq!(lease.lifetime_seconds, 900);
    assert_eq!(lease.epoch, Some(55));
}

#[tokio::test]
async fn nat_pmp_exchange_requests_public_address_before_udp_mapping() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_address = server.local_addr().unwrap();
    let responder = tokio::spawn(async move {
        let mut request = [0_u8; 32];
        let (length, client) = server.recv_from(&mut request).await.unwrap();
        assert_eq!(&request[..length], &[0, 0]);
        let mut address = [0_u8; 12];
        address[1] = 128;
        address[4..8].copy_from_slice(&77_u32.to_be_bytes());
        address[8..12].copy_from_slice(&[203, 0, 113, 6]);
        server.send_to(&address, client).await.unwrap();

        let (length, client) = server.recv_from(&mut request).await.unwrap();
        assert_eq!(length, 12);
        assert_eq!(request[1], NAT_PMP_UDP_MAPPING);
        assert_eq!(&request[4..6], &41_000_u16.to_be_bytes());
        let mut mapping = [0_u8; 16];
        mapping[1] = 128 + NAT_PMP_UDP_MAPPING;
        mapping[4..8].copy_from_slice(&78_u32.to_be_bytes());
        mapping[8..10].copy_from_slice(&41_000_u16.to_be_bytes());
        mapping[10..12].copy_from_slice(&42_001_u16.to_be_bytes());
        mapping[12..16].copy_from_slice(&600_u32.to_be_bytes());
        server.send_to(&mapping, client).await.unwrap();
    });
    let lease = nat_pmp_map_at(
        server_address,
        "127.0.0.1:41000".parse().unwrap(),
        600,
        Duration::from_secs(1),
        None,
        None,
    )
    .await
    .unwrap();
    responder.await.unwrap();
    assert_eq!(lease.protocol, MappingProtocol::NatPmp);
    assert_eq!(lease.external, "203.0.113.6:42001".parse().unwrap());
    assert_eq!(lease.epoch, Some(78));
}
