use super::*;

#[test]
fn padded_probes_are_bounded_canonical_and_fill_both_inner_ip_families() {
    for (source, destination, padding) in
        [("10.0.0.1", "10.0.0.2", 1224), ("fd00::1", "fd00::2", 1204)]
    {
        let message = Coordination {
            generation: 2,
            transaction: [4; 16],
            message: Message::MtuProbe(padding),
        };
        let packet = encode_ip(
            source.parse().unwrap(),
            destination.parse().unwrap(),
            &message,
        )
        .unwrap();
        assert_eq!(packet.len(), 1280);
        assert_eq!(decode_ip(&packet).unwrap(), message);
        let mut bytes = message.encode().unwrap();
        bytes[HEADER] = 1;
        assert!(Coordination::decode(&bytes).is_err());
        bytes[HEADER] = 0;
        for opcode in [1, 2, 3, 4, 6] {
            bytes[1] = opcode;
            assert!(Coordination::decode(&bytes).is_err());
        }
    }
    let mut message = Coordination {
        generation: 2,
        transaction: [4; 16],
        message: Message::MtuProbe(MAX_PROBE_PADDING),
    };
    let mut bytes = message.encode().unwrap();
    assert_eq!(Coordination::decode(&bytes).unwrap(), message);
    bytes.push(0);
    assert!(Coordination::decode(&bytes).is_err());
    message.message = Message::MtuProbe(MAX_PROBE_PADDING + 1);
    assert!(message.encode().is_err());
    message.message = Message::MtuProbe(0);
    assert!(message.encode().is_err());
}

#[test]
fn local_mapping_filter_keeps_usable_addresses_without_weakening_remote_validation() {
    let observed = [
        "127.0.0.1:3478",
        "[::1]:3478",
        "0.0.0.0:3478",
        "255.255.255.255:3478",
        "224.0.0.1:3478",
        "[fe80::1]:3478",
        "192.0.2.1:0",
        "192.0.2.1:1234",
        "192.0.2.1:1234",
        "[2001:db8::1]:5678",
    ]
    .map(|value| value.parse::<SocketAddr>().unwrap());
    assert!(validate_candidates(&observed).is_err());
    assert_eq!(
        filter_wireguard_candidates(observed),
        vec![
            "192.0.2.1:1234".parse::<SocketAddr>().unwrap(),
            "[2001:db8::1]:5678".parse().unwrap()
        ]
    );
    assert!(filter_wireguard_candidates(observed[..7].iter().copied()).is_empty());
    assert_eq!(
        filter_wireguard_candidates((1..=64).map(|port| SocketAddr::from(([192, 0, 2, 1], port))))
            .len(),
        32
    );
}

#[test]
fn internal_packets_are_valid_dual_stack_udp_and_reject_noncanonical_messages() {
    for (source, destination) in [("10.0.0.1", "10.0.0.2"), ("fd00::1", "fd00::2")] {
        for candidates in [
            Vec::new(),
            vec![
                "192.0.2.1:1234".parse().unwrap(),
                "[2001:db8::1]:5678".parse().unwrap(),
            ],
        ] {
            let message = Coordination {
                generation: 42,
                transaction: [7; 16],
                message: Message::Candidates(candidates),
            };
            let packet = encode_ip(
                source.parse().unwrap(),
                destination.parse().unwrap(),
                &message,
            )
            .unwrap();
            assert_eq!(decode_ip(&packet).unwrap(), message);
            for length in 0..packet.len() {
                assert!(decode_ip(&packet[..length]).is_err());
            }
            let mut bytes = message.encode().unwrap();
            bytes.push(0);
            assert!(Coordination::decode(&bytes).is_err());
            let mut bytes = message.encode().unwrap();
            bytes[2] = 1;
            assert!(Coordination::decode(&bytes).is_err());
        }
    }
    for endpoint in [
        "127.0.0.1:1234",
        "[::1]:1234",
        "0.0.0.0:1234",
        "192.0.2.1:0",
        "224.0.0.1:1234",
        "[fe80::1]:1234",
        "255.255.255.255:1234",
    ] {
        assert!(!valid_endpoint(endpoint.parse().unwrap()));
    }
    assert!(validate_candidates(&vec!["192.0.2.1:1234".parse().unwrap(); 33]).is_err());
}
