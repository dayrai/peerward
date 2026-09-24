use super::*;
use uuid::Uuid;

#[path = "state_tests.rs"]
mod state_tests;

#[test]
fn denial_audit_tracking_is_bounded_and_capacity_recovers_after_expiry() {
    let mut evaluator = Evaluator::new(mesh(1), Policy::new(1, Action::Deny, vec![]), 4, 2, 10);
    let original = flow(
        "10.0.0.1".parse().unwrap(),
        "10.0.0.2".parse().unwrap(),
        443,
    );
    let mut emitted = 0;
    for port in 0..10_000 {
        let key = FlowKey {
            source_port: Some(port),
            ..original
        };
        let decision = evaluator.denial(key, None, 100);
        assert_eq!(decision.action, Action::Deny);
        emitted += usize::from(decision.emit_denial_audit);
        assert!(evaluator.denial_audits.len() <= 4);
        assert_eq!(
            evaluator.denial_audits.len(),
            evaluator.denial_expirations.len()
        );
    }
    assert_eq!(emitted, 4);
    let first = FlowKey {
        source_port: Some(0),
        ..original
    };
    assert!(!evaluator.denial(first, None, 101).emit_denial_audit);
    assert!(!evaluator.denial(original, None, 109).emit_denial_audit);
    assert!(evaluator.denial(original, None, 110).emit_denial_audit);
    assert!(!evaluator.denial(original, None, 111).emit_denial_audit);
    evaluator
        .replace_policy(Policy::new(2, Action::Deny, vec![]))
        .unwrap();
    assert!(evaluator.denial_audits.is_empty());
    assert!(evaluator.denial_expirations.is_empty());
    assert!(evaluator.denial(original, None, 111).emit_denial_audit);
}

#[test]
fn disabled_audit_throttling_does_not_retain_flow_identifiers() {
    let mut evaluator = Evaluator::new(mesh(1), Policy::new(1, Action::Deny, vec![]), 4, 2, 0);
    let key = flow(
        "10.0.0.1".parse().unwrap(),
        "10.0.0.2".parse().unwrap(),
        443,
    );
    assert!(evaluator.denial(key, None, 100).emit_denial_audit);
    assert!(evaluator.denial(key, None, 100).emit_denial_audit);
    assert!(evaluator.denial_audits.is_empty());
    assert!(evaluator.denial_expirations.is_empty());
}

#[test]
fn audit_throttling_handles_zero_capacity_clock_reversal_and_timestamp_limits() {
    let key = flow(
        "10.0.0.1".parse().unwrap(),
        "10.0.0.2".parse().unwrap(),
        443,
    );
    let mut disabled = Evaluator::new(mesh(1), Policy::new(1, Action::Deny, vec![]), 0, 0, 10);
    assert!(!disabled.denial(key, None, 0).emit_denial_audit);
    assert!(disabled.denial_audits.is_empty());
    let mut evaluator = Evaluator::new(mesh(1), Policy::new(1, Action::Deny, vec![]), 1, 0, 10);
    assert!(evaluator.denial(key, None, 100).emit_denial_audit);
    assert!(!evaluator.denial(key, None, 1).emit_denial_audit);
    assert!(evaluator.denial(key, None, 110).emit_denial_audit);
    assert!(evaluator.denial(key, None, u64::MAX - 10).emit_denial_audit);
    assert!(!evaluator.denial(key, None, u64::MAX - 1).emit_denial_audit);
    assert!(evaluator.denial(key, None, u64::MAX).emit_denial_audit);
    assert_eq!(evaluator.denial_audits.len(), 1);
    assert_eq!(evaluator.denial_expirations.len(), 1);
}

fn mesh(last: u8) -> MeshId {
    let mut bytes = [0_u8; 16];
    bytes[6] = 0x40;
    bytes[8] = 0x80;
    bytes[15] = last;
    MeshId::from_uuid(Uuid::from_bytes(bytes)).unwrap()
}

fn peer(last: u8, address: [u8; 4], label: (&str, &str)) -> PeerDescriptor {
    let mut bytes = [0_u8; 16];
    bytes[6] = 0x40;
    bytes[8] = 0x80;
    bytes[15] = last;
    PeerDescriptor {
        id: PeerId::from_uuid(Uuid::from_bytes(bytes)).unwrap(),
        address: IpAddr::V4(Ipv4Addr::from(address)),
        labels: BTreeMap::from([(label.0.to_owned(), label.1.to_owned())]),
    }
}

fn rule_id(last: u8) -> RuleId {
    let mut bytes = [0_u8; 16];
    bytes[6] = 0x40;
    bytes[8] = 0x80;
    bytes[15] = last;
    RuleId::from_uuid(Uuid::from_bytes(bytes)).unwrap()
}

fn flow(source: IpAddr, destination: IpAddr, port: u16) -> FlowKey {
    FlowKey {
        source,
        destination,
        protocol: IpProtocol::TCP,
        source_port: Some(50_000),
        destination_port: Some(port),
    }
}

#[test]
fn active_return_traffic_refreshes_idle_expiry_but_cannot_survive_policy_replacement() {
    let source = peer(1, [10, 7, 0, 2], ("team", "blue"));
    let destination = peer(2, [10, 7, 0, 3], ("role", "db"));
    for (protocol, lifetime) in [
        (IpProtocol::TCP, 300),
        (IpProtocol::UDP, 60),
        (IpProtocol::ICMPV4, 30),
    ] {
        let mut evaluator =
            Evaluator::new(mesh(1), Policy::new(1, Action::Allow, vec![]), 4, 2, 10);
        let initial = Packet {
            mesh_id: mesh(1),
            source: &source,
            destination: &destination,
            flow: FlowKey {
                protocol,
                ..flow(source.address, destination.address, 443)
            },
            initiating: true,
            related_flow: None,
            fragment_of: None,
        };
        assert_eq!(evaluator.evaluate(&initial, 1).action, Action::Allow);
        let returned = Packet {
            source: &destination,
            destination: &source,
            flow: initial.flow.reverse(),
            initiating: false,
            ..initial
        };
        for time in 1..=100 {
            assert_eq!(
                evaluator
                    .evaluate(&returned, 1 + time * (lifetime - 1))
                    .action,
                Action::Allow
            );
        }
        let last = 1 + 100 * (lifetime - 1);
        assert_eq!(
            evaluator.evaluate(&returned, last + lifetime).action,
            Action::Deny
        );
        assert_eq!(
            evaluator.evaluate(&initial, last + lifetime + 1).action,
            Action::Allow
        );
        evaluator
            .replace_policy(Policy::new(2, Action::Deny, vec![]))
            .unwrap();
        assert_eq!(
            evaluator.evaluate(&returned, last + lifetime + 2).action,
            Action::Deny
        );
    }
}

#[test]
fn related_errors_fragments_and_cross_mesh_packets_cannot_keep_an_idle_connection_alive() {
    let source = peer(1, [10, 7, 0, 2], ("team", "blue"));
    let destination = peer(2, [10, 7, 0, 3], ("role", "db"));
    let mut evaluator = Evaluator::new(mesh(1), Policy::new(1, Action::Allow, vec![]), 4, 2, 10);
    let initial = Packet {
        mesh_id: mesh(1),
        source: &source,
        destination: &destination,
        flow: flow(source.address, destination.address, 443),
        initiating: true,
        related_flow: None,
        fragment_of: None,
    };
    assert_eq!(evaluator.evaluate(&initial, 1).action, Action::Allow);
    let related = Packet {
        flow: FlowKey {
            protocol: IpProtocol::ICMPV4,
            source_port: None,
            destination_port: None,
            ..initial.flow.reverse()
        },
        initiating: false,
        related_flow: Some(initial.flow),
        ..initial
    };
    let fragment = Packet {
        flow: FlowKey {
            source_port: None,
            destination_port: None,
            ..initial.flow
        },
        initiating: false,
        fragment_of: Some(initial.flow),
        ..initial
    };
    let foreign = Packet {
        mesh_id: mesh(2),
        ..initial
    };
    for now in [100, 200, 300] {
        assert_eq!(evaluator.evaluate(&related, now).action, Action::Allow);
        assert_eq!(evaluator.evaluate(&fragment, now).action, Action::Allow);
        assert_eq!(evaluator.evaluate(&foreign, now).action, Action::Deny);
    }
    assert_eq!(evaluator.evaluate(&related, 301).action, Action::Deny);
    assert_eq!(evaluator.evaluate(&fragment, 301).action, Action::Deny);
    assert_eq!(
        evaluator
            .evaluate(
                &Packet {
                    initiating: false,
                    ..initial
                },
                301
            )
            .action,
        Action::Deny
    );
}

#[test]
fn canonical_policy_document_has_stable_golden_bytes_and_strict_round_trip() {
    let policy = Policy::new(9, Action::Allow, Vec::new());
    let encoded = encode_policy_document(&policy).unwrap();
    assert_eq!(
        hex::encode(&encoded),
        "70656572776172642f706f6c6963792d646f63756d656e742f7632000100000000"
    );
    let decoded = decode_policy_document(9, &encoded).unwrap();
    assert_eq!(decoded.revision, 9);
    assert_eq!(decoded.default, Action::Allow);
    let mut trailing = encoded;
    trailing.push(0);
    assert_eq!(
        decode_policy_document(9, &trailing).unwrap_err(),
        PolicyError::InvalidEncoding
    );
}

#[test]
fn priority_deny_wins_and_audits_are_rate_limited() {
    let source = peer(1, [10, 7, 0, 2], ("team", "blue"));
    let destination = peer(2, [10, 7, 0, 3], ("role", "db"));
    let deny_id = rule_id(10);
    let rules = vec![
        Rule {
            id: rule_id(11),
            priority: 20,
            enabled: true,
            log: false,
            action: Action::Allow,
            source: Selector::any(),
            destination: Selector::any(),
            protocol: PolicyProtocol::Tcp,
            destination_ports: Vec::new(),
        },
        Rule {
            id: deny_id,
            priority: 10,
            enabled: true,
            log: true,
            action: Action::Deny,
            source: Selector::labels(BTreeMap::from([("team".into(), "blue".into())])),
            destination: Selector::peer(destination.id),
            protocol: PolicyProtocol::Tcp,
            destination_ports: vec![PortRange::new(5432, 5432).unwrap()],
        },
    ];
    let mut evaluator = Evaluator::new(mesh(1), Policy::new(1, Action::Deny, rules), 4, 2, 10);
    let key = flow(source.address, destination.address, 5432);
    let packet = Packet {
        mesh_id: mesh(1),
        source: &source,
        destination: &destination,
        flow: key,
        initiating: true,
        related_flow: None,
        fragment_of: None,
    };
    let first = evaluator.evaluate(&packet, 100);
    let second = evaluator.evaluate(&packet, 101);
    assert_eq!(first.action, Action::Deny);
    assert_eq!(first.rule_id, Some(deny_id));
    assert!(first.emit_denial_audit);
    assert!(!second.emit_denial_audit);
}

#[test]
fn return_fragment_and_related_error_require_state() {
    let source = peer(1, [10, 8, 0, 2], ("team", "blue"));
    let destination = peer(2, [10, 8, 0, 3], ("role", "web"));
    let policy = Policy::new(
        5,
        Action::Deny,
        vec![Rule {
            id: rule_id(9),
            priority: 1,
            enabled: true,
            log: false,
            action: Action::Allow,
            source: Selector::peer(source.id),
            destination: Selector::peer(destination.id),
            protocol: PolicyProtocol::Tcp,
            destination_ports: vec![PortRange::new(443, 443).unwrap()],
        }],
    );
    let mut evaluator = Evaluator::new(mesh(2), policy, 8, 8, 1);
    let initial = flow(source.address, destination.address, 443);
    let initiating = Packet {
        mesh_id: mesh(2),
        source: &source,
        destination: &destination,
        flow: initial,
        initiating: true,
        related_flow: None,
        fragment_of: None,
    };
    assert_eq!(evaluator.evaluate(&initiating, 1).action, Action::Allow);

    let returned = Packet {
        mesh_id: mesh(2),
        source: &destination,
        destination: &source,
        flow: initial.reverse(),
        initiating: false,
        related_flow: None,
        fragment_of: None,
    };
    assert_eq!(evaluator.evaluate(&returned, 2).action, Action::Allow);

    // The initiator's ACK and subsequent data use the original tuple, without SYN.
    // Both directions must remain authorized after the initial policy decision.
    let established = Packet {
        initiating: false,
        ..initiating
    };
    assert_eq!(evaluator.evaluate(&established, 3).action, Action::Allow);
    let unrelated = Packet {
        flow: FlowKey {
            source_port: Some(50_001),
            ..initial
        },
        ..established
    };
    assert_eq!(evaluator.evaluate(&unrelated, 3).action, Action::Deny);

    let related = Packet {
        mesh_id: mesh(2),
        source: &destination,
        destination: &source,
        flow: FlowKey {
            protocol: IpProtocol::ICMPV4,
            source_port: None,
            destination_port: None,
            ..initial.reverse()
        },
        initiating: false,
        related_flow: Some(initial),
        fragment_of: None,
    };
    assert_eq!(evaluator.evaluate(&related, 3).action, Action::Allow);

    let fragment = Packet {
        mesh_id: mesh(2),
        source: &source,
        destination: &destination,
        flow: FlowKey {
            source_port: None,
            destination_port: None,
            ..initial
        },
        initiating: false,
        related_flow: None,
        fragment_of: Some(initial),
    };
    assert_eq!(evaluator.evaluate(&fragment, 4).action, Action::Allow);
}

#[test]
fn replacement_invalidates_state_and_meshes_cannot_cross() {
    let source = peer(1, [10, 9, 0, 2], ("a", "b"));
    let destination = peer(2, [10, 9, 0, 3], ("c", "d"));
    let initial = flow(source.address, destination.address, 80);
    let allow = Policy::new(1, Action::Allow, vec![]);
    let mut evaluator = Evaluator::new(mesh(3), allow, 1, 1, 0);
    let mut packet = Packet {
        mesh_id: mesh(3),
        source: &source,
        destination: &destination,
        flow: initial,
        initiating: true,
        related_flow: None,
        fragment_of: None,
    };
    assert_eq!(evaluator.evaluate(&packet, 1).action, Action::Allow);
    assert_eq!(evaluator.state_len(), 1);
    evaluator
        .replace_policy(Policy::new(2, Action::Deny, vec![]))
        .unwrap();
    assert_eq!(evaluator.state_len(), 0);
    packet.mesh_id = mesh(4);
    assert_eq!(evaluator.evaluate(&packet, 2).action, Action::Deny);
}

#[test]
fn composite_selectors_unknown_protocol_and_empty_ports_follow_v2_semantics() {
    let source = peer(1, [10, 10, 0, 2], ("team", "blue"));
    let other_source = peer(3, [10, 10, 0, 4], ("team", "blue"));
    let destination = peer(2, [10, 10, 0, 3], ("role", "db"));
    let allow_unknown = rule_id(20);
    let policy = Policy::new(
        1,
        Action::Deny,
        vec![
            Rule {
                id: rule_id(19),
                priority: 1,
                enabled: false,
                log: false,
                action: Action::Deny,
                source: Selector::any(),
                destination: Selector::any(),
                protocol: PolicyProtocol::Any,
                destination_ports: Vec::new(),
            },
            Rule {
                id: allow_unknown,
                priority: 2,
                enabled: true,
                log: true,
                action: Action::Allow,
                source: Selector::new(
                    [source.id, other_source.id],
                    BTreeMap::from([("team".into(), "blue".into())]),
                    vec!["10.10.0.0/24".parse().unwrap()],
                ),
                destination: Selector::new(
                    [destination.id],
                    BTreeMap::from([("role".into(), "db".into())]),
                    vec!["10.10.0.0/28".parse().unwrap()],
                ),
                protocol: PolicyProtocol::Any,
                destination_ports: Vec::new(),
            },
        ],
    );
    let decision = policy.decide_initiation(&source, &destination, IpProtocol::new(132), None);
    assert_eq!(decision.action, Action::Allow);
    assert_eq!(decision.rule_id, Some(allow_unknown));
    assert!(decision.log);

    let wrong_label = PeerDescriptor {
        labels: BTreeMap::from([("team".into(), "red".into())]),
        ..source.clone()
    };
    assert_eq!(
        policy
            .decide_initiation(&wrong_label, &destination, IpProtocol::new(132), None)
            .action,
        Action::Deny
    );

    let tcp = Policy::new(
        2,
        Action::Deny,
        vec![Rule {
            id: rule_id(21),
            priority: 1,
            enabled: true,
            log: false,
            action: Action::Allow,
            source: Selector::any(),
            destination: Selector::any(),
            protocol: PolicyProtocol::Tcp,
            destination_ports: Vec::new(),
        }],
    );
    assert_eq!(
        tcp.decide_initiation(&source, &destination, IpProtocol::TCP, Some(65_535))
            .action,
        Action::Allow
    );
}

#[test]
fn equal_priority_deny_precedes_allow_before_rule_id_order() {
    let source = peer(1, [10, 11, 0, 2], ("team", "blue"));
    let destination = peer(2, [10, 11, 0, 3], ("role", "db"));
    let policy = Policy::new(
        1,
        Action::Allow,
        vec![
            Rule {
                id: rule_id(1),
                priority: 7,
                enabled: true,
                log: false,
                action: Action::Allow,
                source: Selector::any(),
                destination: Selector::any(),
                protocol: PolicyProtocol::Tcp,
                destination_ports: Vec::new(),
            },
            Rule {
                id: rule_id(250),
                priority: 7,
                enabled: true,
                log: false,
                action: Action::Deny,
                source: Selector::any(),
                destination: Selector::any(),
                protocol: PolicyProtocol::Tcp,
                destination_ports: Vec::new(),
            },
        ],
    );
    assert_eq!(
        policy
            .decide_initiation(&source, &destination, IpProtocol::TCP, Some(443))
            .action,
        Action::Deny
    );
}
