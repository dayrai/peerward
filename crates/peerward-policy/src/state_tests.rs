use super::*;

#[test]
fn bounded_reclamation_never_keeps_expired_return_traffic_authorized() {
    let source = peer(1, [10, 0, 0, 1], ("team", "blue"));
    let destination = peer(2, [10, 0, 0, 2], ("team", "blue"));
    let mut evaluator = Evaluator::new(mesh(1), Policy::new(1, Action::Allow, vec![]), 10, 1, 0);
    let mut packet = Packet {
        mesh_id: mesh(1),
        source: &source,
        destination: &destination,
        flow: flow(source.address, destination.address, 443),
        initiating: true,
        related_flow: None,
        fragment_of: None,
    };
    for port in 1..=10 {
        packet.flow.source_port = Some(port);
        assert_eq!(evaluator.evaluate(&packet, 1).action, Action::Allow);
    }
    packet.initiating = false;
    assert_eq!(evaluator.evaluate(&packet, 301).action, Action::Deny);
    // One reclaimed entry plus exact lookup expiry, with other expired entries queued.
    assert_eq!(evaluator.state_len(), 8);
    assert_eq!(evaluator.state_expirations.len(), 8);
    assert_eq!(evaluator.state_recency.len(), 8);
}

#[test]
fn refreshing_a_flow_keeps_indexes_bounded_and_protects_it_from_lru_eviction() {
    let mut evaluator = Evaluator::new(mesh(1), Policy::new(1, Action::Allow, vec![]), 2, 1, 0);
    let oldest = flow(
        "10.0.0.1".parse().unwrap(),
        "10.0.0.2".parse().unwrap(),
        443,
    );
    let untouched = FlowKey {
        destination_port: Some(444),
        ..oldest
    };
    let new = FlowKey {
        destination_port: Some(445),
        ..oldest
    };
    evaluator.insert_state(oldest, 1);
    evaluator.insert_state(untouched, 2);
    for now in 3..10_000 {
        assert!(evaluator.state_valid(&oldest, now, true));
        assert_eq!(evaluator.state_expirations.len(), 2);
        assert_eq!(evaluator.state_recency.len(), 2);
    }
    evaluator.insert_state(new, 10_000);
    assert!(evaluator.state_valid(&oldest, 10_000, false));
    assert!(!evaluator.state_valid(&untouched, 10_000, false));
    assert!(evaluator.state_valid(&new, 10_000, false));
    // Reversed time must neither shorten authorization nor duplicate index records.
    assert!(evaluator.state_valid(&new, 1, true));
    assert_eq!(evaluator.states[&new].touched_at, 10_000);
    assert_eq!(evaluator.state_expirations.len(), 2);
    evaluator
        .replace_policy(Policy::new(2, Action::Deny, vec![]))
        .unwrap();
    assert_eq!(evaluator.state_len(), 0);
    assert!(evaluator.state_expirations.is_empty());
    assert!(evaluator.state_recency.is_empty());
}
