use super::*;

#[test]
fn flow_refresh_forget_and_policy_replacement_keep_expiry_storage_bounded() {
    let firewall = Firewall::new(1, Action::Allow, vec![], 2, 1);
    let packet = parse_packet(&ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2])).unwrap();
    let flow = FlowKey::from_packet(&packet).unwrap();
    for now in 1..10_000 {
        assert_eq!(firewall.evaluate(&packet, now).action, Action::Allow);
        let state = firewall.shards[0].lock().unwrap();
        assert_eq!(state.flows.len(), 1);
        assert_eq!(state.flow_expirations.len(), 1);
    }
    firewall.forget_flow(&flow.reverse());
    assert_eq!(firewall.state_len(), 0);
    assert!(
        firewall.shards[0]
            .lock()
            .unwrap()
            .flow_expirations
            .is_empty()
    );
    firewall.evaluate(&packet, 10_000);
    firewall.invalidate_state();
    assert_eq!(firewall.state_len(), 0);
    assert!(
        firewall.shards[0]
            .lock()
            .unwrap()
            .flow_expirations
            .is_empty()
    );
}

#[test]
fn fragment_replacement_does_not_evict_an_unrelated_association_or_retain_old_expiries() {
    let firewall = Firewall::new(1, Action::Deny, vec![], 2, 1);
    let mut packet = parse_packet(&ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2])).unwrap();
    packet.fragment = Some(Fragment {
        identification: 1,
        offset: 0,
        more: true,
    });
    let mut other = packet.clone();
    other.fragment.as_mut().unwrap().identification = 2;
    firewall.insert_fragment(&packet, packet.fragment.unwrap(), Action::Allow, None, 1);
    firewall.insert_fragment(&other, other.fragment.unwrap(), Action::Allow, None, 1);
    for now in 2..100 {
        firewall.insert_fragment(&packet, packet.fragment.unwrap(), Action::Allow, None, now);
        let state = firewall.shards[0].lock().unwrap();
        assert_eq!(state.fragments.len(), 2);
        assert_eq!(state.fragment_expirations.len(), 2);
        assert!(
            state
                .fragments
                .contains_key(&fragment_key(&other, other.fragment.unwrap()))
        );
    }
    let later = Fragment {
        offset: 8,
        ..packet.fragment.unwrap()
    };
    assert_eq!(
        firewall.evaluate_later_fragment(&packet, later, 113).action,
        Action::Allow
    );
    assert_eq!(
        firewall.evaluate_later_fragment(&packet, later, 114).action,
        Action::Deny
    );
    firewall.invalidate_state();
    let state = firewall.shards[0].lock().unwrap();
    assert!(state.fragments.is_empty());
    assert!(state.fragment_expirations.is_empty());
}

#[test]
fn forgetting_ipv6_flow_also_revokes_its_protocol_independent_fragment_identity() {
    let firewall = Firewall::new(1, Action::Deny, vec![], 4, 1);
    let mut packet = parse_packet(&ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2])).unwrap();
    packet.source = "fd00::1".parse().unwrap();
    packet.destination = "fd00::2".parse().unwrap();
    packet.fragment = Some(Fragment {
        identification: 7,
        offset: 0,
        more: true,
    });
    let flow = FlowKey::from_packet(&packet).unwrap();
    assert_eq!(
        firewall
            .evaluate_with_policy(&packet, 1, |_| (Action::Allow, None))
            .action,
        Action::Allow
    );
    packet.fragment.as_mut().unwrap().offset = 8;
    assert_eq!(firewall.evaluate(&packet, 2).action, Action::Allow);
    firewall.forget_flow(&flow);
    assert_eq!(firewall.evaluate(&packet, 3).action, Action::Deny);
    let state = firewall.shards[0].lock().unwrap();
    assert!(state.flows.is_empty());
    assert!(state.flow_expirations.is_empty());
    assert!(state.fragments.is_empty());
    assert!(state.fragment_expirations.is_empty());
}
