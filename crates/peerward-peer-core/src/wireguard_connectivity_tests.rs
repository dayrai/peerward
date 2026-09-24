use super::*;

fn candidates(
    paths: &mut Connectivity,
    local: Key,
    remote: Key,
    endpoints: Vec<SocketAddr>,
    now: Instant,
) {
    paths
        .receive(
            local,
            remote,
            Coordination {
                generation: 1,
                transaction: [2; 16],
                message: Message::Candidates(endpoints),
            },
            None,
            now,
        )
        .unwrap();
}

#[test]
fn only_exact_direct_round_trips_validate_a_path_and_failover_is_bounded() {
    let now = Instant::now();
    let local = [1; 32];
    let remote = [2; 32];
    let endpoint = "192.0.2.1:51820".parse().unwrap();
    let mut paths = Connectivity::new(7);
    candidates(&mut paths, local, remote, vec![endpoint], now);
    assert_eq!(paths.endpoint(&remote, now, 96), None);
    let probe = paths
        .poll(now)
        .into_iter()
        .find(|send| send.endpoint.is_some())
        .unwrap();
    let ack = Coordination {
        message: Message::ProbeAck,
        ..probe.coordination
    };
    assert!(
        paths
            .receive(local, remote, ack.clone(), None, now)
            .is_err()
    );
    assert!(
        paths
            .receive(
                local,
                remote,
                ack.clone(),
                Some("192.0.2.2:51820".parse().unwrap()),
                now
            )
            .is_err()
    );
    assert_eq!(paths.endpoint(&remote, now, 96), None);
    paths
        .receive(
            local,
            remote,
            ack.clone(),
            Some(endpoint),
            now + Duration::from_millis(10),
        )
        .unwrap();
    assert_eq!(
        paths.endpoint(&remote, now + Duration::from_millis(20), 96),
        Some(endpoint)
    );
    assert_eq!(
        paths.endpoint(&remote, now + Duration::from_millis(20), 1280),
        None
    );
    assert!(
        paths
            .receive(local, remote, ack.clone(), Some(endpoint), now)
            .is_err()
    );
    // Relay application traffic can record activity, but cannot extend confirmed direct health.
    paths.touch(local, remote, now + Duration::from_secs(3));
    assert_eq!(
        paths.endpoint(&remote, now + Duration::from_millis(3010), 100),
        None
    );
    paths.update(Vec::new()).unwrap();
    assert!(
        paths
            .receive(local, remote, ack, Some(endpoint), now)
            .is_err()
    );
    assert_eq!(paths.endpoint(&remote, now, 96), None);
}

#[test]
fn checks_obey_peer_mesh_budgets_expire_and_exact_revocation_releases_state() {
    let now = Instant::now();
    let mut paths = Connectivity::new(1);
    let endpoints: Vec<_> = (10000..10032)
        .map(|port| SocketAddr::new("192.0.2.1".parse().unwrap(), port))
        .collect();
    for remote in 2..100 {
        candidates(&mut paths, [1; 32], [remote; 32], endpoints.clone(), now);
    }
    paths.poll(now);
    let pending: usize = paths
        .peers
        .values()
        .map(|track| {
            assert!(track.pending.len() <= 4);
            track.pending.len()
        })
        .sum();
    assert!(pending <= MESH_CHECKS);
    paths.retain(|_, remote| remote != &[2; 32]);
    assert!(!paths.peers.contains_key(&[2; 32]));
    assert!(paths.peers.contains_key(&[3; 32]));
    paths.poll(now + Duration::from_secs(2));
    assert!(
        paths
            .peers
            .values()
            .flat_map(|track| track.pending.values())
            .all(|check| check.sent > now)
    );
    paths.clear();
    assert!(paths.peers.is_empty());
}

#[test]
fn idle_probes_do_not_count_as_application_activity_and_candidates_do_not_rekey() {
    let now = Instant::now();
    let mut paths = Connectivity::new(1);
    let endpoint = "192.0.2.1:51820".parse().unwrap();
    candidates(&mut paths, [1; 32], [2; 32], vec![endpoint], now);
    for seconds in 1..40 {
        paths
            .receive(
                [1; 32],
                [2; 32],
                Coordination {
                    generation: 1,
                    transaction: [3; 16],
                    message: Message::Probe,
                },
                Some(endpoint),
                now + Duration::from_secs(seconds),
            )
            .unwrap();
    }
    assert_eq!(paths.peers[&[2; 32]].last_activity, now);
    let later = now + Duration::from_secs(40);
    assert_eq!(
        paths
            .poll(later)
            .iter()
            .filter(|send| send.endpoint.is_some())
            .count(),
        1
    );
    assert!(
        paths
            .poll(later + Duration::from_secs(2))
            .iter()
            .all(|send| send.endpoint.is_none())
    );
}

#[test]
fn healthy_path_checks_alternatives_and_loss_can_outweigh_lower_rtt() {
    let start = Instant::now();
    let local = [1; 32];
    let remote = [2; 32];
    let fast: SocketAddr = "192.0.2.1:51820".parse().unwrap();
    let reliable: SocketAddr = "192.0.2.2:51820".parse().unwrap();
    let mut paths = Connectivity::new(1);
    candidates(&mut paths, local, remote, vec![fast, reliable], start);
    let mut alternatives = 0;
    for second in 0..=18 {
        let now = start + Duration::from_secs(second);
        paths.touch(local, remote, now);
        for send in paths.poll(now) {
            if send.coordination.message != Message::Probe {
                continue;
            }
            let endpoint = send.endpoint.unwrap();
            if second > 0 && endpoint == reliable {
                alternatives += 1;
            }
            // Fast path stays alive (one reply every three seconds) but loses 2/3 probes.
            if endpoint == fast && second % 3 != 0 {
                continue;
            }
            let rtt = Duration::from_millis(if endpoint == fast { 5 } else { 40 });
            paths
                .receive(
                    local,
                    remote,
                    Coordination {
                        message: Message::ProbeAck,
                        ..send.coordination
                    },
                    send.endpoint,
                    now + rtt,
                )
                .unwrap();
        }
        if second < 5 {
            assert_eq!(
                paths.peers[&remote]
                    .verified
                    .as_ref()
                    .unwrap()
                    .route
                    .endpoint,
                fast,
                "a healthy selection is protected by switching hysteresis"
            );
        }
    }
    assert!(alternatives > 0);
    assert_eq!(
        paths.peers[&remote]
            .verified
            .as_ref()
            .unwrap()
            .route
            .endpoint,
        reliable
    );
    assert!(
        paths.peers[&remote].quality[&Route {
            endpoint: fast,
            source: None
        }]
            .score()
            > paths.peers[&remote].quality[&Route {
                endpoint: reliable,
                source: None
            }]
                .score()
    );
    paths.update(Vec::new()).unwrap();
    assert!(paths.peers[&remote].quality.is_empty());
}

#[test]
fn multiple_local_paths_are_paired_bounded_and_acknowledged_on_the_exact_socket() {
    let now = Instant::now();
    let local = [1; 32];
    let remote = [2; 32];
    let local_paths: Vec<SocketAddr> = (1..=8)
        .map(|i| format!("192.0.2.{i}:51820").parse().unwrap())
        .collect();
    let remote_paths: Vec<SocketAddr> = (1..=32)
        .map(|i| format!("198.51.100.{i}:51820").parse().unwrap())
        .collect();
    let mut paths = Connectivity::new(1);
    paths
        .update_paths(local_paths.clone(), local_paths.clone())
        .unwrap();
    candidates(&mut paths, local, remote, remote_paths.clone(), now);
    let pairs = &paths.peers[&remote].pairs;
    assert_eq!(pairs.len(), 128);
    assert!(
        remote_paths
            .iter()
            .all(|remote| pairs.iter().any(|pair| pair.endpoint == *remote))
    );
    assert!(
        local_paths
            .iter()
            .all(|local| pairs.iter().any(|pair| pair.source == Some(*local)))
    );
    let sends = paths.poll(now);
    let check = sends.iter().find(|send| send.endpoint.is_some()).unwrap();
    let ack = Coordination {
        message: Message::ProbeAck,
        ..check.coordination.clone()
    };
    let wrong = local_paths
        .iter()
        .copied()
        .find(|local| Some(*local) != check.source)
        .unwrap();
    assert!(
        paths
            .receive_on(local, remote, ack.clone(), check.endpoint, Some(wrong), now)
            .is_err()
    );
    assert!(
        paths
            .receive_on(local, remote, ack.clone(), check.endpoint, None, now)
            .is_err()
    );
    paths
        .receive_on(
            local,
            remote,
            ack,
            check.endpoint,
            check.source,
            now + Duration::from_millis(5),
        )
        .unwrap();
    assert_eq!(
        paths
            .route(&remote, now + Duration::from_millis(6), 96)
            .unwrap()
            .source,
        check.source
    );
    paths.update_paths(Vec::new(), Vec::new()).unwrap();
    assert!(paths.route(&remote, now, 96).is_none());
    assert!(
        paths
            .poll(now + Duration::from_secs(1))
            .iter()
            .all(|send| send.endpoint.is_none())
    );
}

#[test]
fn pairs_never_send_ipv4_destinations_through_ipv6_sockets() {
    let local: Vec<SocketAddr> = ["192.0.2.1:51820", "[2001:db8::1]:51820"]
        .into_iter()
        .map(|v| v.parse().unwrap())
        .collect();
    let remote: Vec<SocketAddr> = ["198.51.100.1:51820", "[2001:db8:1::1]:51820"]
        .into_iter()
        .map(|v| v.parse().unwrap())
        .collect();
    let paired = pairs(Some(&local), &remote);
    assert_eq!(paired.len(), 2);
    assert!(
        paired
            .iter()
            .all(|pair| pair.source.unwrap().is_ipv4() == pair.endpoint.is_ipv4())
    );
}
