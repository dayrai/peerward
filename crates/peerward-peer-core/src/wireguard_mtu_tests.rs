use super::*;

fn acknowledge(paths: &mut Connectivity, send: &Send, now: Instant) {
    paths
        .receive(
            send.local,
            send.remote,
            Coordination {
                message: Message::ProbeAck,
                ..send.coordination.clone()
            },
            send.endpoint,
            now,
        )
        .unwrap();
}

fn ready(now: Instant) -> Connectivity {
    let mut paths = Connectivity::new(7);
    paths
        .receive(
            [1; 32],
            [2; 32],
            Coordination {
                generation: 1,
                transaction: [2; 16],
                message: Message::Candidates(vec!["192.0.2.1:1234".parse().unwrap()]),
            },
            None,
            now,
        )
        .unwrap();
    let first = paths
        .poll(now)
        .into_iter()
        .find(|send| send.endpoint.is_some())
        .unwrap();
    acknowledge(&mut paths, &first, now + Duration::from_millis(10));
    paths
}

#[test]
fn mtu_requires_exact_direct_proof_and_small_health_does_not_refresh_it() {
    let start = Instant::now();
    let mut paths = ready(start);
    let now = start + Duration::from_secs(1);
    let sends = paths.poll(now);
    let probe = sends
        .iter()
        .find(|send| matches!(send.coordination.message, Message::MtuProbe(_)))
        .unwrap();
    let ack = Coordination {
        message: Message::ProbeAck,
        ..probe.coordination.clone()
    };
    for source in [None, Some("192.0.2.2:1234".parse().unwrap())] {
        assert!(
            paths
                .receive(probe.local, probe.remote, ack.clone(), source, now)
                .is_err()
        );
        assert_eq!(paths.endpoint(&probe.remote, now, 1312), None);
    }
    acknowledge(&mut paths, probe, now + Duration::from_millis(10));
    assert!(
        paths
            .endpoint(&probe.remote, now + Duration::from_millis(20), 1312)
            .is_some()
    );
    assert_eq!(paths.endpoint(&probe.remote, now, 1313), None);
    assert!(
        paths
            .receive(probe.local, probe.remote, ack.clone(), probe.endpoint, now)
            .is_err()
    );
    for seconds in 2..=5 {
        let later = start + Duration::from_secs(seconds);
        for send in paths.poll(later) {
            if send.coordination.message == Message::Probe {
                acknowledge(&mut paths, &send, later);
            }
        }
    }
    let later = start + Duration::from_secs(5);
    assert!(paths.endpoint(&probe.remote, later, 96).is_some());
    assert_eq!(paths.endpoint(&probe.remote, later, 1312), None);
    paths.update(Vec::new()).unwrap();
    assert!(
        paths
            .receive(probe.local, probe.remote, ack, probe.endpoint, later)
            .is_err()
    );
    assert_eq!(paths.endpoint(&probe.remote, later, 96), None);
}

#[test]
fn mtu_blackhole_searches_smaller_sizes_and_reprobes_after_path_improvement() {
    let start = Instant::now();
    let mut paths = ready(start);
    let mut sizes = Vec::new();
    let mut maximum = 960;
    for seconds in 1..=90 {
        let now = start + Duration::from_secs(seconds);
        paths.touch([1; 32], [2; 32], now);
        if seconds == 40 {
            maximum = 1312;
        }
        for send in paths.poll(now) {
            match send.coordination.message {
                Message::MtuProbe(padding) => {
                    let size = 32 + 56 + usize::from(padding);
                    sizes.push(size);
                    if size <= maximum {
                        acknowledge(&mut paths, &send, now);
                    }
                }
                Message::Probe => acknowledge(&mut paths, &send, now),
                _ => (),
            }
        }
        assert!(paths.endpoint(&[2; 32], now, 96).is_some());
        assert_eq!(paths.endpoint(&[2; 32], now, maximum + 1), None);
        assert!(paths.peers[&[2; 32]].pending.len() <= 4);
        if seconds == 39 {
            assert!(
                paths.endpoint(&[2; 32], now, 960).is_some(),
                "search must converge to the usable datagram size"
            );
        }
    }
    assert_eq!(&sizes[..3], [1312; 3]);
    assert!(sizes.iter().any(|size| *size < 960));
    assert!(
        paths
            .endpoint(&[2; 32], start + Duration::from_secs(90), 1312)
            .is_some()
    );
}

#[test]
fn probe_limits_include_wireguard_padding_for_odd_mtu_and_both_ip_families() {
    for mtu in [1280, 1281, 9000] {
        for ipv6 in [false, true] {
            let (message, limit) = mtu::probe(mtu, ipv6).unwrap();
            let (source, destination) = if ipv6 {
                ("fd00::1", "fd00::2")
            } else {
                ("10.0.0.1", "10.0.0.2")
            };
            let packet = crate::coordination::encode_ip(
                source.parse().unwrap(),
                destination.parse().unwrap(),
                &Coordination {
                    generation: 1,
                    transaction: [1; 16],
                    message,
                },
            )
            .unwrap();
            assert_eq!(packet.len(), mtu);
            assert_eq!(limit, 32 + packet.len());
        }
    }
    assert!(mtu::probe(50, false).is_none());
    assert!(mtu::probe(65535, true).is_none());
}
