use super::*;

#[test]
fn device_conditions_fence_peer_and_lan_flows_until_fresh_evidence_arrives() {
    for lan in [false, true] {
        for restrict_source in [false, true] {
            let f = Fixture::new();
            let client = PeerId::new();
            let gateway = PeerId::new();
            let cc = f.credential(client, 10);
            let gc = f.credential(gateway, 20);
            let directory = f.signed(1, vec![f.entry(&cc, "10.0.0.1"), f.entry(&gc, "10.0.0.2")]);
            let mut a = f.runtime(cc.clone(), 10);
            let mut b = f.runtime(gc.clone(), 20);
            let mut config = resource_config(f.mesh, client, gateway);
            config.admission = AdmissionConfiguration {
                enabled: true,
                peers: [
                    (client, AdmissionDecision::unrestricted()),
                    (gateway, AdmissionDecision::unrestricted()),
                ]
                .into(),
            };
            let restricted = if restrict_source { client } else { gateway };
            config.admission.peers.insert(
                restricted,
                AdmissionDecision {
                    allowed: true,
                    valid_until: Some(20),
                    reasons: vec![],
                },
            );
            for runtime in [&mut a, &mut b] {
                runtime.install_directory(&directory, UnixTime(10)).unwrap();
                runtime.install_policy(&f.policy(1, true)).unwrap();
                f.authorize_resources(runtime, config.clone());
            }
            let mut packet = udp(1, 2, 4242, 10);
            let mut reply = udp(2, 1, 1234, 10);
            reply[20..22].copy_from_slice(&4242_u16.to_be_bytes());
            if lan {
                packet[16..20].copy_from_slice(&[192, 168, 45, 50]);
                reply[12..16].copy_from_slice(&[192, 168, 45, 50]);
            }
            checksum(&mut packet);
            checksum(&mut reply);
            let now = Instant::now();
            let first = a.send_tunnel(&packet, UnixTime(10), now).unwrap();
            assert_eq!(
                relay_exchange(&mut a, &mut b, client, gateway, first, now),
                vec![packet.clone()]
            );
            let first = b.send_tunnel(&reply, UnixTime(10), now).unwrap();
            assert_eq!(
                relay_exchange(&mut b, &mut a, gateway, client, first, now),
                vec![reply.clone()]
            );
            for runtime in [&mut a, &mut b] {
                runtime.tick(UnixTime(20), now).unwrap();
                assert_eq!(runtime.pending_bytes(), 0);
                assert!(
                    !runtime.device_admitted(restricted, UnixTime(10)),
                    "wall rollback cannot undo quarantine"
                );
                assert!(
                    runtime.core_application_receipt(UnixTime(20)).is_some(),
                    "control receipts remain available"
                );
            }
            assert!(a.send_tunnel(&packet, UnixTime(20), now).is_err());
            assert!(b.send_tunnel(&reply, UnixTime(20), now).is_err());
            assert!(a.accepts_carrier(&cc, UnixTime(20)));
            assert!(b.accepts_carrier(&gc, UnixTime(20)));
            config
                .admission
                .peers
                .get_mut(&restricted)
                .unwrap()
                .valid_until = Some(100);
            for runtime in [&mut a, &mut b] {
                f.authorize_resources(runtime, config.clone());
            }
            // Reopening admission does not revive a stale LAN return connection.
            if lan {
                assert!(b.send_tunnel(&reply, UnixTime(20), now).is_err());
            }
            let first = a.send_tunnel(&packet, UnixTime(20), now).unwrap();
            assert_eq!(
                relay_exchange(&mut a, &mut b, client, gateway, first, now),
                vec![packet]
            );
        }
    }
}

#[test]
fn stalled_wall_clock_and_restarts_cannot_extend_device_evidence() {
    let f = Fixture::new();
    let local = PeerId::new();
    let remote = PeerId::new();
    let cc = f.credential(local, 10);
    let directory = f.signed(
        1,
        vec![
            f.entry(&cc, "10.0.0.1"),
            f.entry(&f.credential(remote, 20), "10.0.0.2"),
        ],
    );
    let dir = std::env::temp_dir().join(format!("peerward-device-condition-{}", Uuid::new_v4()));
    let mut config = resource_config(f.mesh, local, remote);
    config.admission = AdmissionConfiguration {
        enabled: true,
        peers: [
            (
                local,
                AdmissionDecision {
                    allowed: true,
                    valid_until: Some(20),
                    reasons: vec![],
                },
            ),
            (remote, AdmissionDecision::unrestricted()),
        ]
        .into(),
    };
    {
        let mut runtime = f.runtime(cc.clone(), 10);
        runtime.enable_checkpoint(&dir, UnixTime(10)).unwrap();
        runtime.install_directory(&directory, UnixTime(10)).unwrap();
        runtime.install_policy(&f.policy(1, true)).unwrap();
        f.authorize_resources(&mut runtime, config.clone());
        runtime.elapse_admission_for_test(11);
        runtime.tick(UnixTime(10), Instant::now()).unwrap();
        assert!(!runtime.device_admitted(local, UnixTime(10)));
    }
    let mut runtime = f.runtime(cc, 10);
    runtime.enable_checkpoint(&dir, UnixTime(10)).unwrap();
    runtime.install_directory(&directory, UnixTime(10)).unwrap();
    runtime.install_policy(&f.policy(1, true)).unwrap();
    f.authorize_resources(&mut runtime, config);
    assert!(!runtime.device_admitted(local, UnixTime(10)));
    assert!(
        runtime
            .send_tunnel(&udp(1, 2, 4242, 10), UnixTime(10), Instant::now())
            .is_err()
    );
    drop(runtime);
    std::fs::remove_dir_all(dir).unwrap();
}
