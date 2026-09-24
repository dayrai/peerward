use super::*;

#[test]
fn failed_direct_probes_are_dropped_but_application_ciphertext_can_use_relay() {
    let fixture = crate::wireguard_tests::Fixture::new();
    let owner = fixture.mobile();
    let (_carrier, _) = fixture.carrier(&owner);
    let mut owner = owner.lock().unwrap();
    let now = UnixTime(crate::wall_clock_seconds());
    let clock = Instant::now();
    let authorization = (0..64)
        .find(|epoch| owner.core.delivery_current(*epoch, now))
        .unwrap();
    for path_probe in [true, false] {
        owner
            .enqueue(vec![WireguardOutput::Network {
                local_key: [1; 32],
                peer: Some(PeerId::new()),
                packet: vec![42; 1312],
                reply_to: Some(WireguardIngress::Direct("192.0.2.1:1234".parse().unwrap())),
                path_probe,
                authorization,
                expires: clock + std::time::Duration::from_secs(3),
            }])
            .unwrap();
        let ticket = owner.poll(now, clock).remove(0);
        assert!(
            !owner
                .deliver_direct(ticket.id, now, clock, |_, packet| {
                    assert_eq!(packet, &[42; 1312]);
                    false
                })
                .unwrap()
        );
        let fallback = owner.poll(now, clock);
        if path_probe {
            assert!(fallback.is_empty());
            assert_eq!(owner.output_bytes, 0);
            assert!(owner.outputs.is_empty());
        } else {
            assert_eq!(fallback.len(), 1);
            assert!(fallback[0].endpoint.is_none());
            assert_eq!(owner.output_bytes, 1312);
            assert!(
                owner
                    .deliver(fallback[0].id, now, clock, |output| {
                        assert!(matches!(output, WireguardOutput::Network {
                    packet, reply_to: Some(WireguardIngress::Relay(_)), ..
                } if packet == &[42; 1312]));
                        Ok(())
                    })
                    .unwrap()
            );
            assert_eq!(owner.output_bytes, 0);
        }
    }
}
