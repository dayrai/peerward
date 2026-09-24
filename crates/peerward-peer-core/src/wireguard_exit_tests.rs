use super::*;

#[test]
fn explicit_exit_selection_preserves_provider_identity_and_excludes_metadata() {
    let f = Fixture::new();
    let client = PeerId::new();
    let gateway = PeerId::new();
    let other = PeerId::new();
    let ca = f.credential(client, 10);
    let cb = f.credential(gateway, 20);
    let directory = f.signed(
        1,
        vec![
            f.entry(&ca, "10.0.0.1"),
            f.entry(&cb, "10.0.0.2"),
            f.entry(&f.credential(other, 30), "10.0.0.3"),
        ],
    );
    let mut configuration = resource_config(f.mesh, client, gateway);
    configuration.resources[0].definition.target = ResourceTarget::Internet {
        ipv4: true,
        ipv6: false,
    };
    let exit = configuration.resources[0].id;
    let mut alternative = resource_config(f.mesh, client, other);
    alternative.resources[0].definition.target = ResourceTarget::Internet {
        ipv4: true,
        ipv6: true,
    };
    configuration.resources.extend(alternative.resources);
    configuration.bindings.extend(alternative.bindings);
    configuration
        .advertisements
        .extend(alternative.advertisements);
    configuration.rules.extend(alternative.rules);
    // A withdrawn, different exit is not a global Internet tombstone.
    configuration
        .withdrawals
        .push(peerward_management::ResourceWithdrawal {
            target: ResourceTarget::Internet {
                ipv4: true,
                ipv6: true,
            },
            providers: [gateway].into(),
        });
    let mut a = f.runtime(ca, 10);
    let mut b = f.runtime(cb, 20);
    for runtime in [&mut a, &mut b] {
        runtime.install_directory(&directory, UnixTime(10)).unwrap();
        runtime.install_policy(&f.policy(1, false)).unwrap();
        f.authorize_resources(runtime, configuration.clone());
    }
    let mut packet = udp(1, 2, 4242, 10);
    packet[16..20].copy_from_slice(&[8, 8, 8, 8]);
    checksum(&mut packet);
    let now = Instant::now();
    assert!(
        a.send_tunnel(&packet, UnixTime(10), now).is_err(),
        "approval does not select an exit"
    );
    let preferences = ClientPreferences {
        exit_resource: Some(exit),
        ..ClientPreferences::default()
    };
    a.set_preferences(preferences.clone()).unwrap();
    let capture = configuration.capture_routes(client, &preferences);
    assert!(capture.contains(&"0.0.0.0/0".parse().unwrap()));
    assert!(
        capture.contains(&"::/0".parse().unwrap()),
        "unsupported IPv6 must be captured for rejection"
    );
    let initial = a.send_tunnel(&packet, UnixTime(10), now).unwrap();
    assert_eq!(
        relay_exchange(&mut a, &mut b, client, gateway, initial, now),
        vec![packet.clone()]
    );
    for target in [[169, 254, 169, 254], [192, 168, 1, 1], [100, 100, 100, 200]] {
        packet[16..20].copy_from_slice(&target);
        checksum(&mut packet);
        assert!(a.send_tunnel(&packet, UnixTime(10), now).is_err());
    }
    assert!(
        a.set_preferences(ClientPreferences {
            accept_dns: false,
            ..preferences
        })
        .is_err()
    );
    a.set_preferences(ClientPreferences::default()).unwrap();
    packet[16..20].copy_from_slice(&[8, 8, 8, 8]);
    checksum(&mut packet);
    assert!(a.send_tunnel(&packet, UnixTime(10), now).is_err());
    assert_eq!(a.pending_bytes(), 0);
}
