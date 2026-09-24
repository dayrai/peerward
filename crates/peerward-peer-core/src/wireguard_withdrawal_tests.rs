use super::*;

#[test]
fn removing_a_binding_keeps_the_former_gateway_lan_local_without_authorizing_it() {
    let f = Fixture::new();
    let client = PeerId::new();
    let gateway = PeerId::new();
    let mut config = super::resource_config(f.mesh, client, gateway);
    let target = config.resources[0].definition.target.clone();
    config.bindings.clear();
    config.advertisements.clear();
    config
        .capture_exclusions
        .push(peerward_management::ProviderCaptureExclusion {
            target,
            providers: [gateway].into(),
        });
    config.validate().unwrap();
    let preferences = peerward_management::ClientPreferences::default();
    assert!(
        config
            .private_capture_routes(gateway, &preferences)
            .is_empty()
    );
    assert!(
        !config
            .private_capture_routes(client, &preferences)
            .is_empty()
    );
    let credential = f.credential(client, 10);
    let mut runtime = f.runtime(credential.clone(), 10);
    runtime
        .install_directory(
            &f.signed(
                1,
                vec![
                    f.entry(&credential, "10.0.0.1"),
                    f.entry(&f.credential(gateway, 20), "10.0.0.2"),
                ],
            ),
            UnixTime(10),
        )
        .unwrap();
    runtime.install_policy(&f.policy(1, false)).unwrap();
    f.authorize_resources(&mut runtime, config);
    let mut packet = udp(1, 2, 4242, 10);
    packet[16..20].copy_from_slice(&[192, 168, 45, 50]);
    checksum(&mut packet);
    assert!(
        runtime
            .send_tunnel(&packet, UnixTime(10), Instant::now())
            .is_err(),
        "capture history cannot become a provider grant"
    );
}

#[test]
fn withdrawn_address_is_captured_and_denied_even_under_a_broader_allowed_resource() {
    let f = Fixture::new();
    let client = PeerId::new();
    let gateway = PeerId::new();
    let credential = f.credential(client, 10);
    let mut runtime = f.runtime(credential.clone(), 10);
    runtime
        .install_directory(
            &f.signed(
                1,
                vec![
                    f.entry(&credential, "10.0.0.1"),
                    f.entry(&f.credential(gateway, 20), "10.0.0.2"),
                ],
            ),
            UnixTime(10),
        )
        .unwrap();
    runtime.install_policy(&f.policy(1, false)).unwrap();
    let mut config = super::resource_config(f.mesh, client, gateway);
    let withdrawn = config.resources[0].definition.target.clone();
    if let peerward_management::ResourceTarget::Subnet { prefix, .. } =
        &mut config.resources[0].definition.target
    {
        *prefix = "192.168.45.0/24".parse().unwrap();
    }
    config
        .withdrawals
        .push(peerward_management::ResourceWithdrawal {
            target: withdrawn,
            providers: [gateway].into(),
        });
    let capture =
        config.private_capture_routes(client, &peerward_management::ClientPreferences::default());
    assert!(capture.contains(&"192.168.45.50/32".parse().unwrap()));
    assert!(
        config
            .private_capture_routes(gateway, &peerward_management::ClientPreferences::default())
            .is_empty(),
        "the former gateway must not capture its local LAN after a target change"
    );
    f.authorize_resources(&mut runtime, config);
    let mut packet = udp(1, 2, 4242, 10);
    packet[16..20].copy_from_slice(&[192, 168, 45, 50]);
    checksum(&mut packet);
    assert!(matches!(
        runtime.send_tunnel(&packet, UnixTime(10), Instant::now()),
        Err(PeerError::PolicyDenied)
    ));
    runtime.set_resource_platform_ready(false);
    packet[19] = 51;
    checksum(&mut packet);
    assert!(matches!(
        runtime.send_tunnel(&packet, UnixTime(10), Instant::now()),
        Err(PeerError::PolicyDenied)
    ));
    runtime.set_resource_platform_ready(true);
    assert!(
        runtime
            .send_tunnel(&packet, UnixTime(10), Instant::now())
            .is_ok()
    );
    assert!(
        runtime
            .dns_requires_tunnel("192.168.45.50".parse().unwrap(), UnixTime(10))
            .unwrap()
    );
}

#[test]
fn lease_renewal_preserves_queues_but_duration_change_fences_them() {
    let f = Fixture::new();
    let local = PeerId::new();
    let remote = PeerId::new();
    let credential = f.credential(local, 10);
    let mut runtime = f.runtime(credential.clone(), 10);
    runtime
        .install_directory(
            &f.signed(
                1,
                vec![
                    f.entry(&credential, "10.0.0.1"),
                    f.entry(&f.credential(remote, 20), "10.0.0.2"),
                ],
            ),
            UnixTime(10),
        )
        .unwrap();
    runtime.install_policy(&f.policy(1, true)).unwrap();
    let mut delivery = f.authorize_configuration(
        &mut runtime,
        peerward_management::ResourceConfiguration::default(),
        vec![],
    );
    let output = runtime
        .send_tunnel(&udp(1, 2, 4242, 10), UnixTime(10), Instant::now())
        .unwrap();
    let stamp = output
        .iter()
        .find_map(|output| match output {
            WireguardOutput::Network { authorization, .. } => Some(*authorization),
            WireguardOutput::Tunnel { .. } => None,
        })
        .unwrap();
    assert!(runtime.pending_bytes() > 0);
    for (sequence, duration) in [(2, 900), (3, 300)] {
        let mut lease = delivery.lease.lease.clone();
        lease.sequence = sequence;
        lease.issued_at = 10 + sequence;
        lease.valid_until = lease.issued_at + duration;
        delivery.lease = f.signer.sign_lease(lease).unwrap();
        runtime
            .install_configuration(delivery.clone(), UnixTime(10 + sequence), Instant::now())
            .unwrap();
        assert_eq!(
            runtime.delivery_current(stamp, UnixTime(10 + sequence)),
            duration == 900
        );
        assert_eq!(runtime.pending_bytes() > 0, duration == 900);
    }
}

#[test]
fn collection_membership_withdrawal_discards_encrypted_returns_and_queued_output() {
    use peerward_management::{CollectionKind, ResolvedCollection};
    let f = Fixture::new();
    let client = PeerId::new();
    let gateway = PeerId::new();
    let ca = f.credential(client, 10);
    let cb = f.credential(gateway, 20);
    let directory = f.signed(1, vec![f.entry(&ca, "10.0.0.1"), f.entry(&cb, "10.0.0.2")]);
    let mut a = f.runtime(ca, 10);
    let mut b = f.runtime(cb, 20);
    let group = uuid::Uuid::new_v4();
    let mut config = super::resource_config(f.mesh, client, gateway);
    config.rules[0].source.peers.clear();
    config.rules[0].source_collections.insert(group);
    config.collections.push(ResolvedCollection {
        id: group,
        kind: CollectionKind::Devices,
        members: [client.into_uuid()].into(),
    });
    for runtime in [&mut a, &mut b] {
        runtime.install_directory(&directory, UnixTime(10)).unwrap();
        runtime.install_policy(&f.policy(1, false)).unwrap();
        f.authorize_resources(runtime, config.clone());
    }
    let now = Instant::now();
    let mut request = udp(1, 2, 4242, 10);
    request[16..20].copy_from_slice(&[192, 168, 45, 50]);
    checksum(&mut request);
    let first = a.send_tunnel(&request, UnixTime(10), now).unwrap();
    assert_eq!(
        relay_exchange(&mut a, &mut b, client, gateway, first, now),
        vec![request.clone()]
    );
    let mut reply = udp(2, 1, 1234, 10);
    reply[12..16].copy_from_slice(&[192, 168, 45, 50]);
    reply[20..22].copy_from_slice(&4242u16.to_be_bytes());
    checksum(&mut reply);
    let old_response = b.send_tunnel(&reply, UnixTime(10), now).unwrap();
    let stamp = old_response
        .iter()
        .find_map(|output| match output {
            WireguardOutput::Network { authorization, .. } => Some(*authorization),
            WireguardOutput::Tunnel { .. } => None,
        })
        .unwrap();
    // The resource, rule, approved provider and lease duration remain unchanged.
    // Only the signed collection membership withdraws this client's access.
    config.collections[0].members.clear();
    for runtime in [&mut a, &mut b] {
        f.authorize_resources(runtime, config.clone());
    }
    assert!(!b.delivery_current(stamp, UnixTime(10)));
    assert!(b.send_tunnel(&reply, UnixTime(10), now).is_err());
    assert!(a.send_tunnel(&request, UnixTime(10), now).is_err());
    for output in old_response {
        if let WireguardOutput::Network { packet, .. } = output {
            let result = a.receive(WireguardIngress::Relay(gateway), &packet, UnixTime(10), now);
            assert!(
                result.is_err()
                    || !result
                        .unwrap()
                        .iter()
                        .any(|output| matches!(output, WireguardOutput::Tunnel { .. }))
            );
        }
    }
}
