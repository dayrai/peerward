use super::*;
use peerward_management::*;
use uuid::Uuid;
#[path = "wireguard_alias_tests.rs"]
mod alias_tests;
#[path = "wireguard_device_condition_tests.rs"]
mod device_condition_tests;
#[path = "wireguard_ha_tests.rs"]
mod ha_tests;

fn resource_config(mesh: MeshId, source: PeerId, provider: PeerId) -> ResourceConfiguration {
    let resource = Uuid::new_v4();
    let binding = Uuid::new_v4();
    ResourceConfiguration {
        admission: AdmissionConfiguration::default(),
        collections: vec![],
        withdrawals: vec![],
        capture_exclusions: vec![],
        resources: vec![NetworkResource {
            id: resource,
            mesh_id: mesh,
            version: 1,
            definition: ResourceDefinition {
                name: "printer".into(),
                target: ResourceTarget::Subnet {
                    prefix: "192.168.45.50/32".parse().unwrap(),
                    site_id: Uuid::new_v4(),
                },
                labels: BTreeMap::new(),
                health_probe: None,
            },
        }],
        bindings: vec![GatewayBinding {
            id: binding,
            resource_id: resource,
            peer_id: provider,
            version: 1,
            approved: true,
            priority: 100,
            forwarding: ForwardingMode::Snat,
            return_route_confirmed: false,
            approval_source: ApprovalSource::Manual,
        }],
        advertisements: vec![RouteAdvertisement {
            binding_version: 1,
            binding_id: binding,
            peer_id: provider,
            sequence: 1,
            published: true,
            forwarding_ready: true,
            valid_until: 910,
        }],
        rules: vec![ResourceRule {
            source_collections: std::collections::BTreeSet::new(),
            resource_collections: std::collections::BTreeSet::new(),
            id: Uuid::new_v4(),
            priority: 100,
            enabled: true,
            action: ResourceAction::Allow,
            source: DeviceSelector {
                peers: [source].into(),
                ..DeviceSelector::default()
            },
            resources: [resource].into(),
            providers: std::collections::BTreeSet::default(),
            protocol: 17,
            destination_ports: vec![(4242, 4242)],
            not_after: None,
        }],
    }
}

#[test]
fn encrypted_resource_round_trip_requires_the_approved_provider_and_current_flow() {
    let f = Fixture::new();
    let client = PeerId::new();
    let gateway = PeerId::new();
    let other = PeerId::new();
    let client_credential = f.credential(client, 10);
    let gateway_credential = f.credential(gateway, 20);
    let directory = f.signed(
        1,
        vec![
            f.entry(&client_credential, "10.0.0.1"),
            f.entry(&gateway_credential, "10.0.0.2"),
            f.entry(&f.credential(other, 30), "10.0.0.3"),
        ],
    );
    let mut a = f.runtime(client_credential, 10);
    let mut b = f.runtime(gateway_credential, 20);
    let config = resource_config(f.mesh, client, gateway);
    for runtime in [&mut a, &mut b] {
        runtime.install_directory(&directory, UnixTime(10)).unwrap();
        runtime.install_policy(&f.policy(1, false)).unwrap();
        f.authorize_resources(runtime, config.clone());
    }
    let mut packet = udp(1, 2, 4242, 10);
    packet[16..20].copy_from_slice(&[192, 168, 45, 50]);
    checksum(&mut packet);
    let now = Instant::now();
    let first = a.send_tunnel(&packet, UnixTime(10), now).unwrap();
    assert_eq!(
        relay_exchange(&mut a, &mut b, client, gateway, first, now),
        vec![packet]
    );
    let mut reply = udp(2, 1, 1234, 10);
    reply[12..16].copy_from_slice(&[192, 168, 45, 50]);
    reply[20..22].copy_from_slice(&4242_u16.to_be_bytes());
    checksum(&mut reply);
    let first = b.send_tunnel(&reply, UnixTime(10), now).unwrap();
    assert_eq!(
        relay_exchange(&mut b, &mut a, gateway, client, first, now),
        vec![reply.clone()]
    );
    let mut forged = reply.clone();
    forged[12..16].copy_from_slice(&[10, 0, 0, 3]);
    checksum(&mut forged);
    assert!(
        b.send_tunnel(&forged, UnixTime(10), now).is_err(),
        "gateway cannot impersonate another Peer"
    );
    forged[12..16].copy_from_slice(&[192, 168, 45, 51]);
    checksum(&mut forged);
    assert!(
        b.send_tunnel(&forged, UnixTime(10), now).is_err(),
        "LAN source needs a matching authorized connection"
    );
    let mut withdrawn = config;
    withdrawn.bindings[0].approved = false;
    withdrawn.bindings[0].version += 1;
    f.authorize_resources(&mut b, withdrawn);
    assert!(
        b.send_tunnel(&reply, UnixTime(10), now).is_err(),
        "revoked path cannot retain return state"
    );
}

#[test]
fn lease_expiry_fences_previously_emitted_packets_and_duplicate_lease_cannot_reopen() {
    let f = Fixture::new();
    let client = PeerId::new();
    let remote = PeerId::new();
    let credential = f.credential(client, 10);
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
    f.authorize(&mut runtime);
    let outputs = runtime
        .send_tunnel(&udp(1, 2, 4242, 10), UnixTime(10), Instant::now())
        .unwrap();
    let authorization = outputs
        .iter()
        .find_map(|output| match output {
            WireguardOutput::Network { authorization, .. } => Some(*authorization),
            WireguardOutput::Tunnel { .. } => None,
        })
        .unwrap();
    assert!(runtime.delivery_current(authorization, UnixTime(10)));
    assert!(!runtime.delivery_current(authorization, UnixTime(910)));
    assert_eq!(runtime.pending_bytes(), 0);
    assert!(
        !runtime.local_source_authorized("10.0.0.1".parse().unwrap(), UnixTime(10)),
        "wall rollback cannot revive an expired authorization"
    );
}

#[test]
fn inbound_preference_keeps_local_responses_but_rejects_new_remote_flows() {
    let f = Fixture::new();
    let client = PeerId::new();
    let remote = PeerId::new();
    let credential = f.credential(client, 10);
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
    f.authorize(&mut runtime);
    let policy = runtime.policy();
    let outbound = peerward_dataplane::parse_packet(&udp(1, 2, 4242, 10)).unwrap();
    let mut bytes = udp(2, 1, 1234, 10);
    bytes[20..22].copy_from_slice(&4242u16.to_be_bytes());
    checksum(&mut bytes);
    let reply = peerward_dataplane::parse_packet(&bytes).unwrap();
    assert_eq!(
        policy.evaluate_inbound(&reply, 0, false),
        peerward_dataplane::Action::Deny
    );
    assert_eq!(
        policy.evaluate(&outbound, 0),
        peerward_dataplane::Action::Allow
    );
    assert_eq!(
        policy.evaluate_inbound(&reply, 1, false),
        peerward_dataplane::Action::Allow
    );
    let new_flow = peerward_dataplane::parse_packet(&udp(2, 1, 9000, 10)).unwrap();
    assert_eq!(
        policy.evaluate_inbound(&new_flow, 1, false),
        peerward_dataplane::Action::Deny
    );
    assert_eq!(
        policy.evaluate_inbound(&reply, 100, false),
        peerward_dataplane::Action::Deny
    );
}

#[test]
fn scoped_dns_is_lease_gated_and_cannot_use_another_devices_identity() {
    let f = Fixture::new();
    let client = PeerId::new();
    let other = PeerId::new();
    let credential = f.credential(client, 10);
    let mut runtime = f.runtime(credential.clone(), 10);
    runtime
        .install_directory(
            &f.signed(
                1,
                vec![
                    f.entry(&credential, "10.0.0.1"),
                    f.entry(&f.credential(other, 20), "10.0.0.2"),
                ],
            ),
            UnixTime(10),
        )
        .unwrap();
    runtime.install_policy(&f.policy(1, true)).unwrap();
    let source = "10.0.0.1".parse().unwrap();
    assert!(runtime.effective_dns(source, UnixTime(10)).is_err());
    let mut profile = DnsProfile {
        id: Uuid::new_v4(),
        ..DnsProfile::default()
    };
    profile.scope.peers.insert(client);
    profile.records.insert(
        "printer.office.example".into(),
        vec![DnsRecord::A("192.168.45.50".parse().unwrap())],
    );
    f.authorize_configuration(
        &mut runtime,
        ResourceConfiguration::default(),
        vec![profile],
    );
    let (_, dns) = runtime.effective_dns(source, UnixTime(10)).unwrap();
    assert_eq!(
        dns.answer_records("printer.office.example", 1)
            .unwrap()
            .len(),
        1
    );
    assert!(
        dns.answer_records("printer.office.example", 28)
            .unwrap()
            .is_empty()
    );
    assert!(
        runtime
            .effective_dns("10.0.0.2".parse().unwrap(), UnixTime(10))
            .is_err()
    );
    assert!(runtime.effective_dns(source, UnixTime(910)).is_err());
}

#[path = "wireguard_withdrawal_tests.rs"]
mod withdrawal_tests;

#[path = "wireguard_exit_tests.rs"]
mod exit_tests;
