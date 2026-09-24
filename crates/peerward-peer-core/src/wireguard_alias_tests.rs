use super::*;

#[test]
fn equal_prefix_aliases_do_not_change_the_real_provider_or_bypass_denies() {
    let f = Fixture::new();
    let client = PeerId::new();
    let gateway = PeerId::new();
    let client_credential = f.credential(client, 10);
    let gateway_credential = f.credential(gateway, 20);
    let directory = f.signed(
        1,
        vec![
            f.entry(&client_credential, "10.0.0.1"),
            f.entry(&gateway_credential, "10.0.0.2"),
        ],
    );
    let mut a = f.runtime(client_credential, 10);
    let mut b = f.runtime(gateway_credential, 20);
    let mut config = resource_config(f.mesh, client, gateway);
    let actual = Uuid::parse_str("ffffffff-ffff-4fff-bfff-ffffffffffff").unwrap();
    let alias = Uuid::parse_str("00000000-0000-4000-8000-000000000001").unwrap();
    config.resources[0].id = actual;
    config.bindings[0].resource_id = actual;
    config.rules[0].resources = [actual].into();
    let mut name = config.resources[0].clone();
    name.id = alias;
    name.definition.name = "second name without its own approval".into();
    config.resources.insert(0, name);
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
        vec![packet.clone()]
    );
    let mut reply = udp(2, 1, 1234, 10);
    reply[12..16].copy_from_slice(&[192, 168, 45, 50]);
    reply[20..22].copy_from_slice(&4242u16.to_be_bytes());
    checksum(&mut reply);
    let first = b.send_tunnel(&reply, UnixTime(10), now).unwrap();
    assert_eq!(
        relay_exchange(&mut b, &mut a, gateway, client, first, now),
        vec![reply.clone()]
    );

    let mut deny = config.rules[0].clone();
    deny.id = Uuid::new_v4();
    deny.resources = [alias].into();
    deny.action = ResourceAction::Deny; // same priority: Deny wins across names
    config.rules.push(deny);
    config.resources.reverse();
    for runtime in [&mut a, &mut b] {
        f.authorize_resources(runtime, config.clone());
    }
    assert!(a.send_tunnel(&packet, UnixTime(10), now).is_err());
    assert!(
        b.send_tunnel(&reply, UnixTime(10), now).is_err(),
        "new deny fences the old reverse flow"
    );
}

#[test]
fn address_resolution_and_alias_rules_preserve_specificity_priority_and_provider_scope() {
    let f = Fixture::new();
    let source = PeerId::new();
    let provider = PeerId::new();
    let mut config = resource_config(f.mesh, source, provider);
    let target = config.resources[0].id;
    let mut broader = config.resources[0].clone();
    broader.id = Uuid::new_v4();
    if let ResourceTarget::Subnet { prefix, .. } = &mut broader.definition.target {
        *prefix = "192.168.45.0/24".parse().unwrap();
    }
    config.resources.push(broader.clone());
    let address = "192.168.45.50".parse().unwrap();
    let aliases = packet_resource_aliases(&config.resources, address, None);
    assert_eq!(aliases, vec![target]);
    let labels = BTreeMap::new();
    let access = ResourceAccess {
        source_peer: source,
        source_address: "10.0.0.1".parse().unwrap(),
        source_labels: &labels,
        resource: target,
        provider,
        protocol: 17,
        destination_port: Some(4242),
        now: 10,
    };
    let decide = |config: &ResourceConfiguration, access: &ResourceAccess<'_>| {
        decide_resource_aliases(
            &config.rules,
            &config.collections,
            &aliases,
            &config.bindings,
            access,
        )
    };
    assert_eq!(decide(&config, &access).0, ResourceAction::Allow);
    config.rules[0].not_after = Some(10);
    assert_eq!(decide(&config, &access).0, ResourceAction::Deny);
    config.rules[0].not_after = None;
    assert_eq!(
        decide(
            &config,
            &ResourceAccess {
                provider: PeerId::new(),
                ..access
            }
        )
        .0,
        ResourceAction::Deny
    );
    config.bindings[0].approved = false;
    assert_eq!(decide(&config, &access).0, ResourceAction::Deny);
    config.rules[0].resources = [broader.id].into();
    config.bindings[0].resource_id = broader.id;
    config.bindings[0].approved = true;
    assert_eq!(
        decide(&config, &access).0,
        ResourceAction::Deny,
        "a /24 grant cannot bypass an ungranted /32"
    );
}
