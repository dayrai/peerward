use super::*;
use ed25519_dalek::SigningKey;
use peerward_types::{MeshId, PeerId};
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};
use uuid::Uuid;

fn signed(sequence: u64, issued: u64) -> (SignedManifest, SignedLease, SigningKey) {
    let key = SigningKey::from_bytes(&[23; 32]);
    let manifest = ConfigurationManifest {
        mesh_id: MeshId::new(),
        version: 1,
        parts: [
            ConfigurationPart::Authorities,
            ConfigurationPart::Peers,
            ConfigurationPart::Policy,
            ConfigurationPart::Resources,
            ConfigurationPart::Dns,
            ConfigurationPart::Revocations,
        ]
        .into_iter()
        .map(|part| {
            (
                part,
                ComponentReference {
                    version: 1,
                    digest: [4; 32],
                },
            )
        })
        .collect(),
    };
    let lease = AuthorizationLease {
        mesh_id: manifest.mesh_id,
        configuration_digest: content_digest(&manifest).unwrap(),
        sequence,
        issued_at: issued,
        valid_until: issued + 900,
    };
    (
        SignedManifest::sign(manifest, &key).unwrap(),
        SignedLease::sign(lease, &key).unwrap(),
        key,
    )
}

#[test]
fn initial_empty_signed_components_keep_their_existing_zero_revision() {
    let (signed, _, key) = signed(1, 100);
    let mut manifest = signed.manifest;
    for part in [
        ConfigurationPart::Authorities,
        ConfigurationPart::Peers,
        ConfigurationPart::Policy,
        ConfigurationPart::Revocations,
    ] {
        manifest.parts.get_mut(&part).unwrap().version = 0;
    }
    let signed = SignedManifest::sign(manifest.clone(), &key).unwrap();
    signed
        .verify(&key.verifying_key(), manifest.mesh_id)
        .unwrap();
    manifest
        .parts
        .get_mut(&ConfigurationPart::Resources)
        .unwrap()
        .version = 0;
    assert!(SignedManifest::sign(manifest, &key).is_err());
}

#[test]
fn lease_requires_dependencies_and_replay_never_extends_monotonic_deadline() {
    let (manifest, lease, key) = signed(1, 1000);
    let now = Instant::now();
    let mesh = lease.lease.mesh_id;
    let mut clock = LeaseClock::new(AuthorizationFloor::default());
    assert_eq!(
        clock.install(
            &manifest,
            &lease,
            &key.verifying_key(),
            mesh,
            &BTreeMap::new(),
            1000,
            now
        ),
        Err(ManagementError::Incomplete)
    );
    assert!(
        clock
            .install(
                &manifest,
                &lease,
                &key.verifying_key(),
                mesh,
                &manifest.manifest.parts,
                1000,
                now
            )
            .unwrap()
    );
    assert!(
        !clock
            .install(
                &manifest,
                &lease,
                &key.verifying_key(),
                mesh,
                &manifest.manifest.parts,
                1001,
                now + Duration::from_secs(800)
            )
            .unwrap()
    );
    assert!(!clock.valid(1001, now + Duration::from_mins(15)));
    // Replaying the exact signed lease after restart cannot revive access.
    let mut restarted = LeaseClock::new(clock.floor().clone());
    assert!(
        !restarted
            .install(
                &manifest,
                &lease,
                &key.verifying_key(),
                mesh,
                &manifest.manifest.parts,
                1001,
                now
            )
            .unwrap()
    );
    assert!(!restarted.valid(1001, now));
}

#[test]
fn lease_rejects_wrong_mesh_signature_future_clock_and_sequence_equivocation() {
    let (manifest, lease, key) = signed(1, 1000);
    let now = Instant::now();
    let mesh = lease.lease.mesh_id;
    let mut clock = LeaseClock::new(AuthorizationFloor::default());
    assert_eq!(
        clock.install(
            &manifest,
            &lease,
            &key.verifying_key(),
            MeshId::new(),
            &manifest.manifest.parts,
            1000,
            now
        ),
        Err(ManagementError::Signature)
    );
    assert_eq!(
        clock.install(
            &manifest,
            &lease,
            &key.verifying_key(),
            mesh,
            &manifest.manifest.parts,
            900,
            now
        ),
        Err(ManagementError::Expired)
    );
    clock
        .install(
            &manifest,
            &lease,
            &key.verifying_key(),
            mesh,
            &manifest.manifest.parts,
            1000,
            now,
        )
        .unwrap();
    let mut changed = lease.lease.clone();
    changed.issued_at += 1;
    changed.valid_until += 1;
    assert_eq!(
        clock.install(
            &manifest,
            &SignedLease::sign(changed, &key).unwrap(),
            &key.verifying_key(),
            mesh,
            &manifest.manifest.parts,
            1001,
            now
        ),
        Err(ManagementError::Rollback)
    );
    assert!(!clock.valid(900, now));
    assert!(!clock.valid(1000, now));
}

#[test]
fn resource_conflicts_are_site_scoped_and_never_overlap_virtual_addresses() {
    let site = Uuid::new_v4();
    let target = ResourceTarget::Subnet {
        prefix: "192.168.1.0/24".parse().unwrap(),
        site_id: site,
    };
    let nested = ResourceTarget::Subnet {
        prefix: "192.168.1.10/32".parse().unwrap(),
        site_id: site,
    };
    assert!(validate_resource_conflicts(&target, [&nested], &[]).is_ok());
    let other = ResourceTarget::Subnet {
        prefix: "192.168.1.0/25".parse().unwrap(),
        site_id: Uuid::new_v4(),
    };
    assert!(validate_resource_conflicts(&target, [&other], &[]).is_err());
    assert!(
        validate_resource_conflicts(&target, [], &["192.168.0.0/16".parse().unwrap()]).is_err()
    );
}

#[test]
fn dns_uses_label_boundaries_rejects_ambiguous_groups_and_cname_cycles() {
    let peer = PeerId::new();
    let profile = DnsProfile {
        id: Uuid::new_v4(),
        routes: vec![DnsRoute {
            suffix: "office.test".into(),
            upstreams: vec!["10.0.0.53:53".parse().unwrap()],
        }],
        ..DnsProfile::default()
    };
    let dns = EffectiveDns::for_peer(
        std::slice::from_ref(&profile),
        peer,
        "10.0.0.2".parse().unwrap(),
        &BTreeMap::new(),
    )
    .unwrap();
    assert!(dns.route("printer.office.test.").is_some());
    assert!(dns.route("notoffice.test").is_none());
    assert!(dns.delegates_mesh_child("printer.office.test.", "TEST."));
    assert!(dns.delegates_mesh_child("office.test", "test"));
    assert!(!dns.delegates_mesh_child("printer.office.test", "office.test"));
    assert!(!dns.delegates_mesh_child("printer.office.test", "fice.test"));
    assert!(!dns.delegates_mesh_child("other.test", "test"));
    let mut other = profile.clone();
    other.id = Uuid::new_v4();
    other.routes[0].upstreams = vec!["1.1.1.1:53".parse().unwrap()];
    assert!(
        EffectiveDns::for_peer(
            &[profile, other],
            peer,
            "10.0.0.2".parse().unwrap(),
            &BTreeMap::new()
        )
        .is_err()
    );
    let cycle = DnsProfile {
        id: Uuid::new_v4(),
        records: BTreeMap::from([
            ("a.test".into(), vec![DnsRecord::CNAME("b.test".into())]),
            ("b.test".into(), vec![DnsRecord::CNAME("a.test".into())]),
        ]),
        ..DnsProfile::default()
    };
    assert!(cycle.validate().is_err());
}

#[test]
fn resource_policy_keeps_source_provider_and_target_independent_and_expires() {
    let peer = PeerId::new();
    let provider = PeerId::new();
    let resource = Uuid::new_v4();
    let labels = BTreeMap::new();
    let allow = ResourceRule {
        source_collections: std::collections::BTreeSet::new(),
        resource_collections: std::collections::BTreeSet::new(),
        id: Uuid::new_v4(),
        priority: 100,
        enabled: true,
        action: ResourceAction::Allow,
        source: DeviceSelector {
            peers: [peer].into(),
            ..DeviceSelector::default()
        },
        resources: [resource].into(),
        providers: [provider].into(),
        protocol: 6,
        destination_ports: vec![(631, 631)],
        not_after: Some(2000),
    };
    let mut access = ResourceAccess {
        source_peer: peer,
        source_address: "10.0.0.2".parse().unwrap(),
        source_labels: &labels,
        resource,
        provider,
        protocol: 6,
        destination_port: Some(631),
        now: 1000,
    };
    assert_eq!(
        decide_resource(std::slice::from_ref(&allow), &access).0,
        ResourceAction::Allow
    );
    access.provider = PeerId::new();
    assert_eq!(
        decide_resource(std::slice::from_ref(&allow), &access).0,
        ResourceAction::Deny
    );
    access.provider = provider;
    access.now = 2000;
    assert_eq!(
        decide_resource(std::slice::from_ref(&allow), &access).0,
        ResourceAction::Deny
    );
    access.now = 1000;
    let deny = ResourceRule {
        source_collections: std::collections::BTreeSet::new(),
        resource_collections: std::collections::BTreeSet::new(),
        action: ResourceAction::Deny,
        id: Uuid::new_v4(),
        ..allow.clone()
    };
    assert_eq!(
        decide_resource(&[allow, deny], &access).0,
        ResourceAction::Deny
    );
}

#[test]
fn incomplete_configuration_persists_observation_without_extending_or_restarting_lease() {
    let (manifest, lease, key) = signed(2, 1000);
    let mesh = lease.lease.mesh_id;
    let now = Instant::now();
    let mut clock = LeaseClock::new(AuthorizationFloor::default());
    assert_eq!(
        clock.install(
            &manifest,
            &lease,
            &key.verifying_key(),
            mesh,
            &BTreeMap::new(),
            1000,
            now
        ),
        Err(ManagementError::Incomplete)
    );
    assert_eq!(clock.floor().lease_sequence, 2);
    let mut restarted = LeaseClock::new(clock.floor().clone());
    assert!(
        !restarted
            .install(
                &manifest,
                &lease,
                &key.verifying_key(),
                mesh,
                &manifest.manifest.parts,
                1100,
                now
            )
            .unwrap()
    );
    assert!(!restarted.valid(1100, now));
    let mut older = lease.lease.clone();
    older.sequence = 1;
    assert_eq!(
        restarted.install(
            &manifest,
            &SignedLease::sign(older, &key).unwrap(),
            &key.verifying_key(),
            mesh,
            &manifest.manifest.parts,
            1100,
            now
        ),
        Err(ManagementError::Rollback)
    );
    assert_eq!(
        clock.install(
            &manifest,
            &lease,
            &key.verifying_key(),
            mesh,
            &manifest.manifest.parts,
            1100,
            now + Duration::from_mins(15)
        ),
        Err(ManagementError::Expired)
    );
    assert!(!clock.valid(1100, now));
}
