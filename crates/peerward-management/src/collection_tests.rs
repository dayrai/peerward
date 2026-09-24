use super::*;
use peerward_types::PeerId;
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

#[test]
fn collections_are_explicit_or_controlled_labels_with_no_implicit_all_or_nesting() {
    let a = Uuid::new_v4();
    let b = Uuid::new_v4();
    let c = Uuid::new_v4();
    let data = [
        (a, BTreeMap::new()),
        (b, BTreeMap::from([("team".into(), "finance".into())])),
        (c, BTreeMap::from([("team".into(), "guest".into())])),
    ];
    let mut definition = CollectionDefinition {
        name: "Finance".into(),
        kind: CollectionKind::Devices,
        members: BTreeSet::new(),
        labels: BTreeMap::new(),
    };
    let resolve = |definition: &CollectionDefinition| {
        definition
            .resolve(
                Uuid::new_v4(),
                data.iter().map(|(id, labels)| (*id, labels)),
            )
            .members
    };
    assert!(resolve(&definition).is_empty());
    definition.members.insert(a);
    definition.labels.insert("team".into(), "finance".into());
    assert_eq!(resolve(&definition), [a, b].into());
    let invalid =
        serde_json::json!({"name":"Nested","kind":"devices","collections":[Uuid::new_v4()]});
    assert!(serde_json::from_value::<CollectionDefinition>(invalid).is_err());
}

#[test]
fn empty_wrong_kind_or_removed_membership_never_grants_access() {
    let peer = PeerId::new();
    let resource = Uuid::new_v4();
    let source_group = Uuid::new_v4();
    let target_group = Uuid::new_v4();
    let rule = ResourceRule {
        id: Uuid::new_v4(),
        priority: 100,
        enabled: true,
        action: ResourceAction::Allow,
        source: DeviceSelector::default(),
        resources: BTreeSet::new(),
        source_collections: [source_group].into(),
        resource_collections: [target_group].into(),
        providers: BTreeSet::new(),
        protocol: 6,
        destination_ports: vec![(631, 631)],
        not_after: None,
    };
    let labels = BTreeMap::new();
    let access = ResourceAccess {
        source_peer: peer,
        source_address: "10.0.0.2".parse().unwrap(),
        source_labels: &labels,
        resource,
        provider: PeerId::new(),
        protocol: 6,
        destination_port: Some(631),
        now: 1,
    };
    let mut groups = vec![
        ResolvedCollection {
            id: source_group,
            kind: CollectionKind::Devices,
            members: [peer.into_uuid()].into(),
        },
        ResolvedCollection {
            id: target_group,
            kind: CollectionKind::Resources,
            members: [resource].into(),
        },
    ];
    assert_eq!(
        decide_resource(std::slice::from_ref(&rule), &access).0,
        ResourceAction::Deny
    );
    assert_eq!(
        decide_resource_with_collections(std::slice::from_ref(&rule), &groups, &access).0,
        ResourceAction::Allow
    );
    groups[0].kind = CollectionKind::Resources;
    assert_eq!(
        decide_resource_with_collections(std::slice::from_ref(&rule), &groups, &access).0,
        ResourceAction::Deny
    );
    groups[0].kind = CollectionKind::Devices;
    groups[0].members.clear();
    assert_eq!(
        decide_resource_with_collections(std::slice::from_ref(&rule), &groups, &access).0,
        ResourceAction::Deny
    );
}
