use super::*;
use peerward_management::{ApplicationCategory, ApplicationResult, PeerOperation};

#[test]
fn platform_receipts_require_a_current_local_observation_and_expire_with_the_lease() {
    let f = Fixture::new();
    let owner = f.mobile();
    let (_carrier, _) = f.carrier(&owner);
    let mut owner = owner.lock().unwrap();
    let source = "10.4.0.1".parse().unwrap();
    let current = owner.managed_network(source, f.now).unwrap();
    assert_eq!(owner.application_receipts(f.now).len(), 1);
    assert!(
        owner
            .managed_network("10.4.0.2".parse().unwrap(), f.now)
            .is_err()
    );
    assert!(
        owner
            .observe_network(
                MobileNetworkObservation {
                    preferences_version: current.preferences_version,
                    configuration_version: current.configuration_version + 1,
                    source,
                    result: ApplicationResult::Applied,
                    reason: None,
                },
                f.now
            )
            .is_err()
    );
    owner
        .observe_network(
            MobileNetworkObservation {
                preferences_version: current.preferences_version,
                configuration_version: current.configuration_version,
                source,
                result: ApplicationResult::Rejected,
                reason: Some("route_conflict".into()),
            },
            f.now,
        )
        .unwrap();
    let rejected = owner.application_receipts(f.now);
    assert!(
        rejected
            .iter()
            .filter(|operation| matches!(
                operation,
                PeerOperation::Applied {
                    category: ApplicationCategory::Routes | ApplicationCategory::Dns,
                    result: ApplicationResult::Rejected,
                    ..
                }
            ))
            .count()
            == 2
    );
    owner
        .observe_network(
            MobileNetworkObservation {
                preferences_version: current.preferences_version,
                configuration_version: current.configuration_version,
                source,
                result: ApplicationResult::Applied,
                reason: None,
            },
            f.now,
        )
        .unwrap();
    assert!(
        owner
            .application_receipts(f.now)
            .iter()
            .all(|operation| matches!(
                operation,
                PeerOperation::Applied {
                    result: ApplicationResult::Applied,
                    ..
                }
            ))
    );
    assert!(
        !owner
            .application_receipts(f.now)
            .iter()
            .any(|operation| matches!(
                operation,
                PeerOperation::Applied {
                    category: ApplicationCategory::Firewall,
                    ..
                }
            ))
    );
    let expired = owner.application_receipts(UnixTime(f.now.0 + 901));
    assert!(matches!(expired.as_slice(), [PeerOperation::Applied {
        category: ApplicationCategory::Core,
        result: ApplicationResult::Rejected,
        reason: Some(reason), ..
    }] if reason == peerward_management::FRESH_AUTHORIZATION_REQUIRED));
    assert!(
        owner.managed_network(source, f.now).is_err(),
        "wall rollback cannot revive platform authorization"
    );
}

#[test]
fn persisted_exit_captures_both_families_and_old_preference_receipts_cannot_reopen_it() {
    use peerward_management::{
        ClientPreferenceRequest, ClientPreferences, PreferenceApplication, PreferenceChange,
        SavedClientPreferences,
    };
    let f = Fixture::new();
    let owner = f.mobile();
    let (_carrier, _) = f.carrier(&owner);
    let mut owner = owner.lock().unwrap();
    let source = "10.4.0.1".parse().unwrap();
    let path = std::env::temp_dir().join(format!("peerward-mobile-prefs-{}", uuid::Uuid::new_v4()));
    let change = PreferenceChange {
        request_id: uuid::Uuid::new_v4(),
        expected_version: 0,
        preferences: ClientPreferences {
            exit_resource: Some(uuid::Uuid::new_v4()),
            ..ClientPreferences::default()
        },
    };
    let saved = SavedClientPreferences::new(f.mesh, peer(&f.alice))
        .changed(change)
        .unwrap();
    peerward_credentials::private_files::write_private_atomic(
        &path.join("preferences.json"),
        &serde_json::to_vec(&saved).unwrap(),
    )
    .unwrap();
    owner.load_preferences(&path).unwrap();
    assert!(
        owner.load_preferences(&path).is_err(),
        "runtime cannot replace its preference store"
    );
    let current = owner.managed_network(source, f.now).unwrap();
    assert!(current.routes.contains(&"0.0.0.0/0".parse().unwrap()));
    assert!(
        current.routes.contains(&"::/0".parse().unwrap()),
        "missing IPv6 address/provider is still captured for rejection"
    );
    assert!(current.accept_dns && current.exit_selected && !current.allow_local_lan);
    owner
        .observe_network(
            MobileNetworkObservation {
                configuration_version: current.configuration_version,
                preferences_version: current.preferences_version,
                source,
                result: ApplicationResult::Applied,
                reason: None,
            },
            f.now,
        )
        .unwrap();
    let off = PreferenceChange {
        request_id: uuid::Uuid::new_v4(),
        expected_version: 1,
        preferences: ClientPreferences::default(),
    };
    let request = || ClientPreferenceRequest::Set {
        change: off.clone(),
    };
    let view = owner.client_preferences(request(), f.now).unwrap();
    assert_eq!(view.version, 2);
    assert_eq!(view.application, PreferenceApplication::Pending);
    assert_eq!(
        owner.client_preferences(request(), f.now).unwrap().version,
        2
    );
    assert!(
        owner
            .observe_network(
                MobileNetworkObservation {
                    configuration_version: current.configuration_version,
                    preferences_version: current.preferences_version,
                    source,
                    result: ApplicationResult::Applied,
                    reason: None
                },
                f.now
            )
            .is_err()
    );
    let mut stale = off;
    stale.preferences.allow_inbound = false;
    assert!(
        owner
            .client_preferences(ClientPreferenceRequest::Set { change: stale }, f.now)
            .is_err()
    );
    let written: SavedClientPreferences =
        serde_json::from_slice(&std::fs::read(path.join("preferences.json")).unwrap()).unwrap();
    assert_eq!(written.version, 2);
    assert_eq!(written.preferences.exit_resource, None);
    let late = UnixTime(f.now.0 + 901);
    assert_eq!(
        owner
            .client_preferences(ClientPreferenceRequest::Get {}, late)
            .unwrap()
            .application,
        PreferenceApplication::Unknown
    );
    std::fs::remove_dir_all(path).unwrap();
}
