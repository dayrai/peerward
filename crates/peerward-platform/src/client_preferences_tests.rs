use super::*;
use std::os::unix::fs::PermissionsExt as _;

#[test]
fn preferences_are_bound_versioned_idempotent_and_private() {
    let directory = std::env::temp_dir().join(format!("pw-preferences-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&directory).unwrap();
    let path = directory.join("preferences.json");
    let lock = directory.join("runtime.lock");
    let mesh = MeshId::from_uuid(uuid::Uuid::new_v4()).unwrap();
    let peer = PeerId::from_uuid(uuid::Uuid::new_v4()).unwrap();
    let owner = LocalRuntimeLock::acquire(&lock).unwrap();
    assert!(LocalRuntimeLock::acquire(&lock).is_err());
    let mut store = ClientPreferenceStore::load(&path, mesh, peer).unwrap();
    assert_eq!(store.saved().version, 0);
    let mut change = PreferenceChange {
        request_id: uuid::Uuid::new_v4(),
        expected_version: 0,
        preferences: ClientPreferences {
            exit_resource: Some(uuid::Uuid::new_v4()),
            ..ClientPreferences::default()
        },
    };
    store.commit(change.clone()).unwrap();
    store.commit(change.clone()).unwrap();
    assert_eq!(store.saved().version, 1);
    drop(store);
    let mut store = ClientPreferenceStore::load(&path, mesh, peer).unwrap();
    assert!(!store.validate_change(&change).unwrap());
    change.preferences.exit_resource = None;
    assert!(
        store.commit(change.clone()).is_err(),
        "same ID cannot change its body"
    );
    change.request_id = uuid::Uuid::new_v4();
    assert!(
        store.commit(change.clone()).is_err(),
        "stale version cannot overwrite a selection"
    );
    change.expected_version = 1;
    store.commit(change).unwrap();
    assert_eq!(store.saved().version, 2);
    assert!(
        ClientPreferenceStore::load(
            &path,
            MeshId::from_uuid(uuid::Uuid::new_v4()).unwrap(),
            peer
        )
        .is_err()
    );
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(ClientPreferenceStore::load(&path, mesh, peer).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let linked = directory.join("link.json");
    std::os::unix::fs::symlink(&path, &linked).unwrap();
    assert!(ClientPreferenceStore::load(&linked, mesh, peer).is_err());
    drop(owner);
    let next = LocalRuntimeLock::acquire(&lock).unwrap();
    drop(next);
    std::fs::remove_dir_all(directory).unwrap();
}
