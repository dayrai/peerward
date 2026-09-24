use super::*;

#[test]
fn claim_urls_support_ipv6_loopback_and_reject_decorated_or_public_http_urls() {
    for value in ["http://[::1]:8081/api/v1/join/token/claim", "http://127.0.0.2/claim", "https://control.example/claim"] {
        validate_join_claim_url(&Url::parse(value).unwrap()).unwrap();
    }
    for value in ["http://192.0.2.1/claim", "https://user:secret@control.example/claim", "https://control.example/claim?x=y", "https://control.example/claim#fragment"] {
        assert!(validate_join_claim_url(&Url::parse(value).unwrap()).is_err());
    }
}

#[test]
fn pending_enrollment_preserves_identity_and_never_regenerates_damaged_state() {
    let root = std::env::temp_dir().join(format!("peerward-pending-test-{}", Uuid::new_v4()));
    let output = root.join("profile");
    let (file, state) = PendingEnrollmentFile::open(&output).unwrap();
    let fingerprint = state.fingerprint();
    assert!(
        PendingEnrollmentFile::open(&output).is_err(),
        "a concurrent process cannot issue a second claim"
    );
    let folder = file.folder.clone();
    drop(file);
    drop(state);
    let (file, state) = PendingEnrollmentFile::open(&output).unwrap();
    assert_eq!(
        state.fingerprint(),
        fingerprint,
        "prepare and resume use the same keys"
    );
    drop(file);
    drop(state);
    fs::write(folder.join("state.json"), b"{broken").unwrap();
    assert!(
        PendingEnrollmentFile::open(&output).is_err(),
        "damaged state cannot silently change device identity"
    );
    assert_eq!(fs::read(folder.join("state.json")).unwrap(), b"{broken");
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn enrollment_rejects_public_files_and_symlinked_secret_state() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    let root = std::env::temp_dir().join(format!("peerward-pending-test-{}", Uuid::new_v4()));
    let output = root.join("profile");
    let (file, _) = PendingEnrollmentFile::open(&output).unwrap();
    let folder = file.folder.clone();
    drop(file);
    let state = folder.join("state.json");
    fs::set_permissions(&state, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(PendingEnrollmentFile::open(&output).is_err());
    fs::set_permissions(&state, fs::Permissions::from_mode(0o600)).unwrap();
    let target = root.join("existing-data");
    fs::rename(&state, &target).unwrap();
    let original = fs::read(&target).unwrap();
    symlink(&target, &state).unwrap();
    assert!(PendingEnrollmentFile::open(&output).is_err());
    assert_eq!(fs::read(&target).unwrap(), original);
    let invitation = root.join("invitation");
    fs::write(&invitation, "peerward://join?bundle=private").unwrap();
    fs::set_permissions(&invitation, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(read_join_invitation(None, Some(&invitation)).is_err());
    fs::set_permissions(&invitation, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(read_join_invitation(None, Some(&invitation)).is_ok());
    let link = root.join("invitation-link");
    symlink(&invitation, &link).unwrap();
    assert!(read_join_invitation(None, Some(&link)).is_err());
    fs::remove_dir_all(root).unwrap();
}
