use super::*;

fn manifest(binary: &[u8]) -> (Vec<u8>, ReleaseArtifact) {
    let artifact = ReleaseArtifact {
        platform: "linux".into(),
        architecture: "x86_64".into(),
        kind: ArtifactKind::Binary,
        name: "peerward-linux-x86_64".into(),
        url: "https://github.com/dayrai/peerward/releases/download/v1.0.0/peerward-linux-x86_64"
            .into(),
        sha256: hex::encode(Sha256::digest(binary)),
        size: binary.len() as u64,
    };
    let manifest = ReleaseManifest {
        schema_version: 1,
        sequence: 7,
        version: "1.0.0".into(),
        channel: Channel::Stable,
        published_at: 1_700_000_000,
        expires_at: 1_700_086_400,
        schema_compatibility: CompatibilityRange { min: 1, max: 1 },
        wire_compatibility: CompatibilityRange { min: 2, max: 2 },
        rollback_floor: "1.0.0".into(),
        artifacts: vec![artifact.clone()],
    };
    (serde_json::to_vec(&manifest).unwrap(), artifact)
}

#[test]
fn signed_manifest_selection_and_tamper_rejection_are_exact() {
    let key = [9; 32];
    let public = SigningKey::from_bytes(&key).verifying_key().to_bytes();
    let (bytes, _) = manifest(b"binary");
    let signature = sign_manifest(&bytes, &key);
    let verified = verify_manifest(&bytes, &signature, &public).unwrap();
    assert_eq!(
        verified
            .select(Channel::Stable, "linux", "x86_64", ArtifactKind::Binary)
            .unwrap()
            .name,
        "peerward-linux-x86_64"
    );
    let mut tampered = bytes;
    tampered[10] ^= 1;
    assert!(matches!(
        verify_manifest(&tampered, &signature, &public),
        Err(UpdateError::Signature)
    ));
}

#[test]
fn digest_install_and_rollback_preserve_the_previous_binary() {
    let hash_prefix: [u8; 4] = Sha256::digest(b"isolated")[..4].try_into().unwrap();
    let root = std::env::temp_dir().join(format!(
        "peerward-updater-test-{}-{:08x}",
        std::process::id(),
        u32::from_be_bytes(hash_prefix)
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir(&root).unwrap();
    let destination = root.join("peerward");
    fs::write(&destination, b"old").unwrap();
    let (_, artifact) = manifest(b"new");
    let saved = install_verified(b"new", &artifact, &destination).unwrap();
    assert_eq!(fs::read(&destination).unwrap(), b"new");
    assert_eq!(fs::read(saved).unwrap(), b"old");
    rollback(&destination).unwrap();
    assert_eq!(fs::read(&destination).unwrap(), b"old");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn wrong_digest_never_mutates_destination() {
    let (_, artifact) = manifest(b"expected");
    assert!(matches!(
        verify_artifact(b"different", &artifact),
        Err(UpdateError::Digest)
    ));
}

#[test]
fn artifacts_have_a_global_bound_and_installed_files_are_streamed() {
    let root = std::env::temp_dir().join(format!(
        "peerward-updater-artifact-bound-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir(&root).unwrap();
    let path = root.join("peerward");
    fs::write(&path, b"bounded").unwrap();
    let (_, artifact) = manifest(b"bounded");
    verify_artifact_file(&path, &artifact).unwrap();

    let mut oversized = artifact.clone();
    oversized.size = MAX_ARTIFACT_BYTES as u64 + 1;
    assert!(matches!(
        verify_artifact(b"bounded", &oversized),
        Err(UpdateError::Digest)
    ));
    assert!(matches!(
        verify_artifact_file(&path, &oversized),
        Err(UpdateError::Digest)
    ));

    #[cfg(unix)]
    {
        let fifo = root.join("peerward.fifo");
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .unwrap()
                .success()
        );
        let started = std::time::Instant::now();
        assert!(verify_artifact_file(&fifo, &artifact).is_err());
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn candidate_rejects_expiry_sequence_downgrade_and_incompatible_wire() {
    let (bytes, _) = manifest(b"candidate");
    let manifest: ReleaseManifest = serde_json::from_slice(&bytes).unwrap();
    assert!(
        manifest
            .validate_candidate(1_700_000_001, 6, "1.0.0", 1, 2)
            .is_ok()
    );
    assert!(matches!(
        manifest.validate_candidate(1_700_086_400, 6, "1.0.0", 1, 2),
        Err(UpdateError::Expired)
    ));
    assert!(matches!(
        manifest.validate_candidate(1_700_000_001, 8, "1.0.0", 1, 2),
        Err(UpdateError::Rollback)
    ));
    assert!(matches!(
        manifest.validate_candidate(1_700_000_001, 6, "1.0.0", 1, 1),
        Err(UpdateError::Incompatible)
    ));

    let root = std::env::temp_dir().join(format!(
        "peerward-update-state-{}-{}",
        std::process::id(),
        manifest.sequence
    ));
    let _ = fs::remove_dir_all(&root);
    let state = root.join("accepted.json");
    accept_manifest(&manifest, &state, 1_700_000_001, "1.0.0", 1, 2).unwrap();
    accept_manifest(&manifest, &state, 1_700_000_002, "1.0.0", 1, 2).unwrap();
    let mut conflicting = manifest.clone();
    conflicting.version = "1.0.1".into();
    assert!(matches!(
        accept_manifest(&conflicting, &state, 1_700_000_002, "1.0.0", 1, 2),
        Err(UpdateError::Rollback)
    ));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn candidate_rejects_version_downgrade_and_noncanonical_semver() {
    let (bytes, _) = manifest(b"candidate");
    let mut manifest: ReleaseManifest = serde_json::from_slice(&bytes).unwrap();
    manifest.version = "0.9.9".into();
    manifest.rollback_floor = "0.9.0".into();
    assert_eq!(
        manifest
            .validate_candidate(1_700_000_001, 0, "1.0.0", 1, 2)
            .unwrap_err()
            .to_string(),
        UpdateError::Rollback.to_string()
    );

    manifest.version = "v1.0.1".into();
    assert!(matches!(
        manifest.validate_candidate(1_700_000_001, 0, "1.0.0", 1, 2),
        Err(UpdateError::Malformed)
    ));
}

#[test]
fn candidate_obeys_semver_prerelease_and_build_precedence() {
    let (bytes, _) = manifest(b"candidate");
    let mut manifest: ReleaseManifest = serde_json::from_slice(&bytes).unwrap();
    manifest.rollback_floor = "1.0.0-alpha.1".into();

    manifest.version = "1.0.0-alpha.2".into();
    manifest
        .validate_candidate(1_700_000_001, 0, "1.0.0-alpha.1", 1, 2)
        .unwrap();

    manifest.version = "1.0.0-alpha.1".into();
    assert!(matches!(
        manifest.validate_candidate(1_700_000_001, 0, "1.0.0", 1, 2),
        Err(UpdateError::Rollback)
    ));

    manifest.version = "1.0.0+build.2".into();
    manifest.rollback_floor = "1.0.0+build.1".into();
    manifest
        .validate_candidate(1_700_000_001, 0, "1.0.0+build.1", 1, 2)
        .unwrap();

    manifest.version = "1.0.0+build.0".into();
    manifest
        .validate_candidate(1_700_000_001, 0, "1.0.0+build.1", 1, 2)
        .unwrap();

    manifest.version = "1.0.0-alpha.01".into();
    assert!(matches!(
        manifest.validate_candidate(1_700_000_001, 0, "1.0.0-alpha.1", 1, 2),
        Err(UpdateError::Malformed)
    ));
}

#[test]
fn canary_patch_update_preserves_floor_and_rejects_the_old_release_line() {
    let (bytes, _) = manifest(b"candidate");
    let mut manifest: ReleaseManifest = serde_json::from_slice(&bytes).unwrap();
    manifest.version = "0.1.1".into();
    manifest.rollback_floor = "0.1.0".into();
    manifest.channel = Channel::Canary;
    manifest.schema_compatibility = CompatibilityRange { min: 4, max: 4 };
    manifest.wire_compatibility = CompatibilityRange { min: 5, max: 5 };
    manifest
        .validate_candidate(1_700_000_001, 6, "0.1.0", 4, 5)
        .unwrap();
    for current in ["0.0.9", "0.1.2", "1.0.0-technical-preview.4"] {
        assert!(matches!(
            manifest.validate_candidate(1_700_000_001, 6, current, 4, 5),
            Err(UpdateError::Rollback)
        ));
    }
    assert!(matches!(
        manifest.validate_candidate(1_700_000_001, 6, "0.1.0", 4, 4),
        Err(UpdateError::Incompatible)
    ));
    manifest.rollback_floor = "0.1.1".into();
    assert!(matches!(
        manifest.validate_candidate(1_700_000_001, 6, "0.1.0", 4, 5),
        Err(UpdateError::Rollback)
    ));
}

#[cfg(unix)]
#[test]
fn stable_canary_version_switch_and_role_rollback_are_atomic() {
    let hash_prefix: [u8; 4] = Sha256::digest(b"versioned")[..4].try_into().unwrap();
    let root = std::env::temp_dir().join(format!(
        "peerward-versioned-test-{}-{:08x}",
        std::process::id(),
        u32::from_be_bytes(hash_prefix)
    ));
    let _ = fs::remove_dir_all(&root);
    let (_, old_artifact) = manifest(b"old");
    let (_, new_artifact) = manifest(b"new");
    let current =
        install_versioned_verified(b"old", &old_artifact, "1.0.0", "relay", &root).unwrap();
    assert_eq!(fs::read(&current).unwrap(), b"old");
    install_versioned_verified(b"new", &new_artifact, "1.0.1", "relay", &root).unwrap();
    assert_eq!(fs::read(&current).unwrap(), b"new");
    install_versioned_verified(b"new", &new_artifact, "1.0.1", "relay", &root).unwrap();
    assert_eq!(fs::read(root.join("roles/relay/previous")).unwrap(), b"old");
    rollback_versioned(&root, "relay").unwrap();
    assert_eq!(fs::read(&current).unwrap(), b"old");

    let canary = ReleaseManifest {
        schema_version: 1,
        sequence: 8,
        version: "1.0.2-canary.1".into(),
        channel: Channel::Canary,
        published_at: 1,
        expires_at: 2,
        schema_compatibility: CompatibilityRange { min: 1, max: 1 },
        wire_compatibility: CompatibilityRange { min: 2, max: 2 },
        rollback_floor: "1.0.0".into(),
        artifacts: vec![new_artifact],
    };
    assert!(canary.validate().is_ok());
    assert!(
        canary
            .select(Channel::Stable, "linux", "x86_64", ArtifactKind::Binary)
            .is_err()
    );
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn automatic_rollback_rejects_old_wire_missing_metadata_and_modified_bytes() {
    let root = std::env::temp_dir().join(format!("peerward-wire4-rollback-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    let make_release = |bytes: &[u8], version: &str, wire| {
        let (json, artifact) = manifest(bytes);
        let mut release: ReleaseManifest = serde_json::from_slice(&json).unwrap();
        release.version = version.into();
        release.wire_compatibility = CompatibilityRange {
            min: wire,
            max: wire,
        };
        release.schema_compatibility = CompatibilityRange { min: 3, max: 3 };
        (release, artifact)
    };
    let (old, old_artifact) = make_release(b"wire3", "1.0.0", 3);
    let (new, new_artifact) = make_release(b"wire4", "1.0.1", 4);
    install_versioned_release(b"wire3", &old_artifact, &old, "peer", &root).unwrap();
    let current = install_versioned_release(b"wire4", &new_artifact, &new, "peer", &root).unwrap();
    assert!(matches!(
        rollback_versioned_checked(&root, "peer", 3, 4, "1.0.0"),
        Err(UpdateError::Incompatible)
    ));
    assert_eq!(fs::read(&current).unwrap(), b"wire4");
    let (next, next_artifact) = make_release(b"wire4-next", "1.0.2", 4);
    install_versioned_release(b"wire4-next", &next_artifact, &next, "peer", &root).unwrap();
    assert!(matches!(
        rollback_versioned_checked(&root, "peer", 3, 4, "1.0.2"),
        Err(UpdateError::Incompatible)
    ));
    let previous = root.join("versions/1.0.1/peerward");
    fs::write(&previous, b"altered").unwrap();
    assert!(matches!(
        rollback_versioned_checked(&root, "peer", 3, 4, "1.0.0"),
        Err(UpdateError::Digest)
    ));
    fs::write(&previous, b"wire4").unwrap();
    rollback_versioned_checked(&root, "peer", 3, 4, "1.0.0").unwrap();
    assert_eq!(fs::read(&current).unwrap(), b"wire4");
    fs::remove_file(root.join("versions/1.0.2/compatibility.json")).unwrap();
    assert!(matches!(
        rollback_versioned_checked(&root, "peer", 3, 4, "1.0.0"),
        Err(UpdateError::Incompatible)
    ));
    assert_eq!(fs::read(&current).unwrap(), b"wire4");
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn existing_compatibility_metadata_is_bounded_before_comparison() {
    let root = std::env::temp_dir().join(format!(
        "peerward-compatibility-bound-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    let (json, artifact) = manifest(b"current");
    let release: ReleaseManifest = serde_json::from_slice(&json).unwrap();
    install_versioned_release(b"current", &artifact, &release, "peer", &root).unwrap();
    let metadata = root.join("versions/1.0.0/compatibility.json");
    fs::OpenOptions::new()
        .write(true)
        .open(&metadata)
        .unwrap()
        .set_len(MAX_MANIFEST_BYTES as u64 + 1)
        .unwrap();

    assert!(matches!(
        install_versioned_release(b"current", &artifact, &release, "peer", &root),
        Err(UpdateError::Io(_))
    ));
    fs::remove_dir_all(root).unwrap();
}
