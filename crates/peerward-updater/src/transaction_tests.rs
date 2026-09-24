use super::*;
use std::{
    os::unix::fs::PermissionsExt as _,
    process::Command,
    time::{Duration, Instant},
};

struct Fixture {
    root: PathBuf,
    manifest: ReleaseManifest,
    artifact: ReleaseArtifact,
    role: &'static str,
}
impl Fixture {
    fn new(label: &str, role: &'static str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "peerward-update-journal-{}-{label}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let (old, old_artifact) = release(b"old", "1.0.0", 1);
        install_versioned_release(b"old", &old_artifact, &old, role, &root).unwrap();
        let (manifest, artifact) = release(b"new", "1.0.1", 2);
        accept_manifest(
            &manifest,
            &root.join("accepted-update.json"),
            11,
            "1.0.0",
            4,
            5,
        )
        .unwrap();
        Self {
            root,
            manifest,
            artifact,
            role,
        }
    }
    fn prepare(&self) -> UpdateTransaction {
        UpdateTransaction::prepare(
            &self.root,
            self.role,
            b"new",
            &self.artifact,
            &self.manifest,
            "http://127.0.0.1:9999/readyz",
        )
        .unwrap()
    }
    fn load(&self) -> UpdateTransaction {
        UpdateTransaction::load(&self.root, self.role)
            .unwrap()
            .unwrap()
    }
    fn bytes(&self, name: &str) -> Vec<u8> {
        fs::read(self.root.join("roles").join(self.role).join(name)).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn release(bytes: &[u8], version: &str, sequence: u64) -> (ReleaseManifest, ReleaseArtifact) {
    let artifact = ReleaseArtifact {
        platform: "linux".into(),
        architecture: "x86_64".into(),
        kind: ArtifactKind::Binary,
        name: "peerward".into(),
        url: "https://release.example/peerward".into(),
        sha256: hex::encode(Sha256::digest(bytes)),
        size: bytes.len() as u64,
    };
    (
        ReleaseManifest {
            schema_version: 1,
            sequence,
            version: version.into(),
            channel: Channel::Canary,
            published_at: 10,
            expires_at: 20,
            schema_compatibility: CompatibilityRange { min: 4, max: 4 },
            wire_compatibility: CompatibilityRange { min: 5, max: 5 },
            rollback_floor: "1.0.0".into(),
            artifacts: vec![artifact.clone()],
        },
        artifact,
    )
}

#[test]
fn approved_intent_survives_restart_before_activation() {
    let fixture = Fixture::new("approved-intent", "relay");
    let approved = "a".repeat(64);
    let prepare = |digest| {
        UpdateTransaction::prepare_approved(
            &fixture.root,
            fixture.role,
            b"new",
            &fixture.artifact,
            &fixture.manifest,
            TransactionOptions {
                health_url: "http://127.0.0.1:9999/readyz",
                repair: false,
                approved_preview: Some(digest),
            },
        )
    };
    assert!(matches!(prepare("bad"), Err(UpdateError::Malformed)));
    assert!(
        UpdateTransaction::load(&fixture.root, fixture.role)
            .unwrap()
            .is_none()
    );
    let original = prepare(&approved).unwrap();
    assert_eq!(fixture.bytes("current"), b"old");
    assert_eq!(fixture.load(), original);
    assert_eq!(
        serde_json::to_value(fixture.load()).unwrap()["approved_preview"],
        approved
    );
    assert_eq!(prepare(&approved).unwrap(), original);
    assert!(matches!(
        prepare(&"b".repeat(64)),
        Err(UpdateError::RecoveryRequired)
    ));
    let mut resumed = fixture.load();
    resumed.activate(&fixture.root, 4, 5).unwrap();
    resumed.record_ready(&fixture.root).unwrap();
    assert!(resumed.matches_approved_request(
        &fixture.manifest,
        &fixture.artifact,
        resumed.health_url(),
        Some(&approved)
    ));
}

#[test]
fn journal_retries_preserve_intent_and_the_original_rollback_target() {
    let fixture = Fixture::new("retries", "relay");
    let mut record = fixture.prepare();
    assert_eq!(fixture.bytes("current"), b"old");
    assert_eq!(fixture.load().stage(), UpdateStage::Prepared);
    assert_eq!(
        fs::metadata(fixture.root.join("roles/relay/update-transaction.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(fixture.prepare(), record);
    let stale = record.clone();
    record.activate(&fixture.root, 4, 5).unwrap();
    assert_eq!(fixture.bytes("current"), b"new");
    assert_eq!(fixture.bytes("previous"), b"old");
    let mut stale = stale;
    assert!(matches!(
        stale.record_failure(&fixture.root),
        Err(UpdateError::RecoveryRequired)
    ));
    record.record_failure(&fixture.root).unwrap();
    let mut record = fixture.load();
    record.activate(&fixture.root, 4, 5).unwrap();
    record.record_ready(&fixture.root).unwrap();
    record.request_rollback(&fixture.root, 4, 5).unwrap();
    record.activate(&fixture.root, 4, 5).unwrap();
    assert_eq!(fixture.bytes("current"), b"old");
    // Lost result after rollback pointer switch: repeat the intent, never toggle links.
    let mut record = fixture.load();
    record.activate(&fixture.root, 4, 5).unwrap();
    record.record_ready(&fixture.root).unwrap();
    record.request_rollback(&fixture.root, 4, 5).unwrap();
    record.activate(&fixture.root, 4, 5).unwrap();
    assert_eq!(record.stage(), UpdateStage::RolledBack);
    assert_eq!(fixture.bytes("current"), b"old");
    assert_eq!(fixture.bytes("previous"), b"new");
}

#[test]
fn rollback_floor_is_persistent_and_unfinished_work_cannot_be_replaced() {
    let fixture = Fixture::new("floor", "peer");
    let mut record = fixture.prepare();
    let mut second = fixture.manifest.clone();
    second.sequence += 1;
    second.version = "1.0.2".into();
    assert!(
        UpdateTransaction::prepare(
            &fixture.root,
            "peer",
            b"new",
            &fixture.artifact,
            &second,
            record.health_url()
        )
        .is_err()
    );
    assert!(
        UpdateTransaction::prepare(
            &fixture.root,
            "peer",
            b"new",
            &fixture.artifact,
            &fixture.manifest,
            "http://127.0.0.1:9998"
        )
        .is_err()
    );
    record.activate(&fixture.root, 4, 5).unwrap();
    record.record_ready(&fixture.root).unwrap();
    second.rollback_floor = "1.0.1".into();
    accept_manifest(
        &second,
        &fixture.root.join("accepted-update.json"),
        11,
        "1.0.1",
        4,
        5,
    )
    .unwrap();
    assert_eq!(accepted_rollback_floor(&fixture.root).unwrap(), "1.0.1");
    assert!(matches!(
        record.request_rollback(&fixture.root, 4, 5),
        Err(UpdateError::Incompatible)
    ));
    second.sequence += 1;
    second.rollback_floor = "1.0.0".into();
    accept_manifest(
        &second,
        &fixture.root.join("accepted-update.json"),
        11,
        "1.0.1",
        4,
        5,
    )
    .unwrap();
    assert_eq!(accepted_rollback_floor(&fixture.root).unwrap(), "1.0.1");
    second.sequence += 1;
    second.version = "1.0.0".into();
    assert!(matches!(
        accept_manifest(
            &second,
            &fixture.root.join("accepted-update.json"),
            11,
            "1.0.0",
            4,
            5
        ),
        Err(UpdateError::Rollback)
    ));
    assert_eq!(fixture.bytes("current"), b"new");
}

#[test]
fn control_requires_forward_recovery_and_changed_files_cannot_be_reactivated() {
    let fixture = Fixture::new("control", "control");
    let mut record = fixture.prepare();
    record.activate(&fixture.root, 4, 5).unwrap();
    record.record_failure(&fixture.root).unwrap();
    assert!(matches!(
        record.request_rollback(&fixture.root, 4, 5),
        Err(UpdateError::Incompatible)
    ));
    assert_eq!(fixture.bytes("current"), b"new");
    let target = fixture.root.join("versions/1.0.1/peerward");
    fs::write(&target, b"tampered").unwrap();
    assert!(matches!(
        record.activate(&fixture.root, 4, 5),
        Err(UpdateError::Digest)
    ));
    assert_eq!(fixture.load().stage(), UpdateStage::RecoveryRequired);
    fs::write(&target, b"new").unwrap();
    assert!(matches!(
        record.activate(&fixture.root, 4, 4),
        Err(UpdateError::Incompatible)
    ));
    record.activate(&fixture.root, 4, 5).unwrap();
    record.record_ready(&fixture.root).unwrap();
    assert_eq!(record.stage(), UpdateStage::Succeeded);
}

#[test]
fn corrupt_journals_and_unrelated_pointers_are_not_overwritten() {
    let fixture = Fixture::new("corrupt", "relay");
    let mut record = fixture.prepare();
    replace_symlink(
        &fixture.root.join("roles/relay"),
        "current",
        Path::new("../../versions/9.0.0/peerward"),
    )
    .unwrap();
    assert!(matches!(
        record.activate(&fixture.root, 4, 5),
        Err(UpdateError::RecoveryRequired)
    ));
    let journal = fixture.root.join("roles/relay/update-transaction.json");
    fs::write(&journal, b"{}").unwrap();
    assert!(UpdateTransaction::load(&fixture.root, "relay").is_err());
    assert!(record.record_failure(&fixture.root).is_err());
    assert_eq!(fs::read(&journal).unwrap(), b"{}");
}

#[test]
fn explicit_forward_repair_keeps_failed_evidence_and_requires_a_newer_release() {
    let fixture = Fixture::new("repair", "control");
    let mut record = fixture.prepare();
    record.activate(&fixture.root, 4, 5).unwrap();
    assert!(
        UpdateTransaction::prepare_repair(
            &fixture.root,
            "control",
            b"new",
            &fixture.artifact,
            &fixture.manifest,
            record.health_url()
        )
        .is_err()
    );
    record.record_failure(&fixture.root).unwrap();
    assert!(
        UpdateTransaction::prepare_repair(
            &fixture.root,
            "control",
            b"new",
            &fixture.artifact,
            &fixture.manifest,
            record.health_url()
        )
        .is_err()
    );
    let (manifest, artifact) = release(b"repair", "1.0.2", 3);
    accept_manifest(
        &manifest,
        &fixture.root.join("accepted-update.json"),
        11,
        "1.0.1",
        4,
        5,
    )
    .unwrap();
    let mut repair = UpdateTransaction::prepare_repair(
        &fixture.root,
        "control",
        b"repair",
        &artifact,
        &manifest,
        record.health_url(),
    )
    .unwrap();
    let retained: UpdateTransaction = serde_json::from_slice(
        &fs::read(
            fixture
                .root
                .join("roles/control/previous-update-transaction.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(retained, record);
    assert!(record.activate(&fixture.root, 4, 5).is_err());
    repair.activate(&fixture.root, 4, 5).unwrap();
    repair.record_ready(&fixture.root).unwrap();
    assert_eq!(fixture.bytes("current"), b"repair");
    assert_eq!(fixture.bytes("previous"), b"new");
}

#[test]
fn preview_does_not_consume_release_and_completed_retry_binds_its_original_digest() {
    let fixture = Fixture::new("preview", "relay");
    let state = fixture.root.join("accepted-update.json");
    let before = fs::read(&state).unwrap();
    let (future, _) = release(b"future", "1.0.2", 3);
    assert_eq!(
        preview_manifest(&future, &state, 11, "1.0.0", 4, 5).unwrap(),
        "1.0.0"
    );
    assert_eq!(fs::read(&state).unwrap(), before);
    let mut record = fixture.prepare();
    let digest = "a".repeat(64);
    record.bind_preview(&fixture.root, &digest).unwrap();
    assert!(record.bind_preview(&fixture.root, &"b".repeat(64)).is_err());
    record.activate(&fixture.root, 4, 5).unwrap();
    record.record_ready(&fixture.root).unwrap();
    assert!(record.matches_approved_request(
        &fixture.manifest,
        &fixture.artifact,
        record.health_url(),
        Some(&digest)
    ));
    assert!(!record.matches_approved_request(
        &fixture.manifest,
        &fixture.artifact,
        record.health_url(),
        Some(&"b".repeat(64))
    ));
    assert!(!record.matches_approved_request(
        &fixture.manifest,
        &fixture.artifact,
        record.health_url(),
        None
    ));
}

#[test]
fn sigkill_at_each_durable_boundary_can_resume_without_losing_previous() {
    for phase in ["prepared", "previous", "current", "restart"] {
        let fixture = Fixture::new(phase, "relay");
        fixture.prepare();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "transaction_tests::journal_kill_worker",
                "--exact",
                "--ignored",
            ])
            .env("PEERWARD_TEST_UPDATE_ROOT", &fixture.root)
            .env("PEERWARD_TEST_UPDATE_PHASE", phase)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !fixture.root.join("kill-ready").exists() && Instant::now() < deadline {
            assert!(
                child.try_wait().unwrap().is_none(),
                "worker exited before boundary {phase}"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        let ready = fixture.root.join("kill-ready").exists();
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(ready, "worker did not reach {phase}");
        let mut record = fixture.load();
        record.activate(&fixture.root, 4, 5).unwrap();
        record.record_ready(&fixture.root).unwrap();
        assert_eq!(fixture.bytes("current"), b"new");
        assert_eq!(fixture.bytes("previous"), b"old");
    }
}

#[test]
#[ignore = "subprocess entrypoint for the SIGKILL test"]
fn journal_kill_worker() {
    let root = PathBuf::from(std::env::var_os("PEERWARD_TEST_UPDATE_ROOT").expect("fixture root"));
    let phase = std::env::var("PEERWARD_TEST_UPDATE_PHASE").unwrap();
    let directory = root.join("roles/relay");
    // Explicitly recreate partial durable filesystem states, without adding
    // fault injection or arbitrary pauses to the production updater.
    if matches!(phase.as_str(), "previous" | "current") {
        replace_symlink(
            &directory,
            "previous",
            Path::new("../../versions/1.0.0/peerward"),
        )
        .unwrap();
        sync_directory(&directory).unwrap();
    }
    if phase == "current" {
        replace_symlink(
            &directory,
            "current",
            Path::new("../../versions/1.0.1/peerward"),
        )
        .unwrap();
        sync_directory(&directory).unwrap();
    }
    if phase == "restart" {
        UpdateTransaction::load(&root, "relay")
            .unwrap()
            .unwrap()
            .activate(&root, 4, 5)
            .unwrap();
    }
    File::create(root.join("kill-ready"))
        .unwrap()
        .sync_all()
        .unwrap();
    loop {
        std::thread::park();
    }
}
