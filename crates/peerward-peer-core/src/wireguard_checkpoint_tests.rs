use super::*;
use crate::{SnapshotKind, checkpoint::Checkpoint};
use std::path::PathBuf;

struct PrivateState(PathBuf);
impl PrivateState {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!("peerward-checkpoint-{}", uuid::Uuid::new_v4())))
    }
}
impl Drop for PrivateState {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn restart_rejects_old_or_conflicting_state_and_allows_identical_verified_restore() {
    let f = Fixture::new();
    let local = f.credential(PeerId::new(), 10);
    let remote = f.credential(PeerId::new(), 20);
    let state = PrivateState::new();
    let directory = f.signed(
        8,
        vec![f.entry(&local, "10.0.0.1"), f.entry(&remote, "10.0.0.2")],
    );
    let policy = f.policy(12, true);
    let revocations = f.signer.sign_revocations(f.mesh, 4, vec![]).unwrap();
    {
        let mut runtime = f.runtime(local.clone(), 10);
        runtime.enable_checkpoint(&state.0, UnixTime(10)).unwrap();
        runtime.install_directory(&directory, UnixTime(10)).unwrap();
        runtime.install_policy(&policy).unwrap();
        assert!(!runtime.local_source_authorized("10.0.0.1".parse().unwrap(), UnixTime(10)));
        runtime.revoke(&revocations, UnixTime(10)).unwrap();
        f.authorize(&mut runtime);
        assert!(
            !runtime
                .send_tunnel(&udp(1, 2, 4242, 20), UnixTime(10), Instant::now())
                .unwrap()
                .is_empty()
        );
    }
    let mut runtime = f.runtime(local.clone(), 10);
    runtime.enable_checkpoint(&state.0, UnixTime(10)).unwrap();
    assert!(
        runtime
            .install_directory(
                &f.signed(7, vec![f.entry(&local, "10.0.0.1")]),
                UnixTime(10)
            )
            .is_err()
    );
    assert!(
        runtime
            .install_directory(
                &f.signed(8, vec![f.entry(&local, "10.0.0.1")]),
                UnixTime(10)
            )
            .is_err()
    );
    assert!(runtime.install_policy(&f.policy(11, true)).is_err());
    assert!(runtime.install_policy(&f.policy(12, false)).is_err());
    runtime.install_directory(&directory, UnixTime(10)).unwrap();
    runtime.revoke(&revocations, UnixTime(10)).unwrap();
    // Old policy has not been restored: directory alone cannot reopen local services or data.
    assert!(!runtime.local_source_authorized("10.0.0.1".parse().unwrap(), UnixTime(10)));
    runtime.install_policy(&policy).unwrap();
    runtime.install_directory(&directory, UnixTime(10)).unwrap();
    runtime.install_policy(&policy).unwrap();
    f.authorize(&mut runtime);
    assert!(runtime.local_source_authorized("10.0.0.1".parse().unwrap(), UnixTime(10)));
}

#[test]
fn rejected_signature_and_bad_policy_do_not_poison_durable_floors() {
    let f = Fixture::new();
    let local = f.credential(PeerId::new(), 10);
    let state = PrivateState::new();
    let mut runtime = f.runtime(local.clone(), 10);
    runtime.enable_checkpoint(&state.0, UnixTime(10)).unwrap();
    let initial = std::fs::read(state.0.join("state.json")).unwrap();
    let mut forged = f.signed(100, vec![f.entry(&local, "10.0.0.1")]);
    forged.signature[0] ^= 1;
    assert!(runtime.install_directory(&forged, UnixTime(10)).is_err());
    let malformed = f.signer.sign_policy(f.mesh, 100, vec![0xff]);
    assert!(runtime.install_policy(&malformed).is_err());
    assert_eq!(std::fs::read(state.0.join("state.json")).unwrap(), initial);
    runtime
        .install_directory(
            &f.signed(1, vec![f.entry(&local, "10.0.0.1")]),
            UnixTime(10),
        )
        .unwrap();
    runtime.install_policy(&f.policy(1, true)).unwrap();
}

#[test]
fn revocations_survive_omission_restart_and_local_credential_rotation() {
    let f = Fixture::new();
    let local = f.credential(PeerId::new(), 10);
    let replacement = f.credential(
        match local.subject {
            SubjectId::Peer(id) => id,
            SubjectId::Relay(_) => unreachable!(),
        },
        11,
    );
    let state = PrivateState::new();
    {
        let mut runtime = f.runtime(local.clone(), 10);
        runtime.enable_checkpoint(&state.0, UnixTime(10)).unwrap();
        runtime
            .revoke(
                &f.signer
                    .sign_revocations(f.mesh, 1, vec![local.serial])
                    .unwrap(),
                UnixTime(10),
            )
            .unwrap();
        runtime
            .revoke(
                &f.signer.sign_revocations(f.mesh, 2, vec![]).unwrap(),
                UnixTime(10),
            )
            .unwrap();
    }
    let mut runtime = f.runtime(replacement.clone(), 11);
    runtime.enable_checkpoint(&state.0, UnixTime(10)).unwrap();
    assert_eq!(runtime.revoked_credentials(), vec![local.serial]);
    assert!(
        runtime
            .stage(local, StaticSecret::from([10; 32]), UnixTime(10))
            .is_err()
    );
    runtime
        .install_directory(
            &f.signed(1, vec![f.entry(&replacement, "10.0.0.1")]),
            UnixTime(10),
        )
        .unwrap();
    runtime
        .revoke(
            &f.signer.sign_revocations(f.mesh, 2, vec![]).unwrap(),
            UnixTime(10),
        )
        .unwrap();
    assert_eq!(
        runtime.confirmed_local_credential(UnixTime(10)),
        Some(replacement)
    );
}

#[test]
fn failed_disk_commit_closes_keys_pending_output_and_shared_policy() {
    let f = Fixture::new();
    let local = f.credential(PeerId::new(), 10);
    let remote = f.credential(PeerId::new(), 20);
    let state = PrivateState::new();
    let mut runtime = f.runtime(local.clone(), 10);
    runtime.enable_checkpoint(&state.0, UnixTime(10)).unwrap();
    runtime
        .install_directory(
            &f.signed(
                1,
                vec![f.entry(&local, "10.0.0.1"), f.entry(&remote, "10.0.0.2")],
            ),
            UnixTime(10),
        )
        .unwrap();
    runtime
        .revoke(
            &f.signer.sign_revocations(f.mesh, 1, vec![]).unwrap(),
            UnixTime(10),
        )
        .unwrap();
    runtime.install_policy(&f.policy(1, true)).unwrap();
    f.authorize(&mut runtime);
    let packet = udp(1, 2, 4242, 20);
    let policy = runtime.policy();
    let output = runtime
        .send_tunnel(&packet, UnixTime(10), Instant::now())
        .unwrap();
    let WireguardOutput::Network { authorization, .. } = output[0] else {
        panic!()
    };
    assert!(runtime.pending_bytes() > 0);
    let path = state.0.join("state.json");
    std::fs::remove_file(&path).unwrap();
    std::fs::create_dir(&path).unwrap(); // Atomic rename cannot replace a directory.
    assert!(runtime.install_policy(&f.policy(2, false)).is_err());
    assert_eq!(runtime.credential_count(), 0);
    assert_eq!(runtime.pending_bytes(), 0);
    assert!(!runtime.delivery_current(authorization, UnixTime(10)));
    assert_eq!(
        policy.evaluate(&peerward_dataplane::parse_packet(&packet).unwrap(), 0),
        peerward_dataplane::Action::Deny
    );
}

#[test]
fn persistent_owner_binding_lock_and_corruption_fail_closed() {
    let state = PrivateState::new();
    let mesh = MeshId::new();
    let peer = PeerId::new();
    let (owner, _, _) = Checkpoint::open(&state.0, [1; 32], mesh, peer, UnixTime(10), 100).unwrap();
    assert!(Checkpoint::open(&state.0, [1; 32], mesh, peer, UnixTime(10), 100).is_err());
    drop(owner);
    for (root, bound_mesh, bound_peer) in [
        ([2; 32], mesh, peer),
        ([1; 32], MeshId::new(), peer),
        ([1; 32], mesh, PeerId::new()),
    ] {
        assert!(
            Checkpoint::open(&state.0, root, bound_mesh, bound_peer, UnixTime(10), 100).is_err()
        );
    }
    peerward_credentials::private_files::write_private_atomic(&state.0.join("state.json"), b"{}")
        .unwrap();
    assert!(Checkpoint::open(&state.0, [1; 32], mesh, peer, UnixTime(10), 100).is_err());
}

#[test]
fn every_signed_family_and_generation_lease_survives_clock_rollback() {
    let state = PrivateState::new();
    let mesh = MeshId::new();
    let peer = PeerId::new();
    let families = [
        SnapshotKind::Authorities,
        SnapshotKind::Peers,
        SnapshotKind::Policy,
        SnapshotKind::Revocations,
        SnapshotKind::Services,
        SnapshotKind::Relays,
    ];
    let (mut owner, _, ceiling) =
        Checkpoint::open(&state.0, [1; 32], mesh, peer, UnixTime(100), 10_000).unwrap();
    for kind in families {
        owner
            .commit(kind, 7, b"verified", UnixTime(100), &[])
            .unwrap();
    }
    drop(owner);
    let (mut owner, start, _) =
        Checkpoint::open(&state.0, [1; 32], mesh, peer, UnixTime(1), 1).unwrap();
    assert_eq!(start, ceiling);
    assert_eq!(owner.time_floor(), UnixTime(100));
    for kind in families {
        assert!(owner.check(kind, 6, b"verified").is_err());
        assert!(owner.check(kind, 7, b"substitution").is_err());
        assert!(owner.check(kind, 7, b"verified").unwrap());
        owner
            .commit(kind, 7, b"verified", UnixTime(1), &[])
            .unwrap();
        assert!(!owner.check(kind, 7, b"verified").unwrap());
    }
    let mut connectivity = crate::wireguard_connectivity::Connectivity::new(0);
    connectivity.reserve_generation(ceiling, ceiling + 1);
    connectivity.update(vec![]).unwrap();
    assert!(connectivity.resume().is_err());
}

#[test]
fn observed_expiry_cannot_be_undone_by_restart_with_an_older_clock() {
    let f = Fixture::new();
    let mut local = f.credential(PeerId::new(), 10);
    // Authority expiry (1000) is earlier than this credential's 2000 deadline.
    let state = PrivateState::new();
    let mut runtime = f.runtime(local.clone(), 10);
    runtime.enable_checkpoint(&state.0, UnixTime(10)).unwrap();
    runtime.tick(UnixTime(1000), Instant::now()).unwrap();
    assert_eq!(runtime.credential_count(), 0);
    drop(runtime);
    let mut runtime = f.runtime(local.clone(), 10);
    runtime.enable_checkpoint(&state.0, UnixTime(10)).unwrap();
    assert!(!runtime.accepts_carrier(&local, UnixTime(10)));
    assert_eq!(runtime.credential_count(), 0);
    // Keep this binding independent of any staged directory contents.
    local.signature[0] ^= 1;
    assert!(
        runtime
            .stage(local, StaticSecret::from([10; 32]), UnixTime(10))
            .is_err()
    );
}

#[cfg(unix)]
#[test]
fn private_checkpoint_rejects_symlink_and_world_readable_state() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let state = PrivateState::new();
    let mesh = MeshId::new();
    let peer = PeerId::new();
    let (owner, _, _) = Checkpoint::open(&state.0, [1; 32], mesh, peer, UnixTime(10), 1).unwrap();
    drop(owner);
    let path = state.0.join("state.json");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(Checkpoint::open(&state.0, [1; 32], mesh, peer, UnixTime(10), 1).is_err());
    std::fs::remove_file(&path).unwrap();
    symlink("owner.lock", &path).unwrap();
    assert!(Checkpoint::open(&state.0, [1; 32], mesh, peer, UnixTime(10), 1).is_err());
}

#[test]
fn missing_committed_state_and_late_checkpoint_attachment_are_rejected() {
    let state = PrivateState::new();
    let f = Fixture::new();
    let local = f.credential(PeerId::new(), 10);
    let mut runtime = f.runtime(local.clone(), 10);
    runtime.install_policy(&f.policy(1, true)).unwrap();
    assert!(runtime.enable_checkpoint(&state.0, UnixTime(10)).is_err());
    let mut runtime = f.runtime(local.clone(), 10);
    runtime.enable_checkpoint(&state.0, UnixTime(10)).unwrap();
    drop(runtime);
    std::fs::remove_file(state.0.join("state.json")).unwrap();
    let mut runtime = f.runtime(local, 10);
    assert!(runtime.enable_checkpoint(&state.0, UnixTime(10)).is_err());
    assert_eq!(runtime.credential_count(), 0);
}

#[test]
fn initial_signed_revision_zero_is_distinct_from_missing_state() {
    let f = Fixture::new();
    let local = f.credential(PeerId::new(), 10);
    let state = PrivateState::new();
    let signed = f.signer.sign_revocations(f.mesh, 0, vec![]).unwrap();
    let mut runtime = f.runtime(local.clone(), 10);
    runtime.enable_checkpoint(&state.0, UnixTime(10)).unwrap();
    runtime.revoke(&signed, UnixTime(10)).unwrap();
    drop(runtime);
    let mut runtime = f.runtime(local, 10);
    runtime.enable_checkpoint(&state.0, UnixTime(10)).unwrap();
    runtime.revoke(&signed, UnixTime(10)).unwrap();
    runtime
        .revoke(
            &f.signer.sign_revocations(f.mesh, 1, vec![]).unwrap(),
            UnixTime(10),
        )
        .unwrap();
    assert!(runtime.revoke(&signed, UnixTime(10)).is_err());
}

#[test]
fn pending_manifest_is_durable_and_cannot_be_replayed_into_a_live_lease_after_restart() {
    use peerward_management::*;
    use sha2::{Digest as _, Sha256};
    let f = Fixture::new();
    let local = f.credential(PeerId::new(), 10);
    let state = PrivateState::new();
    let directory = f.signed(1, vec![f.entry(&local, "10.0.0.1")]);
    let deny = f.policy(2, false);
    let delivery = {
        let mut runtime = f.runtime(local.clone(), 10);
        runtime.enable_checkpoint(&state.0, UnixTime(10)).unwrap();
        runtime.install_directory(&directory, UnixTime(10)).unwrap();
        runtime.install_policy(&f.policy(1, true)).unwrap();
        f.authorize(&mut runtime);
        let resources = ResourceConfiguration::default();
        let dns: Vec<DnsProfile> = vec![];
        let mut parts = runtime.configuration_dependencies();
        parts.insert(
            ConfigurationPart::Policy,
            ComponentReference {
                version: 2,
                digest: Sha256::digest(peerward_directory::encode_policy(&deny).unwrap()).into(),
            },
        );
        parts.insert(
            ConfigurationPart::Resources,
            ComponentReference {
                version: 1,
                digest: content_digest(&resources).unwrap(),
            },
        );
        parts.insert(
            ConfigurationPart::Dns,
            ComponentReference {
                version: 1,
                digest: content_digest(&dns).unwrap(),
            },
        );
        let manifest = ConfigurationManifest {
            mesh_id: f.mesh,
            version: 2,
            parts,
        };
        let lease = AuthorizationLease {
            mesh_id: f.mesh,
            configuration_digest: content_digest(&manifest).unwrap(),
            sequence: 2,
            issued_at: 10,
            valid_until: 910,
        };
        let delivery = ConfigurationDelivery {
            manifest: f.signer.sign_manifest(manifest).unwrap(),
            lease: f.signer.sign_lease(lease).unwrap(),
            resources,
            dns,
        };
        assert!(
            !runtime
                .install_configuration(delivery.clone(), UnixTime(10), Instant::now())
                .unwrap()
        );
        assert_eq!(runtime.authorization_floor().lease_sequence, 2);
        assert!(!runtime.local_source_authorized("10.0.0.1".parse().unwrap(), UnixTime(10)));
        delivery
    };
    let mut runtime = f.runtime(local, 10);
    runtime.enable_checkpoint(&state.0, UnixTime(10)).unwrap();
    assert_eq!(runtime.authorization_floor().lease_sequence, 2);
    assert!(!runtime.data_ready(UnixTime(10)));
    assert!(matches!(runtime.core_management_receipt(UnixTime(10)),
        Some(peerward_management::PeerOperation::Applied {
            category: peerward_management::ApplicationCategory::Core,
            result: peerward_management::ApplicationResult::Rejected,
            lease_sequence: 2, reason: Some(reason), ..
        }) if reason == peerward_management::FRESH_AUTHORIZATION_REQUIRED));
    runtime.install_directory(&directory, UnixTime(10)).unwrap();
    runtime.install_policy(&deny).unwrap();
    runtime
        .authorities(
            &f.authority
                .sign_authority_bundle(f.mesh, 1, f.certificate.clone(), vec![], vec![])
                .unwrap(),
            UnixTime(10),
        )
        .unwrap();
    runtime
        .revoke(
            &f.signer.sign_revocations(f.mesh, 1, vec![]).unwrap(),
            UnixTime(10),
        )
        .unwrap();
    assert!(
        !runtime
            .install_configuration(delivery.clone(), UnixTime(10), Instant::now())
            .unwrap()
    );
    assert!(!runtime.local_source_authorized("10.0.0.1".parse().unwrap(), UnixTime(10)));
    let mut fresh = delivery;
    fresh.lease.lease.sequence = 3;
    fresh.lease = f.signer.sign_lease(fresh.lease.lease).unwrap();
    assert!(
        runtime
            .install_configuration(fresh, UnixTime(10), Instant::now())
            .unwrap()
    );
    assert!(runtime.data_ready(UnixTime(10)));
    assert!(matches!(
        runtime.core_management_receipt(UnixTime(10)),
        Some(peerward_management::PeerOperation::Applied {
            result: peerward_management::ApplicationResult::Applied,
            lease_sequence: 3,
            reason: None,
            ..
        })
    ));
    runtime.resume_after_suspend();
    assert!(!runtime.data_ready(UnixTime(10)));
    assert!(matches!(
        runtime.core_management_receipt(UnixTime(10)),
        Some(peerward_management::PeerOperation::Applied {
            result: peerward_management::ApplicationResult::Rejected,
            lease_sequence: 3,
            ..
        })
    ));
}
