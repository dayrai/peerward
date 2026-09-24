use super::*;
use peerward_credentials::{
    AuthoritySigningKey, RootSigningKey, SubjectId, UnsignedAuthority, UnsignedSubject,
};
use peerward_directory::{DirectorySigningKey, PeerCredentialBinding, PeerEntry};
use std::collections::BTreeMap;
use x25519_dalek::{PublicKey, StaticSecret};

struct Fixture {
    mesh: MeshId,
    signer: DirectorySigningKey,
    authority: AuthoritySigningKey,
    trust: TrustSet,
    distribution: DistributionCertificate,
    certificate: peerward_credentials::AuthorityCertificate,
}

impl Fixture {
    fn new() -> Self {
        let mesh = MeshId::new();
        let root = RootSigningKey::from_bytes(&[1; 32]);
        let authority = AuthoritySigningKey::from_bytes(&[2; 32]);
        let signer = DirectorySigningKey::from_bytes(&[3; 32]);
        let certificate = root
            .certify(UnsignedAuthority {
                mesh_id: mesh,
                serial: CredentialSerial::new(),
                public_key: authority.public_key(),
                not_before: UnixTime(1),
                not_after: UnixTime(1000),
            })
            .unwrap();
        let mut trust = TrustSet::new(root.public_key(), mesh);
        trust
            .add_authority(certificate.clone(), UnixTime(10))
            .unwrap();
        let distribution =
            authority.certify_distribution(mesh, signer.public_key().to_bytes(), [4; 32], [5; 32]);
        Self {
            mesh,
            signer,
            authority,
            trust,
            distribution,
            certificate,
        }
    }

    fn credential(&self, peer: PeerId, seed: u8) -> SubjectCredential {
        self.authority
            .issue(UnsignedSubject {
                subject: SubjectId::Peer(peer),
                mesh_id: self.mesh,
                identity_public_key: [seed; 32],
                public_noise_key: [seed + 1; 32],
                wireguard_public_key: PublicKey::from(&StaticSecret::from([seed; 32])).to_bytes(),
                serial: CredentialSerial::new(),
                not_before: UnixTime(1),
                not_after: UnixTime(2000),
            })
            .unwrap()
    }

    fn entry(&self, credential: &SubjectCredential, address: &str) -> PeerEntry {
        let SubjectId::Peer(peer_id) = credential.subject else {
            panic!("Peer fixture");
        };
        PeerEntry {
            secondary_address: None,
            mesh_id: self.mesh,
            peer_id,
            address: address.parse().unwrap(),
            identity_public_key: credential.identity_public_key,
            noise_public_key: credential.public_noise_key,
            credential_serial: credential.serial,
            accepted_credentials: vec![PeerCredentialBinding::from_subject(credential, None)],
            enabled: true,
            labels: BTreeMap::new(),
            not_after: credential.not_after,
        }
    }

    fn signed(&self, revision: u64, entries: Vec<PeerEntry>) -> SignedPeerDirectory {
        self.signer
            .sign_peers(
                self.mesh,
                revision,
                entries
                    .into_iter()
                    .map(|entry| self.signer.sign_peer(entry))
                    .collect(),
            )
            .unwrap()
    }

    fn directory(&self) -> WireguardDirectory {
        WireguardDirectory::new(
            self.mesh,
            self.trust.clone(),
            &self.distribution,
            UnixTime(10),
        )
        .unwrap()
    }
}

#[test]
fn directory_signer_cannot_substitute_root_signed_wireguard_keys() {
    let f = Fixture::new();
    let credential = f.credential(PeerId::new(), 10);
    let entry = f.entry(&credential, "10.0.0.2");
    let mut directory = f.directory();
    directory
        .install(&f.signed(1, vec![entry.clone()]), UnixTime(10))
        .unwrap();
    let mut forged = entry.clone();
    forged.accepted_credentials[0].wireguard_public_key =
        PublicKey::from(&StaticSecret::from([31; 32])).to_bytes();
    assert!(
        directory
            .install(&f.signed(2, vec![forged]), UnixTime(10))
            .is_err()
    );
    assert_eq!(directory.revision(), Some(1));
    assert!(
        directory
            .get(&credential.wireguard_public_key, UnixTime(10))
            .is_some()
    );
    assert!(
        directory
            .install(&f.signed(1, vec![entry.clone()]), UnixTime(10))
            .is_err()
    );
    assert!(directory.owns_source(
        &credential.wireguard_public_key,
        "10.0.0.2".parse().unwrap(),
        UnixTime(10)
    ));
    assert!(!directory.owns_source(
        &credential.wireguard_public_key,
        "10.0.0.3".parse().unwrap(),
        UnixTime(10)
    ));
    let foreign = Fixture::new();
    assert!(
        WireguardDirectory::new(foreign.mesh, f.trust.clone(), &f.distribution, UnixTime(10))
            .is_err()
    );
    let mut duplicate = entry.clone();
    duplicate.peer_id = PeerId::new();
    duplicate.address = "10.0.0.3".parse().unwrap();
    assert!(
        directory
            .install(&f.signed(2, vec![entry, duplicate]), UnixTime(10))
            .is_err()
    );
}

#[test]
fn exact_revocation_preserves_replacement_and_unrelated_peer_and_clears_engine_queue() {
    let f = Fixture::new();
    let local = PeerId::new();
    let remote = PeerId::new();
    let local_credential = f.credential(local, 10);
    let old = f.credential(remote, 20);
    let replacement = f.credential(remote, 30);
    let unrelated = f.credential(PeerId::new(), 40);
    let mut remote_entry = f.entry(&replacement, "10.0.0.3");
    remote_entry
        .accepted_credentials
        .push(PeerCredentialBinding::from_subject(
            &old,
            Some(UnixTime(100)),
        ));
    let entries = vec![
        f.entry(&local_credential, "10.0.0.2"),
        remote_entry,
        f.entry(&unrelated, "10.0.0.4"),
    ];
    let mut directory = f.directory();
    directory
        .install(&f.signed(1, entries.clone()), UnixTime(10))
        .unwrap();
    let mut engine = Engine::new(
        StaticSecret::from([10; 32]),
        peerward_wireguard::Limits::default(),
    )
    .unwrap();
    directory
        .reconcile_engine(&mut engine, local, UnixTime(10))
        .unwrap();
    assert_eq!(engine.peer_keys().len(), 3);
    let mut packet = vec![0_u8; 20];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&20_u16.to_be_bytes());
    engine
        .send(
            &old.wireguard_public_key,
            &packet,
            std::time::Instant::now(),
            |_, _| true,
        )
        .unwrap();
    assert_eq!(engine.pending_bytes(), packet.len());
    let revocations = f
        .signer
        .sign_revocations(f.mesh, 1, vec![old.serial])
        .unwrap();
    assert_eq!(
        directory.revoke(&revocations, UnixTime(10)).unwrap(),
        vec![old.wireguard_public_key]
    );
    directory
        .reconcile_engine(&mut engine, local, UnixTime(10))
        .unwrap();
    assert_eq!(engine.pending_bytes(), 0);
    assert_eq!(engine.peer_keys().len(), 2);
    assert_eq!(
        directory
            .active(remote, UnixTime(10))
            .unwrap()
            .credential
            .serial,
        replacement.serial
    );
    assert!(
        directory
            .get(&unrelated.wireguard_public_key, UnixTime(10))
            .is_some()
    );
    directory
        .revoke(
            &f.signer.sign_revocations(f.mesh, 2, Vec::new()).unwrap(),
            UnixTime(10),
        )
        .unwrap();
    directory
        .install(&f.signed(2, entries), UnixTime(10))
        .unwrap();
    assert!(
        directory
            .get(&old.wireguard_public_key, UnixTime(10))
            .is_none()
    );
    assert!(directory.revoke(&revocations, UnixTime(10)).is_err());
    directory
        .revoke(
            &f.signer
                .sign_revocations(f.mesh, 3, vec![local_credential.serial])
                .unwrap(),
            UnixTime(10),
        )
        .unwrap();
    assert!(
        directory
            .reconcile_engine(&mut engine, local, UnixTime(10))
            .is_err()
    );
    assert_eq!(
        engine.install(unrelated.wireguard_public_key),
        Err(peerward_wireguard::Error::Closed)
    );
}

#[test]
fn authority_expiry_bounds_longer_credentials_and_clock_rollback_does_not_reopen() {
    let f = Fixture::new();
    let peer = PeerId::new();
    let credential = f.credential(peer, 10);
    let mut directory = f.directory();
    directory
        .install(
            &f.signed(1, vec![f.entry(&credential, "10.0.0.2")]),
            UnixTime(10),
        )
        .unwrap();
    assert_eq!(
        directory
            .get(&credential.wireguard_public_key, UnixTime(10))
            .unwrap()
            .valid_until,
        UnixTime(1000)
    );
    assert!(
        directory
            .get(&credential.wireguard_public_key, UnixTime(1000))
            .is_none()
    );
    assert_eq!(
        directory.expire(UnixTime(1000)),
        vec![credential.wireguard_public_key]
    );
    assert!(
        directory
            .get(&credential.wireguard_public_key, UnixTime(10))
            .is_none()
    );
    assert!(
        directory
            .install(
                &f.signed(2, vec![f.entry(&credential, "10.0.0.2")]),
                UnixTime(10)
            )
            .is_err()
    );
}

#[path = "wireguard_runtime_tests.rs"]
mod runtime_tests;

#[test]
fn future_binding_does_not_commit_a_partial_directory_or_consume_its_revision() {
    let f = Fixture::new();
    let initial = f.credential(PeerId::new(), 10);
    let future = f
        .authority
        .issue(UnsignedSubject {
            subject: initial.subject,
            mesh_id: f.mesh,
            serial: initial.serial,
            identity_public_key: initial.identity_public_key,
            public_noise_key: initial.public_noise_key,
            wireguard_public_key: initial.wireguard_public_key,
            not_before: UnixTime(20),
            not_after: initial.not_after,
        })
        .unwrap();
    let signed = f.signed(1, vec![f.entry(&future, "10.0.0.1")]);
    let mut directory = f.directory();
    assert!(directory.install(&signed, UnixTime(10)).is_err());
    assert_eq!(directory.revision(), None);
    directory.install(&signed, UnixTime(20)).unwrap();
    assert!(
        directory
            .get(&future.wireguard_public_key, UnixTime(20))
            .is_some()
    );
}
