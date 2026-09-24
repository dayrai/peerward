/// A real authenticated Relay publishes the already-active replacement while the committed
/// old credential has expired. Recovery may inspect staged files, but cannot trust the journal alone.
async fn assert_staged_recovery_through_relay(
    current: &peerward_credentials::SubjectCredential,
    noise: [u8; 32],
    authority: &AuthoritySigningKey,
    root: &RootSigningKey,
    certificate: &peerward_credentials::AuthorityCertificate,
    distribution: &peerward_credentials::DistributionCertificate,
    relay: RelayId,
    endpoint: std::net::SocketAddr,
    remote: [u8; 32],
    now: u64,
) {
    use peerward_credentials::private_files::{read_private, write_private_atomic};
    use std::os::unix::fs::DirBuilderExt;
    let SubjectId::Peer(peer) = current.subject else {
        panic!()
    };
    let folder = std::env::temp_dir().join(format!(
        "peerward-rotation-recovery-{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&folder)
        .unwrap();
    let old_identity = [91; 32];
    let old_noise = [92; 32];
    let old_data = [93; 32];
    let old = authority
        .issue(UnsignedSubject {
            subject: current.subject,
            mesh_id: current.mesh_id,
            identity_public_key: ed25519_dalek::SigningKey::from_bytes(&old_identity)
                .verifying_key()
                .to_bytes(),
            public_noise_key: x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(
                old_noise,
            ))
            .to_bytes(),
            wireguard_public_key: x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(
                old_data,
            ))
            .to_bytes(),
            serial: CredentialSerial::new(),
            not_before: UnixTime(now - 60),
            not_after: UnixTime(now - 1),
        })
        .unwrap();
    for (name, bytes) in [
        ("peer.identity.key", old_identity),
        ("peer.key", old_noise),
        ("peer.wireguard.key", old_data),
        ("peer.identity.key.next", [1; 32]),
        ("peer.key.next", noise),
        ("peer.wireguard.key.next", [0x70; 32]),
    ] {
        write_private_atomic(&folder.join(name), hex::encode(bytes).as_bytes()).unwrap();
    }
    write_private_atomic(&folder.join("peer.credential"), &old.encode()).unwrap();
    write_private_atomic(&folder.join("peer.credential.next"), &current.encode()).unwrap();
    write_private_atomic(
        &folder.join("peer.key.rotation"),
        format!("staged:{}", peerward_types::RotationId::new()).as_bytes(),
    )
    .unwrap();
    write_private_atomic(&folder.join("distribution.cert"), &distribution.encode()).unwrap();
    let config: peerward_peer::PeerConfig = toml::from_str(&format!(
        "config_version = 4\nmesh_id = \"{}\"\npeer_id = \"{}\"\ncredential_file = \"{}/peer.credential\"\nidentity_private_key_file = \"{}/peer.identity.key\"\nprivate_key_file = \"{}/peer.key\"\nwireguard_private_key_file = \"{}/peer.wireguard.key\"\ndistribution_certificate_file = \"{}/distribution.cert\"\n[[relays]]\nrelay_id = \"{}\"\nendpoints = [\"tcp://{}\"]\npublic_key = \"{}\"\n",
        current.mesh_id, peer, folder.display(), folder.display(), folder.display(), folder.display(), folder.display(), relay, endpoint, hex::encode(remote),
    )).unwrap();
    let mut trust = TrustSet::new(root.public_key(), current.mesh_id);
    trust
        .add_authority(certificate.clone(), UnixTime(now))
        .unwrap();
    assert!(trust.verify_subject(&old, UnixTime(now)).is_err());
    let trust = Arc::new(trust);
    assert!(
        peerward_peer::staged_peer_identity_config(&config)
            .unwrap()
            .is_some()
    );
    assert!(
        peerward_peer::recover_activated_peer_identity(&config, Arc::clone(&trust))
            .await
            .unwrap()
    );
    assert_eq!(
        read_private(&folder.join("peer.credential"), 225).unwrap(),
        current.encode()
    );
    assert_eq!(
        read_private(&folder.join("peer.key"), 128).unwrap(),
        hex::encode(noise).as_bytes()
    );
    assert_eq!(
        read_private(&folder.join("peer.wireguard.key"), 128).unwrap(),
        hex::encode([0x70; 32]).as_bytes()
    );
    assert!(!folder.join("peer.key.rotation").exists());
    assert!(
        !peerward_peer::recover_activated_peer_identity(&config, trust)
            .await
            .unwrap()
    );
    std::fs::remove_dir_all(folder).unwrap();
}
