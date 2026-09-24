use super::*;

#[test]
fn packet_runtime_errors_are_not_misreported_as_relay_unavailability() {
    use std::error::Error as _;
    for error in [
        PacketPumpError::InvalidControl,
        PacketPumpError::SessionPending,
    ] {
        let message = error.to_string();
        let converted = packet_error_to_peer(error);
        assert!(matches!(converted, PeerError::PacketRuntime(_)));
        assert_eq!(converted.source().unwrap().to_string(), message);
    }
}

#[test]
fn redundant_peer_directory_delivery_preserves_committed_state() {
    let mesh = MeshId::new();
    let signing_key = DirectorySigningKey::from_bytes(&[41; 32]);
    let mut state = DirectPeerDirectory::new(mesh, signing_key.public_key());
    for revision in [1, 1, 2, 1, 2, 3] {
        let signed = signing_key.sign_peers(mesh, revision, Vec::new()).unwrap();
        let previous = state
            .signed_directory()
            .map(|value| value.directory.revision);
        let committed = state
            .apply_chunk(&peerward_wire::PeerDirectoryChunk {
                mesh_id: mesh.as_bytes().to_vec(),
                revision,
                index: 0,
                count: 1,
                body: encode_peer_directory(&signed).unwrap(),
            })
            .unwrap();
        assert_eq!(committed, previous.is_none_or(|value| revision > value));
        assert_eq!(
            state.signed_directory().unwrap().directory.revision,
            previous.unwrap_or(0).max(revision)
        );
    }
}

#[test]
fn signed_peer_directory_preserves_dns_and_exact_revocation() {
    let mesh = MeshId::from_str("970a3f18-1c6f-4da6-a223-f9623958a928").unwrap();
    let remote_peer = PeerId::from_str("778f4317-0d08-4aab-9620-ca2c99a5ee3e").unwrap();
    let serial = CredentialSerial::from_uuid(
        uuid::Uuid::parse_str("40ee7506-2ee1-4b0b-a00c-8f6ec9900011").unwrap(),
    )
    .unwrap();
    let (_, remote_public) = noise_pair();
    let directory_signer = DirectorySigningKey::from_bytes(&[41; 32]);
    let entry = directory_signer.sign_peer(PeerEntry {
        secondary_address: None,
        mesh_id: mesh,
        peer_id: remote_peer,
        address: "10.44.0.9".parse().unwrap(),
        identity_public_key: [32; 32],
        noise_public_key: remote_public,
        credential_serial: serial,
        accepted_credentials: vec![peerward_directory::PeerCredentialBinding {
            serial,
            identity_public_key: [32; 32],
            noise_public_key: remote_public,
            wireguard_public_key: {
                let mut key = [0x77; 32];
                key[..16].copy_from_slice((serial).as_bytes());
                key
            },
            not_before: peerward_types::UnixTime(0),
            not_after: UnixTime(100),
            overlap_until: None,
            signature: [0; 64],
        }],
        enabled: true,
        labels: BTreeMap::from([("name".into(), "device".into())]),
        not_after: UnixTime(100),
    });
    let signed = directory_signer.sign_peers(mesh, 1, vec![entry]).unwrap();
    let encoded = encode_peer_directory(&signed).unwrap();
    let mut state = DirectPeerDirectory::new(mesh, directory_signer.public_key());
    assert!(
        state
            .apply_chunk(&peerward_wire::PeerDirectoryChunk {
                mesh_id: mesh.as_bytes().to_vec(),
                revision: 1,
                index: 0,
                count: 1,
                body: encoded,
            })
            .unwrap()
    );
    assert!(state.dns_by_name("device").is_some());
    let relay_id = RelayId::new();
    let relays = directory_signer
        .sign_relays(
            mesh,
            1,
            vec![RelayEntry {
                relay_id,
                peer_endpoints: vec!["tcp://127.0.0.1:7777".parse().unwrap()],
                backbone_endpoints: vec!["tcp://127.0.0.1:7778".parse().unwrap()],
                noise_public_key: [91; 32],
                credential_serial: CredentialSerial::new(),
            }],
        )
        .unwrap();
    assert!(
        state
            .apply_relay_chunk(&peerward_wire::RelayDirectoryChunk {
                mesh_id: mesh.as_bytes().to_vec(),
                revision: 1,
                index: 0,
                count: 1,
                body: encode_relay_directory(&relays).unwrap(),
            })
            .unwrap()
    );
    assert!(
        state
            .apply_relay_chunk(&peerward_wire::RelayDirectoryChunk {
                mesh_id: mesh.as_bytes().to_vec(),
                revision: 1,
                index: 0,
                count: 1,
                body: vec![1],
            })
            .is_ok_and(|committed| !committed)
    );
    state.revoke(serial);
    assert!(state.dns_by_name("device").is_none());
    // A subsequent signed directory must not resurrect a known revoked credential.
    let retained = state.signed_directory().unwrap().directory.entries;
    let newer = directory_signer.sign_peers(mesh, 2, retained).unwrap();
    state
        .apply_chunk(&peerward_wire::PeerDirectoryChunk {
            mesh_id: mesh.as_bytes().to_vec(),
            revision: 2,
            index: 0,
            count: 1,
            body: encode_peer_directory(&newer).unwrap(),
        })
        .unwrap();
    assert!(state.dns_by_name("device").is_none());
}
