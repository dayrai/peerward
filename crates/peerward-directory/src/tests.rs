use std::str::FromStr;

use super::*;

#[test]
fn redundant_chunks_deduplicate_without_weakening_strict_assembly() {
    let chunks = split_chunks(mesh(), 1, b"abcdef", 3).unwrap();
    let mut assembler = ChunkAssembler::new(mesh(), 8, 32);
    assert_eq!(assembler.push_redundant(chunks[0].clone()).unwrap(), None);
    assert_eq!(assembler.push_redundant(chunks[0].clone()).unwrap(), None);
    assert_eq!(
        assembler.push_redundant(chunks[1].clone()).unwrap(),
        Some(b"abcdef".to_vec())
    );
    assembler.commit(1).unwrap();
    for chunk in &chunks {
        assert_eq!(assembler.push_redundant(chunk.clone()).unwrap(), None);
    }
    assert_eq!(assembler.accepted_revision(), Some(1));
    assert!(matches!(
        assembler.push(chunks[0].clone()),
        Err(DirectoryError::Rollback)
    ));
    let mut foreign = chunks[0].clone();
    foreign.mesh_id = MeshId::new();
    assert!(matches!(
        assembler.push_redundant(foreign),
        Err(DirectoryError::WrongMesh)
    ));
}

#[test]
fn redundant_chunks_reject_conflicting_parts_and_keep_bounds() {
    let chunks = split_chunks(mesh(), 1, b"abcdef", 3).unwrap();
    let mut assembler = ChunkAssembler::new(mesh(), 8, 32);
    assembler.push_redundant(chunks[0].clone()).unwrap();
    let mut conflict = chunks[0].clone();
    conflict.body = b"xyz".to_vec();
    assert!(matches!(
        assembler.push_redundant(conflict),
        Err(DirectoryError::MixedChunks)
    ));
    let mut bounded = ChunkAssembler::new(mesh(), 8, 5);
    bounded.push_redundant(chunks[0].clone()).unwrap();
    assert!(matches!(
        bounded.push_redundant(chunks[1].clone()),
        Err(DirectoryError::MixedChunks)
    ));
}

fn mesh() -> MeshId {
    MeshId::from_str("970a3f18-1c6f-4da6-a223-f9623958a928").unwrap()
}

fn peer(value: &str) -> PeerId {
    PeerId::from_str(value).unwrap()
}

fn serial(value: &str) -> CredentialSerial {
    CredentialSerial::from_str(value).unwrap()
}

fn relay(index: u16) -> RelayId {
    RelayId::from_str(&format!("00000000-0000-4000-8000-{index:012x}")).unwrap()
}

fn entry(id: &str, address: [u8; 4]) -> PeerEntry {
    PeerEntry {
        secondary_address: None,
        mesh_id: mesh(),
        peer_id: peer(id),
        address: IpAddr::V4(std::net::Ipv4Addr::from(address)),
        identity_public_key: [6; 32],
        noise_public_key: [7; 32],
        credential_serial: serial("40ee7506-2ee1-4b0b-a00c-8f6ec9900011"),
        accepted_credentials: vec![PeerCredentialBinding {
            serial: serial("40ee7506-2ee1-4b0b-a00c-8f6ec9900011"),
            identity_public_key: [6; 32],
            noise_public_key: [7; 32],
            wireguard_public_key: {
                let mut key = [0x77; 32];
                key[..16].copy_from_slice(peer(id).as_bytes());
                key
            },
            not_before: peerward_types::UnixTime(0),
            not_after: UnixTime(1_900_000_000),
            overlap_until: None,
            signature: [0; 64],
        }],
        enabled: true,
        labels: BTreeMap::from([("region".into(), "east".into())]),
        not_after: UnixTime(1_900_000_000),
    }
}

#[test]
fn signatures_cover_entries_order_and_revision() {
    let key = DirectorySigningKey::from_bytes(&[19; 32]);
    let a = key.sign_peer(entry("778f4317-0d08-4aab-9620-ca2c99a5ee3e", [10, 0, 0, 2]));
    let b = key.sign_peer(entry("092a279f-d029-45b9-a6ad-6c31bde133e2", [10, 0, 0, 3]));
    let mut signed = key.sign_peers(mesh(), 8, vec![a, b]).unwrap();
    assert_eq!(
        key.public_key().verify_peers(&signed, mesh(), Some(7)),
        Ok(())
    );
    signed.directory.entries[0].entry.address = "fd42::99".parse().unwrap();
    assert_eq!(
        key.public_key().verify_peers(&signed, mesh(), Some(7)),
        Err(DirectoryError::InvalidSignature)
    );
}

#[test]
fn chunk_assembly_is_order_independent_and_rejects_mixing_and_rollback() {
    let chunks = split_chunks(mesh(), 4, b"abcdefghij", 3).unwrap();
    let mut assembler = ChunkAssembler::new(mesh(), 8, 32);
    assert_eq!(assembler.push(chunks[2].clone()).unwrap(), None);
    assert_eq!(assembler.push(chunks[0].clone()).unwrap(), None);
    assert_eq!(assembler.push(chunks[3].clone()).unwrap(), None);
    assert_eq!(
        assembler.push(chunks[1].clone()).unwrap(),
        Some(b"abcdefghij".to_vec())
    );
    assembler.commit(4).unwrap();
    assert_eq!(
        assembler.push(chunks[0].clone()),
        Err(DirectoryError::Rollback)
    );

    let mut mixed = ChunkAssembler::new(mesh(), 8, 32);
    mixed.push(chunks[0].clone()).unwrap();
    let mut foreign_revision = chunks[1].clone();
    foreign_revision.revision = 5;
    assert_eq!(
        mixed.push(foreign_revision),
        Err(DirectoryError::MixedChunks)
    );
}

#[test]
fn signed_state_chunks_support_multi_megabyte_distributions_with_a_fixed_bound() {
    let body = vec![0x5a; 2 * 1024 * 1024];
    let chunks = split_chunks(mesh(), 9, &body, 48 * 1024).unwrap();
    let mut assembler = ChunkAssembler::new(
        mesh(),
        peerward_types::MAX_SIGNED_STATE_CHUNKS,
        peerward_types::MAX_SIGNED_STATE_BYTES,
    );
    let mut completed = None;
    for chunk in chunks {
        completed = assembler.push(chunk).unwrap().or(completed);
    }
    assert_eq!(completed.as_deref(), Some(body.as_slice()));
}

#[test]
fn ten_thousand_overlapping_peer_credentials_fit_the_shared_distribution_bound() {
    let key = DirectorySigningKey::from_bytes(&[29; 32]);
    let entries = (0_u32..10_000)
        .map(|index| {
            let mut entry = PeerEntry {
                secondary_address: None,
                mesh_id: mesh(),
                peer_id: peer(&format!("00000000-0000-4000-8000-{index:012x}")),
                address: IpAddr::V4(std::net::Ipv4Addr::from(0x0a60_0000 + index + 2)),
                identity_public_key: [u8::try_from(index % 250 + 1).unwrap(); 32],
                noise_public_key: [u8::try_from((index + 1) % 250 + 1).unwrap(); 32],
                credential_serial: serial(&format!(
                    "00000000-0000-4000-8001-{:012x}",
                    index + 20_001
                )),
                accepted_credentials: vec![PeerCredentialBinding {
                    serial: serial(&format!("00000000-0000-4000-8001-{:012x}", index + 20_001)),
                    identity_public_key: [u8::try_from(index % 250 + 1).unwrap(); 32],
                    noise_public_key: [u8::try_from((index + 1) % 250 + 1).unwrap(); 32],
                    wireguard_public_key: {
                        let mut key = [0x77; 32];
                        key[..16].copy_from_slice(
                            (serial(&format!("00000000-0000-4000-8001-{:012x}", index + 20_001)))
                                .as_bytes(),
                        );
                        key
                    },
                    not_before: peerward_types::UnixTime(0),
                    not_after: UnixTime(1_900_000_000),
                    overlap_until: None,
                    signature: [255; 64],
                }],
                enabled: true,
                labels: BTreeMap::from([("scale".into(), "10000".into())]),
                not_after: UnixTime(1_900_000_000),
            };
            let mut previous = entry.accepted_credentials[0].clone();
            previous.serial = serial(&format!("00000000-0000-4000-8002-{:012x}", index + 20_001));
            previous.wireguard_public_key[..16].copy_from_slice(previous.serial.as_bytes());
            previous.overlap_until = Some(UnixTime(1_800_000_000));
            entry.accepted_credentials.push(previous);
            key.sign_peer(entry)
        })
        .collect();
    let directory = key.sign_peers(mesh(), 10_000, entries).unwrap();
    let encoded = encode_peer_directory(&directory).unwrap();
    assert!(encoded.len() > 8 * 1024 * 1024);
    assert!(encoded.len() <= peerward_types::MAX_SIGNED_STATE_BYTES);
    let chunks = split_chunks(mesh(), 10_000, &encoded, 48 * 1024).unwrap();
    assert!(chunks.len() <= peerward_types::MAX_SIGNED_STATE_CHUNKS as usize);
    let mut assembler = ChunkAssembler::new(
        mesh(),
        peerward_types::MAX_SIGNED_STATE_CHUNKS,
        peerward_types::MAX_SIGNED_STATE_BYTES,
    );
    let mut result = None;
    for chunk in chunks {
        result = assembler.push(chunk).unwrap().or(result);
    }
    assert_eq!(result.as_deref(), Some(encoded.as_slice()));
}

#[test]
fn peer_transcript_and_signature_have_stable_golden_vectors() {
    let key = DirectorySigningKey::from_bytes(&[19; 32]);
    let signed = key.sign_peer(entry("778f4317-0d08-4aab-9620-ca2c99a5ee3e", [10, 0, 0, 2]));
    assert_eq!(
        hex::encode(peer_entry_transcript(&signed.entry)),
        "70656572776172642f706565722d6469726563746f72792d656e7472792f763400970a3f181c6f4da6a223f9623958a928778f43170d084aab9620ca2c99a5ee3e040a000002000606060606060606060606060606060606060606060606060606060606060606070707070707070707070707070707070707070707070707070707070707070740ee75062ee14b0ba00c8f6ec99000110000000101970a3f181c6f4da6a223f9623958a928778f43170d084aab9620ca2c99a5ee3e06060606060606060606060606060606060606060606060606060606060606060707070707070707070707070707070707070707070707070707070707070707778f43170d084aab9620ca2c99a5ee3e7777777777777777777777777777777740ee75062ee14b0ba00c8f6ec9900011000000000000000000000000713fb3000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000100000006726567696f6e000000046561737400000000713fb300"
    );
    assert_eq!(
        hex::encode(signed.signature),
        "b83c43fb53b17c194561e04f6ad62155d18a9f865abf1d36595252f41f593a68b4878f6026937813b5455156b48084e1df00a7e4f479e06d438bcf31db9a6f0e"
    );
}

#[test]
fn relay_validation_rejects_bad_endpoints_and_rollbacks() {
    let key = DirectorySigningKey::from_bytes(&[9; 32]);
    let relay_id = RelayId::from_str("81708cad-c18b-4d0f-a580-026c4c285845").unwrap();
    let item = RelayEntry {
        relay_id,
        peer_endpoints: vec!["tcp://127.0.0.1:7777".parse().unwrap()],
        backbone_endpoints: vec!["tcp://127.0.0.1:7778".parse().unwrap()],
        noise_public_key: [3; 32],
        credential_serial: serial("68d07b9e-b046-4402-b688-d606a29e797e"),
    };
    let signed = key.sign_relays(mesh(), 2, vec![item]).unwrap();
    assert_eq!(
        key.public_key().verify_relays(&signed, mesh(), Some(1)),
        Ok(())
    );
    assert_eq!(
        key.public_key().verify_relays(&signed, mesh(), Some(2)),
        Err(DirectoryError::Rollback)
    );
}

#[test]
fn topology_rolls_from_full_mesh_to_bounded_regional_graph() {
    let nodes = (1_u16..=8)
        .map(|index| RelayTopologyNodeV1 {
            relay_id: relay(index),
            region: if index <= 4 { "east" } else { "west" }.into(),
            routing_weight: 100 + index,
            capabilities: peerward_wire_sparse_capability_for_test(),
        })
        .collect::<Vec<_>>();
    let sparse = RelayTopologyV1::build(
        mesh(),
        3,
        nodes.clone(),
        8,
        peerward_wire_sparse_capability_for_test(),
    )
    .unwrap();
    assert_eq!(sparse.mode, RelayTopologyMode::Sparse);
    assert!(sparse.edges.len() < 28);
    assert!(!sparse.next_hops(relay(1), relay(8)).is_empty());

    let mut mixed = nodes;
    mixed[0].capabilities = 0;
    let compatibility = RelayTopologyV1::build(
        mesh(),
        4,
        mixed,
        8,
        peerward_wire_sparse_capability_for_test(),
    )
    .unwrap();
    assert_eq!(compatibility.mode, RelayTopologyMode::FullMesh);
    assert_eq!(compatibility.edges.len(), 28);
}

#[test]
fn topology_routes_use_control_aggregated_rtt_and_loss_costs() {
    let nodes = (1_u16..=4)
        .map(|index| RelayTopologyNodeV1 {
            relay_id: relay(index),
            region: "default".into(),
            routing_weight: 100,
            capabilities: 0,
        })
        .collect();
    let mut topology = RelayTopologyV1::build(
        mesh(),
        5,
        nodes,
        8,
        peerward_wire_sparse_capability_for_test(),
    )
    .unwrap();
    topology
        .apply_link_health(&BTreeMap::from([
            ((relay(1), relay(2)), (10, 0)),
            ((relay(2), relay(4)), (10, 0)),
            ((relay(1), relay(3)), (20, 0)),
            ((relay(3), relay(4)), (20, 0)),
            ((relay(1), relay(4)), (1_000, 0)),
        ]))
        .unwrap();
    assert_eq!(
        topology.next_hops(relay(1), relay(4)),
        vec![relay(2), relay(3)]
    );

    assert!(
        topology
            .apply_link_health(&BTreeMap::from([((relay(1), relay(2)), (120_001, 0),)]))
            .is_err()
    );
}

#[test]
fn thirty_two_relay_sparse_topology_is_redundant_and_four_hop_reachable() {
    let nodes = (1_u16..=32)
        .map(|index| RelayTopologyNodeV1 {
            relay_id: relay(index),
            region: format!("region-{}", (index - 1) / 8),
            routing_weight: 100 + index,
            capabilities: peerward_wire_sparse_capability_for_test(),
        })
        .collect::<Vec<_>>();
    let topology = RelayTopologyV1::build(
        mesh(),
        6,
        nodes,
        8,
        peerward_wire_sparse_capability_for_test(),
    )
    .unwrap();
    assert_eq!(topology.mode, RelayTopologyMode::Sparse);
    assert!(topology.edges.len() < 32 * 10);
    for source in 1_u16..=32 {
        for destination in 1_u16..=32 {
            if source != destination {
                assert_eq!(
                    topology.next_hops(relay(source), relay(destination)).len(),
                    2,
                    "missing redundant bounded route {source}->{destination}",
                );
            }
        }
    }
}

#[test]
fn topology_has_an_independent_authenticated_transcript() {
    let key = DirectorySigningKey::from_bytes(&[31; 32]);
    let topology = RelayTopologyV1::build(
        mesh(),
        9,
        vec![
            RelayTopologyNodeV1 {
                relay_id: relay(1),
                region: "default".into(),
                routing_weight: 100,
                capabilities: 0,
            },
            RelayTopologyNodeV1 {
                relay_id: relay(2),
                region: "default".into(),
                routing_weight: 100,
                capabilities: 0,
            },
        ],
        8,
        peerward_wire_sparse_capability_for_test(),
    )
    .unwrap();
    let mut signed = key.sign_relay_topology(topology).unwrap();
    assert_eq!(
        key.public_key()
            .verify_relay_topology(&signed, mesh(), Some(8)),
        Ok(())
    );
    let encoded = encode_relay_topology(&signed).unwrap();
    assert_eq!(decode_relay_topology(&encoded).unwrap(), signed);
    signed.topology.nodes[0].routing_weight += 1;
    assert_eq!(
        key.public_key()
            .verify_relay_topology(&signed, mesh(), Some(8)),
        Err(DirectoryError::InvalidSignature)
    );
}

const fn peerward_wire_sparse_capability_for_test() -> u64 {
    1 << 2
}

#[test]
fn revision_relay_and_policy_signatures_are_golden_vectors() {
    let signer = DirectorySigningKey::from_bytes(&[23; 32]);
    let peer_entry = signer.sign_peer(entry("778f4317-0d08-4aab-9620-ca2c99a5ee3e", [10, 0, 0, 2]));
    let peers = signer.sign_peers(mesh(), 11, vec![peer_entry]).unwrap();
    let relay_entry = RelayEntry {
        relay_id: RelayId::from_str("81708cad-c18b-4d0f-a580-026c4c285845").unwrap(),
        peer_endpoints: vec!["tcp://127.0.0.1:7777".parse().unwrap()],
        backbone_endpoints: vec!["tcp://127.0.0.1:7778".parse().unwrap()],
        noise_public_key: [5; 32],
        credential_serial: serial("68d07b9e-b046-4402-b688-d606a29e797e"),
    };
    let relays = signer.sign_relays(mesh(), 12, vec![relay_entry]).unwrap();
    let policy = signer.sign_policy(mesh(), 13, vec![1, 3, 3, 7]);
    let actual = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        hex::encode(peer_revision_transcript(&peers.directory)),
        hex::encode(peers.signature),
        hex::encode(relay_transcript(&relays.directory)),
        hex::encode(relays.signature),
        hex::encode(policy_transcript(&policy.bundle)),
        hex::encode(policy.signature),
    );
    let expected = concat!(
        "70656572776172642f706565722d6469726563746f72792d7265766973696f6e2f763100970a3f181c6f4da6a223f9623958a928000000000000000b00000001778f43170d084aab9620ca2c99a5ee3e717de0c9d47417703fa79543d5c2a22124e550b8edd0df3775d83d1538af5478c126c67d65322875bb92b05fa568374a5b6bd393ae25568f861e5868b128ee07\n",
        "79e1a7a3c1838d1398a9d6d565b8d313f78348c800c30213fed2d173daeacf9f9e300cc94c0b2a2719ab7cc9ecaadb2e0651b173530489a22cde8862acdb4f0c\n",
        "70656572776172642f72656c61792d6469726563746f72792f763200970a3f181c6f4da6a223f9623958a928000000000000000c0000000181708cadc18b4d0fa580026c4c28584500000001000000147463703a2f2f3132372e302e302e313a3737373700000001000000147463703a2f2f3132372e302e302e313a37373738050505050505050505050505050505050505050505050505050505050505050568d07b9eb0464402b688d606a29e797e\n",
        "d5f4a458a2a6d0abe47637439f4e22b8e1bad6a1aa57f0d1b5e7da0e0fbb372a42b098e591b0ec2a1de0239e7b737efc401a2516d47b7d33106a8362aebd130b\n",
        "70656572776172642f706f6c6963792d62756e646c652f763100970a3f181c6f4da6a223f9623958a928000000000000000d0000000401030307\n",
        "4e7b475b90aac2db2734634603ba4a0cb09a06b2812662c7b1b86f5beeb5ae380673e581345b80a1e3fae232f264cf20a99334587ba4538dbc1137ac350b4607",
    );
    assert_eq!(actual, expected);
}
