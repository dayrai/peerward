async fn unused_addresses() -> [std::net::SocketAddr; 4] {
    let mut listeners = Vec::new();
    for _ in 0..4 {
        listeners.push(TcpListener::bind("127.0.0.1:0").await.unwrap());
    }
    listeners
        .iter()
        .map(|listener| listener.local_addr().unwrap())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

fn noise_pair() -> ([u8; 32], [u8; 32]) {
    let pair = Builder::new(peerward_wire::IK_SUITE.parse().unwrap())
        .generate_keypair()
        .unwrap();
    (
        pair.private.try_into().unwrap(),
        pair.public.try_into().unwrap(),
    )
}

async fn wait_for_listener(address: std::net::SocketAddr) {
    for _ in 0..50 {
        if TcpStream::connect(address).await.is_ok() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("relay listener did not become ready");
}

fn udp_packet(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
) -> Vec<u8> {
    let mut packet = vec![0_u8; 28];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&28_u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&source.octets());
    packet[16..20].copy_from_slice(&destination.octets());
    packet[20..22].copy_from_slice(&source_port.to_be_bytes());
    packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
    packet[24..26].copy_from_slice(&8_u16.to_be_bytes());
    let mut sum = 0_u32;
    for pair in packet[..20].chunks_exact(2) {
        sum += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    packet[10..12].copy_from_slice(&(!u16::try_from(sum).unwrap()).to_be_bytes());
    packet
}

fn signed_test_configuration(
    mesh: MeshId,
    signer: &DirectorySigningKey,
    now: u64,
    states: &[(SignedStateKind, u64, Vec<u8>)],
) -> peerward_management::ConfigurationDelivery {
    use peerward_management::{
        AuthorizationLease, ComponentReference, ConfigurationDelivery, ConfigurationManifest,
        ConfigurationPart as Part, ResourceConfiguration, content_digest,
    };
    use sha2::{Digest as _, Sha256};

    let resources = ResourceConfiguration::default();
    let dns = Vec::new();
    let mut parts = BTreeMap::new();
    for (kind, version, bytes) in states {
        let part = match kind {
            SignedStateKind::Authorities => Part::Authorities,
            SignedStateKind::Peers => Part::Peers,
            SignedStateKind::Policy => Part::Policy,
            SignedStateKind::Revocations => Part::Revocations,
            _ => continue,
        };
        parts.insert(
            part,
            ComponentReference {
                version: *version,
                digest: Sha256::digest(bytes).into(),
            },
        );
    }
    parts.insert(
        Part::Resources,
        ComponentReference {
            version: 1,
            digest: content_digest(&resources).unwrap(),
        },
    );
    parts.insert(
        Part::Dns,
        ComponentReference {
            version: 1,
            digest: content_digest(&dns).unwrap(),
        },
    );
    let manifest = ConfigurationManifest {
        mesh_id: mesh,
        version: 1,
        parts,
    };
    let lease = AuthorizationLease {
        mesh_id: mesh,
        configuration_digest: content_digest(&manifest).unwrap(),
        sequence: 1,
        issued_at: now,
        valid_until: now + 900,
    };
    ConfigurationDelivery {
        manifest: signer.sign_manifest(manifest).unwrap(),
        lease: signer.sign_lease(lease).unwrap(),
        resources,
        dns,
    }
}

async fn assert_opaque_handshake_is_routed(
    sessions: &mut [RelayTestSession],
    mesh_id: MeshId,
    source_peer: PeerId,
    destination_peer: PeerId,
    destination_index: usize,
) {
    sessions[0]
        .0
        .send_control(ControlEnvelope {
            trace_context: None,
            message: Some(ControlMessage::Opaque(RelayEnvelopeV2 {
                major: peerward_wire::PROTOCOL_MAJOR,
                mesh_id: mesh_id.as_bytes().to_vec(),
                destination_peer: destination_peer.as_bytes().to_vec(),
                source_peer: Vec::new(),
                kind: OpaqueFrameKind::Session as i32,
                opaque: vec![9, 8, 7],
            })),
        })
        .await
        .unwrap();
    let routed = tokio::time::timeout(
        Duration::seconds(10).unsigned_abs(),
        receive_opaque(&mut sessions[destination_index]),
    )
    .await
    .expect("Relay must deliver the opaque end-to-end handshake");
    assert_eq!(routed.source_peer, source_peer.as_bytes());
    assert_eq!(routed.destination_peer, destination_peer.as_bytes());
    assert_eq!(routed.kind, OpaqueFrameKind::Session as i32);
    assert_eq!(routed.opaque, vec![9, 8, 7]);
}
