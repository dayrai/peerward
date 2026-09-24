use super::*;
use ed25519_dalek::{Signer, SigningKey};
use peerward_credentials::{
    AuthorityCertificate, AuthoritySigningKey, RootSigningKey, UnsignedAuthority, UnsignedSubject,
};
use peerward_directory::{
    DirectorySigningKey, PeerEntry, RelayEntry, encode_peer_directory, encode_policy,
    encode_relay_directory,
};
use peerward_policy::{Action as PolicyAction, Policy, encode_policy_document};
use peerward_service::ServiceSnapshotSigningKey;
use peerward_types::{AttachmentId, CredentialSerial, PeerId, RelayId};
use peerward_wire::{
    Keepalive, PeerDirectoryChunk, PolicyBundle, RelayDirectoryChunk,
    control_envelope::Message as ControlMessage, ik_responder,
};

fn uuid(value: u128) -> Uuid {
    Uuid::from_u128(value | (4 << 76) | (2 << 62))
}

pub(super) fn udp_packet(
    source: [u8; 4],
    destination: [u8; 4],
    source_port: u16,
    port: u16,
) -> Vec<u8> {
    let mut packet = vec![0_u8; 28];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&28_u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&source);
    packet[16..20].copy_from_slice(&destination);
    packet[20..22].copy_from_slice(&source_port.to_be_bytes());
    packet[22..24].copy_from_slice(&port.to_be_bytes());
    packet[24..26].copy_from_slice(&8_u16.to_be_bytes());
    let mut sum = 0_u32;
    for pair in packet[..20].chunks_exact(2) {
        sum += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let checksum = !u16::try_from(sum).expect("IPv4 checksum is folded");
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    packet
}

pub(super) fn dns_query(name: &str, qtype: u16) -> Vec<u8> {
    let mut query = Vec::from([0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        query.push(u8::try_from(label.len()).unwrap());
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(&qtype.to_be_bytes());
    query.extend_from_slice(&1_u16.to_be_bytes());
    query
}

#[test]
#[allow(clippy::too_many_lines)] // One contiguous transcript makes interop ordering auditable.
fn exact_native_entry_interoperates_with_rust_relay_noise_and_records() {
    let mesh = MeshId::from_uuid(uuid(1)).unwrap();
    let peer_id = PeerId::from_uuid(uuid(2)).unwrap();
    let relay_id = RelayId::from_uuid(uuid(3)).unwrap();
    let root = RootSigningKey::from_bytes(&[7; 32]);
    let authority = AuthoritySigningKey::from_bytes(&[8; 32]);
    let authority_certificate = root
        .certify(UnsignedAuthority {
            mesh_id: mesh,
            serial: CredentialSerial::from_uuid(uuid(4)).unwrap(),
            public_key: authority.public_key(),
            not_before: UnixTime(10),
            not_after: UnixTime(10_000),
        })
        .unwrap();
    let peer_provider = Arc::new(RawStaticDh::new([11; 32]));
    let peer_public = peer_provider.public_key();
    let relay_private = [12; 32];
    let relay_public = RawStaticDh::new(relay_private).public_key();
    let identity = SigningKey::from_bytes(&[13; 32]);
    let peer_credential = authority
        .issue(UnsignedSubject {
            subject: SubjectId::Peer(peer_id),
            mesh_id: mesh,
            identity_public_key: identity.verifying_key().to_bytes(),
            public_noise_key: peer_public,
            serial: CredentialSerial::from_uuid(uuid(5)).unwrap(),
            not_before: UnixTime(10),
            not_after: UnixTime(10_000),
            wireguard_public_key: [0x77; 32],
        })
        .unwrap();
    let relay_credential = authority
        .issue(UnsignedSubject {
            subject: SubjectId::Relay(relay_id),
            mesh_id: mesh,
            identity_public_key: [0; 32],
            public_noise_key: relay_public,
            serial: CredentialSerial::from_uuid(uuid(6)).unwrap(),
            not_before: UnixTime(10),
            not_after: UnixTime(10_000),
            wireguard_public_key: [0; 32],
        })
        .unwrap();
    let mut client_credentials = TrustSet::new(root.public_key(), mesh);
    client_credentials
        .add_authority(authority_certificate.clone(), UnixTime(100))
        .unwrap();
    let directory_signer = DirectorySigningKey::from_bytes(&[13; 32]);
    let service_signer = ServiceSnapshotSigningKey::from_bytes(&[14; 32]);
    let distribution_certificate = authority.certify_distribution(
        mesh,
        directory_signer.public_key().to_bytes(),
        service_signer.verifier().to_bytes(),
        peerward_wire::audit_recipient_public(&[15; 32]),
    );
    let mut mismatched_credentials = TrustSet::new(root.public_key(), mesh);
    mismatched_credentials
        .add_authority(authority_certificate.clone(), UnixTime(100))
        .unwrap();
    assert!(matches!(
        MobileTrust::new(
            mesh,
            mismatched_credentials,
            DirectorySigningKey::from_bytes(&[15; 32]).public_key(),
            service_signer.verifier(),
            distribution_certificate.audit_public_key,
            &distribution_certificate,
            UnixTime(100),
        ),
        Err(MobileError::InvalidInput)
    ));
    let trust = MobileTrust::new(
        mesh,
        client_credentials,
        directory_signer.public_key(),
        service_signer.verifier(),
        distribution_certificate.audit_public_key,
        &distribution_certificate,
        UnixTime(100),
    )
    .unwrap();

    let attachment = AttachmentId::from_uuid(uuid(7)).unwrap();
    let (mut client, first) = NativeSession::initiate(
        peer_provider,
        relay_public,
        &peer_credential,
        *attachment.as_bytes(),
        peerward_wire::PRIMARY_ATTACHMENT_CAPABILITY | 0b111,
        UnixTime(100),
        trust,
    )
    .unwrap();

    let mut relay_handshake = ik_responder(&relay_private).unwrap();
    let mut plaintext = vec![0; MAX_HANDSHAKE];
    let count = relay_handshake
        .read_message(&first, &mut plaintext)
        .unwrap();
    let hello = HandshakePayload::decode(&plaintext[..count]).unwrap();
    assert_eq!(
        SubjectCredential::decode(&hello.credential).unwrap(),
        peer_credential
    );
    assert_eq!(relay_handshake.get_remote_static().unwrap(), peer_public);
    let welcome = HandshakePayload {
        major: peerward_wire::PROTOCOL_MAJOR,
        minor: 0,
        capabilities: 0b101,
        credential: relay_credential.encode(),
        attachment_id: attachment.as_bytes().to_vec(),
    };
    let mut response = vec![0; MAX_HANDSHAKE];
    let count = relay_handshake
        .write_message(&welcome.encode_to_vec(), &mut response)
        .unwrap();
    response.truncate(count);
    assert_eq!(
        client
            .finish_handshake(&response, UnixTime(100), 1)
            .unwrap(),
        0b101
    );
    assert_eq!(client.primary_relay(), Some(relay_id));
    let mut relay_transport = StreamTransport::from_handshake(relay_handshake, 1).unwrap();
    let ready = relay_transport
        .encode(&Record::Control(ControlEnvelope {
            trace_context: None,
            message: Some(ControlMessage::Welcome(peerward_wire::Welcome {
                mesh_id: mesh.as_bytes().to_vec(),
                body: b"link_ready".to_vec(),
            })),
        }))
        .unwrap();
    client.confirm_link_ready(&ready, 1).unwrap();
    assert!(!client.link_replacement_due(2_700).unwrap());
    assert!(client.link_replacement_due(2_701).unwrap());
    assert!(matches!(
        client.encrypt(
            &Record::Control(ControlEnvelope {
                trace_context: None,
                message: Some(ControlMessage::Keepalive(Keepalive {
                    monotonic_timestamp: 1,
                })),
            }),
            3_601,
        ),
        Err(MobileError::Wire(WireError::RekeyRequired))
    ));

    let remote_peer = PeerId::from_uuid(uuid(8)).unwrap();
    let directory = directory_signer
        .sign_peers(
            mesh,
            1,
            vec![
                directory_signer.sign_peer(PeerEntry {
                    secondary_address: None,
                    mesh_id: mesh,
                    peer_id,
                    address: "10.42.0.2".parse().unwrap(),
                    identity_public_key: peer_credential.identity_public_key,
                    noise_public_key: peer_public,
                    credential_serial: peer_credential.serial,
                    accepted_credentials: vec![peerward_directory::PeerCredentialBinding {
                        serial: peer_credential.serial,
                        identity_public_key: peer_credential.identity_public_key,
                        noise_public_key: peer_public,
                        wireguard_public_key: {
                            let mut key = [0x77; 32];
                            key[..16].copy_from_slice((peer_credential.serial).as_bytes());
                            key
                        },
                        not_before: peerward_types::UnixTime(0),
                        not_after: UnixTime(10_000),
                        overlap_until: None,
                        signature: [0; 64],
                    }],
                    enabled: true,
                    labels: [("name".into(), "phone".into())].into(),
                    not_after: UnixTime(10_000),
                }),
                directory_signer.sign_peer(PeerEntry {
                    secondary_address: None,
                    mesh_id: mesh,
                    peer_id: remote_peer,
                    address: "10.42.0.3".parse().unwrap(),
                    identity_public_key: [17; 32],
                    noise_public_key: [16; 32],
                    credential_serial: CredentialSerial::from_uuid(uuid(9)).unwrap(),
                    accepted_credentials: vec![peerward_directory::PeerCredentialBinding {
                        serial: CredentialSerial::from_uuid(uuid(9)).unwrap(),
                        identity_public_key: [17; 32],
                        noise_public_key: [16; 32],
                        wireguard_public_key: {
                            let mut key = [0x77; 32];
                            key[..16].copy_from_slice(
                                (CredentialSerial::from_uuid(uuid(9)).unwrap()).as_bytes(),
                            );
                            key
                        },
                        not_before: peerward_types::UnixTime(0),
                        not_after: UnixTime(10_000),
                        overlap_until: None,
                        signature: [0; 64],
                    }],
                    enabled: true,
                    labels: [("name".into(), "laptop".into())].into(),
                    not_after: UnixTime(10_000),
                }),
            ],
        )
        .unwrap();
    let directory_control = ControlEnvelope {
        trace_context: None,
        message: Some(ControlMessage::PeerDirectory(PeerDirectoryChunk {
            mesh_id: mesh.as_bytes().to_vec(),
            revision: 1,
            index: 0,
            count: 1,
            body: encode_peer_directory(&directory).unwrap(),
        })),
    };
    let frame = relay_transport
        .encode(&Record::Control(directory_control))
        .unwrap();
    assert_eq!(
        client.decrypt(&frame, 2).unwrap().1,
        Some(AcceptedUpdate::PeerDirectory(1))
    );

    let relays = directory_signer
        .sign_relays(
            mesh,
            1,
            vec![RelayEntry {
                relay_id,
                peer_endpoints: vec!["tcp://127.0.0.1:7777".parse().unwrap()],
                backbone_endpoints: vec!["tcp://127.0.0.1:7778".parse().unwrap()],
                noise_public_key: relay_public,
                credential_serial: relay_credential.serial,
            }],
        )
        .unwrap();
    let frame = relay_transport
        .encode(&Record::Control(ControlEnvelope {
            trace_context: None,
            message: Some(ControlMessage::RelayDirectory(RelayDirectoryChunk {
                mesh_id: mesh.as_bytes().to_vec(),
                revision: 1,
                index: 0,
                count: 1,
                body: encode_relay_directory(&relays).unwrap(),
            })),
        }))
        .unwrap();
    assert_eq!(
        client.decrypt(&frame, 2).unwrap().1,
        Some(AcceptedUpdate::RelayDirectory(1))
    );

    let allow = Policy::new(1, PolicyAction::Allow, Vec::new());
    let signed_allow = directory_signer.sign_policy(
        mesh,
        allow.revision,
        encode_policy_document(&allow).unwrap(),
    );
    let policy_bytes = encode_policy(&signed_allow).unwrap();
    let midpoint = policy_bytes.len() / 2;
    let first_policy_chunk = ControlEnvelope {
        trace_context: None,
        message: Some(ControlMessage::Policy(PolicyBundle {
            mesh_id: mesh.as_bytes().to_vec(),
            revision: signed_allow.bundle.revision,
            index: 0,
            count: 2,
            body: policy_bytes[..midpoint].to_vec(),
        })),
    };
    let frame = relay_transport
        .encode(&Record::Control(first_policy_chunk))
        .unwrap();
    assert_eq!(
        client.decrypt(&frame, 2).unwrap().1,
        Some(AcceptedUpdate::Control)
    );
    let last_policy_chunk = ControlEnvelope {
        trace_context: None,
        message: Some(ControlMessage::Policy(PolicyBundle {
            mesh_id: mesh.as_bytes().to_vec(),
            revision: signed_allow.bundle.revision,
            index: 1,
            count: 2,
            body: policy_bytes[midpoint..].to_vec(),
        })),
    };
    let frame = relay_transport
        .encode(&Record::Control(last_policy_chunk))
        .unwrap();
    assert_eq!(
        client.decrypt(&frame, 2).unwrap().1,
        Some(AcceptedUpdate::Policy(1))
    );

    let dns = client
        .resolve_dns(
            &dns_query("laptop.mesh.test", 1),
            "10.42.0.2".parse().unwrap(),
            "mesh.test",
        )
        .unwrap();
    assert_eq!(&dns[..2], &[0x12, 0x34]);
    assert_eq!(&dns[dns.len() - 4..], &[10, 42, 0, 3]);
    let no_ipv6 = client
        .resolve_dns(
            &dns_query("laptop.mesh.test", 28),
            "10.42.0.2".parse().unwrap(),
            "mesh.test",
        )
        .unwrap();
    assert_eq!(u16::from_be_bytes([no_ipv6[2], no_ipv6[3]]) & 0xf, 0);
    assert_eq!(u16::from_be_bytes([no_ipv6[6], no_ipv6[7]]), 0);
    assert!(
        client
            .resolve_dns(
                &dns_query("outside.example", 1),
                "10.42.0.2".parse().unwrap(),
                "mesh.test",
            )
            .unwrap()
            .is_empty()
    );

    let ipv4 = udp_packet([10, 42, 0, 2], [10, 42, 0, 3], 40_000, 53);
    assert!(matches!(
        client.encrypt(&Record::Ipv4(ipv4), 2),
        Err(MobileError::InvalidInput)
    ));

    let returned = udp_packet([10, 42, 0, 3], [10, 42, 0, 2], 53, 40_000);
    let frame = relay_transport.encode(&Record::Ipv4(returned)).unwrap();
    assert!(matches!(
        client.decrypt(&frame, 3),
        Err(MobileError::InvalidInput)
    ));

    let control = ControlEnvelope {
        trace_context: None,
        message: Some(ControlMessage::Keepalive(Keepalive {
            monotonic_timestamp: 99,
        })),
    };
    let frame = relay_transport
        .encode(&Record::Control(control.clone()))
        .unwrap();
    assert_eq!(
        client.decrypt(&frame, 2).unwrap(),
        (Record::Control(control), Some(AcceptedUpdate::Control))
    );

    let deny = Policy::new(2, PolicyAction::Deny, Vec::new());
    let signed_deny =
        directory_signer.sign_policy(mesh, deny.revision, encode_policy_document(&deny).unwrap());
    let frame = relay_transport
        .encode(&Record::Control(ControlEnvelope {
            trace_context: None,
            message: Some(ControlMessage::Policy(PolicyBundle {
                mesh_id: mesh.as_bytes().to_vec(),
                revision: signed_deny.bundle.revision,
                index: 0,
                count: 1,
                body: encode_policy(&signed_deny).unwrap(),
            })),
        }))
        .unwrap();
    assert_eq!(
        client.decrypt(&frame, 4).unwrap().1,
        Some(AcceptedUpdate::Policy(2))
    );
    let self_dns = client
        .resolve_dns(
            &dns_query("phone.mesh.test", 1),
            "10.42.0.2".parse().unwrap(),
            "mesh.test",
        )
        .unwrap();
    assert_eq!(&self_dns[self_dns.len() - 4..], &[10, 42, 0, 2]);
    let hidden_remote = client
        .resolve_dns(
            &dns_query("laptop.mesh.test", 1),
            "10.42.0.2".parse().unwrap(),
            "mesh.test",
        )
        .unwrap();
    assert_eq!(
        u16::from_be_bytes([hidden_remote[2], hidden_remote[3]]) & 0xf,
        3
    );
    assert_eq!(u16::from_be_bytes([hidden_remote[6], hidden_remote[7]]), 0);
    client.record_audit(
        peerward_wire::AuditDirectionV1::Egress,
        &MobileError::PolicyDenied,
    );
    let transcript = client.audit_signature_transcript(UnixTime(101)).unwrap();
    let signature = identity.sign(&transcript).to_bytes();
    let audit_control =
        ControlEnvelope::decode(client.complete_audit(signature).unwrap().as_slice()).unwrap();
    let Some(ControlMessage::Opaque(audit_envelope)) = audit_control.message else {
        panic!("native audit did not produce an opaque Relay envelope")
    };
    assert_eq!(
        audit_envelope.kind,
        peerward_wire::OpaqueFrameKind::Audit as i32
    );
    assert_eq!(
        audit_envelope.destination_peer,
        peerward_wire::CONTROL_AUDIT_DESTINATION,
    );
    let sealed =
        peerward_wire::SealedAuditBatchV1::decode(audit_envelope.opaque.as_slice()).unwrap();
    let opened =
        peerward_wire::open_audit_batch(&sealed, &[15; 32], &identity.verifying_key().to_bytes())
            .unwrap();
    assert_eq!(opened.events[0].count, 1);
    assert_eq!(
        opened.events[0].reason,
        peerward_wire::AuditReasonV1::PolicyDenied as i32,
    );
    client.close();
    assert!(matches!(
        client.encrypt(
            &Record::Control(ControlEnvelope {
                trace_context: None,
                message: Some(ControlMessage::Keepalive(Keepalive {
                    monotonic_timestamp: 1,
                })),
            }),
            2
        ),
        Err(MobileError::InvalidState)
    ));
}

#[test]
fn authority_transport_codec_is_exact_and_rejects_trailing_bytes() {
    let mesh = MeshId::from_uuid(uuid(20)).unwrap();
    let root = RootSigningKey::from_bytes(&[21; 32]);
    let certificate = root
        .certify(UnsignedAuthority {
            mesh_id: mesh,
            serial: CredentialSerial::from_uuid(uuid(22)).unwrap(),
            public_key: AuthoritySigningKey::from_bytes(&[23; 32]).public_key(),
            not_before: UnixTime(1),
            not_after: UnixTime(2),
        })
        .unwrap();
    assert_eq!(
        AuthorityCertificate::decode(&certificate.encode()).unwrap(),
        certificate
    );
    let mut trailing = certificate.encode();
    trailing.push(0);
    assert_eq!(
        AuthorityCertificate::decode(&trailing),
        Err(CredentialError::Malformed)
    );
}
