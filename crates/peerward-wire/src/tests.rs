use ed25519_dalek::SigningKey;
use rand::{SeedableRng, rngs::StdRng};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use super::{control_envelope::Message as ControlMessage, *};

fn complete_ik() -> (StreamTransport, StreamTransport) {
    let initiator_private = [1_u8; 32];
    let responder_public = snow::Builder::new(IK_SUITE.parse().unwrap())
        .generate_keypair()
        .unwrap();
    // Build the actual responder from the generated private value so its public key is known.
    let responder_private: [u8; 32] = responder_public.private.try_into().unwrap();
    let responder_public: [u8; 32] = responder_public.public.try_into().unwrap();
    let mut initiator = ik_initiator(&initiator_private, &responder_public).unwrap();
    let mut responder = ik_responder(&responder_private).unwrap();
    let mut message = [0_u8; 1024];
    let mut payload = [0_u8; 1024];
    let size = initiator.write_message(b"init", &mut message).unwrap();
    let read = responder
        .read_message(&message[..size], &mut payload)
        .unwrap();
    assert_eq!(&payload[..read], b"init");
    let size = responder.write_message(b"reply", &mut message).unwrap();
    let read = initiator
        .read_message(&message[..size], &mut payload)
        .unwrap();
    assert_eq!(&payload[..read], b"reply");
    (
        StreamTransport::from_handshake(initiator, 10).unwrap(),
        StreamTransport::from_handshake(responder, 10).unwrap(),
    )
}

#[test]
fn noise_stream_round_trip_and_strict_boundary() {
    let (mut sender, mut receiver) = complete_ik();
    let envelope = ControlEnvelope {
        trace_context: None,
        message: Some(ControlMessage::Keepalive(Keepalive {
            monotonic_timestamp: 87,
        })),
    };
    let frame = sender.encode(&Record::Control(envelope.clone())).unwrap();
    assert_eq!(receiver.decode(&frame).unwrap(), Record::Control(envelope));

    let (mut sender, mut receiver) = complete_ik();
    let mut frame = sender.encode(&Record::Ipv4(vec![0x45, 0, 0, 20])).unwrap();
    frame.push(0);
    assert!(matches!(
        receiver.decode(&frame),
        Err(WireError::TrailingBytes)
    ));
}

#[test]
fn ipv6_record_round_trip_and_kind_validation() {
    let (mut sender, mut receiver) = complete_ik();
    let packet = vec![0x60, 0, 0, 0, 0, 0, 59, 64];
    let frame = sender.encode(&Record::Ipv6(packet.clone())).unwrap();
    assert_eq!(receiver.decode(&frame).unwrap(), Record::Ipv6(packet));

    let (mut sender, mut receiver) = complete_ik();
    let frame = sender.encode(&Record::Ipv6(vec![0x45])).unwrap();
    assert!(matches!(
        receiver.decode(&frame),
        Err(WireError::KindMismatch)
    ));
}

#[test]
fn oversized_local_records_leave_the_noise_session_usable() {
    let (mut sender, mut receiver) = complete_ik();
    for oversized in [
        Record::Ipv4(vec![0x45; MAX_CIPHERTEXT_LEN]),
        Record::Ipv6(vec![0x60; MAX_CIPHERTEXT_LEN]),
        Record::Control(ControlEnvelope {
            message: Some(ControlMessage::Hello(Hello {
                mesh_id: vec![1; 16],
                body: vec![0; MAX_CIPHERTEXT_LEN],
            })),
            trace_context: None,
        }),
    ] {
        assert!(matches!(
            sender.encode(&oversized),
            Err(WireError::InvalidLength)
        ));
        let record = Record::Ipv4(vec![0x45; MAX_CIPHERTEXT_LEN - 20]);
        let frame = sender.encode(&record).unwrap();
        assert_eq!(frame.len(), MAX_CIPHERTEXT_LEN + 4);
        assert_eq!(receiver.decode(&frame).unwrap(), record);
    }
}

#[test]
fn handshake_negotiates_only_intersection() {
    let payload = HandshakePayload {
        major: PROTOCOL_MAJOR,
        minor: 3,
        capabilities: 0b1011,
        credential: vec![1],
        attachment_id: vec![2; 16],
    };
    assert_eq!(payload.negotiate(0b0110).unwrap(), 0b0010);
    let mut legacy = payload;
    legacy.major = 1;
    assert!(matches!(
        legacy.negotiate(u64::MAX),
        Err(WireError::UnsupportedMajor)
    ));
}

#[test]
fn relay_envelope_overwrites_untrusted_source_without_inspecting_payload() {
    let mut envelope = RelayEnvelopeV2 {
        major: PROTOCOL_MAJOR,
        mesh_id: vec![1; 16],
        destination_peer: vec![2; 16],
        source_peer: vec![0xff; 16],
        kind: OpaqueFrameKind::Session as i32,
        opaque: vec![0xde, 0xad, 0xbe, 0xef],
    };
    envelope.validate_for_relay().unwrap();
    envelope.bind_authenticated_source([3; 16]);
    assert_eq!(envelope.source_peer, vec![3; 16]);
    assert_eq!(envelope.opaque, vec![0xde, 0xad, 0xbe, 0xef]);
}

#[test]
fn hpke_audit_round_trip_binds_identity_source_and_hides_event_details() {
    let recipient_private = StaticSecret::from([41; 32]);
    let recipient_public = X25519PublicKey::from(&recipient_private).to_bytes();
    let identity = SigningKey::from_bytes(&[42; 32]);
    let mesh = uuid_v4_bytes(1);
    let peer = uuid_v4_bytes(2);
    let batch_id = uuid_v4_bytes(3);
    let batch = AuditBatchV1 {
        major: PROTOCOL_MAJOR,
        schema_version: 1,
        mesh_id: mesh.to_vec(),
        source_peer: peer.to_vec(),
        batch_id: batch_id.to_vec(),
        observed_at: 1_700_000_000,
        events: vec![AuditEventV1 {
            direction: AuditDirectionV1::Ingress as i32,
            reason: AuditReasonV1::SecurityAnomaly as i32,
            count: 7,
        }],
        runtime_health: None,
    };
    let sealed = seal_audit_batch(
        &batch,
        &recipient_public,
        &identity,
        StdRng::from_seed([43; 32]),
    )
    .unwrap();
    let encoded = sealed.encode_to_vec();
    assert!(
        !encoded
            .windows(8)
            .any(|window| window == 7_u64.to_be_bytes())
    );
    assert_eq!(
        open_audit_batch(
            &sealed,
            &recipient_private.to_bytes(),
            &identity.verifying_key().to_bytes(),
        )
        .unwrap(),
        batch,
    );

    let mut forged_source = sealed.clone();
    forged_source.source_peer = uuid_v4_bytes(4).to_vec();
    assert!(matches!(
        open_audit_batch(
            &forged_source,
            &recipient_private.to_bytes(),
            &identity.verifying_key().to_bytes(),
        ),
        Err(WireError::Authentication)
    ));
    let mut tampered = sealed;
    tampered.ciphertext[0] ^= 1;
    assert!(matches!(
        open_audit_batch(
            &tampered,
            &recipient_private.to_bytes(),
            &identity.verifying_key().to_bytes(),
        ),
        Err(WireError::Authentication)
    ));
}

#[test]
fn encrypted_runtime_health_is_bounded_and_contains_no_relationship_data() {
    let recipient_private = StaticSecret::from([51; 32]);
    let recipient_public = X25519PublicKey::from(&recipient_private).to_bytes();
    let identity = SigningKey::from_bytes(&[52; 32]);
    let batch = AuditBatchV1 {
        major: PROTOCOL_MAJOR,
        schema_version: 1,
        mesh_id: uuid_v4_bytes(5).to_vec(),
        source_peer: uuid_v4_bytes(6).to_vec(),
        batch_id: uuid_v4_bytes(7).to_vec(),
        observed_at: 1_700_000_000,
        events: Vec::new(),
        runtime_health: Some(RuntimeHealthV1 {
            sequence: 12,
            direct_path_count: 2,
            relay_packets: 30,
            direct_packets: 70,
            degraded_reasons: vec![RuntimeDegradedReasonV1::DnsDegraded as i32],
            signed_revision: 9,
        }),
    };
    let sealed = seal_audit_batch(
        &batch,
        &recipient_public,
        &identity,
        StdRng::from_seed([53; 32]),
    )
    .unwrap();
    assert!(sealed.encoded_len() <= 4 * 1024);
    assert_eq!(
        open_audit_batch(
            &sealed,
            &recipient_private.to_bytes(),
            &identity.verifying_key().to_bytes(),
        )
        .unwrap(),
        batch,
    );
}

fn uuid_v4_bytes(seed: u8) -> [u8; 16] {
    let mut bytes = [seed; 16];
    bytes[6] = 0x40 | (seed & 0x0f);
    bytes[8] = 0x80 | (seed & 0x3f);
    bytes
}

#[test]
fn wire_four_rejects_legacy_offer_answer_probe_and_handshake_envelopes() {
    for tag in [10_u8, 11, 12, 13, 23] {
        let key = (u16::from(tag) << 3) | 2;
        let mut encoded = vec![0, 1, 0, 0]; // control record
        if key >= 128 {
            encoded.extend_from_slice(&[
                u8::try_from(key & 127).unwrap() | 128,
                u8::try_from(key >> 7).unwrap(),
            ]);
        } else {
            encoded.push(u8::try_from(key).unwrap());
        }
        encoded.push(0); // empty legacy submessage
        assert!(matches!(
            Record::decode_plaintext(&encoded),
            Err(WireError::KindMismatch)
        ));
    }
    let frame = RelayEnvelopeV2 {
        major: PROTOCOL_MAJOR,
        mesh_id: vec![1; 16],
        destination_peer: vec![2; 16],
        source_peer: Vec::new(),
        kind: 0,
        opaque: vec![1; 148],
    };
    assert!(frame.validate_from_peer().is_err());
}
