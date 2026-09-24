#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, str::FromStr};

    use peerward_directory::{DirectorySigningKey, PeerEntry};

    use super::*;

    fn mesh() -> MeshId {
        MeshId::from_str("970a3f18-1c6f-4da6-a223-f9623958a928").unwrap()
    }

    fn peer(value: &str) -> PeerId {
        PeerId::from_str(value).unwrap()
    }

    fn relay(value: &str) -> RelayId {
        RelayId::from_str(value).unwrap()
    }

    fn serial(value: &str) -> CredentialSerial {
        CredentialSerial::from_str(value).unwrap()
    }

    fn source() -> PeerId {
        peer("778f4317-0d08-4aab-9620-ca2c99a5ee3e")
    }

    fn destination() -> PeerId {
        peer("092a279f-d029-45b9-a6ad-6c31bde133e2")
    }

    fn source_serial() -> CredentialSerial {
        serial("68d07b9e-b046-4402-b688-d606a29e797e")
    }

    fn destination_serial() -> CredentialSerial {
        serial("40ee7506-2ee1-4b0b-a00c-8f6ec9900011")
    }

    fn attachment(peer_id: PeerId, generation: i64, credential: CredentialSerial) -> Attachment {
        Attachment {
            peer_id,
            attachment_id: AttachmentId::new(),
            role: PresenceRole::Primary,
            generation,
            credential_serial: credential,
        }
    }

    fn router(capacity: usize) -> OpaqueRouter {
        let signer = DirectorySigningKey::from_bytes(&[7; 32]);
        let entries = [
            (source(), source_serial(), "10.0.0.2"),
            (destination(), destination_serial(), "10.0.0.3"),
        ]
        .into_iter()
        .map(|(peer_id, credential_serial, address)| {
            signer.sign_peer(PeerEntry {
                secondary_address: None,
                mesh_id: mesh(),
                peer_id,
                address: address.parse().unwrap(),
                identity_public_key: [1; 32],
                noise_public_key: [2; 32],
                credential_serial,
                accepted_credentials: vec![peerward_directory::PeerCredentialBinding {
                    serial: credential_serial,
                    identity_public_key: [1; 32],
                    noise_public_key: [2; 32],
                    wireguard_public_key: {
                        let mut key = [0x77; 32];
                        key[..16].copy_from_slice((credential_serial).as_bytes());
                        key
                    },
                    not_before: peerward_types::UnixTime(0),
                    not_after: UnixTime(u64::MAX),
                    overlap_until: None,
                    signature: [0; 64],
                }],
                enabled: true,
                labels: BTreeMap::new(),
                not_after: UnixTime(u64::MAX),
            })
        })
        .collect();
        let mut router = OpaqueRouter::new(
            mesh(),
            relay("81708cad-c18b-4d0f-a580-026c4c285845"),
            signer.public_key(),
            capacity,
        )
        .unwrap();
        router
            .install_directory(&signer.sign_peers(mesh(), 1, entries).unwrap())
            .unwrap();
        router.install_attachment(attachment(source(), 7, source_serial()));
        router.install_attachment(attachment(destination(), 9, destination_serial()));
        router
    }

    fn opaque_control() -> ControlEnvelope {
        ControlEnvelope {
            trace_context: None,
            message: Some(ControlMessage::Opaque(peerward_wire::RelayEnvelopeV2 {
                major: peerward_wire::PROTOCOL_MAJOR,
                mesh_id: mesh().as_bytes().to_vec(),
                destination_peer: destination().as_bytes().to_vec(),
                source_peer: source().as_bytes().to_vec(),
                kind: peerward_wire::OpaqueFrameKind::Session as i32,
                opaque: b"end-to-end-ciphertext".to_vec(),
            })),
        }
    }

    #[test]
    fn opaque_router_preserves_ciphertext_and_enforces_fences() {
        let mut router = router(2);
        let envelope = opaque_control();
        let encoded_bytes=u64::try_from(envelope.encoded_len()).unwrap();
        assert_eq!(router.queued_usage(),(0,0));
        router
            .route_control(RoutedControl {
                source: source(),
                destination: destination(),
                generation: 7,
                envelope: envelope.clone(),
            })
            .unwrap();
        assert_eq!(router.queued_usage(),(1,encoded_bytes));
        assert!(matches!(
            router.receive_control(destination(), 8),
            Err(RelayError::StaleFence)
        ));
        assert_eq!(
            router.receive_control(destination(), 9).unwrap(),
            Some(envelope)
        );
        assert_eq!(router.queued_usage(),(0,0));
        assert!(matches!(
            router.route_control(RoutedControl {
                source: source(),
                destination: destination(),
                generation: 6,
                envelope: opaque_control(),
            }),
            Err(RelayError::StaleFence)
        ));
    }

    #[test]
    fn opaque_router_queue_is_bounded_and_revocation_is_exact() {
        let mut router = router(1);
        let queued_control = || RoutedControl {
            source: source(),
            destination: destination(),
            generation: 7,
            envelope: opaque_control(),
        };
        router.route_control(queued_control()).unwrap();
        assert!(matches!(
            router.route_control(queued_control()),
            Err(RelayError::QueueFull)
        ));
        router.revoke(destination_serial());
        assert_eq!(router.queued_usage(),(0,0));
        assert!(matches!(
            router.receive_control(destination(), 9),
            Err(RelayError::StaleFence)
        ));
        assert_eq!(
            router.attachments.get(&source()).unwrap().credential_serial,
            source_serial()
        );
    }

    #[test]
    fn backbone_destination_pressure_and_departure_do_not_end_the_link() {
        let mut router = router(1);
        let missing = AtomicU64::new(0);
        let full = AtomicU64::new(0);
        let frame = || RoutedControl {
            source: source(),
            destination: destination(),
            generation: 7,
            envelope: opaque_control(),
        };
        let accepted = |result| accept_backbone_delivery(result, &missing, &full);
        assert!(accepted(router.accept_cross_relay_control(frame())).unwrap());
        assert!(!accepted(router.accept_cross_relay_control(frame())).unwrap());
        assert_eq!(full.load(Ordering::Relaxed), 1);
        router.detach(destination(), 9);
        assert!(!accepted(router.accept_cross_relay_control(frame())).unwrap());
        assert_eq!(missing.load(Ordering::Relaxed), 1);
        router.install_attachment(attachment(destination(), 10, destination_serial()));
        assert!(accepted(router.accept_cross_relay_control(frame())).unwrap());
        assert_eq!(
            router.receive_control(destination(), 10).unwrap(),
            Some(opaque_control())
        );
        assert!(matches!(
            accepted(Err(RelayError::StaleFence)),
            Err(RelayError::StaleFence)
        ));
        assert!(matches!(
            accepted(Err(RelayError::MalformedForwarded)),
            Err(RelayError::MalformedForwarded)
        ));
    }

    #[test]
    fn backbone_rejects_removed_plaintext_packet_tag() {
        let mut legacy = vec![1];
        legacy.extend_from_slice(source().as_bytes());
        legacy.extend_from_slice(&[0; 64]);
        assert!(matches!(
            decode_backbone_payload(&legacy),
            Err(RelayError::MalformedForwarded)
        ));
    }

    #[test]
    fn backbone_round_trip_contains_only_control_envelopes() {
        let routed = RoutedControl {
            source: source(),
            destination: destination(),
            generation: 7,
            envelope: opaque_control(),
        };
        let encoded = encode_backbone_payload(&BackbonePayload::Control(routed.clone())).unwrap();
        let BackbonePayload::Control(decoded) = decode_backbone_payload(&encoded).unwrap() else {
            panic!("only control is decodable from backbone forwarding");
        };
        assert_eq!(decoded.source, routed.source);
        assert_eq!(decoded.destination, routed.destination);
        assert_eq!(decoded.generation, routed.generation);
        assert_eq!(decoded.envelope, routed.envelope);
    }

    #[test]
    fn peer_opaque_source_is_overwritten_by_authenticated_link() {
        let mut envelope = opaque_control();
        let Some(ControlMessage::Opaque(message)) = envelope.message.as_mut() else {
            unreachable!();
        };
        message.source_peer.clear();
        let routed = normalize_direct_control(mesh(), source(), &mut envelope).unwrap();
        assert_eq!(routed, destination());
        let Some(ControlMessage::Opaque(message)) = envelope.message else {
            unreachable!();
        };
        assert_eq!(message.source_peer, source().as_bytes());
        assert_eq!(message.opaque, b"end-to-end-ciphertext");
    }

    #[test]
    fn audit_destination_is_reserved_and_body_remains_opaque() {
        let opaque = b"sealed-audit".to_vec();
        let envelope = ControlEnvelope {
            trace_context: None,
            message: Some(ControlMessage::Opaque(peerward_wire::RelayEnvelopeV2 {
                major: peerward_wire::PROTOCOL_MAJOR,
                mesh_id: mesh().as_bytes().to_vec(),
                destination_peer: peerward_wire::CONTROL_AUDIT_DESTINATION.to_vec(),
                source_peer: Vec::new(),
                kind: peerward_wire::OpaqueFrameKind::Audit as i32,
                opaque: opaque.clone(),
            })),
        };
        let ingress = normalize_control_audit(mesh(), source(), &envelope)
            .unwrap()
            .unwrap();
        assert_eq!(ingress.source_peer, source());
        assert_eq!(ingress.envelope, opaque);
    }

    #[test]
    fn deterministic_backbone_dial_has_one_initiator() {
        let left = relay("81708cad-c18b-4d0f-a580-026c4c285845");
        let right = relay("63dcbd61-99ec-46e8-9808-3d9e9890e917");
        assert_ne!(should_initiate(left, right), should_initiate(right, left));
        assert!(!should_initiate(left, left));
    }

    #[test]
    fn full_mesh_presence_snapshot_uses_the_presence_control_message() {
        let update = PresenceAnnouncement {
            entry: PresenceCacheEntry {
                peer_id: source(),
                relay_id: relay("81708cad-c18b-4d0f-a580-026c4c285845"),
                attachment_id: AttachmentId::new(),
                role: PresenceRole::Primary,
                generation: 7,
                lease_deadline: OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap(),
            },
            released: false,
        };
        let envelope =
            backbone_control_envelope(mesh(), &BackbonePayload::Presence(update)).unwrap();
        let Some(ControlMessage::Presence(message)) = envelope.message else {
            panic!("full-mesh presence must not use a forwarded payload");
        };
        assert_eq!(message.mesh_id, mesh().as_bytes());
        assert_eq!(decode_presence(&message.body).unwrap(), update);
    }

    #[test]
    fn presence_cache_keeps_two_standbys_and_fences_each_relay_independently() {
        let peer_id = source();
        let first_relay = relay("81708cad-c18b-4d0f-a580-026c4c285845");
        let second_relay = relay("63dcbd61-99ec-46e8-9808-3d9e9890e917");
        let deadline = OffsetDateTime::now_utc() + time::Duration::minutes(1);
        let entry = |relay_id| PresenceCacheEntry {
            peer_id,
            relay_id,
            attachment_id: AttachmentId::new(),
            role: PresenceRole::Standby,
            generation: 1,
            lease_deadline: deadline,
        };
        let first = entry(first_relay);
        let second = entry(second_relay);
        let mut cache = PresenceCache::default();
        cache.observe_local(first).unwrap();
        cache.observe_local(second).unwrap();
        assert!(cache.authenticates_source(
            peer_id,
            first_relay,
            1,
            OffsetDateTime::now_utc(),
            false,
        ));
        assert!(cache.authenticates_source(
            peer_id,
            second_relay,
            1,
            OffsetDateTime::now_utc(),
            false,
        ));
        cache.release_local(first).unwrap();
        assert!(!cache.authenticates_source(
            peer_id,
            first_relay,
            1,
            OffsetDateTime::now_utc(),
            false,
        ));
        assert!(cache.authenticates_source(
            peer_id,
            second_relay,
            1,
            OffsetDateTime::now_utc(),
            false,
        ));
    }

    #[test]
    fn backbone_health_tracks_ewma_bounded_loss_and_failure_threshold() {
        let remote = relay("81708cad-c18b-4d0f-a580-026c4c285845");
        let mut health = ConnectionHealth::new(3).unwrap();
        assert!(!health.probe(100));
        assert!(health.reply(100, 110));
        assert!(!health.probe(200));
        assert!(!health.probe(300));
        assert!(health.reply(300, 330));
        let snapshot = health.snapshot(remote).unwrap();
        assert_eq!(snapshot.rtt_millis, 12);
        assert_eq!(snapshot.loss_permyriad, 3_333);
        assert_eq!(snapshot.samples, 3);

        for timestamp in 400..440 {
            assert!(!health.probe(timestamp));
            assert!(health.reply(timestamp, timestamp + 5));
        }
        assert_eq!(health.snapshot(remote).unwrap().samples, 32);

        assert!(!health.probe(500));
        assert!(!health.probe(501));
        assert!(!health.probe(502));
        assert!(health.probe(503));
    }

    #[test]
    fn presence_snapshot_cannot_erase_arrivals_renewals_or_release_tombstones() {
        let entry = PresenceCacheEntry {
            peer_id: source(),
            relay_id: relay("81708cad-c18b-4d0f-a580-026c4c285845"),
            attachment_id: AttachmentId::new(),
            role: PresenceRole::Primary,
            generation: 1,
            lease_deadline: OffsetDateTime::now_utc() + time::Duration::minutes(1),
        };
        let row = |value: PresenceCacheEntry| peerward_store::PresenceSnapshot {
            peer_id: value.peer_id,
            relay_id: value.relay_id,
            attachment_id: value.attachment_id,
            role: value.role,
            generation: value.generation,
            lease_deadline: value.lease_deadline,
        };
        let mut cache = PresenceCache::default();
        let before_arrival = cache.revision;
        cache.observe_local(entry).unwrap();
        cache.install_snapshot(&[], before_arrival).unwrap();
        assert_eq!(cache.entries[&presence_key(entry)], entry);
        let before_renewal = cache.revision;
        let renewed = PresenceCacheEntry {
            lease_deadline: entry.lease_deadline + time::Duration::minutes(1),
            ..entry
        };
        cache.observe_local(renewed).unwrap();
        cache
            .install_snapshot(&[row(entry)], before_renewal)
            .unwrap();
        assert_eq!(cache.entries[&presence_key(entry)], renewed);
        let before_release = cache.revision;
        cache.release_local(renewed).unwrap();
        cache
            .install_snapshot(&[row(renewed)], before_release)
            .unwrap();
        assert!(cache.entries.is_empty());
        // Even a query started after release may still see the DB row while its
        // exact conditional deletion is in flight. The same generation stays dead.
        cache
            .install_snapshot(&[row(renewed)], cache.revision)
            .unwrap();
        assert!(cache.entries.is_empty());
        let replacement = PresenceCacheEntry {
            generation: 2,
            attachment_id: AttachmentId::new(),
            ..renewed
        };
        cache
            .install_snapshot(&[row(replacement)], cache.revision)
            .unwrap();
        assert_eq!(cache.entries[&presence_key(entry)], replacement);
        cache.install_snapshot(&[], cache.revision).unwrap();
        assert!(cache.entries.is_empty());
        let query_started = cache.revision;
        let arrival = PresenceCacheEntry {
            generation: 3,
            ..replacement
        };
        cache.observe_local(arrival).unwrap();
        let newer_database_owner = PresenceCacheEntry {
            generation: 4,
            attachment_id: AttachmentId::new(),
            ..arrival
        };
        cache
            .install_snapshot(&[row(newer_database_owner)], query_started)
            .unwrap();
        assert_eq!(cache.entries[&presence_key(entry)], newer_database_owner);
    }
}
