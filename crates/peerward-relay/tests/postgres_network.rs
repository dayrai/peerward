use std::{collections::BTreeMap, env, net::Ipv4Addr, path::PathBuf, sync::Arc};

use peerward_credentials::{
    AuthoritySigningKey, RootSigningKey, SubjectId, TrustSet, UnsignedAuthority, UnsignedSubject,
};
use peerward_directory::{
    DirectorySigningKey, PeerEntry, RelayEntry, encode_peer_directory, encode_policy,
    encode_relay_directory, encode_revocations,
};
use peerward_peer::{
    NoiseRelayReceiver, NoiseRelaySender, OpaqueRelaySender, PacketReceiver,
    connect_relay_ik_routed, split_noise_relay,
};
use peerward_policy::{Action as PolicyAction, Policy, encode_policy_document};
use peerward_relay::{
    CredentialGate, OpaqueRouter, RelayConfig, RelayDatabasePolicy, RelayError, RoutedControl,
    serve_with_database_policy,
};
use peerward_service::{RemoteServiceSnapshot, ServiceSnapshotSigningKey};
use peerward_store::{DefaultPolicy, NewMesh, PresenceLease, PresenceRole, SignedStateKind, Store};
use peerward_types::{
    AttachmentId, CredentialSerial, MeshId, PeerId, RelayId, ServiceId, UnixTime,
};
use peerward_wire::{
    ControlEnvelope, HandshakePayload, OpaqueFrameKind, RelayEnvelopeV2, ServicePublish,
    ServiceRemove, control_envelope::Message as ControlMessage,
};
use snow::Builder;
use time::{Duration, OffsetDateTime};
use tokio::net::{TcpListener, TcpStream};

mod support;
use support::DatabaseFaultProxy;
include!("support/diagnostic_probe.rs");
include!("postgres_network_cases/console_renewal.rs");

fn database_url() -> String {
    let value = env::var("PEERWARD_TEST_DATABASE_URL")
        .expect("PEERWARD_TEST_DATABASE_URL must identify ephemeral PostgreSQL");
    assert!(
        value
            .parse::<sqlx::postgres::PgConnectOptions>()
            .is_ok_and(|options| options.get_database() == Some("peerward_test")),
        "relay integration refuses a database not named peerward_test"
    );
    value
}

#[tokio::test]
async fn newer_database_fence_stops_old_relay_forwarding() {
    let store = Store::connect(&database_url(), 8).await.unwrap();
    sqlx::raw_sql("DROP SCHEMA public CASCADE; CREATE SCHEMA public")
        .execute(store.pool())
        .await
        .unwrap();
    store.migrate().await.unwrap();
    let mesh = store
        .create_mesh(
            &NewMesh {
                name: "relay-integration".into(),
                address_cidr: "10.91.0.0/24".parse().unwrap(),
                gateway: Ipv4Addr::new(10, 91, 0, 1).into(),
                dns_suffix: "relay.test".into(),
                mtu: 1380,
                reserved: Vec::new(),
                default_policy: DefaultPolicy::Deny,
                quarantine_seconds: 1,
                rotation_overlap_seconds: 30,
            },
            "integration",
        )
        .await
        .unwrap();
    let peer = PeerId::new();
    sqlx::query("INSERT INTO peers(id,mesh_id,name) VALUES($1,$2,'peer-a')")
        .bind(peer.into_uuid())
        .bind(mesh.id.into_uuid())
        .execute(store.pool())
        .await
        .unwrap();
    let first_relay = RelayId::new();
    let second_relay = RelayId::new();
    for (id, name, peer_port, backbone_port) in [
        (first_relay, "first", 17777, 17778),
        (second_relay, "second", 27777, 27778),
    ] {
        sqlx::query(
            "INSERT INTO relays(id,mesh_id,name,peer_endpoints,backbone_endpoints)
             VALUES($1,$2,$3,$4,$5)",
        )
        .bind(id.into_uuid())
        .bind(mesh.id.into_uuid())
        .bind(name)
        .bind(vec![format!("tcp://127.0.0.1:{peer_port}")])
        .bind(vec![format!("tcp://127.0.0.1:{backbone_port}")])
        .execute(store.pool())
        .await
        .unwrap();
    }
    let signer = DirectorySigningKey::from_bytes(&[8; 32]);
    let serial = CredentialSerial::new();
    let mut old_router = OpaqueRouter::new(mesh.id, first_relay, signer.public_key(), 4).unwrap();
    let first_lease = PresenceLease {
        mesh_id: mesh.id,
        peer_id: peer,
        relay_id: first_relay,
        attachment_id: AttachmentId::new(),
        role: PresenceRole::Primary,
        lease_deadline: OffsetDateTime::now_utc() + Duration::minutes(1),
    };
    let first = old_router
        .acquire(&store, first_lease.clone(), serial)
        .await
        .unwrap();
    let second_lease = PresenceLease {
        relay_id: second_relay,
        attachment_id: AttachmentId::new(),
        ..first_lease.clone()
    };
    let mut new_router = OpaqueRouter::new(mesh.id, second_relay, signer.public_key(), 4).unwrap();
    let second = new_router
        .acquire(&store, second_lease, CredentialSerial::new())
        .await
        .unwrap();
    assert_eq!(second.generation, first.generation + 1);
    assert!(
        old_router
            .renew(&store, &first_lease, first.generation)
            .await
            .is_err()
    );
    old_router.observe_fence(peer, second.generation).unwrap();
    let stale = old_router.route_control(RoutedControl {
        source: peer,
        destination: PeerId::new(),
        generation: first.generation,
        envelope: ControlEnvelope {
            trace_context: None,
            message: Some(ControlMessage::Keepalive(peerward_wire::Keepalive {
                monotonic_timestamp: 1,
            })),
        },
    });
    assert!(matches!(stale, Err(RelayError::StaleFence)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn production_relay_forwards_between_two_real_noise_sessions() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let store = Store::connect(&database_url(), 16).await.unwrap();
    sqlx::raw_sql("DROP SCHEMA public CASCADE; CREATE SCHEMA public")
        .execute(store.pool())
        .await
        .unwrap();
    store.migrate().await.unwrap();
    let mesh = store
        .create_mesh(
            &NewMesh {
                name: "relay-runtime".into(),
                address_cidr: "10.97.0.0/24".parse().unwrap(),
                gateway: "10.97.0.1".parse().unwrap(),
                dns_suffix: "runtime.test".into(),
                mtu: 1380,
                reserved: Vec::new(),
                default_policy: DefaultPolicy::Allow,
                quarantine_seconds: 1,
                rotation_overlap_seconds: 30,
            },
            "integration",
        )
        .await
        .unwrap();
    let now = OffsetDateTime::now_utc();
    let now_seconds = u64::try_from(now.unix_timestamp()).unwrap();
    let root = RootSigningKey::from_bytes(&[61; 32]);
    let authority = AuthoritySigningKey::from_bytes(&[62; 32]);
    let authority_certificate = root
        .certify(UnsignedAuthority {
            mesh_id: mesh.id,
            serial: CredentialSerial::new(),
            public_key: authority.public_key(),
            not_before: UnixTime(now_seconds - 60),
            not_after: UnixTime(now_seconds + 3_600),
        })
        .unwrap();
    let authority_id = uuid::Uuid::new_v4();
    sqlx::query(
        "INSERT INTO mesh_authorities(id,mesh_id,serial,public_key,not_before,not_after,
         lifecycle,certificate) VALUES($1,$2,$3,$4,$5,$6,'active',$7)",
    )
    .bind(authority_id)
    .bind(mesh.id.into_uuid())
    .bind(authority_certificate.serial.into_uuid())
    .bind(authority_certificate.public_key.to_vec())
    .bind(now - Duration::minutes(1))
    .bind(now + Duration::hours(1))
    .bind(authority_certificate.encode())
    .execute(store.pool())
    .await
    .unwrap();

    let relay_ids = [RelayId::new(), RelayId::new()];
    let endpoints = unused_addresses().await;
    let peer_endpoints = [endpoints[0], endpoints[1]];
    let backbone_endpoints = [endpoints[2], endpoints[3]];
    let relay_keys = [noise_pair(), noise_pair()];
    let mut relay_credentials = Vec::new();
    let mut relay_serials = Vec::new();
    for index in 0..2 {
        sqlx::query(
            "INSERT INTO relays(id,mesh_id,name,peer_endpoints,backbone_endpoints)
             VALUES($1,$2,$3,$4,$5)",
        )
        .bind(relay_ids[index].into_uuid())
        .bind(mesh.id.into_uuid())
        .bind(format!("runtime-relay-{index}"))
        .bind(vec![format!("tcp://{}", peer_endpoints[index])])
        .bind(vec![format!("tcp://{}", backbone_endpoints[index])])
        .execute(store.pool())
        .await
        .unwrap();
        let serial = CredentialSerial::new();
        let credential = authority
            .issue(UnsignedSubject {
                subject: SubjectId::Relay(relay_ids[index]),
                mesh_id: mesh.id,
                identity_public_key: [0; 32],
                public_noise_key: relay_keys[index].1,
                serial,
                not_before: UnixTime(now_seconds - 60),
                not_after: UnixTime(now_seconds + 3_600),
                wireguard_public_key: [0; 32],
            })
            .unwrap();
        sqlx::query(
            "INSERT INTO relay_credentials
             (id,mesh_id,relay_id,authority_id,serial,public_key,not_before,not_after,
              lifecycle,signature)
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,'active',$9)",
        )
        .bind(uuid::Uuid::new_v4())
        .bind(mesh.id.into_uuid())
        .bind(relay_ids[index].into_uuid())
        .bind(authority_id)
        .bind(serial.into_uuid())
        .bind(relay_keys[index].1.to_vec())
        .bind(now - Duration::minutes(1))
        .bind(now + Duration::hours(1))
        .bind(credential.signature.to_vec())
        .execute(store.pool())
        .await
        .unwrap();
        relay_serials.push(serial);
        relay_credentials.push(credential);
    }

    let directory_signer = DirectorySigningKey::from_bytes(&[63; 32]);
    let service_signer = ServiceSnapshotSigningKey::from_bytes(&[64; 32]);
    let distribution = authority.certify_distribution(
        mesh.id,
        directory_signer.public_key().to_bytes(),
        service_signer.verifier().to_bytes(),
        [65; 32],
    );
    let peer_ids = [PeerId::new(), PeerId::new(), PeerId::new()];
    let addresses = [
        Ipv4Addr::new(10, 97, 0, 2),
        Ipv4Addr::new(10, 97, 0, 3),
        Ipv4Addr::new(10, 97, 0, 4),
    ];
    let mut peer_private = Vec::new();
    let mut credentials = Vec::new();
    let mut entries = Vec::new();
    for (index, (peer_id, address)) in peer_ids.iter().zip(addresses).enumerate() {
        let (private, public) = noise_pair();
        let serial = CredentialSerial::new();
        let credential = authority
            .issue(UnsignedSubject {
                subject: SubjectId::Peer(*peer_id),
                mesh_id: mesh.id,
                identity_public_key: ed25519_dalek::SigningKey::from_bytes(
                    &[u8::try_from(index + 1).unwrap(); 32],
                )
                .verifying_key()
                .to_bytes(),
                public_noise_key: public,
                serial,
                not_before: UnixTime(now_seconds - 60),
                not_after: UnixTime(now_seconds + 3_600),
                wireguard_public_key: x25519_dalek::PublicKey::from(
                    &x25519_dalek::StaticSecret::from([u8::try_from(index + 0x70).unwrap(); 32]),
                )
                .to_bytes(),
            })
            .unwrap();
        sqlx::query("INSERT INTO peers(id,mesh_id,name) VALUES($1,$2,$3)")
            .bind(peer_id.into_uuid())
            .bind(mesh.id.into_uuid())
            .bind(format!("peer-{index}"))
            .execute(store.pool())
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO peer_addresses(id,mesh_id,peer_id,address,state)
             VALUES($1,$2,$3,$4::inet,'active')",
        )
        .bind(uuid::Uuid::new_v4())
        .bind(mesh.id.into_uuid())
        .bind(peer_id.into_uuid())
        .bind(address.to_string())
        .execute(store.pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO peer_credentials
             (id,mesh_id,peer_id,authority_id,serial,identity_public_key,public_key,
              not_before,not_after,lifecycle,signature,wireguard_public_key)
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'active',$10,$11)",
        )
        .bind(uuid::Uuid::new_v4())
        .bind(mesh.id.into_uuid())
        .bind(peer_id.into_uuid())
        .bind(authority_id)
        .bind(serial.into_uuid())
        .bind(credential.identity_public_key.to_vec())
        .bind(public.to_vec())
        .bind(now - Duration::minutes(1))
        .bind(now + Duration::hours(1))
        .bind(credential.signature.to_vec())
        .bind(credential.wireguard_public_key.to_vec())
        .execute(store.pool())
        .await
        .unwrap();
        entries.push(directory_signer.sign_peer(PeerEntry {
            secondary_address: None,
            mesh_id: mesh.id,
            peer_id: *peer_id,
            address: address.into(),
            identity_public_key: credential.identity_public_key,
            noise_public_key: public,
            credential_serial: serial,
            accepted_credentials: vec![peerward_directory::PeerCredentialBinding::from_subject(
                &credential,
                None,
            )],
            enabled: true,
            labels: BTreeMap::new(),
            not_after: UnixTime(now_seconds + 3_600),
        }));
        peer_private.push(private);
        credentials.push(credential);
    }
    let peer_directory = directory_signer.sign_peers(mesh.id, 1, entries).unwrap();
    let relay_directory = directory_signer
        .sign_relays(
            mesh.id,
            1,
            (0..2)
                .map(|index| RelayEntry {
                    relay_id: relay_ids[index],
                    peer_endpoints: vec![
                        format!("tcp://{}", peer_endpoints[index]).parse().unwrap(),
                    ],
                    backbone_endpoints: vec![
                        format!("tcp://{}", backbone_endpoints[index])
                            .parse()
                            .unwrap(),
                    ],
                    noise_public_key: relay_keys[index].1,
                    credential_serial: relay_serials[index],
                })
                .collect(),
        )
        .unwrap();
    let policy_document =
        encode_policy_document(&Policy::new(0, PolicyAction::Allow, Vec::new())).unwrap();
    let policy = directory_signer.sign_policy(mesh.id, 0, policy_document);
    let services = service_signer
        .sign(RemoteServiceSnapshot {
            mesh_id: mesh.id,
            revision: 0,
            services: Vec::new(),
        })
        .unwrap();
    let revocations = directory_signer
        .sign_revocations(mesh.id, 0, Vec::new())
        .unwrap();
    let authorities = authority
        .sign_authority_bundle(
            mesh.id,
            0,
            authority_certificate.clone(),
            Vec::new(),
            Vec::new(),
        )
        .unwrap();
    let mut states = vec![
        (
            SignedStateKind::Authorities,
            0,
            authorities.encode().unwrap(),
        ),
        (
            SignedStateKind::Peers,
            1,
            encode_peer_directory(&peer_directory).unwrap(),
        ),
        (
            SignedStateKind::Relays,
            1,
            encode_relay_directory(&relay_directory).unwrap(),
        ),
        (SignedStateKind::Policy, 0, encode_policy(&policy).unwrap()),
        (
            SignedStateKind::Services,
            0,
            serde_json::to_vec(&services).unwrap(),
        ),
        (
            SignedStateKind::Revocations,
            0,
            encode_revocations(&revocations).unwrap(),
        ),
    ];
    let configuration = signed_test_configuration(mesh.id, &directory_signer, now_seconds, &states);
    states.push((
        SignedStateKind::Configuration,
        1,
        serde_json::to_vec(&configuration).unwrap(),
    ));
    store.publish_signed_states(mesh.id, &states).await.unwrap();
    let (database_proxy, relay_database_url) = DatabaseFaultProxy::start(&database_url()).await;
    let database_policy = RelayDatabasePolicy::for_test(1, 7).unwrap();
    let mut shutdowns = Vec::new();
    let mut servers = Vec::new();
    for index in 0..2 {
        let mut trust = TrustSet::new(root.public_key(), mesh.id);
        trust
            .add_authority(authority_certificate.clone(), UnixTime(now_seconds))
            .unwrap();
        let config = RelayConfig {
            relay_transport: peerward_carrier::ClientOptions::default(),
            config_version: 1,
            relay_id: relay_ids[index],
            mesh_id: mesh.id,
            peer_address: peer_endpoints[index],
            backbone_address: backbone_endpoints[index],
            health_address: None,
            database_url: Some(relay_database_url.clone()),
            private_key_file: PathBuf::from("unused.key"),
            credential_file: PathBuf::from("unused.credential"),
            root_public_key_file: PathBuf::from("unused.root"),
            authority_certificate_file: PathBuf::from("unused.authority"),
            distribution_certificate_file: PathBuf::from("unused.distribution"),
            queue_capacity: 64,
            lease_seconds: 30,
            keepalive_seconds: 10,
            max_peer_sessions: 10_000,
            max_pending_handshakes: 256,
            max_pending_handshakes_per_ip: 16,
            handshake_timeout_seconds: 5,
        };
        let gate = Arc::new(CredentialGate::new(trust));
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let server_store = Store::connect(&relay_database_url, 8).await.unwrap();
        let private = relay_keys[index].0;
        let relay_credential = relay_credentials[index].encode();
        servers.push(tokio::spawn(async move {
            serve_with_database_policy(
                config,
                private,
                relay_credential,
                distribution,
                gate,
                server_store,
                shutdown_rx,
                database_policy,
            )
            .await
        }));
        shutdowns.push(shutdown_tx);
    }
    for endpoint in peer_endpoints {
        wait_for_listener(endpoint).await;
    }
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert_staged_recovery_through_relay(
        &credentials[0],
        peer_private[0],
        &authority,
        &root,
        &authority_certificate,
        &distribution,
        relay_ids[0],
        peer_endpoints[0],
        relay_keys[0].1,
        now_seconds,
    )
    .await;
    let mut sessions = Vec::new();
    for index in 0..3 {
        let relay_index = usize::from(index == 2);
        let hello = HandshakePayload {
            major: peerward_wire::PROTOCOL_MAJOR,
            minor: 0,
            capabilities: if index == 2 {
                u64::MAX & !peerward_wire::CREDENTIAL_RENEWAL_V1_CAPABILITY
            } else {
                u64::MAX
            },
            credential: credentials[index].encode(),
            attachment_id: AttachmentId::new().as_bytes().to_vec(),
        };
        let (socket, transport, _) = connect_relay_ik_routed(
            peer_endpoints[relay_index],
            &peer_private[index],
            &relay_keys[relay_index].1,
            mesh.id,
            relay_ids[relay_index],
            hello,
        )
        .await
        .unwrap();
        let (control_tx, control_rx) = tokio::sync::mpsc::channel(32);
        let (sender, receiver) = split_noise_relay(socket, transport, control_tx);
        sessions.push((sender, receiver, control_rx));
    }
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert_console_renewal_delivery(
        &store,
        mesh.id,
        &credentials,
        &directory_signer,
        &mut sessions,
        now_seconds,
    )
    .await;
    assert_diagnostic_probe_preserves_presence(
        &store,
        peer_endpoints[0],
        relay_ids[0],
        &relay_keys[0].1,
        &peer_private[0],
        &credentials[0],
        root.public_key(),
        authority_certificate.clone(),
        UnixTime(now_seconds),
    )
    .await;
    let packet = udp_packet(addresses[0], addresses[1], 40_000, 53);
    sessions[0]
        .0
        .send_opaque(mesh.id, peer_ids[1], &packet)
        .await
        .unwrap();
    let received = tokio::time::timeout(
        Duration::seconds(10).unsigned_abs(),
        receive_opaque(&mut sessions[1]),
    )
    .await
    .unwrap();
    assert_eq!(received.opaque, packet);
    assert_eq!(received.source_peer, peer_ids[0].as_bytes());
    let cross_packet = udp_packet(addresses[0], addresses[2], 40_001, 443);
    sessions[0]
        .0
        .send_opaque(mesh.id, peer_ids[2], &cross_packet)
        .await
        .unwrap();
    let received = tokio::time::timeout(
        Duration::seconds(10).unsigned_abs(),
        receive_opaque(&mut sessions[2]),
    )
    .await
    .unwrap();
    assert_eq!(received.opaque, cross_packet);

    assert_opaque_handshake_is_routed(&mut sessions, mesh.id, peer_ids[0], peer_ids[1], 1).await;
    assert_opaque_handshake_is_routed(&mut sessions, mesh.id, peer_ids[0], peer_ids[2], 2).await;
    assert_wireguard_relay_packets(
        &mut sessions,
        &credentials,
        &peer_directory,
        &policy,
        &distribution,
        &root,
        &authority_certificate,
        &authorities,
        &revocations,
        &configuration,
        now_seconds,
    )
    .await;

    let standby_hello = HandshakePayload {
        major: peerward_wire::PROTOCOL_MAJOR,
        minor: 0,
        capabilities: !peerward_wire::PRIMARY_ATTACHMENT_CAPABILITY,
        credential: credentials[0].encode(),
        attachment_id: AttachmentId::new().as_bytes().to_vec(),
    };
    let (standby_socket, standby_transport, _) = connect_relay_ik_routed(
        peer_endpoints[1],
        &peer_private[0],
        &relay_keys[1].1,
        mesh.id,
        relay_ids[1],
        standby_hello,
    )
    .await
    .unwrap();
    let (standby_control_tx, standby_controls) = tokio::sync::mpsc::channel(32);
    let (standby_sender, standby_receiver) =
        split_noise_relay(standby_socket, standby_transport, standby_control_tx);
    sessions.push((standby_sender, standby_receiver, standby_controls));
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let standby_packet = udp_packet(addresses[0], addresses[1], 42_000, 53);
    sessions[3]
        .0
        .send_opaque(mesh.id, peer_ids[1], &standby_packet)
        .await
        .unwrap();
    let received = tokio::time::timeout(
        Duration::seconds(10).unsigned_abs(),
        receive_opaque(&mut sessions[1]),
    )
    .await
    .unwrap();
    assert_eq!(received.opaque, standby_packet);
    let primary = store.active_presence(mesh.id, peer_ids[0]).await.unwrap();
    assert_eq!(primary.relay_id, relay_ids[0]);

    let primary_packet = udp_packet(addresses[0], addresses[1], 42_001, 53);
    sessions[0]
        .0
        .send_opaque(mesh.id, peer_ids[1], &primary_packet)
        .await
        .unwrap();
    let received = tokio::time::timeout(
        Duration::seconds(10).unsigned_abs(),
        receive_opaque(&mut sessions[1]),
    )
    .await
    .unwrap();
    assert_eq!(received.opaque, primary_packet);

    let service_id = ServiceId::new();
    sessions[1]
        .0
        .send_control(ControlEnvelope {
            trace_context: None,
            message: Some(ControlMessage::ServicePublish(ServicePublish {
                mesh_id: mesh.id.as_bytes().to_vec(),
                service_id: service_id.as_bytes().to_vec(),
                protocols: vec![1],
                listen_port: 8_443,
                alias: "echo".into(),
            })),
        })
        .await
        .unwrap();
    assert_service_result(
        &mut sessions,
        mesh.id,
        3,
        1,
        peer_ids[1],
        addresses[0],
        addresses[1],
        service_id,
        43_000,
    )
    .await;
    let service_state: String =
        sqlx::query_scalar("SELECT state FROM services WHERE mesh_id=$1 AND id=$2 AND peer_id=$3")
            .bind(mesh.id.into_uuid())
            .bind(service_id.into_uuid())
            .bind(peer_ids[1].into_uuid())
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert_eq!(service_state, "enabled");
    sessions[1]
        .0
        .send_control(ControlEnvelope {
            trace_context: None,
            message: Some(ControlMessage::ServiceRemove(ServiceRemove {
                mesh_id: mesh.id.as_bytes().to_vec(),
                service_id: service_id.as_bytes().to_vec(),
            })),
        })
        .await
        .unwrap();
    assert_service_result(
        &mut sessions,
        mesh.id,
        3,
        1,
        peer_ids[1],
        addresses[0],
        addresses[1],
        service_id,
        43_001,
    )
    .await;
    let service_state: String =
        sqlx::query_scalar("SELECT state FROM services WHERE mesh_id=$1 AND id=$2")
            .bind(mesh.id.into_uuid())
            .bind(service_id.into_uuid())
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert_eq!(service_state, "disabled");

    database_proxy.set_blocked(true);
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    assert_cached_packet(
        &mut sessions,
        mesh.id,
        peer_ids[2],
        addresses[1],
        addresses[2],
        44_000,
    )
    .await;
    let denied_hello = HandshakePayload {
        major: peerward_wire::PROTOCOL_MAJOR,
        minor: 0,
        capabilities: u64::MAX,
        credential: credentials[1].encode(),
        attachment_id: AttachmentId::new().as_bytes().to_vec(),
    };
    let denied = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        connect_relay_ik_routed(
            peer_endpoints[0],
            &peer_private[1],
            &relay_keys[0].1,
            mesh.id,
            relay_ids[0],
            denied_hello,
        ),
    )
    .await;
    assert!(
        matches!(denied, Ok(Err(_))),
        "stale Relay must promptly reject a new session"
    );

    database_proxy.set_blocked(false);
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    database_proxy.set_blocked(true);
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    assert_cached_packet(
        &mut sessions,
        mesh.id,
        peer_ids[2],
        addresses[1],
        addresses[2],
        44_001,
    )
    .await;
    tokio::time::sleep(std::time::Duration::from_secs(6)).await;
    for server in servers {
        let result = tokio::time::timeout(std::time::Duration::from_secs(2), server)
            .await
            .expect("Relay must stop after the existing-session database grace")
            .unwrap();
        assert!(result.is_err());
    }
    for shutdown in shutdowns {
        let _ = shutdown.send(true);
    }
}

type RelayTestSession = (
    NoiseRelaySender,
    NoiseRelayReceiver,
    tokio::sync::mpsc::Receiver<ControlEnvelope>,
);

async fn receive_matching_control<T>(
    session: &mut RelayTestSession,
    mut select: impl FnMut(ControlEnvelope) -> Option<T>,
) -> T {
    loop {
        let (_, receiver, controls) = session;
        tokio::select! {
            result = receiver.receive_packet() => {
                panic!("blind Relay delivered an invalid plaintext record: {result:?}")
            }
            control = controls.recv() => {
                let control = control.expect("Relay control stream closed");
                if let Some(selected) = select(control) {
                    return selected;
                }
            }
        }
    }
}

async fn receive_opaque(session: &mut RelayTestSession) -> RelayEnvelopeV2 {
    receive_matching_control(session, |control| match control.message {
        Some(ControlMessage::Opaque(envelope)) => Some(envelope),
        _ => None,
    })
    .await
}

async fn assert_cached_packet(
    sessions: &mut [RelayTestSession],
    mesh_id: MeshId,
    destination_peer: PeerId,
    source: Ipv4Addr,
    destination: Ipv4Addr,
    source_port: u16,
) {
    let packet = udp_packet(source, destination, source_port, 53);
    sessions[1]
        .0
        .send_opaque(mesh_id, destination_peer, &packet)
        .await
        .unwrap();
    let received = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        receive_opaque(&mut sessions[2]),
    )
    .await
    .unwrap();
    assert_eq!(received.opaque, packet);
}

async fn assert_service_result(
    sessions: &mut [RelayTestSession],
    mesh_id: MeshId,
    source_index: usize,
    destination_index: usize,
    destination_peer: PeerId,
    source_address: Ipv4Addr,
    destination_address: Ipv4Addr,
    service_id: ServiceId,
    source_port: u16,
) {
    let result = tokio::time::timeout(
        Duration::seconds(10).unsigned_abs(),
        receive_matching_control(
            &mut sessions[destination_index],
            |envelope| match envelope.message {
                Some(ControlMessage::ServiceResult(result)) => Some(result),
                _ => None,
            },
        ),
    )
    .await
    .expect("Relay must acknowledge the committed service mutation");
    assert!(
        result.committed,
        "service mutation failed: {}",
        result.error
    );
    assert_eq!(result.service_id, service_id.as_bytes());

    let packet = udp_packet(source_address, destination_address, source_port, 9);
    sessions[source_index]
        .0
        .send_opaque(mesh_id, destination_peer, &packet)
        .await
        .unwrap();
    let received = tokio::time::timeout(
        Duration::seconds(10).unsigned_abs(),
        receive_opaque(&mut sessions[destination_index]),
    )
    .await
    .unwrap();
    assert_eq!(received.opaque, packet);
}

include!("postgres_network_cases/helpers.rs");

include!("postgres_network_cases/wireguard.rs");
include!("postgres_network_cases/recovery.rs");
