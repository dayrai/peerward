use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr},
    os::fd::OwnedFd,
    str::FromStr,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    time::Duration,
};

use peerward_credentials::{
    AuthoritySigningKey, RootSigningKey, UnsignedAuthority, UnsignedSubject,
};
use peerward_dataplane::Action;
use peerward_directory::{
    DirectorySigningKey, PeerEntry, RelayEntry, encode_peer_directory, encode_relay_directory,
};
use peerward_policy::{Action as IdentityAction, PeerDescriptor, Policy, encode_policy_document};
use peerward_types::RelayId;
use tokio::sync::mpsc;

use super::*;

#[path = "relay_read_tests.rs"]
mod relay_read_tests;
#[path = "wireguard_path_tests.rs"]
mod wireguard_path_tests;

fn udp_packet() -> Vec<u8> {
    let mut packet = vec![0_u8; 28];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&28_u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&[10, 20, 0, 2]);
    packet[16..20].copy_from_slice(&[10, 20, 0, 3]);
    packet[20..22].copy_from_slice(&40_000_u16.to_be_bytes());
    packet[22..24].copy_from_slice(&53_u16.to_be_bytes());
    packet[24..26].copy_from_slice(&8_u16.to_be_bytes());
    let mut sum = 0_u32;
    for pair in packet[..20].chunks_exact(2) {
        sum += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let folded = u16::try_from(sum).expect("checksum is folded to sixteen bits");
    packet[10..12].copy_from_slice(&(!folded).to_be_bytes());
    packet
}

fn stun_response(request: &[u8], mapped: std::net::SocketAddrV4) -> Vec<u8> {
    const MAGIC: u32 = peerward_p2p::STUN_MAGIC;
    let mut response = vec![0_u8; 32];
    response[..2].copy_from_slice(&0x0101_u16.to_be_bytes());
    response[2..4].copy_from_slice(&12_u16.to_be_bytes());
    response[4..8].copy_from_slice(&MAGIC.to_be_bytes());
    response[8..20].copy_from_slice(&request[8..20]);
    response[20..22].copy_from_slice(&0x0020_u16.to_be_bytes());
    response[22..24].copy_from_slice(&8_u16.to_be_bytes());
    response[25] = 1;
    response[26..28].copy_from_slice(&(mapped.port() ^ (MAGIC >> 16) as u16).to_be_bytes());
    for (index, octet) in mapped.ip().octets().iter().enumerate() {
        response[28 + index] = *octet ^ MAGIC.to_be_bytes()[index];
    }
    response
}

struct ChannelReader(mpsc::Receiver<Vec<u8>>);

#[async_trait]
impl PacketReader for ChannelReader {
    async fn read_packet(&mut self, buffer: &mut [u8]) -> Result<usize, PacketPumpError> {
        let packet = self
            .0
            .recv()
            .await
            .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))?;
        buffer[..packet.len()].copy_from_slice(&packet);
        Ok(packet.len())
    }
}

struct ChannelWriter(mpsc::Sender<Vec<u8>>);

#[derive(Clone)]
struct CapturingControl(mpsc::UnboundedSender<ControlEnvelope>);

#[async_trait]
impl ControlSender for CapturingControl {
    async fn send_control(&self, control: ControlEnvelope) -> Result<(), PacketPumpError> {
        self.0
            .send(control)
            .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe).into())
    }
}

#[async_trait]
impl PacketWriter for ChannelWriter {
    async fn write_packet(&mut self, packet: &[u8]) -> Result<(), PacketPumpError> {
        self.0
            .send(packet.to_vec())
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
        Ok(())
    }
}

#[tokio::test]
async fn relay_pool_promotes_standby_preserves_packets_and_reuses_recovered_slot() {
    let primary_healthy = Arc::new(AtomicBool::new(false));
    let standby_healthy = Arc::new(AtomicBool::new(true));
    let primary_attempts = Arc::new(AtomicUsize::new(0));
    let standby_attempts = Arc::new(AtomicUsize::new(0));
    let (delivered_tx, mut delivered_rx) = mpsc::channel(8);
    let mut slots = Vec::new();
    for (healthy, attempts) in [
        (Arc::clone(&primary_healthy), Arc::clone(&primary_attempts)),
        (Arc::clone(&standby_healthy), Arc::clone(&standby_attempts)),
    ] {
        let (sender, mut receiver) = mpsc::channel(8);
        slots.push(sender);
        let delivered = delivered_tx.clone();
        tokio::spawn(async move {
            while let Some(command) = receiver.recv().await {
                match command {
                    RelaySlotCommand::Wireguard(_, _) => {
                        panic!("control-only fixture received WG data")
                    }
                    RelaySlotCommand::Control(envelope, reply) => {
                        attempts.fetch_add(1, Ordering::SeqCst);
                        let accepted = healthy.load(Ordering::SeqCst);
                        if accepted && let Some(ControlMessage::Opaque(opaque)) = envelope.message {
                            delivered.send(opaque.opaque).await.unwrap();
                        }
                        let _ = reply.send(accepted);
                    }
                }
            }
        });
    }
    drop(delivered_tx);
    let mut pool = RelayPoolSender {
        state: Arc::new(Mutex::new(RelayPoolState {
            primary: 0,
            primary_since: monotonic_seconds(),
            better_streak: vec![0; slots.len()],
            slots,
            flow_assignments: BTreeMap::new(),
        })),
        health: Arc::new(Mutex::new(vec![
            RelaySlotHealth {
                connected: true,
                ..RelaySlotHealth::default()
            },
            RelaySlotHealth {
                connected: true,
                ..RelaySlotHealth::default()
            },
        ])),
        observability: None,
    };

    for packet in [b"first".as_slice(), b"second".as_slice()] {
        assert_eq!(
            pool.send_opaque(MeshId::new(), PeerId::new(), packet)
                .await
                .unwrap(),
            DataPath::Relay
        );
        assert_eq!(delivered_rx.recv().await.unwrap(), packet);
    }
    assert_eq!(primary_attempts.load(Ordering::SeqCst), 1);
    assert_eq!(standby_attempts.load(Ordering::SeqCst), 2);

    standby_healthy.store(false, Ordering::SeqCst);
    primary_healthy.store(true, Ordering::SeqCst);
    for packet in [b"third".as_slice(), b"fourth".as_slice()] {
        assert_eq!(
            pool.send_opaque(MeshId::new(), PeerId::new(), packet)
                .await
                .unwrap(),
            DataPath::Relay
        );
        assert_eq!(delivered_rx.recv().await.unwrap(), packet);
    }
    assert_eq!(standby_attempts.load(Ordering::SeqCst), 3);
    assert_eq!(primary_attempts.load(Ordering::SeqCst), 3);
}

struct FallbackSender {
    direct_fails: Arc<AtomicBool>,
    delivered: mpsc::Sender<(DataPath, Vec<u8>)>,
}

#[async_trait]
impl PacketSender for FallbackSender {
    async fn send_packet(&mut self, packet: &[u8], _: u64) -> Result<DataPath, PacketPumpError> {
        let path = if self.direct_fails.load(Ordering::Relaxed) {
            DataPath::Relay
        } else {
            DataPath::Direct
        };
        self.delivered
            .send((path, packet.to_vec()))
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
        Ok(path)
    }
}

#[async_trait]
impl OpaqueRelaySender for FallbackSender {
    async fn send_opaque(
        &mut self,
        _: MeshId,
        _: PeerId,
        ciphertext: &[u8],
    ) -> Result<DataPath, PacketPumpError> {
        self.delivered
            .send((DataPath::Relay, ciphertext.to_vec()))
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
        Ok(DataPath::Relay)
    }
}

struct ChannelReceiver(mpsc::Receiver<(DataPath, Vec<u8>)>);

#[async_trait]
impl PacketReceiver for ChannelReceiver {
    async fn receive_packet(&mut self) -> Result<(DataPath, Vec<u8>), PacketPumpError> {
        self.0
            .recv()
            .await
            .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof).into())
    }
}

#[tokio::test]
async fn pump_delivers_after_direct_failure_through_relay_and_accepts_inbound() {
    let packet = udp_packet();
    let firewall = Arc::new(Firewall::new(1, Action::Allow, Vec::new(), 32, 2));
    let (tun_tx, tun_rx) = mpsc::channel(2);
    let (written_tx, mut written_rx) = mpsc::channel(2);
    let (sent_tx, mut sent_rx) = mpsc::channel(2);
    let (receive_tx, receive_rx) = mpsc::channel(2);
    let direct_fails = Arc::new(AtomicBool::new(true));
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let pump = tokio::spawn(run_packet_pump(
        ChannelReader(tun_rx),
        ChannelWriter(written_tx),
        FallbackSender {
            direct_fails,
            delivered: sent_tx,
        },
        ChannelReceiver(receive_rx),
        Arc::clone(&firewall),
        firewall,
        1380,
        shutdown_rx,
    ));
    tun_tx.send(packet.clone()).await.unwrap();
    let (path, relayed) = sent_rx.recv().await.unwrap();
    assert_eq!(path, DataPath::Relay);
    assert_eq!(relayed, packet);
    receive_tx
        .send((DataPath::Relay, packet.clone()))
        .await
        .unwrap();
    assert_eq!(written_rx.recv().await.unwrap(), packet);
    shutdown_tx.send(true).unwrap();
    let counters = pump.await.unwrap().unwrap();
    assert_eq!(counters.relay_sent, 1);
    assert_eq!(counters.ingress_allowed, 1);
}

#[test]
fn signed_live_policy_denies_until_verified_and_invalidates_return_state_on_replace() {
    let mesh_id = MeshId::new();
    let local_peer = PeerId::new();
    let remote_peer = PeerId::new();
    let signer = DirectorySigningKey::from_bytes(&[73; 32]);
    let policy = LivePeerPolicy::new(mesh_id, local_peer, signer.public_key(), 32, 2);
    let outbound = parse_packet(&udp_packet()).unwrap();
    assert_eq!(policy.evaluate_packet(&outbound, 1), Action::Deny);

    policy
        .install_directory(vec![
            PeerDescriptor {
                id: local_peer,
                address: IpAddr::V4(Ipv4Addr::new(10, 20, 0, 2)),
                labels: BTreeMap::new(),
            },
            PeerDescriptor {
                id: remote_peer,
                address: IpAddr::V4(Ipv4Addr::new(10, 20, 0, 3)),
                labels: BTreeMap::new(),
            },
        ])
        .unwrap();
    let allow = Policy::new(1, IdentityAction::Allow, Vec::new());
    policy
        .install_policy(signer.sign_policy(
            mesh_id,
            allow.revision,
            encode_policy_document(&allow).unwrap(),
        ))
        .unwrap();
    assert_eq!(policy.evaluate_packet(&outbound, 2), Action::Allow);
    let returned = parse_packet(&reverse_udp(&udp_packet())).unwrap();
    assert_eq!(policy.evaluate_packet(&returned, 3), Action::Allow);

    let deny = Policy::new(2, IdentityAction::Deny, Vec::new());
    policy
        .install_policy(signer.sign_policy(
            mesh_id,
            deny.revision,
            encode_policy_document(&deny).unwrap(),
        ))
        .unwrap();
    assert_eq!(policy.evaluate_packet(&returned, 4), Action::Deny);
}

#[tokio::test]
async fn credential_rotation_recovers_four_files_and_reordered_delivery() {
    let mesh_id = MeshId::new();
    let peer_id = PeerId::new();
    let now = wall_clock_seconds();
    let root = RootSigningKey::from_bytes(&[81; 32]);
    let authority = AuthoritySigningKey::from_bytes(&[82; 32]);
    let authority_certificate = root
        .certify(UnsignedAuthority {
            mesh_id,
            serial: CredentialSerial::new(),
            public_key: authority.public_key(),
            not_before: UnixTime(now - 60),
            not_after: UnixTime(now + 86_400),
        })
        .unwrap();
    let (old_private, old_public) = noise_pair();
    let old_identity = IdentitySigningKey::from_bytes(&[83; 32]);
    let current = authority
        .issue(UnsignedSubject {
            subject: SubjectId::Peer(peer_id),
            mesh_id,
            identity_public_key: old_identity.verifying_key().to_bytes(),
            public_noise_key: old_public,
            serial: CredentialSerial::new(),
            not_before: UnixTime(now - 60),
            not_after: UnixTime(now + 120),
            wireguard_public_key: [0x77; 32],
        })
        .unwrap();
    let mut trust = TrustSet::new(root.public_key(), mesh_id);
    trust
        .add_authority(authority_certificate, UnixTime(now))
        .unwrap();
    let trust = Arc::new(trust);
    let directory = std::env::temp_dir().join(format!("peerward-rotation-{}", RotationId::new()));
    peerward_credentials::private_files::private_dir(&directory).unwrap();
    let private_key_file = directory.join("peer.key");
    let wireguard_private_key_file = directory.join("peer.wireguard.key");
    let identity_private_key_file = directory.join("peer.identity.key");
    let credential_file = directory.join("peer.credential");
    let old_credential = current.encode();
    write_secure(
        &private_key_file,
        format!("{}\n", hex::encode(old_private)).as_bytes(),
    )
    .unwrap();
    write_secure(
        &identity_private_key_file,
        format!("{}\n", hex::encode(old_identity.to_bytes())).as_bytes(),
    )
    .unwrap();
    write_secure(&credential_file, &old_credential).unwrap();
    let config = PeerConfig {
        relay_transport: peerward_carrier::ClientOptions::default(),
        config_version: 4,
        mesh_id,
        peer_id,
        credential_file: credential_file.clone(),
        identity_private_key_file: identity_private_key_file.clone(),
        private_key_file: private_key_file.clone(),
        wireguard_private_key_file: wireguard_private_key_file.clone(),
        root_public_key_file: None,
        authority_certificate_files: Vec::new(),
        distribution_certificate_file: None,
        relays: Vec::new(),
        packet_queue_capacity: 8,
        keepalive_seconds: 1,
        unhealthy_after_missed: 1,
        management_socket: directory.join("management.sock"),
        service_state_file: directory.join("services.json"),
        linux: None,
        stun_servers: Vec::new(),
        p2p_endpoints: Vec::new(),
        nat_mapping: crate::NatMappingMode::Auto,
        symmetric_nat_prediction: false,
        relay_pool_size: 3,
        distribution_public_key: None,
        service_distribution_public_key: None,
        audit_public_key: None,
    };
    let (identity, identity_rx) = watch::channel(RelayIdentity {
        private_key: old_private,
        credential: current.encode(),
    });
    let mut rotator = CredentialRotator::new(
        &config,
        &current.encode(),
        DynamicTrust::new((*trust).clone()),
        identity,
    )
    .unwrap();
    let (sent, mut controls) = mpsc::unbounded_channel();
    let control = CapturingControl(sent);
    let audit_private = x25519_dalek::StaticSecret::from([91; 32]);
    let reporter = PeerAuditReporter {
        mesh_id,
        peer_id,
        recipient_public: x25519_dalek::PublicKey::from(&audit_private).to_bytes(),
        identity_file: identity_private_key_file.clone(),
        control: control.clone(),
        observability: None,
        last_health_sequence: 0,
    };
    let signer = peerward_directory::DirectorySigningKey::from_bytes(&[85; 32]);
    rotator.renewal_distribution = Some(authority.certify_distribution(
        mesh_id,
        signer.public_key().to_bytes(),
        [86; 32],
        [87; 32],
    ));
    let command = signer
        .sign_credential_renewal(peerward_management::CredentialRenewalCommand {
            request_id: uuid::Uuid::new_v4(),
            mesh_id,
            peer_id,
            current_serial: current.serial,
            issued_at: now,
            expires_at: now + 300,
        })
        .unwrap();
    let body = serde_json::to_vec(&command).unwrap();
    rotator.request_from_console(&body, &control).await.unwrap();
    rotator.request_from_console(&body, &control).await.unwrap();
    let ControlMessage::RotationRequest(request) = controls.recv().await.unwrap().message.unwrap()
    else {
        panic!("expected rotation request")
    };
    // Crash after sending a request, before any Authority replacement exists.
    recover_peer_identity_files(
        &identity_private_key_file,
        &private_key_file,
        &wireguard_private_key_file,
        &credential_file,
    )
    .unwrap();
    let mut requested = CredentialRotator::new(
        &config,
        &current.encode(),
        DynamicTrust::new((*trust).clone()),
        rotator.identity.clone(),
    )
    .unwrap();
    requested.request_if_due(&control).await.unwrap();
    let ControlMessage::RotationRequest(replayed) = controls.recv().await.unwrap().message.unwrap()
    else {
        panic!("expected recovered rotation request")
    };
    assert_eq!(request, replayed);
    drop(rotator);
    let mut rotator = requested;
    assert_ne!(request.session_public_key, old_private);
    let session_public_key: [u8; 32] = request.session_public_key.as_slice().try_into().unwrap();
    let identity_public_key: [u8; 32] = request.identity_public_key.as_slice().try_into().unwrap();
    let replacement = authority
        .issue(UnsignedSubject {
            subject: SubjectId::Peer(peer_id),
            mesh_id,
            identity_public_key,
            public_noise_key: session_public_key,
            serial: CredentialSerial::new(),
            not_before: UnixTime(now - 1),
            not_after: UnixTime(now + 86_000),
            wireguard_public_key: request.wireguard_public_key.as_slice().try_into().unwrap(),
        })
        .unwrap();
    rotator
        .accept_replacement(
            &CredentialReplacement {
                mesh_id: mesh_id.as_bytes().to_vec(),
                request_id: request.request_id,
                credential: replacement.encode(),
                activation_challenge: [90; 32].to_vec(),
            },
            &control,
        )
        .await
        .unwrap();
    assert!(matches!(
        controls.recv().await.unwrap().message,
        Some(ControlMessage::Activation(_))
    ));
    let mut recovered = CredentialRotator::new(
        &config,
        &current.encode(),
        DynamicTrust::new((*trust).clone()),
        rotator.identity.clone(),
    )
    .unwrap();
    assert_eq!(
        recovered.pending.as_ref().unwrap().wireguard_public_key,
        replacement.wireguard_public_key
    );
    // A reconnect can receive the signed directory before the replacement.
    recovered
        .commit_if_published(&PeerEntry {
            secondary_address: None,
            mesh_id,
            peer_id,
            address: "10.42.0.2".parse().unwrap(),
            identity_public_key,
            noise_public_key: session_public_key,
            credential_serial: replacement.serial,
            accepted_credentials: vec![
                peerward_directory::PeerCredentialBinding::from_subject(&replacement, None),
                peerward_directory::PeerCredentialBinding::from_subject(
                    &current,
                    Some(current.not_after),
                ),
            ],
            enabled: true,
            labels: BTreeMap::new(),
            not_after: replacement.not_after,
        })
        .unwrap();
    assert_eq!(identity_rx.borrow().credential, old_credential);
    assert_eq!(std::fs::read(&credential_file).unwrap(), old_credential);
    let request_id = recovered.pending.as_ref().unwrap().id.as_bytes().to_vec();
    recovered
        .accept_replacement(
            &CredentialReplacement {
                mesh_id: mesh_id.as_bytes().to_vec(),
                request_id,
                credential: replacement.encode(),
                activation_challenge: [90; 32].to_vec(),
            },
            &control,
        )
        .await
        .unwrap();
    assert!(matches!(
        controls.recv().await.unwrap().message,
        Some(ControlMessage::Activation(_))
    ));
    drop(rotator);
    assert!(recovered.pending_commit.is_none());
    assert_eq!(
        std::fs::read(&credential_file).unwrap(),
        replacement.encode()
    );
    assert_eq!(
        hex::decode(std::fs::read_to_string(&private_key_file).unwrap().trim()).unwrap(),
        identity_rx.borrow().private_key,
    );

    let next_private = adjacent_path(&private_key_file, "next");
    reporter
        .flush(&mut BTreeMap::from([(
            (
                peerward_wire::AuditDirectionV1::Egress as i32,
                peerward_wire::AuditReasonV1::PolicyDenied as i32,
            ),
            1,
        )]))
        .await
        .unwrap();
    let Some(ControlMessage::Opaque(audit)) = controls.recv().await.unwrap().message else {
        panic!("expected rotated audit")
    };
    let sealed = peerward_wire::SealedAuditBatchV1::decode(audit.opaque.as_slice()).unwrap();
    assert!(
        peerward_wire::open_audit_batch(
            &sealed,
            &audit_private.to_bytes(),
            &current.identity_public_key
        )
        .is_err()
    );
    let decoded = peerward_wire::open_audit_batch(
        &sealed,
        &audit_private.to_bytes(),
        &replacement.identity_public_key,
    )
    .unwrap();
    assert_eq!(decoded.events[0].count, 1);
    let next_wireguard = adjacent_path(&wireguard_private_key_file, "next");
    let next_identity_private = adjacent_path(&identity_private_key_file, "next");
    let next_credential = adjacent_path(&credential_file, "next");
    let marker = adjacent_path(&private_key_file, "rotation");
    write_secure(&next_private, b"recovered-private").unwrap();
    write_secure(&next_wireguard, b"abandoned-wireguard").unwrap();
    write_secure(&next_identity_private, b"recovered-identity").unwrap();
    write_secure(&next_credential, b"recovered-credential").unwrap();
    write_secure(&marker, format!("staged:{}", RotationId::new()).as_bytes()).unwrap();
    recover_peer_identity_files(
        &identity_private_key_file,
        &private_key_file,
        &wireguard_private_key_file,
        &credential_file,
    )
    .unwrap();
    assert_eq!(
        std::fs::read(&private_key_file).unwrap(),
        format!("{}\n", hex::encode(identity_rx.borrow().private_key)).as_bytes()
    );
    assert_eq!(
        std::fs::read(&credential_file).unwrap(),
        replacement.encode()
    );
    assert!(marker.exists());
    assert_eq!(
        std::fs::read(&next_wireguard).unwrap(),
        b"abandoned-wireguard"
    );

    write_secure(&next_private, b"committed-private").unwrap();
    write_secure(&next_wireguard, b"committed-wireguard").unwrap();
    write_secure(&next_identity_private, b"committed-identity").unwrap();
    write_secure(&next_credential, b"committed-credential").unwrap();
    write_secure(
        &marker,
        format!("committing:{}", RotationId::new()).as_bytes(),
    )
    .unwrap();
    recover_peer_identity_files(
        &identity_private_key_file,
        &private_key_file,
        &wireguard_private_key_file,
        &credential_file,
    )
    .unwrap();
    assert_eq!(
        std::fs::read(&private_key_file).unwrap(),
        b"committed-private"
    );
    assert_eq!(
        std::fs::read(&credential_file).unwrap(),
        b"committed-credential"
    );
    assert_eq!(
        std::fs::read(&identity_private_key_file).unwrap(),
        b"committed-identity"
    );
    assert_eq!(
        std::fs::read(&wireguard_private_key_file).unwrap(),
        b"committed-wireguard"
    );
    std::fs::remove_dir_all(directory).unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn attached_tun_adapter_reads_and_writes_a_real_file_descriptor() {
    use std::os::unix::net::UnixStream as StdUnixStream;

    let (attached, peer) = StdUnixStream::pair().unwrap();
    attached.set_nonblocking(true).unwrap();
    peer.set_nonblocking(true).unwrap();
    let file = std::fs::File::from(OwnedFd::from(attached));
    let (mut reader, mut writer) = AttachedTun::from_file(file).unwrap();
    let mut peer = tokio::net::UnixStream::from_std(peer).unwrap();
    let packet = udp_packet();
    peer.write_all(&packet).await.unwrap();
    let mut buffer = [0_u8; 64];
    let length = reader.read_packet(&mut buffer).await.unwrap();
    assert_eq!(&buffer[..length], packet);
    writer.write_packet(&packet).await.unwrap();
    peer.read_exact(&mut buffer[..packet.len()]).await.unwrap();
    assert_eq!(&buffer[..packet.len()], packet);
}

include!("packet_test_support.rs");

include!("tests_packet_data_path.rs");
#[path = "stun_demux_tests.rs"]
mod stun_demux_tests;
