use std::str::FromStr;

use peerward_credentials::{
    AuthoritySigningKey, RootSigningKey, SubjectId, UnsignedAuthority, UnsignedSubject,
};
use peerward_directory::DirectorySigningKey;
use peerward_types::{CredentialSerial, SubjectRole, UnixTime};
use prost::Message as _;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::*;

fn mesh() -> MeshId {
    MeshId::from_str("970a3f18-1c6f-4da6-a223-f9623958a928").unwrap()
}

fn relay(value: &str) -> RelayId {
    RelayId::from_str(value).unwrap()
}

fn serial(value: &str) -> CredentialSerial {
    CredentialSerial::from_str(value).unwrap()
}

fn session(relay_id: RelayId, role: AttachmentRole) -> RelaySession {
    RelaySession {
        relay_id,
        attachment_id: AttachmentId::new(),
        role,
        fencing_generation: 1,
        rtt_millis: None,
        missed_keepalives: 0,
        connected: true,
    }
}

fn manager() -> SessionManager {
    let key = DirectorySigningKey::from_bytes(&[1; 32]);
    SessionManager::new(
        mesh(),
        key.public_key(),
        serial("68d07b9e-b046-4402-b688-d606a29e797e"),
        2,
        3,
    )
    .unwrap()
}

#[test]
fn warm_standby_promotes_after_three_misses() {
    let first = relay("81708cad-c18b-4d0f-a580-026c4c285845");
    let second = relay("63dcbd61-99ec-46e8-9808-3d9e9890e917");
    let mut manager = manager();
    manager
        .attach(session(first, AttachmentRole::Primary))
        .unwrap();
    manager
        .attach(session(second, AttachmentRole::Standby))
        .unwrap();
    assert!(!manager.miss_keepalive(first).unwrap());
    assert!(!manager.miss_keepalive(first).unwrap());
    assert!(manager.miss_keepalive(first).unwrap());
    assert_eq!(manager.primary().unwrap().relay_id, second);
}

#[test]
fn queue_pressure_is_bounded_and_shutdown_discards_plaintext() {
    let mut manager = manager();
    manager
        .attach(session(
            relay("81708cad-c18b-4d0f-a580-026c4c285845"),
            AttachmentRole::Primary,
        ))
        .unwrap();
    manager.enqueue_packet(vec![0x45, 1]).unwrap();
    manager.enqueue_packet(vec![0x45, 2]).unwrap();
    assert!(matches!(
        manager.enqueue_packet(vec![0x45, 3]),
        Err(PeerError::QueueFull)
    ));
    assert_eq!(manager.dequeue_packet().unwrap(), Some(vec![0x45, 1]));
    manager.graceful_shutdown();
    assert!(matches!(manager.dequeue_packet(), Err(PeerError::NoRelay)));
}

#[test]
fn exact_revocation_preserves_active_replacement() {
    let old = serial("68d07b9e-b046-4402-b688-d606a29e797e");
    let new = serial("40ee7506-2ee1-4b0b-a00c-8f6ec9900011");
    let mut manager = manager();
    manager.stage_rotation(new).unwrap();
    manager.activate_rotation().unwrap();
    assert!(manager.revoke(old).is_ok());
    assert_eq!(manager.active_serial(), new);
}

#[test]
fn relay_restart_replaces_attachment_without_dropping_packet_identity() {
    let relay_id = relay("81708cad-c18b-4d0f-a580-026c4c285845");
    let mut manager = manager();
    let original = session(relay_id, AttachmentRole::Primary);
    let old_attachment = original.attachment_id;
    manager.attach(original).unwrap();
    manager.enqueue_packet(vec![0x45, 9]).unwrap();
    let mut restarted = session(relay_id, AttachmentRole::Primary);
    restarted.fencing_generation = 2;
    manager.attach(restarted).unwrap();
    assert_ne!(manager.primary().unwrap().attachment_id, old_attachment);
    assert_eq!(manager.primary().unwrap().fencing_generation, 2);
    assert_eq!(manager.dequeue_packet().unwrap(), Some(vec![0x45, 9]));
}

#[test]
fn reconnect_backoff_is_bounded_and_identity_stable() {
    let relay_id = relay("81708cad-c18b-4d0f-a580-026c4c285845");
    assert!(
        SessionManager::reconnect_delay(3, relay_id) < SessionManager::reconnect_delay(4, relay_id)
    );
    assert_eq!(
        SessionManager::reconnect_delay(6, relay_id),
        SessionManager::reconnect_delay(40, relay_id)
    );
}

#[test]
fn config_is_strict_versioned_and_resolves_paths() {
    let text = r#"config_version = 4
mesh_id = "970a3f18-1c6f-4da6-a223-f9623958a928"
peer_id = "778f4317-0d08-4aab-9620-ca2c99a5ee3e"
credential_file = "peer.cert"
identity_private_key_file = "peer.identity.key"
private_key_file = "peer.key"
wireguard_private_key_file = "peer.wireguard.key"
distribution_public_key = "0000000000000000000000000000000000000000000000000000000000000000"
[[relays]]
relay_id = "81708cad-c18b-4d0f-a580-026c4c285845"
endpoints = ["tcp://127.0.0.1:7777"]
public_key = "00"
"#;
    let config = PeerConfig::parse(text, Path::new("/etc/peerward/peer.toml")).unwrap();
    assert_eq!(config.credential_file, Path::new("/etc/peerward/peer.cert"));
    assert!(PeerConfig::parse(&format!("{text}unknown = 1\n"), Path::new("peer.toml")).is_err());
}

#[test]
fn relay_dns_addresses_are_deduplicated_and_family_interleaved() {
    let v6_first: SocketAddr = "[2001:db8::1]:7777".parse().unwrap();
    let v6_second: SocketAddr = "[2001:db8::2]:7777".parse().unwrap();
    let v4_first: SocketAddr = "192.0.2.1:7777".parse().unwrap();
    let v4_second: SocketAddr = "192.0.2.2:7777".parse().unwrap();
    assert_eq!(
        interleave_addresses([v6_first, v6_first, v6_second, v4_first, v4_second]),
        [v6_first, v4_first, v6_second, v4_second]
    );
}

#[tokio::test]
async fn relay_happy_eyeballs_does_not_wait_for_a_stalled_dns_address() {
    let mesh_id = MeshId::new();
    let relay_id = RelayId::new();
    let (peer_private, _) = test_noise_pair();
    let (relay_private, relay_public) = test_noise_pair();
    let root = RootSigningKey::from_bytes(&[41; 32]);
    let authority = AuthoritySigningKey::from_bytes(&[42; 32]);
    let authority_certificate = root
        .certify(UnsignedAuthority {
            mesh_id,
            serial: CredentialSerial::new(),
            public_key: authority.public_key(),
            not_before: UnixTime(1),
            not_after: UnixTime(10_000),
        })
        .unwrap();
    let relay_credential = authority
        .issue(UnsignedSubject {
            subject: SubjectId::Relay(relay_id),
            mesh_id,
            identity_public_key: [0; 32],
            public_noise_key: relay_public,
            serial: CredentialSerial::new(),
            not_before: UnixTime(1),
            not_after: UnixTime(10_000),
            wireguard_public_key: [0; 32],
        })
        .unwrap();
    assert_eq!(relay_credential.role, SubjectRole::Relay);
    let mut trust = TrustSet::new(root.public_key(), mesh_id);
    trust
        .add_authority(authority_certificate, UnixTime(100))
        .unwrap();

    let stalled = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stalled_address = stalled.local_addr().unwrap();
    let stalled_task = tokio::spawn(async move {
        let _connection = stalled.accept().await.unwrap();
        std::future::pending::<()>().await;
    });
    let valid = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let valid_address = valid.local_addr().unwrap();
    let valid_task = tokio::spawn(async move {
        let (mut socket, _) = valid.accept().await.unwrap();
        let mut routing = [0; peerward_wire::RELAY_PREFACE_LEN];
        socket.read_exact(&mut routing).await.unwrap();
        let routing = peerward_wire::RelayPreface::decode(&routing).unwrap();
        assert_eq!(routing.mesh_id, mesh_id);
        assert_eq!(routing.target, relay_id);
        let length = socket.read_u16().await.unwrap();
        let mut request = vec![0; usize::from(length)];
        socket.read_exact(&mut request).await.unwrap();
        let mut handshake = routing.handshake(false, &relay_private, None).unwrap();
        let mut plaintext = vec![0; 65_535];
        handshake.read_message(&request, &mut plaintext).unwrap();
        let welcome = HandshakePayload {
            major: peerward_wire::PROTOCOL_MAJOR,
            minor: 0,
            capabilities: u64::MAX,
            credential: relay_credential.encode(),
            attachment_id: AttachmentId::new().as_bytes().to_vec(),
        };
        let mut response = vec![0; 65_535];
        let count = handshake
            .write_message(&welcome.encode_to_vec(), &mut response)
            .unwrap();
        socket
            .write_u16(u16::try_from(count).unwrap())
            .await
            .unwrap();
        socket.write_all(&response[..count]).await.unwrap();
        let mut transport = StreamTransport::from_handshake(handshake, 0).unwrap();
        let ready = Record::Control(ControlEnvelope {
            trace_context: None,
            message: Some(ControlMessage::Welcome(peerward_wire::Welcome {
                mesh_id: mesh_id.as_bytes().to_vec(),
                body: b"link_ready".to_vec(),
            })),
        });
        socket
            .write_all(&transport.encode(&ready).unwrap())
            .await
            .unwrap();
    });
    let hello = HandshakePayload {
        major: peerward_wire::PROTOCOL_MAJOR,
        minor: 0,
        capabilities: u64::MAX,
        credential: vec![1],
        attachment_id: AttachmentId::new().as_bytes().to_vec(),
    };
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        prepare_resolved_trusted(
            vec![stalled_address, valid_address],
            peer_private,
            relay_public,
            relay_id,
            mesh_id,
            trust,
            UnixTime(100),
            hello,
            Arc::new(LinuxUnderlayNetwork::default()),
            format!("tcp://{valid_address}").parse().unwrap(),
            peerward_carrier::ClientOptions::default(),
        ),
    )
    .await
    .expect("a stalled first DNS address must not consume the five-second timeout")
    .unwrap();
    valid_task.await.unwrap();
    stalled_task.abort();
}

fn test_noise_pair() -> ([u8; 32], [u8; 32]) {
    let pair = snow::Builder::new(peerward_wire::IK_SUITE.parse().unwrap())
        .generate_keypair()
        .unwrap();
    (
        pair.private.try_into().unwrap(),
        pair.public.try_into().unwrap(),
    )
}

#[test]
fn linux_config_is_validated_and_converted() {
    let text = r#"config_version = 4
mesh_id = "970a3f18-1c6f-4da6-a223-f9623958a928"
peer_id = "778f4317-0d08-4aab-9620-ca2c99a5ee3e"
credential_file = "peer.cert"
identity_private_key_file = "peer.identity.key"
private_key_file = "peer.key"
wireguard_private_key_file = "peer.wireguard.key"

[[relays]]
relay_id = "81708cad-c18b-4d0f-a580-026c4c285845"
endpoints = ["tcp://127.0.0.1:7777"]
public_key = "00"

[linux]
interface = "peerward-test0"
address = "10.42.0.7/24"
routes = ["10.42.0.0/16", "fd42::/64"]
dns_suffix = "mesh.test"
dns_server = "10.42.0.1"
dns_upstreams = ["127.0.0.1:5300"]
dns_backend = "network_manager"
network_manager_connection = "peerward-test"
mtu = 1280
attached_tun_file = "tun.fd"

[[linux.nft_allow]]
destination = "10.42.1.0/24"
protocol = "tcp"
destination_port = 443
"#;
    let config = PeerConfig::parse(text, Path::new("/tmp/peerward/peer.toml")).unwrap();
    let linux_document = config.linux.unwrap();
    assert_eq!(
        linux_document.attached_tun_file.as_deref(),
        Some(Path::new("/tmp/peerward/tun.fd"))
    );
    assert_eq!(linux_document.dns_upstreams.len(), 1);
    let linux = linux_document.platform_config().unwrap();
    assert_eq!(linux.interface, "peerward-test0");
    assert_eq!(linux.routes.len(), 2);
    assert_eq!(linux.nft_allow.len(), 1);

    let invalid_protocol = text.replace("protocol = \"tcp\"", "protocol = \"sctp\"");
    assert!(PeerConfig::parse(&invalid_protocol, Path::new("peer.toml")).is_err());
    let unknown = text.replace("mtu = 1280", "mtu = 1280\nmystery = true");
    assert!(PeerConfig::parse(&unknown, Path::new("peer.toml")).is_err());

    let automatic = text
        .replace("dns_backend = \"network_manager\"\n", "")
        .replace("network_manager_connection = \"peerward-test\"\n", "");
    let automatic = PeerConfig::parse(&automatic, Path::new("peer.toml")).unwrap();
    let mut automatic_linux = automatic.linux.unwrap();
    assert!(matches!(automatic_linux.dns_backend, LinuxDnsBackend::Auto));

    let test_root = std::env::temp_dir().join(format!(
        "peerward-systemd-resolved-test-{}",
        uuid::Uuid::new_v4()
    ));
    let systemd_dir = test_root.join("resolve");
    std::fs::create_dir_all(&systemd_dir).unwrap();
    let stub = systemd_dir.join("stub-resolv.conf");
    std::fs::write(&stub, "nameserver 127.0.0.53\n").unwrap();
    std::fs::write(
        systemd_dir.join("resolv.conf"),
        "nameserver 127.0.0.53\nnameserver 192.0.2.53\n",
    )
    .unwrap();
    let config_link = test_root.join("resolv.conf");
    std::os::unix::fs::symlink(&stub, &config_link).unwrap();
    automatic_linux.dns_upstreams.clear();
    automatic_linux.resolv_conf_path = config_link;
    automatic_linux.populate_dns_upstreams().unwrap();
    assert_eq!(
        automatic_linux.dns_upstreams,
        ["192.0.2.53:53".parse().unwrap()]
    );
    std::fs::remove_dir_all(test_root).unwrap();

    let legacy_openresolv = text
        .replace(
            "dns_backend = \"network_manager\"",
            "dns_backend = \"open_resolv\"",
        )
        .replace("network_manager_connection = \"peerward-test\"\n", "");
    let legacy_openresolv = PeerConfig::parse(&legacy_openresolv, Path::new("peer.toml")).unwrap();
    assert!(matches!(
        legacy_openresolv.linux.unwrap().dns_backend,
        LinuxDnsBackend::OpenResolv
    ));
}
