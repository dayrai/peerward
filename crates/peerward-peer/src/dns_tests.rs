use std::{
    collections::BTreeMap,
    str::FromStr,
    sync::atomic::{AtomicUsize, Ordering},
};

use peerward_dataplane::{Action, Firewall};
use peerward_directory::{DirectorySigningKey, PeerEntry, encode_peer_directory};
use peerward_service::{
    RemoteService, RemoteServiceSnapshot, RemoteServiceTable, ServiceProtocol,
    ServiceSnapshotSigningKey,
};
use peerward_types::{CredentialSerial, MeshId, PeerId, ServiceId, UnixTime};
use tokio::task::JoinHandle;

use super::*;

struct CollisionBinder {
    occupied: SocketAddr,
    calls: AtomicUsize,
    always_collide: bool,
}

impl DnsSocketBinder for CollisionBinder {
    fn bind_udp(&self, address: SocketAddr) -> BindFuture<UdpSocket> {
        let call = self.calls.fetch_add(1, Ordering::Relaxed);
        let collide = self.always_collide || call == 0;
        let selected = if collide { self.occupied } else { address };
        Box::pin(async move { UdpSocket::bind(selected).await })
    }

    fn bind_tcp(&self, address: SocketAddr) -> BindFuture<TcpListener> {
        Box::pin(async move { TcpListener::bind(address).await })
    }
}

fn dns_query(id: u16, name: &str, kind: u16) -> Vec<u8> {
    let mut query = Vec::new();
    query.extend_from_slice(&id.to_be_bytes());
    query.extend_from_slice(&0x0100_u16.to_be_bytes());
    query.extend_from_slice(&1_u16.to_be_bytes());
    query.extend_from_slice(&[0; 6]);
    query.extend_from_slice(&encode_name(name));
    query.extend_from_slice(&kind.to_be_bytes());
    query.extend_from_slice(&1_u16.to_be_bytes());
    query
}

#[test]
fn local_dns_accepts_its_tun_alias_but_not_remote_peers() {
    let primary = "10.44.0.9".parse().unwrap();
    let secondary = Some("fd44::9".parse().unwrap());
    let proxy = "10.44.0.1".parse().unwrap();
    for address in ["127.0.0.1", "::1", "10.44.0.9", "fd44::9", "10.44.0.1"] {
        assert!(local_dns_source(
            address.parse().unwrap(),
            primary,
            secondary,
            proxy
        ));
    }
    for address in ["10.44.0.10", "fd44::10", "192.168.1.2", "8.8.8.8"] {
        assert!(!local_dns_source(
            address.parse().unwrap(),
            primary,
            secondary,
            proxy
        ));
    }
}

#[test]
fn managed_dns_encodes_aliases_and_nodata_without_forwarding() {
    use peerward_management::{DnsRecord, EffectiveDns};
    let mut dns = EffectiveDns::default();
    dns.records.insert(
        "printer.office.example".into(),
        vec![DnsRecord::CNAME("physical.office.example".into())],
    );
    dns.records.insert(
        "physical.office.example".into(),
        vec![DnsRecord::A("192.168.45.50".parse().unwrap())],
    );
    let query = dns_query(45, "printer.office.example", 1);
    let question = parse_question(&query).unwrap();
    let reply = managed_records(&query, &question, &dns, false);
    assert_eq!(read_u16(&reply, 6).unwrap(), 2);
    assert!(reply.ends_with(&[192, 168, 45, 50]));
    let query = dns_query(46, "physical.office.example", 28);
    let question = parse_question(&query).unwrap();
    let reply = managed_records(&query, &question, &dns, false);
    assert_eq!(read_u16(&reply, 2).unwrap() & 15, 0);
    assert_eq!(read_u16(&reply, 6).unwrap(), 0);
}

fn ids() -> (MeshId, PeerId, CredentialSerial) {
    (
        MeshId::from_str("970a3f18-1c6f-4da6-a223-f9623958a928").unwrap(),
        PeerId::from_str("778f4317-0d08-4aab-9620-ca2c99a5ee3e").unwrap(),
        CredentialSerial::from_str("40ee7506-2ee1-4b0b-a00c-8f6ec9900011").unwrap(),
    )
}

fn dns_state() -> (
    Arc<RwLock<DirectPeerDirectory>>,
    Arc<Mutex<RemoteServiceTable>>,
) {
    dns_state_with_secondary(None)
}

fn dns_state_with_secondary(
    secondary_address: Option<IpAddr>,
) -> (
    Arc<RwLock<DirectPeerDirectory>>,
    Arc<Mutex<RemoteServiceTable>>,
) {
    let (mesh, peer, serial) = ids();
    let signer = DirectorySigningKey::from_bytes(&[51; 32]);
    let mut labels = BTreeMap::new();
    labels.insert("name".into(), "laptop".into());
    let entry = signer.sign_peer(PeerEntry {
        secondary_address,
        mesh_id: mesh,
        peer_id: peer,
        address: IpAddr::V4(Ipv4Addr::new(10, 44, 0, 9)),
        identity_public_key: [7; 32],
        noise_public_key: [8; 32],
        credential_serial: serial,
        accepted_credentials: vec![peerward_directory::PeerCredentialBinding {
            serial,
            identity_public_key: [7; 32],
            noise_public_key: [8; 32],
            wireguard_public_key: {
                let mut key = [0x77; 32];
                key[..16].copy_from_slice((serial).as_bytes());
                key
            },
            not_before: peerward_types::UnixTime(0),
            not_after: UnixTime(u64::MAX),
            overlap_until: None,
            signature: [0; 64],
        }],
        enabled: true,
        labels,
        not_after: UnixTime(u64::MAX),
    });
    let revision = signer.sign_peers(mesh, 1, vec![entry]).unwrap();
    let encoded = encode_peer_directory(&revision).unwrap();
    let mut directory = DirectPeerDirectory::new(mesh, signer.public_key());
    directory
        .apply_chunk(&peerward_wire::PeerDirectoryChunk {
            mesh_id: mesh.as_bytes().to_vec(),
            revision: 1,
            index: 0,
            count: 1,
            body: encoded,
        })
        .unwrap();

    let service_signer = ServiceSnapshotSigningKey::from_bytes(&[52; 32]);
    let mut services = RemoteServiceTable::new(mesh, service_signer.verifier());
    services
        .reconcile(
            &service_signer
                .sign(RemoteServiceSnapshot {
                    mesh_id: mesh,
                    revision: 1,
                    services: vec![RemoteService {
                        id: ServiceId::from_str("831e8d08-30ab-4ed7-9d31-6606b43de332").unwrap(),
                        owner: peer,
                        credential_serial: serial,
                        virtual_address: IpAddr::V4(Ipv4Addr::new(10, 44, 0, 10)),
                        protocols: vec![ServiceProtocol::Tcp],
                        listen_port: 443,
                        alias: Some("portal".into()),
                    }],
                })
                .unwrap(),
        )
        .unwrap();
    (
        Arc::new(RwLock::new(directory)),
        Arc::new(Mutex::new(services)),
    )
}

async fn start_server(
    upstreams: Vec<SocketAddr>,
    firewall: Arc<Firewall>,
) -> (
    SocketAddr,
    watch::Sender<bool>,
    JoinHandle<io::Result<()>>,
    Arc<RwLock<DirectPeerDirectory>>,
    Arc<Mutex<RemoteServiceTable>>,
) {
    let (directory, services) = dns_state();
    let server = DnsServer::bind(DnsServerConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        suffix: "mesh.test".into(),
        network: "10.44.0.0/16".parse().unwrap(),
        upstreams,
    })
    .await
    .unwrap();
    let address = server.local_addr().unwrap();
    let (shutdown, receiver) = watch::channel(false);
    let task = tokio::spawn(server.serve(
        Arc::clone(&directory),
        Arc::clone(&services),
        firewall,
        receiver,
    ));
    (address, shutdown, task, directory, services)
}

async fn udp_request(server: SocketAddr, query: &[u8]) -> Vec<u8> {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.send_to(query, server).await.unwrap();
    let mut reply = vec![0; MAX_DNS_MESSAGE];
    let (length, _) = timeout(Duration::from_secs(1), socket.recv_from(&mut reply))
        .await
        .unwrap()
        .unwrap();
    reply.truncate(length);
    reply
}

async fn tcp_request(server: SocketAddr, query: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(server).await.unwrap();
    stream
        .write_u16(u16::try_from(query.len()).unwrap())
        .await
        .unwrap();
    stream.write_all(query).await.unwrap();
    let length = stream.read_u16().await.unwrap();
    let mut reply = vec![0; usize::from(length)];
    stream.read_exact(&mut reply).await.unwrap();
    reply
}

#[tokio::test]
async fn actual_udp_tcp_dns_serves_visible_peer_service_ptr_and_rejects_hidden_or_malformed() {
    let allow = Arc::new(Firewall::new(1, Action::Allow, Vec::new(), 8, 1));
    let (server, shutdown, task, directory, services) = start_server(Vec::new(), allow).await;
    let peer = udp_request(server, &dns_query(1, "laptop.mesh.test", 1)).await;
    assert_eq!(read_u16(&peer, 6).unwrap(), 1);
    assert!(peer.ends_with(&[10, 44, 0, 9]));
    let service = tcp_request(server, &dns_query(2, "portal.mesh.test", 1)).await;
    assert_eq!(read_u16(&service, 6).unwrap(), 1);
    assert!(service.ends_with(&[10, 44, 0, 10]));
    let reverse = udp_request(server, &dns_query(3, "9.0.44.10.in-addr.arpa", 12)).await;
    assert_eq!(read_u16(&reverse, 6).unwrap(), 1);
    assert!(reverse.windows(6).any(|window| window == b"laptop"));
    let (_, _, serial) = ids();
    services.lock().await.revoke_credential(serial);
    directory.write().unwrap().revoke(serial);
    let removed_peer = udp_request(server, &dns_query(5, "laptop.mesh.test", 1)).await;
    let removed_service = udp_request(server, &dns_query(6, "portal.mesh.test", 1)).await;
    assert_eq!(read_u16(&removed_peer, 2).unwrap() & 0xf, 3);
    assert_eq!(read_u16(&removed_service, 2).unwrap() & 0xf, 3);
    let malformed = udp_request(server, &[0x12, 0x34, 0]).await;
    assert_eq!(read_u16(&malformed, 2).unwrap() & 0xf, 1);
    shutdown.send(true).unwrap();
    timeout(Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();

    let deny = Arc::new(Firewall::new(1, Action::Deny, Vec::new(), 8, 1));
    let (server, shutdown, task, _, _) = start_server(Vec::new(), deny).await;
    let hidden = udp_request(server, &dns_query(4, "portal.mesh.test", 1)).await;
    assert_eq!(read_u16(&hidden, 2).unwrap() & 0xf, 3);
    assert_eq!(read_u16(&hidden, 6).unwrap(), 0);
    shutdown.send(true).unwrap();
    timeout(Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn dns_shutdown_cancels_an_idle_tcp_connection() {
    let allow = Arc::new(Firewall::new(1, Action::Allow, Vec::new(), 8, 1));
    let (server, shutdown, task, _, _) = start_server(Vec::new(), allow).await;
    let mut idle = TcpStream::connect(server).await.unwrap();
    idle.write_all(&[0]).await.unwrap();
    tokio::task::yield_now().await;

    shutdown.send(true).unwrap();
    timeout(Duration::from_secs(1), task)
        .await
        .expect("DNS shutdown must not wait for an idle TCP client")
        .unwrap()
        .unwrap();
    let mut byte = [0_u8; 1];
    let closed = timeout(Duration::from_secs(1), idle.read(&mut byte))
        .await
        .expect("DNS shutdown must close an idle TCP client");
    assert!(matches!(closed, Ok(0) | Err(_)));
}

#[tokio::test]
async fn forwarding_is_udp_size_safe_and_tcp_retries_the_upstream_transport() {
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = tcp.local_addr().unwrap();
    let udp = UdpSocket::bind(upstream).await.unwrap();
    let udp_task = tokio::spawn(async move {
        let mut request = vec![0; MAX_DNS_MESSAGE];
        let (length, client) = udp.recv_from(&mut request).await.unwrap();
        let mut response = vec![0; 700];
        response[..length].copy_from_slice(&request[..length]);
        response[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
        udp.send_to(&response, client).await.unwrap();
    });
    let tcp_task = tokio::spawn(async move {
        let (mut stream, _) = tcp.accept().await.unwrap();
        let length = stream.read_u16().await.unwrap();
        let mut request = vec![0; usize::from(length)];
        stream.read_exact(&mut request).await.unwrap();
        request[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
        stream.write_u16(length).await.unwrap();
        stream.write_all(&request).await.unwrap();
    });
    let allow = Arc::new(Firewall::new(1, Action::Allow, Vec::new(), 8, 1));
    let (server, shutdown, task, _, _) = start_server(vec![upstream], allow).await;
    let query = dns_query(9, "outside.example", 1);
    let udp_reply = udp_request(server, &query).await;
    assert_ne!(read_u16(&udp_reply, 2).unwrap() & 0x0200, 0);
    assert_eq!(read_u16(&udp_reply, 6).unwrap(), 0);
    let tcp_reply = tcp_request(server, &query).await;
    assert_eq!(tcp_reply, {
        let mut expected = query;
        expected[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
        expected
    });
    udp_task.await.unwrap();
    tcp_task.await.unwrap();
    shutdown.send(true).unwrap();
    timeout(Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn forwarding_configuration_rejects_a_self_loop() {
    let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = occupied.local_addr().unwrap();
    drop(occupied);
    let error = DnsServer::bind(DnsServerConfig {
        listen: address,
        suffix: "mesh.test".into(),
        network: "10.44.0.0/16".parse().unwrap(),
        upstreams: vec![address],
    })
    .await
    .err()
    .unwrap();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
}

#[tokio::test]
async fn dynamic_bind_retries_when_the_udp_candidate_is_occupied_by_tcp() {
    let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let binder = CollisionBinder {
        occupied: occupied.local_addr().unwrap(),
        calls: AtomicUsize::new(0),
        always_collide: false,
    };
    let server = DnsServer::bind_with(
        DnsServerConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            suffix: "mesh.test".into(),
            network: "10.44.0.0/16".parse().unwrap(),
            upstreams: Vec::new(),
        },
        &binder,
    )
    .await
    .unwrap();
    assert_ne!(server.local_addr().unwrap().port(), binder.occupied.port());
    // Other concurrent bind tests can occupy additional ephemeral TCP ports.
    // The forced first collision must retry, within the production bound.
    assert!((2..=DYNAMIC_BIND_ATTEMPTS).contains(&binder.calls.load(Ordering::Relaxed)));
}

#[tokio::test]
async fn dynamic_bind_stops_after_the_bounded_number_of_conflicts() {
    let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let binder = CollisionBinder {
        occupied: occupied.local_addr().unwrap(),
        calls: AtomicUsize::new(0),
        always_collide: true,
    };
    let error = DnsServer::bind_with(
        DnsServerConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            suffix: "mesh.test".into(),
            network: "10.44.0.0/16".parse().unwrap(),
            upstreams: Vec::new(),
        },
        &binder,
    )
    .await
    .err()
    .unwrap();
    assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
    assert_eq!(binder.calls.load(Ordering::Relaxed), DYNAMIC_BIND_ATTEMPTS);
}

#[tokio::test]
async fn fixed_port_failure_releases_the_other_protocol_socket() {
    let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = occupied.local_addr().unwrap();
    let error = DnsServer::bind(DnsServerConfig {
        listen: address,
        suffix: "mesh.test".into(),
        network: "10.44.0.0/16".parse().unwrap(),
        upstreams: Vec::new(),
    })
    .await
    .err()
    .unwrap();
    assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
    UdpSocket::bind(address).await.unwrap();
}

#[tokio::test]
async fn dynamic_ipv6_bind_uses_one_public_port_for_both_protocols() {
    let server = match DnsServer::bind(DnsServerConfig {
        listen: "[::1]:0".parse().unwrap(),
        suffix: "mesh.test".into(),
        network: "fd00:44::/64".parse().unwrap(),
        upstreams: Vec::new(),
    })
    .await
    {
        Ok(server) => server,
        Err(error) if matches!(error.kind(), io::ErrorKind::AddrNotAvailable) => return,
        Err(error) => panic!("unexpected IPv6 bind error: {error}"),
    };
    let address = server.local_addr().unwrap();
    assert!(address.is_ipv6());
    assert_ne!(address.port(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn one_thousand_concurrent_dynamic_dns_binds_are_race_free() {
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..1_000 {
        tasks.spawn(async {
            DnsServer::bind(DnsServerConfig {
                listen: "127.0.0.1:0".parse().unwrap(),
                suffix: "mesh.test".into(),
                network: "10.44.0.0/16".parse().unwrap(),
                upstreams: Vec::new(),
            })
            .await
        });
    }
    let mut servers = Vec::with_capacity(1_000);
    while let Some(result) = tasks.join_next().await {
        let server = result.unwrap().unwrap();
        assert_ne!(server.local_addr().unwrap().port(), 0);
        servers.push(server);
    }
    assert_eq!(servers.len(), 1_000);
}

#[tokio::test]
async fn dual_stack_peer_dns_uses_query_family_and_preserves_authorized_reverse_owner() {
    let secondary: IpAddr = "fd44::9".parse().unwrap();
    let (directory, services) = dns_state_with_secondary(Some(secondary));
    let allow = Firewall::new(1, Action::Allow, Vec::new(), 8, 1);
    for (kind, tail) in [
        (1, vec![10, 44, 0, 9]),
        (
            28,
            "fd44::9"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets()
                .to_vec(),
        ),
    ] {
        let reply = answer(
            &dns_query(kind, "laptop.mesh.test", kind),
            "10.44.0.8".parse().unwrap(),
            false,
            "mesh.test",
            "10.44.0.0/24".parse().unwrap(),
            &[],
            &directory,
            &services,
            &allow,
            None,
        )
        .await
        .unwrap();
        assert_eq!(read_u16(&reply, 6).unwrap(), 1);
        assert!(reply.ends_with(&tail));
    }
    let record = directory.read().unwrap().dns_by_address(secondary).unwrap();
    assert_eq!(record.peer_id, ids().1);
    let deny = Firewall::new(1, Action::Deny, Vec::new(), 8, 1);
    let reply = answer(
        &dns_query(3, "laptop.mesh.test", 28),
        "10.44.0.8".parse().unwrap(),
        false,
        "mesh.test",
        "10.44.0.0/24".parse().unwrap(),
        &[],
        &directory,
        &services,
        &deny,
        None,
    )
    .await
    .unwrap();
    assert_eq!(read_u16(&reply, 2).unwrap() & 15, 3);
}
