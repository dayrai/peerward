use peerward_platform::{LinuxUnderlayNetwork, UnderlayNetwork};
use peerward_wireguard::{Engine, Event, Ingress, Key};
use std::{
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};
use tokio::net::UdpSocket;
use x25519_dalek::{PublicKey, StaticSecret};

const CLIENT_PRIVATE: [u8; 32] = [0x31; 32];
const SERVER_PRIVATE: [u8; 32] = [0x42; 32];

fn engine(local: [u8; 32], remote: [u8; 32]) -> (Engine, Key) {
    let remote = PublicKey::from(&StaticSecret::from(remote)).to_bytes();
    let mut engine = Engine::new(StaticSecret::from(local), Default::default()).unwrap();
    engine.install(remote).unwrap();
    (engine, remote)
}

fn packet(marker: u8) -> Vec<u8> {
    let mut packet = vec![0; 29];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&29_u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&[10, 42, 0, 1]);
    packet[16..20].copy_from_slice(&[10, 42, 0, 2]);
    packet[20..22].copy_from_slice(&1234_u16.to_be_bytes());
    packet[22..24].copy_from_slice(&1235_u16.to_be_bytes());
    packet[24..26].copy_from_slice(&9_u16.to_be_bytes());
    packet[28] = marker;
    let mut sum: u32 = packet[..20]
        .chunks_exact(2)
        .map(|p| u32::from(u16::from_be_bytes([p[0], p[1]])))
        .sum();
    while sum > 65535 {
        sum = (sum & 65535) + (sum >> 16);
    }
    packet[10..12].copy_from_slice(&(!u16::try_from(sum).unwrap()).to_be_bytes());
    packet
}

async fn receive(socket: &UdpSocket) -> (Vec<u8>, SocketAddr) {
    let mut bytes = vec![0; 65535];
    let (length, source) =
        tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut bytes))
            .await
            .unwrap()
            .unwrap();
    bytes.truncate(length);
    (bytes, source)
}

async fn emit(socket: &UdpSocket, remote: SocketAddr, events: Vec<Event>) {
    for event in events {
        if let Event::Network { packet, .. } = event {
            socket.send_to(&packet, remote).await.unwrap();
        }
    }
}

async fn server(bind: SocketAddr) {
    let socket = UdpSocket::bind(bind).await.unwrap();
    let (mut engine, remote) = engine(SERVER_PRIVATE, CLIENT_PRIVATE);
    let mut first_source = None;
    let mut replay_rejected = false;
    loop {
        let (bytes, source) = receive(&socket).await;
        let events = match engine.receive(Ingress::Direct(source), &bytes) {
            Ok(events) => events,
            Err(_) => {
                replay_rejected = true;
                continue;
            }
        };
        for event in events {
            match event {
                Event::Network { packet, .. } => {
                    socket.send_to(&packet, source).await.unwrap();
                }
                Event::Plaintext {
                    peer,
                    packet: plaintext,
                } => {
                    assert_eq!(peer, remote);
                    let done = first_source.is_some();
                    if let Some(previous) = first_source {
                        assert!(replay_rejected);
                        assert_ne!(source, previous);
                        assert_eq!(plaintext, packet(2));
                    } else {
                        assert_eq!(plaintext, packet(1));
                        first_source = Some(source);
                    }
                    emit(
                        &socket,
                        source,
                        engine
                            .send(&remote, &plaintext, Instant::now(), |_, _| true)
                            .unwrap(),
                    )
                    .await;
                    if done {
                        return;
                    }
                }
            }
        }
    }
}

async fn client(server: SocketAddr) {
    let first = UdpSocket::bind("0.0.0.0:0").await.unwrap();
    let second = UdpSocket::bind("0.0.0.0:0").await.unwrap();
    let (mut engine, remote) = engine(CLIENT_PRIVATE, SERVER_PRIVATE);
    emit(&first, server, engine.initiate(&remote).unwrap()).await;
    let (answer, source) = receive(&first).await;
    assert_eq!(source, server);
    emit(
        &first,
        server,
        engine.receive(Ingress::Direct(source), &answer).unwrap(),
    )
    .await;
    let mut original = None;
    for (marker, socket) in [(1, &first), (2, &second)] {
        let events = engine
            .send(&remote, &packet(marker), Instant::now(), |_, _| true)
            .unwrap();
        if marker == 1 {
            original = events.iter().find_map(|e| match e {
                Event::Network { packet, .. } if packet.first() == Some(&4) => Some(packet.clone()),
                _ => None,
            });
        }
        emit(socket, server, events).await;
        loop {
            let (bytes, source) = receive(socket).await;
            let events = engine.receive(Ingress::Direct(source), &bytes).unwrap();
            let echoed = events
                .iter()
                .any(|e| matches!(e, Event::Plaintext { packet: p, .. } if p == &packet(marker)));
            emit(socket, server, events).await;
            if echoed {
                break;
            }
        }
        if marker == 1 {
            first
                .send_to(original.as_ref().unwrap(), server)
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

async fn underlay(initial_gateway: IpAddr, replacement_gateway: IpAddr) {
    let underlay = LinuxUnderlayNetwork::default();
    let mut changes = underlay.network_changes();
    assert_eq!(underlay.default_gateway().await.unwrap(), initial_gateway);
    println!("ready");
    tokio::time::timeout(std::time::Duration::from_secs(5), changes.changed())
        .await
        .expect("underlay route change timed out")
        .expect("underlay monitor stopped");
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert_eq!(*changes.borrow(), 1, "route event storm was not debounced");
    assert_eq!(
        underlay.default_gateway().await.unwrap(),
        replacement_gateway
    );
}

async fn underlay_polling(gateway: IpAddr) {
    let underlay = LinuxUnderlayNetwork::polling_fallback_for_test();
    let mut changes = underlay.network_changes();
    assert_eq!(underlay.default_gateway().await.unwrap(), gateway);
    println!("ready");
    tokio::time::timeout(std::time::Duration::from_secs(6), changes.changed())
        .await
        .expect("underlay polling fallback timed out")
        .expect("underlay polling fallback stopped");
    assert_eq!(*changes.borrow(), 1);
    assert_eq!(underlay.default_gateway().await.unwrap(), gateway);
}

async fn underlay_missing(initial_gateway: IpAddr) {
    let underlay = LinuxUnderlayNetwork::default();
    let mut changes = underlay.network_changes();
    assert_eq!(underlay.default_gateway().await.unwrap(), initial_gateway);
    println!("ready");
    tokio::time::timeout(std::time::Duration::from_secs(5), changes.changed())
        .await
        .expect("underlay link-down event timed out")
        .expect("underlay monitor stopped");
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert!(underlay.default_gateway().await.is_err());
}

async fn gateway_missing() {
    let underlay = LinuxUnderlayNetwork::default();
    assert!(underlay.default_gateway().await.is_err());
}

async fn resource_apply(intent_path: &str, journal: &str) {
    use peerward_platform::{LinuxCommandBackend, ResourceNetworkIntent, StateCoordinator};
    use std::io::Write as _;
    let intent: ResourceNetworkIntent =
        serde_json::from_slice(&std::fs::read(intent_path).unwrap()).unwrap();
    let routes = peerward_platform::linux_resource_routes().await.unwrap();
    let mut coordinator = StateCoordinator::with_journal(LinuxCommandBackend, journal);
    coordinator.recover().unwrap();
    coordinator
        .apply_resource_network(&intent, &routes)
        .unwrap();
    println!("ready");
    std::io::stdout().flush().unwrap();
    std::io::stdin().read_line(&mut String::new()).unwrap();
    coordinator.shutdown().unwrap();
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let mut arguments = std::env::args().skip(1);
    let role = arguments.next().expect("role is required");
    match role.as_str() {
        "exit-routes" => {
            use std::io::Write as _;
            let path = arguments.next().expect("routing intent required");
            let journal = arguments.next().expect("routing journal required");
            assert!(arguments.next().is_none());
            let intent: peerward_platform::ExitRoutingIntent =
                serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
            let mut coordinator = peerward_platform::StateCoordinator::with_journal(
                peerward_platform::LinuxCommandBackend,
                journal,
            );
            coordinator.recover().unwrap();
            coordinator.apply_exit_routing(&intent).unwrap();
            println!("ready");
            std::io::stdout().flush().unwrap();
            std::io::stdin().read_line(&mut String::new()).unwrap();
            coordinator.shutdown().unwrap();
        }
        "protected-echo" => {
            let address: SocketAddr = arguments
                .next()
                .expect("echo address required")
                .parse()
                .unwrap();
            assert!(arguments.next().is_none());
            let underlay = LinuxUnderlayNetwork::protected();
            let socket = underlay
                .bind_udp(
                    if address.is_ipv4() {
                        "0.0.0.0:0"
                    } else {
                        "[::]:0"
                    }
                    .parse()
                    .unwrap(),
                )
                .await
                .unwrap();
            socket.send_to(b"probe", address).await.unwrap();
            let mut bytes = [0; 128];
            let size =
                tokio::time::timeout(std::time::Duration::from_secs(2), socket.recv(&mut bytes))
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!(&bytes[..size], b"probe");
        }
        "exit-arm" | "exit-restore" | "exit-disable" => {
            use peerward_platform::{ExitProtection, ExitProtectionIntent, LinuxCommandBackend};
            use std::io::Write as _;
            let journal = arguments.next().expect("journal required");
            let mut guard = ExitProtection::new(LinuxCommandBackend, journal);
            if role == "exit-arm" {
                let path = arguments.next().expect("intent file required");
                let intent: ExitProtectionIntent =
                    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
                guard.arm(intent).unwrap();
            } else if role == "exit-restore" {
                assert!(guard.restore().unwrap().is_some());
            } else {
                guard.disarm().unwrap();
            }
            assert!(arguments.next().is_none(), "unexpected argument");
            println!("ready");
            std::io::stdout().flush().unwrap();
            if role == "exit-arm" {
                std::io::stdin().read_line(&mut String::new()).unwrap();
            }
        }
        "resource-apply" => {
            let intent = arguments.next().expect("intent file required");
            let journal = arguments.next().expect("journal file required");
            assert!(arguments.next().is_none(), "unexpected argument");
            resource_apply(&intent, &journal).await;
        }
        "resource-recover" => {
            let journal = arguments.next().expect("journal file required");
            assert!(arguments.next().is_none(), "unexpected argument");
            peerward_platform::StateCoordinator::with_journal(
                peerward_platform::LinuxCommandBackend,
                journal,
            )
            .recover()
            .unwrap();
        }
        "server" | "client" => {
            let address: SocketAddr = arguments
                .next()
                .expect("address is required")
                .parse()
                .expect("address is invalid");
            assert!(arguments.next().is_none(), "unexpected argument");
            if role == "server" {
                server(address).await;
            } else {
                client(address).await;
            }
        }
        "underlay" => {
            let initial = arguments
                .next()
                .expect("initial gateway is required")
                .parse()
                .expect("initial gateway is invalid");
            let replacement = arguments
                .next()
                .expect("replacement gateway is required")
                .parse()
                .expect("replacement gateway is invalid");
            assert!(arguments.next().is_none(), "unexpected argument");
            underlay(initial, replacement).await;
        }
        "underlay-poll" => {
            let gateway = arguments
                .next()
                .expect("gateway is required")
                .parse()
                .expect("gateway is invalid");
            assert!(arguments.next().is_none(), "unexpected argument");
            underlay_polling(gateway).await;
        }
        "underlay-missing" => {
            let initial = arguments
                .next()
                .expect("initial gateway is required")
                .parse()
                .expect("initial gateway is invalid");
            assert!(arguments.next().is_none(), "unexpected argument");
            underlay_missing(initial).await;
        }
        "gateway-missing" => {
            assert!(arguments.next().is_none(), "unexpected argument");
            gateway_missing().await;
        }
        _ => panic!("unsupported probe role"),
    }
}
