use super::*;
use crate::tests::Certificates;
use peerward_types::{MeshId, PeerId, RelayId};
use peerward_wire::{Keepalive, PROTOCOL_MAJOR};
use x25519_dalek::{PublicKey, StaticSecret};

fn preface() -> RelayPreface {
    RelayPreface {
        mesh_id: MeshId::new(),
        target: RelayId::new(),
        source: None,
    }
}
fn budgets() -> (Budget, Budget) {
    (Budget::new(1024 * 1024), Budget::new(512 * 1024))
}
fn envelope(preface: RelayPreface, source: Vec<u8>, size: usize) -> RelayEnvelopeV2 {
    RelayEnvelopeV2 {
        major: PROTOCOL_MAJOR,
        mesh_id: preface.mesh_id.as_bytes().to_vec(),
        destination_peer: PeerId::new().as_bytes().to_vec(),
        source_peer: source,
        kind: OpaqueFrameKind::Session as i32,
        opaque: vec![7; size],
    }
}
fn keepalive(stamp: u64) -> ControlEnvelope {
    ControlEnvelope {
        trace_context: None,
        message: Some(ControlMessage::Keepalive(Keepalive {
            monotonic_timestamp: stamp,
        })),
    }
}

async fn pending_pair(route: RelayPreface) -> (PendingQuic, PendingQuic, Listener) {
    let cert = Certificates::new();
    let listener = Listener::bind(
        UdpSocket::bind("127.0.0.1:0").unwrap(),
        &cert.certificate,
        &cert.key,
    )
    .unwrap();
    let (left, right) = pending_on_listener(route, &listener, cert.options()).await;
    (left, right, listener)
}
async fn pending_on_listener(
    route: RelayPreface,
    listener: &Listener,
    options: ClientOptions,
) -> (PendingQuic, PendingQuic) {
    let address = listener.local_addr().unwrap();
    let client = tokio::spawn(async move {
        let mut pending = connect(
            UdpSocket::bind(if address.is_ipv6() {
                "[::1]:0"
            } else {
                "127.0.0.1:0"
            })
            .unwrap(),
            address,
            "localhost",
            &options,
        )
        .await
        .unwrap();
        pending.control().write_all(&route.encode()).await.unwrap();
        pending
    });
    let mut server = listener
        .accept(listener.incoming().await.unwrap())
        .await
        .unwrap();
    let mut bytes = [0; peerward_wire::RELAY_PREFACE_LEN];
    server.control().read_exact(&mut bytes).await.unwrap();
    assert_eq!(RelayPreface::decode(&bytes).unwrap(), route);
    (client.await.unwrap(), server)
}

fn noise_states(route: RelayPreface) -> (snow::HandshakeState, snow::HandshakeState) {
    let client = [41; 32];
    let server = [43; 32];
    let server_public = PublicKey::from(&StaticSecret::from(server)).to_bytes();
    let client_public = PublicKey::from(&StaticSecret::from(client)).to_bytes();
    (
        route
            .handshake(true, &client, Some(&server_public))
            .unwrap(),
        route
            .handshake(false, &server, route.source.map(|_| &client_public))
            .unwrap(),
    )
}
async fn authenticate(
    left: &mut PendingQuic,
    right: &mut PendingQuic,
    route: RelayPreface,
) -> (StreamTransport, StreamTransport) {
    let (mut initiator, mut responder) = noise_states(route);
    let mut frame = vec![0; 65535];
    let mut plain = frame.clone();
    let len = initiator
        .write_message(b"fixture Noise identity", &mut frame)
        .unwrap();
    left.control()
        .write_u16(u16::try_from(len).unwrap())
        .await
        .unwrap();
    left.control().write_all(&frame[..len]).await.unwrap();
    let len = right.control().read_u16().await.unwrap() as usize;
    right.control().read_exact(&mut frame[..len]).await.unwrap();
    responder.read_message(&frame[..len], &mut plain).unwrap();
    let len = responder
        .write_message(b"fixture Noise identity", &mut frame)
        .unwrap();
    right
        .control()
        .write_u16(u16::try_from(len).unwrap())
        .await
        .unwrap();
    right.control().write_all(&frame[..len]).await.unwrap();
    let len = left.control().read_u16().await.unwrap() as usize;
    left.control().read_exact(&mut frame[..len]).await.unwrap();
    initiator.read_message(&frame[..len], &mut plain).unwrap();
    (
        StreamTransport::from_handshake(initiator, 100).unwrap(),
        StreamTransport::from_handshake(responder, 100).unwrap(),
    )
}
async fn pair(route: RelayPreface) -> (QuicLink, QuicLink, Listener) {
    let (mut left, mut right, listener) = pending_pair(route).await;
    let (a, b) = authenticate(&mut left, &mut right, route).await;
    let (process, mesh) = budgets();
    let (left, right) = tokio::join!(
        left.admit(a, route, process.clone(), mesh.clone(), 100),
        right.admit(b, route, process, mesh, 100)
    );
    (left.unwrap(), right.unwrap(), listener)
}
fn datagram_bytes(envelope: RelayEnvelopeV2) -> Vec<u8> {
    ControlEnvelope {
        trace_context: None,
        message: Some(ControlMessage::Opaque(envelope)),
    }
    .encode_to_vec()
}
async fn receive(link: &mut QuicLink) -> Received {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let record = link.receive().await.unwrap();
            match record {
                Received::Ping(sequence) => {
                    link.heartbeat(sequence, true).await.unwrap();
                    continue;
                }
                Received::Pong(_) | Received::Acknowledged(_) => continue,
                Received::Control(_) => link.acknowledge(link.received_control()).await.unwrap(),
                _ => {}
            }
            return record;
        }
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn real_quic_datagrams_reassemble_and_reliable_control_remains_ordered() {
    let route = preface();
    let (mut client, mut server, _listener) = pair(route).await;
    let message = envelope(route, vec![], 9000);
    assert!(client.send_opaque(&message).unwrap());
    let Received::Opaque(received) = receive(&mut server).await else {
        panic!("expected DATAGRAM");
    };
    assert_eq!(received, message);
    assert!(client.stats().sent_fragments > 1);
    for stamp in 0..20 {
        server.send_control(keepalive(stamp)).await.unwrap();
        let Received::Control(message) = receive(&mut client).await else {
            panic!("expected control");
        };
        assert_eq!(message, keepalive(stamp));
    }
    assert_eq!(server.stats().received_frames, 1);
}

#[tokio::test]
async fn incomplete_and_reordered_datagrams_do_not_stall_or_corrupt_control() {
    let route = preface();
    let (mut client, mut server, _listener) = pair(route).await;
    let message = envelope(route, vec![], 4000);
    let mut parts = fragments::split(100, &datagram_bytes(message.clone()), 1000).unwrap();
    let first = parts.remove(0);
    for part in parts.into_iter().rev() {
        let mut bytes = client.send_token.to_vec();
        bytes.extend_from_slice(&part);
        client.owner.connection.send_datagram(bytes.into()).unwrap();
    }
    client.send_control(keepalive(91)).await.unwrap();
    assert!(matches!(receive(&mut server).await, Received::Control(_)));
    // Missing data never blocked a reliable record. Complete it afterwards.
    let mut bytes = client.send_token.to_vec();
    bytes.extend_from_slice(&first);
    client
        .owner
        .connection
        .send_datagram(bytes.clone().into())
        .unwrap();
    assert!(matches!(receive(&mut server).await, Received::Opaque(frame) if frame == message));
    client.owner.connection.send_datagram(bytes.into()).unwrap();
    client.send_control(keepalive(92)).await.unwrap();
    assert!(matches!(receive(&mut server).await, Received::Control(_)));
    assert_eq!(server.stats().received_frames, 1);
}

#[tokio::test]
async fn admission_binds_noise_to_tls_and_rejects_a_terminating_splice() {
    let route = preface();
    let (mut origin, mut attacker_a, _a) = pending_pair(route).await;
    let (mut attacker_b, destination, _b) = pending_pair(route).await;
    // Establish end-to-end Noise keys while deliberately splicing the outer TLS links.
    let (left, right) = authenticate(&mut origin, &mut attacker_a, route).await;
    // Transfer the responder Noise state to the far connection. The attacker
    // can copy ciphertext but must not be able to authorize either TLS link.
    let (process, mesh) = budgets();
    let relay = tokio::spawn(async move {
        let _ = tokio::io::copy_bidirectional(attacker_a.control(), attacker_b.control()).await;
    });
    let (left, right) = tokio::join!(
        origin.admit(left, route, process.clone(), mesh.clone(), 100),
        destination.admit(right, route, process.clone(), mesh.clone(), 100)
    );
    assert!(left.is_err());
    assert!(right.is_err());
    assert_eq!(process.used(), 0);
    assert_eq!(mesh.used(), 0);
    tokio::time::timeout(Duration::from_secs(2), relay)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn wrong_mesh_binding_and_pre_admission_packets_are_rejected() {
    let route = preface();
    let (mut left, mut right, _listener) = pending_pair(route).await;
    let (a, b) = authenticate(&mut left, &mut right, route).await;
    let mut early = vec![0; TOKEN_LEN];
    early.extend_from_slice(
        &fragments::split(1, &envelope(route, vec![], 20).encode_to_vec(), 1100).unwrap()[0],
    );
    left.owner.connection.send_datagram(early.into()).unwrap();
    let (process, mesh) = budgets();
    let (left, right) = tokio::join!(
        left.admit(a, route, process.clone(), mesh.clone(), 100),
        right.admit(b, route, process, mesh, 100)
    );
    let mut left = left.unwrap();
    let mut right = right.unwrap();
    left.send_opaque(&envelope(route, vec![], 40)).unwrap();
    assert!(
        matches!(receive(&mut right).await, Received::Opaque(frame) if frame.opaque.len() == 40)
    );
    assert_eq!(right.stats().malformed_fragments, 1);
    let (mut left, mut right, _listener2) = pending_pair(route).await;
    let (a, b) = authenticate(&mut left, &mut right, route).await;
    let other = RelayPreface {
        mesh_id: MeshId::new(),
        ..route
    };
    let (process, mesh) = budgets();
    let (left, right) = tokio::join!(
        left.admit(a, route, process.clone(), mesh.clone(), 100),
        right.admit(b, other, process, mesh, 100)
    );
    assert!(left.is_err());
    assert!(right.is_err());
}

#[tokio::test]
async fn mesh_source_kind_and_carrier_boundaries_are_enforced() {
    let route = preface();
    let (mut client, mut server, _listener) = pair(route).await;
    let mut frame = envelope(route, vec![1; 16], 20);
    assert!(client.send_opaque(&frame).is_err()); // Peer cannot claim another source.
    frame.source_peer.clear();
    frame.mesh_id = MeshId::new().as_bytes().to_vec();
    assert!(client.send_opaque(&frame).is_err());
    frame.mesh_id = route.mesh_id.as_bytes().to_vec();
    frame.kind = OpaqueFrameKind::Audit as i32;
    assert!(client.send_opaque(&frame).is_err());
    frame.kind = OpaqueFrameKind::Session as i32;
    assert!(server.send_opaque(&frame).is_err()); // Relay must supply authenticated source.
    assert!(
        client
            .send_control(ControlEnvelope {
                trace_context: None,
                message: Some(ControlMessage::Opaque(frame.clone()))
            })
            .await
            .is_err()
    );
    assert!(client.send_opaque(&frame).unwrap());
    assert!(matches!(receive(&mut server).await, Received::Opaque(_)));
}

#[tokio::test]
async fn close_releases_incomplete_frames_and_fences_future_writes() {
    let route = preface();
    let (mut client, mut server, _listener) = pair(route).await;
    let (process, mesh) = budgets();
    server.reassembly = Reassembler::new(process.clone(), mesh);
    let parts = fragments::split(1, &datagram_bytes(envelope(route, vec![], 4000)), 1000).unwrap();
    let mut bytes = client.send_token.to_vec();
    bytes.extend_from_slice(&parts[0]);
    client.owner.connection.send_datagram(bytes.into()).unwrap();
    // Poll until the partial datagram was consumed, cancelling safely afterwards.
    assert!(
        tokio::time::timeout(Duration::from_millis(100), server.receive())
            .await
            .is_err()
    );
    assert!(server.reassembly.buffered() > 0);
    assert!(process.used() > 0);
    server.close();
    assert_eq!(server.reassembly.buffered(), 0);
    assert_eq!(process.used(), 0);
    assert!(server.send_control(keepalive(1)).await.is_err());
    assert!(
        server
            .send_opaque(&envelope(route, vec![1; 16], 20))
            .is_err()
    );
    client.close();
}

#[tokio::test]
async fn partial_control_survives_receive_cancellation_and_timer_releases_loss() {
    let route = preface();
    let (mut client, mut server, _listener) = pair(route).await;
    let frame = client
        .transport
        .encode(&Record::Control(wrap_control(route, 1, &keepalive(42))))
        .unwrap();
    client.sent_control = 1;
    client.control.write_all(&frame[..7]).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(100), server.receive())
            .await
            .is_err()
    );
    assert_eq!(server.frame_read, 7);
    client.control.write_all(&frame[7..]).await.unwrap();
    assert!(
        matches!(receive(&mut server).await, Received::Control(value) if value == keepalive(42))
    );
    let data = datagram_bytes(envelope(route, vec![], 4000));
    let mut bytes = client.send_token.to_vec();
    bytes.extend_from_slice(&fragments::split(200, &data, 1000).unwrap()[0]);
    client.owner.connection.send_datagram(bytes.into()).unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(100), server.receive())
            .await
            .is_err()
    );
    assert!(server.reassembly.buffered() > 0);
    assert!(
        tokio::time::timeout(Duration::from_millis(2500), server.receive())
            .await
            .is_err()
    );
    assert_eq!(server.reassembly.buffered(), 0);
}

#[tokio::test]
async fn tls_name_ca_and_explicit_proxy_fail_before_admission() {
    let cert = Certificates::new();
    let listener = Listener::bind(
        UdpSocket::bind("127.0.0.1:0").unwrap(),
        &cert.certificate,
        &cert.key,
    )
    .unwrap();
    for (name, options) in [
        ("wrong.example", cert.options()),
        ("localhost", ClientOptions::default()),
    ] {
        let client = connect(
            UdpSocket::bind("127.0.0.1:0").unwrap(),
            listener.local_addr().unwrap(),
            name,
            &options,
        );
        let server = async { listener.accept(listener.incoming().await.unwrap()).await };
        let (client, server) = tokio::join!(client, server);
        assert!(client.is_err());
        assert!(server.is_err());
    }
    let options = ClientOptions {
        http_connect_proxy: Some("tcp://127.0.0.1:1234".parse().unwrap()),
        ..cert.options()
    };
    assert!(
        connect(
            UdpSocket::bind("127.0.0.1:0").unwrap(),
            listener.local_addr().unwrap(),
            "localhost",
            &options
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn fixed_listener_accepts_separate_meshes_and_closing_a_preserves_b() {
    let cert = Certificates::new();
    let listener = Listener::bind(
        UdpSocket::bind("127.0.0.1:0").unwrap(),
        &cert.certificate,
        &cert.key,
    )
    .unwrap();
    let mut links = Vec::new();
    let (process, mesh_a) = budgets();
    for mesh in [mesh_a, Budget::new(512 * 1024)] {
        let route = preface();
        let (mut left, mut right) = pending_on_listener(route, &listener, cert.options()).await;
        let (a, b) = authenticate(&mut left, &mut right, route).await;
        let (left, right) = tokio::join!(
            left.admit(a, route, process.clone(), mesh.clone(), 100),
            right.admit(b, route, process.clone(), mesh, 100)
        );
        links.push((left.unwrap(), right.unwrap()));
    }
    let (mut a, mut b) = links.remove(0);
    let (mut c, mut d) = links.remove(0);
    a.close();
    b.close();
    drop(a);
    drop(b);
    c.send_control(keepalive(4)).await.unwrap();
    assert!(matches!(receive(&mut d).await, Received::Control(value) if value == keepalive(4)));
}

#[tokio::test]
async fn bounded_send_pressure_drops_whole_frame_and_link_lifetime_is_enforced() {
    let route = preface();
    let (mut client, mut server, _listener) = pair(route).await;
    let frame = envelope(route, vec![], 9000);
    // No await between sends: QUIC's queue is filled before its driver runs.
    let mut dropped = false;
    for _ in 0..100 {
        dropped |= !client.send_opaque(&frame).unwrap();
    }
    assert!(dropped);
    assert!(client.stats().dropped_frames > 0);
    server.started = Instant::now()
        .checked_sub(Duration::from_secs(peerward_wire::REKEY_HARD_SECONDS))
        .unwrap();
    assert!(server.rekey_due());
    assert!(server.receive().await.is_err());
    assert!(server.send_control(keepalive(1)).await.is_err());
}

#[tokio::test]
async fn genuine_wireguard_handshake_and_full_mtu_ciphertext_cross_quic_datagrams() {
    use peerward_wireguard::{Engine, Event, Ingress, Limits};
    fn network(events: Vec<Event>) -> Vec<u8> {
        assert_eq!(events.len(), 1);
        let Event::Network { packet, .. } = events.into_iter().next().unwrap() else {
            panic!("network event");
        };
        packet
    }
    let route = preface();
    let (mut client, mut server, _listener) = pair(route).await;
    let mut a = Engine::new(
        StaticSecret::from([1; 32]),
        Limits {
            mtu: 9000,
            ..Limits::default()
        },
    )
    .unwrap();
    let mut b = Engine::new(
        StaticSecret::from([2; 32]),
        Limits {
            mtu: 9000,
            ..Limits::default()
        },
    )
    .unwrap();
    a.install(b.public_key()).unwrap();
    b.install(a.public_key()).unwrap();
    let from_a = Ingress::Relay {
        peer: a.public_key(),
    };
    let from_b = Ingress::Relay {
        peer: b.public_key(),
    };
    let mut plain = vec![0; 1280];
    plain[0] = 0x45;
    plain[2..4].copy_from_slice(&1280_u16.to_be_bytes());
    plain[8] = 64;
    plain[9] = 17;
    plain[12..16].copy_from_slice(&[10, 42, 0, 1]);
    plain[16..20].copy_from_slice(&[10, 42, 0, 2]);
    let now = Instant::now();
    let mut outbound = envelope(route, vec![], 1);
    outbound.opaque = network(a.send(&b.public_key(), &plain, now, |_, _| true).unwrap());
    assert_eq!(outbound.opaque.len(), 148);
    client.send_opaque(&outbound).unwrap();
    let Received::Opaque(init) = receive(&mut server).await else {
        panic!("WG init");
    };
    let mut response = envelope(route, PeerId::new().as_bytes().to_vec(), 1);
    response.opaque = network(b.receive(from_a, &init.opaque).unwrap());
    assert_eq!(response.opaque.len(), 92);
    server.send_opaque(&response).unwrap();
    let Received::Opaque(reply) = receive(&mut client).await else {
        panic!("WG response");
    };
    outbound.opaque = network(a.receive(from_b, &reply.opaque).unwrap());
    client.send_opaque(&outbound).unwrap();
    let Received::Opaque(confirm) = receive(&mut server).await else {
        panic!("WG confirmation");
    };
    assert!(b.receive(from_a, &confirm.opaque).unwrap().is_empty());
    outbound.opaque = network(a.tick(now, |_, _| true));
    assert_eq!(outbound.opaque.len(), 1312);
    client.send_opaque(&outbound).unwrap();
    let Received::Opaque(ciphertext) = receive(&mut server).await else {
        panic!("WG data");
    };
    assert_eq!(ciphertext.opaque, outbound.opaque);
    assert_eq!(
        b.receive(from_a, &ciphertext.opaque).unwrap(),
        vec![Event::Plaintext {
            peer: a.public_key(),
            packet: plain.clone()
        }]
    );
    assert!(b.receive(from_a, &ciphertext.opaque).is_err());
    plain.resize(9000, 0);
    plain[2..4].copy_from_slice(&9000_u16.to_be_bytes());
    outbound.opaque = network(
        a.send(&b.public_key(), &plain, Instant::now(), |_, _| true)
            .unwrap(),
    );
    let before = client.stats();
    client.send_opaque(&outbound).unwrap();
    let Received::Opaque(ciphertext) = receive(&mut server).await else {
        panic!("large WG data");
    };
    assert_eq!(ciphertext.opaque, outbound.opaque);
    assert_eq!(
        b.receive(from_a, &ciphertext.opaque).unwrap(),
        vec![Event::Plaintext {
            peer: a.public_key(),
            packet: plain
        }]
    );
    assert!(client.stats().sent_fragments - before.sent_fragments >= 2);
}

#[tokio::test]
async fn cancelled_control_write_fences_both_directions() {
    let route = preface();
    let (mut client, _server, _listener) = pair(route).await;
    let mut audit = envelope(route, vec![], 60_000);
    audit.kind = OpaqueFrameKind::Audit as i32;
    let message = ControlEnvelope {
        trace_context: None,
        message: Some(ControlMessage::Opaque(audit)),
    };
    let mut cancelled = false;
    for _ in 0..40 {
        if tokio::time::timeout(
            Duration::from_millis(20),
            client.send_control(message.clone()),
        )
        .await
        .is_err()
        {
            cancelled = true;
            break;
        }
    }
    assert!(
        cancelled,
        "bounded QUIC flow control must exert backpressure"
    );
    assert!(client.write_in_progress);
    assert!(client.send_control(keepalive(1)).await.is_err());
    assert!(client.receive().await.is_err());
}

#[tokio::test]
async fn backbone_kk_uses_the_same_tls_binding_and_datagram_carrier() {
    let route = RelayPreface {
        source: Some(RelayId::new()),
        ..preface()
    };
    let (mut left, mut right, _listener) = pair(route).await;
    let frame = envelope(route, PeerId::new().as_bytes().to_vec(), 4000);
    left.send_opaque(&frame).unwrap();
    assert!(matches!(receive(&mut right).await, Received::Opaque(value) if value == frame));
    right.send_control(keepalive(71)).await.unwrap();
    assert!(matches!(receive(&mut left).await, Received::Control(value) if value == keepalive(71)));
}

#[tokio::test]
async fn ipv6_socket_carries_authenticated_control_and_fragmented_datagrams() {
    let cert = Certificates::new();
    let listener = Listener::bind(
        UdpSocket::bind("[::1]:0").unwrap(),
        &cert.certificate,
        &cert.key,
    )
    .unwrap();
    let route = preface();
    let (mut left, mut right) = pending_on_listener(route, &listener, cert.options()).await;
    let (a, b) = authenticate(&mut left, &mut right, route).await;
    let (process, mesh) = budgets();
    let (left, right) = tokio::join!(
        left.admit(a, route, process.clone(), mesh.clone(), 100),
        right.admit(b, route, process, mesh, 100)
    );
    let mut left = left.unwrap();
    let mut right = right.unwrap();
    assert!(left.owner.connection.remote_address().is_ipv6());
    let frame = envelope(route, vec![], 9000);
    left.send_opaque(&frame).unwrap();
    assert!(matches!(receive(&mut right).await, Received::Opaque(value) if value == frame));
    assert!(left.stats().sent_fragments > 1);
    right.send_control(keepalive(6)).await.unwrap();
    assert!(matches!(receive(&mut left).await, Received::Control(value) if value == keepalive(6)));
}

include!("quic_integration_tests.rs");
