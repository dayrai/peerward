use std::{net::Ipv4Addr, str::FromStr};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

use super::*;

fn mesh() -> MeshId {
    MeshId::from_str("970a3f18-1c6f-4da6-a223-f9623958a928").unwrap()
}

fn peer() -> PeerId {
    PeerId::from_str("778f4317-0d08-4aab-9620-ca2c99a5ee3e").unwrap()
}

fn serial(value: &str) -> CredentialSerial {
    CredentialSerial::from_str(value).unwrap()
}

fn service(
    id: &str,
    credential_serial: CredentialSerial,
    protocol: ServiceProtocol,
    port: u16,
    alias: &str,
) -> RemoteService {
    RemoteService {
        id: ServiceId::from_str(id).unwrap(),
        owner: peer(),
        credential_serial,
        virtual_address: IpAddr::V4(Ipv4Addr::new(10, 44, 0, 9)),
        protocols: vec![protocol],
        listen_port: port,
        alias: Some(alias.into()),
    }
}

#[tokio::test]
async fn loopback_transport_exchanges_udp_with_ipv6_target() {
    let target = UdpSocket::bind("[::1]:0").await.unwrap();
    let transport = LoopbackServiceTransport::default();
    let service = service(
        "ef3440ac-d7c7-47c8-a116-78a3a207002d",
        serial("40ee7506-2ee1-4b0b-a00c-8f6ec9900011"),
        ServiceProtocol::Udp,
        5353,
        "dns",
    );
    transport
        .register(service.id, target.local_addr().unwrap())
        .await
        .unwrap();
    let echo = tokio::spawn(async move {
        let mut bytes = [0; 32];
        let (length, source) = target.recv_from(&mut bytes).await.unwrap();
        target.send_to(&bytes[..length], source).await.unwrap();
    });
    let result = transport
        .exchange_udp(&service, b"ipv6", Duration::from_secs(1))
        .await;
    if result.is_err() {
        echo.abort();
    }
    let echoed = echo.await;
    assert_eq!(result.unwrap(), b"ipv6");
    echoed.unwrap();
}

#[tokio::test]
async fn signed_snapshot_add_acl_route_and_exact_revoke_use_localhost_sockets() {
    let authority = ServiceSnapshotSigningKey::from_bytes(&[7; 32]);
    let old_serial = serial("68d07b9e-b046-4402-b688-d606a29e797e");
    let current_serial = serial("40ee7506-2ee1-4b0b-a00c-8f6ec9900011");
    let tcp = service(
        "831e8d08-30ab-4ed7-9d31-6606b43de332",
        old_serial,
        ServiceProtocol::Tcp,
        8443,
        "web",
    );
    let udp = service(
        "ef3440ac-d7c7-47c8-a116-78a3a207002d",
        current_serial,
        ServiceProtocol::Udp,
        5353,
        "dns",
    );
    let distribution = authority
        .sign(RemoteServiceSnapshot {
            mesh_id: mesh(),
            revision: 1,
            services: vec![udp.clone(), tcp.clone()],
        })
        .unwrap();
    let mut table = RemoteServiceTable::new(mesh(), authority.verifier());
    let control = snapshot_control(&distribution).unwrap();
    apply_snapshot_control(&mut table, &control).unwrap();
    let source = IpAddr::V4(Ipv4Addr::new(10, 44, 0, 2));
    let allow = Firewall::new(1, Action::Allow, Vec::new(), 16, 2);
    let deny = Firewall::new(1, Action::Deny, Vec::new(), 16, 2);
    assert_eq!(
        table.resolve_visible("WEB", source, |source, service| {
            firewall_allows_service(&allow, source, service, ServiceProtocol::Tcp, 1)
        }),
        Some(tcp.virtual_address)
    );
    assert_eq!(
        table.resolve_visible("web", source, |source, service| {
            firewall_allows_service(&deny, source, service, ServiceProtocol::Tcp, 1)
        }),
        None
    );

    let transport = LoopbackServiceTransport::default();
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    transport
        .register(tcp.id, target.local_addr().unwrap())
        .await
        .unwrap();
    let target_task = tokio::spawn(async move {
        let (mut socket, _) = target.accept().await.unwrap();
        let mut request = Vec::new();
        socket.read_to_end(&mut request).await.unwrap();
        assert_eq!(request, b"signed-service");
        socket.write_all(b"after-half-close").await.unwrap();
    });
    let ingress = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ingress_address = ingress.local_addr().unwrap();
    let permitted = table
        .permitted(tcp.id, ServiceProtocol::Tcp, source, |source, service| {
            firewall_allows_service(&allow, source, service, ServiceProtocol::Tcp, 2)
        })
        .unwrap();
    let forwarding = async {
        let (stream, _) = ingress.accept().await.unwrap();
        forward_remote_tcp(stream, &permitted, &transport)
            .await
            .unwrap();
    };
    let client = async {
        let mut stream = TcpStream::connect(ingress_address).await.unwrap();
        stream.write_all(b"signed-service").await.unwrap();
        stream.shutdown().await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, b"after-half-close");
    };
    tokio::join!(forwarding, client);
    target_task.await.unwrap();

    let udp_target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    transport
        .register(udp.id, udp_target.local_addr().unwrap())
        .await
        .unwrap();
    let udp_task = tokio::spawn(async move {
        let mut request = [0_u8; 32];
        let (length, remote) = udp_target.recv_from(&mut request).await.unwrap();
        udp_target
            .send_to(&request[..length], remote)
            .await
            .unwrap();
    });
    let permitted_udp = table
        .permitted(udp.id, ServiceProtocol::Udp, source, |_, _| true)
        .unwrap();
    assert_eq!(
        transport
            .exchange_udp(&permitted_udp, b"datagram", Duration::from_secs(1))
            .await
            .unwrap(),
        b"datagram"
    );
    udp_task.await.unwrap();

    table.revoke_credential(old_serial);
    assert!(
        table
            .permitted(tcp.id, ServiceProtocol::Tcp, source, |_, _| true)
            .is_err()
    );
    assert_eq!(table.resolve_visible("web", source, |_, _| true), None);
    assert!(
        table
            .permitted(udp.id, ServiceProtocol::Udp, source, |_, _| true)
            .is_ok()
    );

    let replacement = authority
        .sign(RemoteServiceSnapshot {
            mesh_id: mesh(),
            revision: 2,
            services: Vec::new(),
        })
        .unwrap();
    table.reconcile(&replacement).unwrap();
    assert!(
        table
            .permitted(udp.id, ServiceProtocol::Udp, source, |_, _| true)
            .is_err()
    );
}

#[test]
fn snapshot_signature_and_revision_are_strict() {
    let authority = ServiceSnapshotSigningKey::from_bytes(&[11; 32]);
    let distribution = authority
        .sign(RemoteServiceSnapshot {
            mesh_id: mesh(),
            revision: 8,
            services: Vec::new(),
        })
        .unwrap();
    let mut table = RemoteServiceTable::new(mesh(), authority.verifier());
    table.reconcile(&distribution).unwrap();
    assert!(table.reconcile(&distribution).is_err());
    let mut tampered = distribution;
    tampered.snapshot.revision = 9;
    assert!(table.reconcile(&tampered).is_err());
}

#[test]
fn service_v2_transcript_and_signature_are_stable() {
    let authority = ServiceSnapshotSigningKey::from_bytes(&[29; 32]);
    let service = RemoteService {
        id: ServiceId::from_str("831e8d08-30ab-4ed7-9d31-6606b43de332").unwrap(),
        owner: peer(),
        credential_serial: serial("40ee7506-2ee1-4b0b-a00c-8f6ec9900011"),
        virtual_address: "fd42::9".parse().unwrap(),
        protocols: vec![ServiceProtocol::Tcp, ServiceProtocol::Udp],
        listen_port: 8443,
        alias: None,
    };
    let signed = authority
        .sign(RemoteServiceSnapshot {
            mesh_id: mesh(),
            revision: 17,
            services: vec![service],
        })
        .unwrap();
    assert_eq!(
        hex::encode(snapshot_transcript(&signed.snapshot)),
        "70656572776172642f736572766963652d6469726563746f72792f763200970a3f181c6f4da6a223f9623958a928000000000000001100000001831e8d0830ab4ed79d316606b43de332778f43170d084aab9620ca2c99a5ee3e40ee75062ee14b0ba00c8f6ec990001106fd42000000000000000000000000000902010220fb00"
    );
    assert_eq!(
        hex::encode(signed.signature),
        "4629a349b2d9078ecf8b3679a986a557bfa7a812f39f9c93eaa602fa35c1fc83618f84f1742dab7778357aa67c6162a6f2f8ef1cd2f51ca78aac12bd18c6af02"
    );
}
