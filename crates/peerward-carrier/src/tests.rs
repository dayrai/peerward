use super::*;
use futures_util::{SinkExt, StreamExt};
use std::{
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};
use tokio::{
    net::{TcpListener, TcpStream},
    time::timeout,
};
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{Message, protocol::Role},
};

pub(crate) struct Certificates {
    directory: PathBuf,
    pub(crate) certificate: Vec<u8>,
    pub(crate) key: Vec<u8>,
}
impl Certificates {
    pub(crate) fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let directory = std::env::temp_dir().join(format!(
            "peerward-carrier-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).unwrap();
        let output = Command::new("openssl")
            .current_dir(&directory)
            .args([
                "req",
                "-x509",
                "-newkey",
                "ed25519",
                "-nodes",
                "-days",
                "1",
                "-subj",
                "/CN=localhost",
                "-addext",
                "subjectAltName=DNS:localhost,IP:127.0.0.1",
                "-addext",
                "basicConstraints=critical,CA:FALSE",
                "-keyout",
                "key.pem",
                "-out",
                "cert.pem",
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "test certificate generation failed"
        );
        Self {
            certificate: std::fs::read(directory.join("cert.pem")).unwrap(),
            key: std::fs::read(directory.join("key.pem")).unwrap(),
            directory,
        }
    }
    pub(crate) fn options(&self) -> ClientOptions {
        ClientOptions {
            ca_pem: Some(String::from_utf8(self.certificate.clone()).unwrap()),
            ..ClientOptions::default()
        }
    }
}
impl Drop for Certificates {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

async fn tls_pair() -> (BoxStream, BoxStream) {
    let certificates = Certificates::new();
    let tls = server_tls(&certificates.certificate, &certificates.key).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let accepted = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        server(Box::new(socket), Some(tls)).await.unwrap()
    });
    let endpoint = format!("wss://localhost:{}/peerward", address.port())
        .parse()
        .unwrap();
    let socket = TcpStream::connect(address).await.unwrap();
    let connected = client(Box::new(socket), &endpoint, &certificates.options())
        .await
        .unwrap();
    (connected, accepted.await.unwrap())
}

#[tokio::test]
async fn tls_binary_stream_preserves_frames_under_fragmentation_and_backpressure() {
    timeout(Duration::from_secs(10), async {
        let (mut left, mut right) = tls_pair().await;
        let payload = (0..262_144)
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect::<Vec<_>>();
        let expected = payload.clone();
        let send = tokio::spawn(async move {
            for bytes in payload.chunks(997) {
                left.write_all(bytes).await.unwrap();
            }
            let mut echoed = vec![0; payload.len()];
            left.read_exact(&mut echoed).await.unwrap();
            assert_eq!(echoed, payload);
        });
        let mut received = vec![0; expected.len()];
        right.read_exact(&mut received).await.unwrap();
        assert_eq!(received, expected);
        right.write_all(&received).await.unwrap();
        send.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn private_ca_and_hostname_are_both_required() {
    let certificates = Certificates::new();
    for (hostname, options) in [
        ("localhost", ClientOptions::default()),
        ("wrong.example", certificates.options()),
    ] {
        let tls = server_tls(&certificates.certificate, &certificates.key).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let accepted = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            assert!(server(Box::new(socket), Some(tls)).await.is_err());
        });
        let endpoint = format!("wss://{hostname}:{}/peerward", address.port())
            .parse()
            .unwrap();
        assert!(
            client(
                Box::new(TcpStream::connect(address).await.unwrap()),
                &endpoint,
                &options
            )
            .await
            .is_err()
        );
        accepted.await.unwrap();
    }
}

#[tokio::test]
async fn explicit_connect_tunnels_tls_without_resolving_target_locally() {
    let certificates = Certificates::new();
    let tls = server_tls(&certificates.certificate, &certificates.key).unwrap();
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = proxy.local_addr().unwrap();
    let proxy_task = tokio::spawn(async move {
        let (mut socket, _) = proxy.accept().await.unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            request.push(socket.read_u8().await.unwrap());
        }
        assert_eq!(
            request,
            b"CONNECT localhost:443 HTTP/1.1\r\nHost: localhost:443\r\n\r\n"
        );
        socket
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .unwrap();
        let mut carrier = server(Box::new(socket), Some(tls)).await.unwrap();
        assert_eq!(carrier.read_u32().await.unwrap(), 0x5046_5734);
        carrier.write_u32(42).await.unwrap();
        // Wait for the other side to consume the response before dropping.
        assert_eq!(carrier.read_u8().await.unwrap(), 1);
    });
    let endpoint = "wss://localhost:443/peerward".parse().unwrap();
    let mut options = certificates.options();
    options.http_connect_proxy = Some(format!("tcp://{address}").parse().unwrap());
    assert_eq!(
        options.dial_endpoint(&endpoint).unwrap().socket_addr(),
        Some(address)
    );
    let mut carrier = client(
        Box::new(TcpStream::connect(address).await.unwrap()),
        &endpoint,
        &options,
    )
    .await
    .unwrap();
    carrier.write_u32(0x5046_5734).await.unwrap();
    assert_eq!(carrier.read_u32().await.unwrap(), 42);
    carrier.write_u8(1).await.unwrap();
    proxy_task.await.unwrap();
}

#[tokio::test]
async fn connect_rejects_redirect_auth_failure_and_oversized_headers() {
    for response in [
        b"HTTP/1.1 302 Found\r\n\r\n".to_vec(),
        b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n".to_vec(),
        vec![b'x'; MAX_HTTP + 1],
    ] {
        let (local, mut remote) = tokio::io::duplex(MAX_HTTP * 2);
        let task = tokio::spawn(async move {
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(remote.read_u8().await.unwrap());
            }
            remote.write_all(&response).await.unwrap();
        });
        let mut socket: BoxStream = Box::new(local);
        assert!(
            timeout(
                Duration::from_secs(1),
                connect_proxy(&mut socket, "relay:443")
            )
            .await
            .unwrap()
            .is_err()
        );
        task.await.unwrap();
    }
}

#[tokio::test]
async fn connect_preserves_coalesced_tunnel_bytes_and_ipv6_authority() {
    let (local, mut remote) = tokio::io::duplex(1024);
    let task = tokio::spawn(async move {
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            request.push(remote.read_u8().await.unwrap());
        }
        assert!(request.starts_with(b"CONNECT [::1]:443 HTTP/1.1\r\n"));
        remote
            .write_all(b"HTTP/1.1 200 OK\r\n\r\nTLS")
            .await
            .unwrap();
    });
    let mut socket: BoxStream = Box::new(local);
    connect_proxy(&mut socket, "[::1]:443").await.unwrap();
    let mut bytes = [0; 3];
    socket.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"TLS");
    task.await.unwrap();
}

#[tokio::test]
async fn websocket_rejects_text_and_oversized_binary_messages() {
    for message in [
        Message::text("invalid"),
        Message::binary(vec![0; WS_LIMIT + 1]),
    ] {
        let (left, right) = tokio::io::duplex(WS_LIMIT * 2);
        let socket = WebSocketStream::from_raw_socket(left, Role::Server, Some(ws_config())).await;
        let mut application = websocket::bridge(socket);
        let mut sender = WebSocketStream::from_raw_socket(right, Role::Client, None).await;
        sender.send(message).await.unwrap();
        assert_eq!(
            timeout(Duration::from_secs(1), application.read(&mut [0; 1]))
                .await
                .unwrap()
                .unwrap(),
            0
        );
    }
}

#[tokio::test]
async fn cancelled_reads_preserve_stream_bytes_and_drop_closes_pump() {
    let (mut left, mut right) = tls_pair().await;
    assert!(
        timeout(Duration::from_millis(10), left.read_u8())
            .await
            .is_err()
    );
    right.write_all(b"abc").await.unwrap();
    assert_eq!(left.read_u8().await.unwrap(), b'a');
    assert_eq!(left.read_u16().await.unwrap(), u16::from_be_bytes(*b"bc"));
    drop(left);
    assert_eq!(
        timeout(Duration::from_secs(1), right.read(&mut [0; 1]))
            .await
            .unwrap()
            .unwrap(),
        0
    );
}

#[test]
fn blocking_close_interrupts_a_read_without_waiting_for_its_mutex() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (_remote, _) = listener.accept().unwrap();
    let socket = BlockingSocket::new(client, None, &ClientOptions::default()).unwrap();
    let reader = Arc::clone(&socket);
    let (tx, rx) = std::sync::mpsc::channel();
    let thread = std::thread::spawn(move || {
        tx.send(
            reader
                .reader
                .lock()
                .unwrap()
                .read_exact(&mut [0; 1])
                .is_err(),
        )
        .unwrap();
    });
    socket.close();
    assert!(rx.recv_timeout(Duration::from_secs(1)).unwrap());
    thread.join().unwrap();
}

#[test]
fn configuration_rejects_invalid_proxy_ca_and_tcp_proxy_downgrade() {
    let tcp: NetworkEndpoint = "tcp://localhost:7777".parse().unwrap();
    let wss = "wss://localhost:443/peerward".parse().unwrap();
    assert!(
        ClientOptions {
            ca_pem: Some("bad".into()),
            ..ClientOptions::default()
        }
        .validate()
        .is_err()
    );
    assert!(
        ClientOptions {
            http_connect_proxy: Some(wss),
            ..ClientOptions::default()
        }
        .validate()
        .is_err()
    );
    assert!(
        ClientOptions {
            http_connect_proxy: Some(tcp.clone()),
            ..ClientOptions::default()
        }
        .dial_endpoint(&tcp)
        .is_err()
    );
}

#[tokio::test]
async fn graceful_shutdown_delivers_the_terminal_frame_before_close() {
    let (mut left, mut right) = tls_pair().await;
    let sender = tokio::spawn(async move {
        left.write_all(b"signed terminal frame").await.unwrap();
        left.shutdown().await.unwrap();
    });
    let mut received = Vec::new();
    timeout(Duration::from_secs(1), right.read_to_end(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received, b"signed terminal frame");
    sender.await.unwrap();
}

#[tokio::test]
async fn websocket_flush_observes_network_backpressure() {
    let (left, mut right) = tokio::io::duplex(32);
    let socket = WebSocketStream::from_raw_socket(left, Role::Server, Some(ws_config())).await;
    let mut application = websocket::bridge(socket);
    application.write_all(&[7; 1024]).await.unwrap();
    assert!(
        timeout(Duration::from_millis(10), application.flush())
            .await
            .is_err()
    );
    drop(application);
    let mut partial = Vec::new();
    timeout(Duration::from_secs(1), right.read_to_end(&mut partial))
        .await
        .unwrap()
        .unwrap();
    assert!(partial.len() <= 32);
}

#[tokio::test]
async fn ping_pong_does_not_require_application_data() {
    let (left, right) = tokio::io::duplex(1024);
    let socket = WebSocketStream::from_raw_socket(left, Role::Server, Some(ws_config())).await;
    let _application = websocket::bridge(socket);
    let mut remote = WebSocketStream::from_raw_socket(right, Role::Client, None).await;
    remote
        .send(Message::Ping(b"health".to_vec().into()))
        .await
        .unwrap();
    assert_eq!(
        timeout(Duration::from_secs(1), remote.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
        Message::Pong(b"health".to_vec().into())
    );
}

#[test]
fn blocking_read_failure_fences_the_other_direction() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (remote, _) = listener.accept().unwrap();
    let socket = BlockingSocket::new(client, None, &ClientOptions::default()).unwrap();
    remote.shutdown(std::net::Shutdown::Write).unwrap();
    assert!(
        socket
            .reader
            .lock()
            .unwrap()
            .read_exact(&mut [0; 1])
            .is_err()
    );
    assert!(
        socket
            .writer
            .lock()
            .unwrap()
            .write_all(b"next frame")
            .is_err()
    );
}

#[test]
fn prepared_quic_close_interrupts_blackholed_tls_and_prevents_reuse() {
    let certificates = Certificates::new();
    let blackhole = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    blackhole
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let remote = blackhole.local_addr().unwrap();
    let endpoint = format!("quic://localhost:{}", remote.port())
        .parse()
        .unwrap();
    let pending = BlockingSocket::prepare_quic(
        std::net::UdpSocket::bind("127.0.0.1:0").unwrap(),
        remote,
        &endpoint,
        &certificates.options(),
    )
    .unwrap();
    let connecting = Arc::clone(&pending);
    let worker = std::thread::spawn(move || connecting.connect());
    let mut initial = [0; 2048];
    blackhole.recv_from(&mut initial).unwrap(); // Proves TLS actually started.
    let start = std::time::Instant::now();
    pending.close();
    assert!(worker.join().unwrap().is_err());
    assert!(start.elapsed() < Duration::from_secs(1));
    assert!(pending.connect().is_err());
}
