//! QUIC transport building block. This is not an application admission gate:
//! callers must verify Root/Authority, Mesh, credential and revocation before
//! `admit`, and retain the existing forwarding/source/lease fences afterwards.
pub use quinn::Incoming;
use std::{
    io,
    net::{SocketAddr, UdpSocket},
    pin::Pin,
    sync::Arc,
    task::{Context as TaskContext, Poll},
    time::{Duration, Instant},
};

use super::{
    BoxStream, ClientOptions,
    fragments::{self, Budget, Reassembler},
    invalid,
};
use bytes::Bytes;
use peerward_wire::control_envelope::Message as ControlMessage;
use peerward_wire::{
    ControlEnvelope, OpaqueFrameKind, Record, RelayEnvelopeV2, RelayPreface, StreamTransport,
    Welcome,
};
use prost::Message;
use quinn::{
    Connection, Endpoint, RecvStream, SendStream,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
};
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

const ALPN: &[u8] = b"peerward-relay-4";
const BINDING_LABEL: &[u8] = b"EXPORTER-Peerward-Relay-Wire4";
const BINDING_PREFIX: &[u8] = b"quic_datagram_binding_v1\0";
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const TOKEN_LEN: usize = 32;
const QUEUE_BYTES: usize = 256 * 1024;

fn transport_config() -> Arc<quinn::TransportConfig> {
    let mut config = quinn::TransportConfig::default();
    config
        // Keep UDP payloads at QUIC's mandatory 1200-byte floor. An already
        // established path can shrink after a mobile/network transition. We
        // do not wait for loss-driven PMTU convergence to deliver full WG frames.
        .initial_mtu(1200)
        .min_mtu(1200)
        .mtu_discovery_config(None)
        .enable_segmentation_offload(false)
        .max_concurrent_bidi_streams(1_u8.into())
        .max_concurrent_uni_streams(0_u8.into())
        .receive_window(
            u32::try_from(QUEUE_BYTES)
                .expect("fixed queue bound")
                .into(),
        )
        .stream_receive_window(
            u32::try_from(QUEUE_BYTES)
                .expect("fixed queue bound")
                .into(),
        )
        .send_window(QUEUE_BYTES as u64)
        .crypto_buffer_size(16_384)
        .datagram_receive_buffer_size(Some(QUEUE_BYTES))
        .datagram_send_buffer_size(QUEUE_BYTES)
        .keep_alive_interval(Some(Duration::from_secs(25)))
        .max_idle_timeout(Some(
            Duration::from_mins(1).try_into().expect("fixed timeout"),
        ));
    Arc::new(config)
}

/// Consumes a bound, platform-protected UDP socket; never opens another socket.
/// Resolution and network selection remain with Linux/Android platform code.
/// HTTP CONNECT applies only to WSS, so a configured proxy rejects QUIC here.
pub async fn connect(
    socket: UdpSocket,
    remote: SocketAddr,
    server_name: &str,
    options: &ClientOptions,
) -> io::Result<PendingQuic> {
    options.validate()?;
    if options.http_connect_proxy.is_some() {
        return Err(invalid("QUIC cannot use HTTP CONNECT"));
    }
    let mut tls = (*options.tls_config()?).clone();
    tls.alpn_protocols = vec![ALPN.to_vec()];
    tls.enable_early_data = false;
    let mut config = quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(tls).map_err(io::Error::other)?,
    ));
    config.transport_config(transport_config());
    socket.set_nonblocking(true)?;
    let mut endpoint = Endpoint::new(
        quinn::EndpointConfig::default(),
        None,
        socket,
        Arc::new(quinn::TokioRuntime),
    )?;
    endpoint.set_default_client_config(config);
    tokio::time::timeout(IO_TIMEOUT, async {
        // Await the full handshake. Never call into_0rtt().
        let connection = endpoint
            .connect(remote, server_name)
            .map_err(io::Error::other)?
            .await
            .map_err(io::Error::other)?;
        let owner = Owner {
            connection,
            _endpoint: endpoint,
        };
        let (send, recv) = owner.connection.open_bi().await.map_err(io::Error::other)?;
        Ok(PendingQuic {
            owner,
            control: Box::new(ControlStream { send, recv }),
        })
    })
    .await
    .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
}

/// Fixed host-level listener. Caller acquires host/session/IP/handshake permits
/// before accepting an Incoming, and releases them on every error/close path.
pub struct Listener {
    endpoint: Endpoint,
}
impl Listener {
    pub fn bind(socket: UdpSocket, certificate: &[u8], private_key: &[u8]) -> io::Result<Self> {
        use rustls::pki_types::{PrivateKeyDer, pem::PemObject};
        if private_key.len() > super::MAX_PEM {
            return Err(invalid("QUIC key too large"));
        }
        let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(io::Error::other)?
        .with_no_client_auth()
        .with_single_cert(
            super::certificates(certificate)?,
            PrivateKeyDer::from_pem_slice(private_key).map_err(io::Error::other)?,
        )
        .map_err(io::Error::other)?;
        tls.alpn_protocols = vec![ALPN.to_vec()];
        tls.max_early_data_size = 0;
        let mut config = quinn::ServerConfig::with_crypto(Arc::new(
            QuicServerConfig::try_from(tls).map_err(io::Error::other)?,
        ));
        config
            .transport_config(transport_config())
            .max_incoming(128)
            .incoming_buffer_size(16_384)
            .incoming_buffer_size_total(2 * 1024 * 1024)
            .migration(false);
        socket.set_nonblocking(true)?;
        Ok(Self {
            endpoint: Endpoint::new(
                quinn::EndpointConfig::default(),
                Some(config),
                socket,
                Arc::new(quinn::TokioRuntime),
            )?,
        })
    }
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.endpoint.local_addr()
    }
    /// Inspect/retry/refuse before TLS work. No forwarding is available here.
    pub async fn incoming(&self) -> Option<quinn::Incoming> {
        self.endpoint.accept().await
    }
    pub async fn accept(&self, incoming: quinn::Incoming) -> io::Result<PendingQuic> {
        tokio::time::timeout(IO_TIMEOUT, async {
            let connection = incoming.await.map_err(io::Error::other)?;
            let owner = Owner {
                connection,
                _endpoint: self.endpoint.clone(),
            };
            let (send, recv) = owner
                .connection
                .accept_bi()
                .await
                .map_err(io::Error::other)?;
            Ok(PendingQuic {
                owner,
                control: Box::new(ControlStream { send, recv }),
            })
        })
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
    }
}
impl Drop for Listener {
    fn drop(&mut self) {
        self.endpoint.close(0_u8.into(), b"listener stopped");
    }
}
struct Owner {
    connection: Connection,
    _endpoint: Endpoint,
}
impl Drop for Owner {
    fn drop(&mut self) {
        self.connection.close(0_u8.into(), b"link stopped");
    }
}
struct ControlStream {
    send: SendStream,
    recv: RecvStream,
}
impl AsyncRead for ControlStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}
impl AsyncWrite for ControlStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.send), cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.send), cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.send), cx)
    }
}

/// Only a reliable stream is exposed before application identity validation.
/// There is intentionally no pre-admission DATAGRAM send/receive API.
pub struct PendingQuic {
    owner: Owner,
    control: BoxStream,
}
impl PendingQuic {
    /// Run the Wire 4 preface and existing IK/KK authentication on this stream.
    pub fn control(&mut self) -> &mut BoxStream {
        &mut self.control
    }

    /// Consume an already verified Noise link, then prove in BOTH directions
    /// that it belongs to this exact TLS connection and canonical Wire preface.
    /// A TLS-terminating attacker relaying Noise between connections cannot
    /// reproduce the exporter binding. Failure closes the entire connection.
    pub async fn admit(
        mut self,
        mut transport: StreamTransport,
        preface: RelayPreface,
        process_budget: Budget,
        mesh_budget: Budget,
        now: u64,
    ) -> io::Result<QuicLink> {
        let started = Instant::now();
        RelayPreface::decode(&preface.encode()).map_err(io::Error::other)?;
        if transport.hard_expired(now) {
            return Err(invalid("expired Noise link"));
        }
        let mut exporter = [0; 32];
        self.owner
            .connection
            .export_keying_material(&mut exporter, BINDING_LABEL, &preface.encode())
            .map_err(|_| invalid("QUIC exporter unavailable"))?;
        let mut receive_token = [0; TOKEN_LEN];
        rand::rngs::OsRng
            .try_fill_bytes(&mut receive_token)
            .map_err(io::Error::other)?;
        let mut body = BINDING_PREFIX.to_vec();
        body.extend_from_slice(&exporter);
        body.extend_from_slice(&receive_token);
        let expected = Record::Control(ControlEnvelope {
            trace_context: None,
            message: Some(ControlMessage::Welcome(Welcome {
                mesh_id: preface.mesh_id.as_bytes().to_vec(),
                body,
            })),
        });
        let binding = transport.encode(&expected).map_err(io::Error::other)?;
        let send_token = tokio::time::timeout(IO_TIMEOUT, async {
            self.control.write_all(&binding).await?;
            self.control.flush().await?;
            let length = self.control.read_u32().await? as usize;
            // A binding has a fixed small purpose; never allocate 64 KiB here.
            if length == 0 || length > 256 {
                return Err(invalid("invalid QUIC admission binding length"));
            }
            let mut frame = vec![0; length + 4];
            frame[..4]
                .copy_from_slice(&u32::try_from(length).expect("binding bound").to_be_bytes());
            self.control.read_exact(&mut frame[4..]).await?;
            let Record::Control(ControlEnvelope {
                trace_context: None,
                message: Some(ControlMessage::Welcome(Welcome { mesh_id, body })),
            }) = transport.decode(&frame).map_err(io::Error::other)?
            else {
                return Err(invalid("invalid QUIC admission binding"));
            };
            let prefix = BINDING_PREFIX.len();
            if mesh_id != preface.mesh_id.as_bytes()
                || body.len() != prefix + 32 + TOKEN_LEN
                || &body[..prefix] != BINDING_PREFIX
                || body[prefix..prefix + 32] != exporter
            {
                return Err(invalid("QUIC admission binding mismatch"));
            }
            let token: [u8; TOKEN_LEN] = body[prefix + 32..].try_into().expect("checked binding");
            Ok(token)
        })
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
        if transport.hard_expired(now.saturating_add(started.elapsed().as_secs())) {
            return Err(invalid("Noise link expired during QUIC binding"));
        }
        if self.owner.connection.max_datagram_size().is_none() {
            return Err(invalid("Relay lacks QUIC DATAGRAM support"));
        }
        Ok(QuicLink {
            owner: self.owner,
            control: self.control,
            transport,
            preface,
            reassembly: Reassembler::new(process_budget, mesh_budget),
            next_id: 1,
            send_token,
            receive_token,
            write_in_progress: false,
            frame: vec![0; 4],
            frame_read: 0,
            started,
            epoch: now,
            sweep: tokio::time::interval(Duration::from_millis(250)),
            stats: DatagramStats::default(),
            sent_control: 0,
            received_control: 0,
            acknowledged_control: 0,
        })
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct DatagramStats {
    pub sent_frames: u64,
    pub sent_fragments: u64,
    pub received_frames: u64,
    pub received_fragments: u64,
    pub dropped_frames: u64,
    pub malformed_fragments: u64,
}
pub enum Received {
    Control(ControlEnvelope),
    Opaque(RelayEnvelopeV2),
    Acknowledged(u64),
    Ping(u64),
    Pong(u64),
    Datagram(ControlEnvelope),
}
pub struct QuicLink {
    owner: Owner,
    control: BoxStream,
    transport: StreamTransport,
    preface: RelayPreface,
    reassembly: Reassembler,
    next_id: u64,
    send_token: [u8; TOKEN_LEN],
    receive_token: [u8; TOKEN_LEN],
    write_in_progress: bool,
    frame: Vec<u8>,
    frame_read: usize,
    started: Instant,
    epoch: u64,
    sweep: tokio::time::Interval,
    stats: DatagramStats,
    sent_control: u64,
    received_control: u64,
    acknowledged_control: u64,
}
include!("quic_link.rs");
include!("quic_context.rs");

#[cfg(test)]
#[path = "quic_tests.rs"]
mod tests;
