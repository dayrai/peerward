//! Bounded Relay carriers. TLS is transport protection; Mesh admission still
//! requires the retained format-4 preface and an authenticated Wire 5 Noise link.
use std::{io, sync::Arc, time::Duration};

use peerward_types::NetworkEndpoint;
use rustls::{
    ClientConfig, RootCertStore, ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject},
};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
pub use tokio_rustls::TlsAcceptor;
use tokio_rustls::TlsConnector;
use tokio_tungstenite::{
    accept_hdr_async_with_config, client_async_with_config,
    tungstenite::{
        handshake::server::{Request, Response},
        protocol::WebSocketConfig,
    },
};

mod records;
pub use records::RecordTransport;
mod blocking;
pub mod fragments;
pub mod quic;
mod quic_bridge;
mod quic_data;
mod websocket;
pub use blocking::{BlockingReader, BlockingSocket, BlockingWriter};

/// A connected carrier. Dropping it also stops its bounded WebSocket pump.
pub trait RelayIo: AsyncRead + AsyncWrite + Unpin + Send {
    fn carrier(&self) -> &'static str {
        if self.is_quic() { "quic" } else { "tcp" }
    }
    fn take_quic(&mut self) -> Option<quic::Context> {
        None
    }
    fn is_quic(&self) -> bool {
        false
    }
}
impl RelayIo for tokio::net::TcpStream {}
impl RelayIo for tokio::io::DuplexStream {}
impl<T: RelayIo + ?Sized> RelayIo for Box<T> {
    fn carrier(&self) -> &'static str {
        (**self).carrier()
    }
    fn take_quic(&mut self) -> Option<quic::Context> {
        (**self).take_quic()
    }
    fn is_quic(&self) -> bool {
        (**self).is_quic()
    }
}
impl<T: RelayIo> RelayIo for tokio_rustls::client::TlsStream<T> {}
impl<T: RelayIo> RelayIo for tokio_rustls::server::TlsStream<T> {}
pub type BoxStream = Box<dyn RelayIo>;

const UPGRADE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_PEM: usize = 65_536;
const MAX_HTTP: usize = 8_192;
const WS_LIMIT: usize = 65_539;

/// Local transport settings, independent of signed Mesh identities. An explicit
/// proxy is a canonical TCP endpoint, never read from process environment.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClientOptions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_connect_proxy: Option<NetworkEndpoint>,
    /// Optional public PEM trust anchor for a privately operated WSS listener.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_pem: Option<String>,
}

impl ClientOptions {
    pub fn is_default(&self) -> bool {
        self.http_connect_proxy.is_none() && self.ca_pem.is_none()
    }

    pub fn validate(&self) -> io::Result<()> {
        if self
            .http_connect_proxy
            .as_ref()
            .is_some_and(|endpoint| !endpoint.is_tcp())
            || self
                .ca_pem
                .as_ref()
                .is_some_and(|pem| pem.is_empty() || pem.len() > MAX_PEM)
        {
            return Err(invalid("invalid Relay carrier settings"));
        }
        if self.ca_pem.is_some() {
            self.tls_config()?;
        }
        Ok(())
    }

    /// Address to dial through the platform's protected socket implementation.
    pub fn dial_endpoint<'a>(
        &'a self,
        target: &'a NetworkEndpoint,
    ) -> io::Result<&'a NetworkEndpoint> {
        self.validate()?;
        if let Some(proxy) = &self.http_connect_proxy {
            if !target.is_wss() {
                return Err(invalid("HTTP CONNECT requires a WSS target"));
            }
            Ok(proxy)
        } else {
            Ok(target)
        }
    }

    fn tls_config(&self) -> io::Result<Arc<ClientConfig>> {
        let mut roots = RootCertStore::empty();
        if let Some(pem) = &self.ca_pem {
            if pem.is_empty() || pem.len() > MAX_PEM {
                return Err(invalid("invalid WSS CA"));
            }
            let certs = certificates(pem.as_bytes())?;
            for certificate in certs {
                roots.add(certificate).map_err(io::Error::other)?;
            }
        } else {
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }
        Ok(Arc::new(
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .map_err(io::Error::other)?
                .with_root_certificates(roots)
                .with_no_client_auth(),
        ))
    }
}

/// Upgrade an already connected, platform-protected socket. The caller owns
/// DNS/address racing; no additional socket is opened by this function.
pub async fn client(
    socket: BoxStream,
    endpoint: &NetworkEndpoint,
    options: &ClientOptions,
) -> io::Result<BoxStream> {
    options.dial_endpoint(endpoint)?;
    if endpoint.is_quic() {
        return Err(invalid("QUIC requires a protected UDP socket"));
    }
    if !endpoint.is_wss() {
        return Ok(socket);
    }
    tokio::time::timeout(UPGRADE_TIMEOUT, async {
        let mut socket = socket;
        if options.http_connect_proxy.is_some() {
            connect_proxy(&mut socket, &endpoint.authority()).await?;
        }
        let name = ServerName::try_from(endpoint.host())
            .map_err(|_| invalid("invalid WSS server name"))?;
        let socket = TlsConnector::from(options.tls_config()?)
            .connect(name, socket)
            .await?;
        let (socket, _) = client_async_with_config(endpoint.as_str(), socket, Some(ws_config()))
            .await
            .map_err(io::Error::other)?;
        Ok(websocket::bridge(socket))
    })
    .await
    .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
}

/// Build a dedicated WSS server identity; Control mTLS credentials are separate.
pub fn server_tls(certificate_pem: &[u8], private_key_pem: &[u8]) -> io::Result<TlsAcceptor> {
    if private_key_pem.len() > MAX_PEM {
        return Err(invalid("WSS key too large"));
    }
    let key = PrivateKeyDer::from_pem_slice(private_key_pem).map_err(io::Error::other)?;
    let config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(io::Error::other)?
            .with_no_client_auth()
            .with_single_cert(certificates(certificate_pem)?, key)
            .map_err(io::Error::other)?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// Accept WSS, or a loopback WebSocket backend behind an HTTPS reverse proxy.
/// Host session/IP/handshake limits must be acquired before calling this.
pub async fn server(socket: BoxStream, tls: Option<TlsAcceptor>) -> io::Result<BoxStream> {
    tokio::time::timeout(UPGRADE_TIMEOUT, async {
        let socket: BoxStream = if let Some(tls) = tls {
            Box::new(tls.accept(socket).await?)
        } else {
            socket
        };
        // Tungstenite fixes this callback error type to an HTTP response.
        #[allow(clippy::result_large_err)]
        let callback = |request: &Request, response: Response| {
            if request.uri().path() == "/peerward" && request.uri().query().is_none() {
                Ok(response)
            } else {
                let mut error = tokio_tungstenite::tungstenite::http::Response::new(Some(
                    "invalid Relay path".into(),
                ));
                *error.status_mut() = tokio_tungstenite::tungstenite::http::StatusCode::NOT_FOUND;
                Err(error)
            }
        };
        let socket = accept_hdr_async_with_config(socket, callback, Some(ws_config()))
            .await
            .map_err(io::Error::other)?;
        Ok(websocket::bridge(socket))
    })
    .await
    .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
}

fn certificates(pem: &[u8]) -> io::Result<Vec<CertificateDer<'static>>> {
    if pem.len() > MAX_PEM {
        return Err(invalid("WSS certificates too large"));
    }
    let certs = CertificateDer::pem_slice_iter(pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(io::Error::other)?;
    if certs.is_empty() {
        return Err(invalid("missing WSS certificate"));
    }
    Ok(certs)
}

fn ws_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .read_buffer_size(16_384)
        .write_buffer_size(0)
        .max_write_buffer_size(WS_LIMIT * 2)
        .max_message_size(Some(WS_LIMIT))
        .max_frame_size(Some(WS_LIMIT))
}

async fn connect_proxy(socket: &mut BoxStream, authority: &str) -> io::Result<()> {
    let request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n");
    socket.write_all(request.as_bytes()).await?;
    socket.flush().await?;
    // Read exactly through CRLFCRLF. Coalesced TLS bytes remain in the socket.
    let mut header = Vec::with_capacity(256);
    while !header.ends_with(b"\r\n\r\n") {
        if header.len() == MAX_HTTP {
            return Err(invalid("CONNECT response headers too large"));
        }
        header.push(socket.read_u8().await?);
    }
    let status = header
        .split(|byte| *byte == b'\n')
        .next()
        .unwrap_or_default();
    if !(status.starts_with(b"HTTP/1.1 200 ") || status.starts_with(b"HTTP/1.0 200 ")) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "HTTP CONNECT refused",
        ));
    }
    Ok(())
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests;
