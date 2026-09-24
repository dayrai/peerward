//! Blocking platform entrypoints share the same carrier implementation. Close
//! interrupts reads and blocked writes without taking either direction's lock.
use super::{BoxStream, ClientOptions};
use peerward_types::NetworkEndpoint;
use std::{
    io,
    sync::{Arc, Mutex, OnceLock},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf},
    runtime::{Builder, Runtime},
};
use tokio_util::sync::CancellationToken;

fn runtime() -> io::Result<&'static Runtime> {
    static RUNTIME: OnceLock<Result<Runtime, String>> = OnceLock::new();
    RUNTIME
        .get_or_init(|| {
            Builder::new_multi_thread()
                .worker_threads(2)
                .thread_name("peerward-carrier")
                .enable_all()
                .build()
                .map_err(|error| error.to_string())
        })
        .as_ref()
        .map_err(|error| io::Error::other(error.clone()))
}

pub struct BlockingSocket {
    pub reader: Mutex<BlockingReader>,
    pub writer: Mutex<BlockingWriter>,
    cancel: CancellationToken,
    pending: Mutex<Option<StreamFuture>>,
}
type StreamFuture =
    std::pin::Pin<Box<dyn std::future::Future<Output = io::Result<BoxStream>> + Send>>;
pub struct BlockingReader {
    inner: Option<ReadHalf<BoxStream>>,
    cancel: CancellationToken,
}
pub struct BlockingWriter {
    timeout: std::time::Duration,
    inner: Option<WriteHalf<BoxStream>>,
    cancel: CancellationToken,
}

impl BlockingSocket {
    /// Always consumes the owned descriptor, including failed upgrades.
    pub fn new(
        socket: std::net::TcpStream,
        endpoint: Option<&NetworkEndpoint>,
        options: &ClientOptions,
    ) -> io::Result<Arc<Self>> {
        let prepared = Self::prepare_tcp(socket, endpoint, options)?;
        prepared.connect()?;
        Ok(prepared)
    }

    pub fn prepare_tcp(
        socket: std::net::TcpStream,
        endpoint: Option<&NetworkEndpoint>,
        options: &ClientOptions,
    ) -> io::Result<Arc<Self>> {
        socket.set_nonblocking(true)?;
        socket.set_nodelay(true)?;
        options.validate()?;
        let endpoint = endpoint.cloned();
        let options = options.clone();
        Ok(Self::pending(Box::pin(async move {
            let stream: BoxStream = Box::new(tokio::net::TcpStream::from_std(socket)?);
            match endpoint {
                Some(endpoint) => super::client(stream, &endpoint, &options).await,
                None => Ok(stream),
            }
        })))
    }

    pub fn prepare_quic(
        socket: std::net::UdpSocket,
        remote: std::net::SocketAddr,
        endpoint: &NetworkEndpoint,
        options: &ClientOptions,
    ) -> io::Result<Arc<Self>> {
        if !endpoint.is_quic() {
            return Err(super::invalid("QUIC endpoint required"));
        }
        options.validate()?;
        let endpoint = endpoint.clone();
        let options = options.clone();
        Ok(Self::pending(Box::pin(async move {
            Ok(
                super::quic::connect(socket, remote, &endpoint.host(), &options)
                    .await?
                    .into_stream(),
            )
        })))
    }

    fn pending(future: StreamFuture) -> Arc<Self> {
        let cancel = CancellationToken::new();
        Arc::new(Self {
            reader: Mutex::new(BlockingReader {
                inner: None,
                cancel: cancel.clone(),
            }),
            writer: Mutex::new(BlockingWriter {
                timeout: std::time::Duration::from_secs(5),
                inner: None,
                cancel: cancel.clone(),
            }),
            pending: Mutex::new(Some(future)),
            cancel,
        })
    }

    /// The platform receives a closeable handle BEFORE any TLS/QUIC/CONNECT
    /// work. Closing a losing race or changing Network cancels this immediately.
    pub fn connect(&self) -> io::Result<()> {
        let pending = self
            .pending
            .lock()
            .map_err(|_| closed())?
            .take()
            .ok_or_else(closed)?;
        let result = runtime()?.block_on(async {
            tokio::select! { biased;
                () = self.cancel.cancelled() => Err(closed()),
                result = pending => result,
            }
        });
        let socket = match result {
            Ok(socket) => socket,
            Err(error) => {
                self.close();
                return Err(error);
            }
        };
        let mut reader = self.reader.lock().map_err(|_| closed())?;
        let mut writer = self.writer.lock().map_err(|_| closed())?;
        if self.cancel.is_cancelled() {
            return Err(closed());
        }
        let (input, output) = tokio::io::split(socket);
        reader.inner = Some(input);
        writer.inner = Some(output);
        Ok(())
    }

    /// Only called by the connection factory, after Noise credential validation
    /// and before publishing the socket to the connection pool. Close remains
    /// lock-free and can interrupt exporter binding on a changing Network.
    pub fn activate(
        &self,
        transport: super::RecordTransport,
        preface: peerward_wire::RelayPreface,
        now: u64,
    ) -> io::Result<super::RecordTransport> {
        let mut reader = self.reader.lock().map_err(|_| closed())?;
        let mut writer = self.writer.lock().map_err(|_| closed())?;
        let input = reader.inner.take().ok_or_else(closed)?;
        let output = writer.inner.take().ok_or_else(closed)?;
        let result = runtime()?.block_on(async {
            tokio::select! { biased;
                () = self.cancel.cancelled() => Err(closed()),
                result = super::quic::activate(input.unsplit(output), transport, Some(preface), now) => result,
            }
        });
        match result {
            Ok((socket, mut transport)) => {
                let (input, output) = tokio::io::split(socket);
                reader.inner = Some(input);
                writer.inner = Some(output);
                let selected = peerward_wire::Record::Control(peerward_wire::ControlEnvelope {
                    trace_context: None,
                    message: Some(peerward_wire::control_envelope::Message::Welcome(
                        peerward_wire::Welcome {
                            mesh_id: preface.mesh_id.as_bytes().to_vec(),
                            body: b"link_admit".to_vec(),
                        },
                    )),
                });
                writer.write_all(&transport.encode(&selected).map_err(io::Error::other)?)?;
                Ok(transport)
            }
            Err(error) => {
                self.close();
                Err(error)
            }
        }
    }

    pub fn close(&self) {
        self.cancel.cancel();
    }
}

impl BlockingReader {
    pub fn read_exact(&mut self, bytes: &mut [u8]) -> io::Result<()> {
        let inner = self.inner.as_mut().ok_or_else(closed)?;
        let result = runtime()?.block_on(async {
            tokio::select! { biased;
                () = self.cancel.cancelled() => Err(closed()),
                result = inner.read_exact(bytes) => result.map(|_| ()),
            }
        });
        // A partial frame or timed-out write cannot be resumed with a new
        // authenticated record. Fence both halves until the owner reconnects.
        if result.is_err() {
            self.cancel.cancel();
        }
        result
    }
}

impl BlockingWriter {
    pub fn write_with_timeout(
        &mut self,
        bytes: &[u8],
        timeout: std::time::Duration,
    ) -> io::Result<()> {
        let previous = self.timeout;
        self.timeout = timeout;
        let result = self.write_all(bytes);
        self.timeout = previous;
        result
    }
    pub fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        let inner = self.inner.as_mut().ok_or_else(closed)?;
        let result = runtime()?.block_on(async {
            tokio::select! { biased;
                () = self.cancel.cancelled() => Err(closed()),
                result = tokio::time::timeout(self.timeout, async {
                    inner.write_all(bytes).await?;
                    inner.flush().await
                }) => result.map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?,
            }
        });
        // A partial frame or timed-out write cannot be resumed with a new
        // authenticated record. Fence both halves until the owner reconnects.
        if result.is_err() {
            self.cancel.cancel();
        }
        result
    }
}

fn closed() -> io::Error {
    io::Error::from(io::ErrorKind::ConnectionAborted)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn packet_deadline_does_not_shorten_later_control_writes() {
        let (client, mut server) = tokio::io::duplex(4);
        let socket = BlockingSocket::pending(Box::pin(async { Ok(Box::new(client) as BoxStream) }));
        socket.connect().unwrap();
        let mut writer = socket.writer.lock().unwrap();
        writer
            .write_with_timeout(b"data", std::time::Duration::from_millis(20))
            .unwrap();
        let worker = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(80));
            runtime().unwrap().block_on(async {
                let mut records = [0; 11];
                server.read_exact(&mut records).await.unwrap();
                assert_eq!(&records, b"datacontrol");
            });
        });
        writer.write_all(b"control").unwrap();
        worker.join().unwrap();
    }
}
