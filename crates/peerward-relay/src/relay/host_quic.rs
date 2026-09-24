/// At most one TLS-authenticated UDP listener per family, independent of Mesh count.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuicListenerConfig {
    pub address: SocketAddr,
    #[serde(default)]
    pub additional_address: Option<SocketAddr>,
    pub certificate_file: PathBuf,
    pub private_key_file: PathBuf,
}

impl QuicListenerConfig {
    fn validate(&mut self, path: &Path, stun: &[SocketAddr]) -> Result<(), RelayError> {
        if self
            .additional_address
            .is_some_and(|other| other.is_ipv4() == self.address.is_ipv4())
            || std::iter::once(self.address)
                .chain(self.additional_address)
                .any(|address| {
                    address.port() == 0
                        || address.ip().is_multicast()
                        || stun.iter().any(|other| {
                            other.port() == address.port()
                                && other.is_ipv4() == address.is_ipv4()
                                && (other.ip() == address.ip()
                                    || other.ip().is_unspecified()
                                    || address.ip().is_unspecified())
                        })
                })
            || self.certificate_file.as_os_str().is_empty()
            || self.private_key_file.as_os_str().is_empty()
        {
            return Err(RelayError::InvalidConfig);
        }
        let base = path.parent().unwrap_or_else(|| Path::new("."));
        for file in [&mut self.certificate_file, &mut self.private_key_file] {
            if file.is_relative() {
                *file = base.join(&*file);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "host_quic_tests.rs"]
mod quic_listener_tests;

async fn accept_quic(
    listener: Option<&Arc<peerward_carrier::quic::Listener>>,
) -> Option<peerward_carrier::quic::Incoming> {
    match listener {
        Some(listener) => listener.incoming().await,
        None => std::future::pending().await,
    }
}

fn open_quic_listener(
    config: Option<&QuicListenerConfig>,
    additional: bool,
) -> Result<Option<Arc<peerward_carrier::quic::Listener>>, RelayError> {
    let Some(config) = config else {
        return Ok(None);
    };
    let Some(address) = (if additional {
        config.additional_address
    } else {
        Some(config.address)
    }) else {
        return Ok(None);
    };
    let domain = if address.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let socket = socket2::Socket::new(domain, socket2::Type::DGRAM, None)?;
    if address.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.set_nonblocking(true)?;
    socket.bind(&address.into())?;
    Ok(Some(Arc::new(peerward_carrier::quic::Listener::bind(
        socket.into(),
        &read_bounded_regular_file(&config.certificate_file, 1024 * 1024)?,
        &read_private(&config.private_key_file, 65_536)?,
    )?)))
}

fn admit_quic(
    incoming: peerward_carrier::quic::Incoming,
    listener: Arc<peerward_carrier::quic::Listener>,
    registry: &Registry,
    terminals: &Terminals,
    sessions: &Arc<Semaphore>,
    handshakes: &Arc<Semaphore>,
    ips: &Arc<IpHandshakeLimiter>,
    tasks: &tokio_util::task::TaskTracker,
    cancel: &tokio_util::sync::CancellationToken,
) {
    // Stateless address validation precedes expensive TLS, Noise and Mesh work.
    if !incoming.remote_address_validated() {
        let _ = incoming.retry();
        return;
    }
    let Ok(session) = Arc::clone(sessions).try_acquire_owned() else {
        incoming.refuse();
        return;
    };
    let Ok(handshake) = Arc::clone(handshakes).try_acquire_owned() else {
        incoming.refuse();
        return;
    };
    let Some(ip) = ips.try_acquire(incoming.remote_address().ip()) else {
        incoming.refuse();
        return;
    };
    let registry = Arc::clone(registry);
    let terminals = Arc::clone(terminals);
    let cancel = cancel.clone();
    tasks.spawn(async move {
        let _session = session;
        tokio::select! {
            () = cancel.cancelled() => {},
            result = async {
                let socket = listener.accept(incoming).await?.into_stream();
                dispatch_stream(socket, None, registry, terminals, handshake, ip).await
            } => {
                if let Err(error) = result { tracing::debug!(?error, "Shared QUIC Relay session ended"); }
            }
        }
    });
}
