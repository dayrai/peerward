/// Dedicated server TLS files, or a loopback backend for an HTTPS reverse proxy.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WssListenerConfig {
    pub address: SocketAddr,
    pub certificate_file: Option<PathBuf>,
    pub private_key_file: Option<PathBuf>,
}

impl WssListenerConfig {
    fn validate(&mut self, config_path: &Path, occupied: &[SocketAddr]) -> Result<(), RelayError> {
        if self.address.port() == 0
            || self.address.ip().is_multicast()
            || occupied.contains(&self.address)
            || self.certificate_file.is_some() != self.private_key_file.is_some()
            || (self.certificate_file.is_none() && !self.address.ip().is_loopback())
        {
            return Err(RelayError::InvalidConfig);
        }
        let base = config_path.parent().unwrap_or_else(|| Path::new("."));
        for file in [&mut self.certificate_file, &mut self.private_key_file]
            .into_iter()
            .flatten()
        {
            if file.is_relative() {
                *file = base.join(&*file);
            }
        }
        Ok(())
    }
}

#[derive(Clone)]
enum IncomingCarrier {
    Tcp(bool),
    WebSocket(Option<peerward_carrier::TlsAcceptor>),
}

impl IncomingCarrier {
    async fn upgrade(self, socket: TcpStream) -> Result<BoxStream, RelayError> {
        socket.set_nodelay(true)?;
        match self {
            Self::Tcp(_) => Ok(Box::new(socket)),
            Self::WebSocket(tls) => Ok(peerward_carrier::server(Box::new(socket), tls).await?),
        }
    }
}

async fn open_wss_listener(
    config: Option<&WssListenerConfig>,
) -> Result<Option<(TcpListener, IncomingCarrier)>, RelayError> {
    let Some(config) = config else {
        return Ok(None);
    };
    let tls = match (&config.certificate_file, &config.private_key_file) {
        (Some(certificate), Some(key)) => Some(peerward_carrier::server_tls(
            &read_bounded_regular_file(certificate, 1024 * 1024)?,
            &read_private(key, 65_536)?,
        )?),
        (None, None) if config.address.ip().is_loopback() => None,
        _ => return Err(RelayError::InvalidConfig),
    };
    Ok(Some((
        TcpListener::bind(config.address).await?,
        IncomingCarrier::WebSocket(tls),
    )))
}

async fn accept_wss(
    listener: Option<&(TcpListener, IncomingCarrier)>,
) -> std::io::Result<(TcpStream, SocketAddr, IncomingCarrier)> {
    match listener {
        Some((listener, carrier)) => {
            let (socket, remote) = listener.accept().await?;
            Ok((socket, remote, carrier.clone()))
        }
        None => std::future::pending().await,
    }
}

#[cfg(test)]
#[path = "host_wss_tests.rs"]
mod wss_tests;
