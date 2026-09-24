fn admit_socket(
    socket: TcpStream,
    remote: IpAddr,
    carrier: IncomingCarrier,
    registry: &Registry,
    terminals: &Terminals,
    sessions: &Arc<Semaphore>,
    handshakes: &Arc<Semaphore>,
    ips: &Arc<IpHandshakeLimiter>,
    tasks: &tokio_util::task::TaskTracker,
    cancel: &tokio_util::sync::CancellationToken,
) {
    let Ok(session) = Arc::clone(sessions).try_acquire_owned() else {
        return;
    };
    let Ok(handshake) = Arc::clone(handshakes).try_acquire_owned() else {
        return;
    };
    let Some(ip) = ips.try_acquire(remote) else {
        return;
    };
    let registry = Arc::clone(registry);
    let terminals = Arc::clone(terminals);
    let cancel = cancel.clone();
    tasks.spawn(async move {
        let _session = session;
        tokio::select! {
            () = cancel.cancelled() => {},
            result = dispatch_socket(socket, carrier, registry, terminals, handshake, ip) => {
                if let Err(error) = result { tracing::debug!(?error, "Shared Relay session ended"); }
            }
        }
    });
}

async fn dispatch_socket(
    socket: TcpStream,
    carrier: IncomingCarrier,
    registry: Registry,
    terminals: Terminals,
    handshake: tokio::sync::OwnedSemaphorePermit,
    ip: IpHandshakePermit,
) -> Result<(), RelayError> {
    let expected_role = match &carrier {
        IncomingCarrier::Tcp(role) => Some(*role),
        IncomingCarrier::WebSocket(_) => None,
    };
    let socket = carrier.upgrade(socket).await?;
    dispatch_stream(socket, expected_role, registry, terminals, handshake, ip).await
}

async fn dispatch_stream(
    mut socket: BoxStream,
    expected_role: Option<bool>,
    registry: Registry,
    terminals: Terminals,
    handshake: tokio::sync::OwnedSemaphorePermit,
    ip: IpHandshakePermit,
) -> Result<(), RelayError> {
    let mut bytes = [0; peerward_wire::RELAY_PREFACE_LEN];
    tokio::time::timeout(Duration::from_secs(5), socket.read_exact(&mut bytes))
        .await
        .map_err(|_| RelayError::HandshakeLimited)??;
    let preface = peerward_wire::RelayPreface::decode(&bytes)?;
    let backbone = preface.source.is_some();
    if expected_role.is_some_and(|expected| expected != backbone) {
        return Err(RelayError::NoRoute);
    }
    let terminal = terminals.read().await.get(&preface.mesh_id).cloned();
    if let Some((target, terminal)) = terminal {
        if target != preface.target {
            return Err(RelayError::NoRoute);
        }
        tokio::time::timeout(Duration::from_secs(5), async {
            // Drain the bounded first Noise frame before a clean terminal reply.
            let len = socket.read_u16().await?;
            let mut initial = vec![0; usize::from(len)];
            socket.read_exact(&mut initial).await?;
            socket.write_u16(228).await?;
            socket.write_all(&terminal).await?;
            socket.flush().await?;
            if socket.is_quic() {
                let mut receipt = [0; 4];
                socket.read_exact(&mut receipt).await?;
                if receipt != *b"PWTA" {
                    return Err(std::io::Error::from(std::io::ErrorKind::InvalidData));
                }
            }
            socket.shutdown().await
        })
        .await
        .map_err(|_| RelayError::HandshakeLimited)??;
        return Ok(());
    }
    let shared = registry
        .read()
        .await
        .get(&preface.mesh_id)
        .cloned()
        .ok_or(RelayError::NoRoute)?;
    if shared.config.relay_id != preface.target
        || shared.cancel.is_cancelled()
        || shared.termination.borrow().is_some()
        || (!backbone && !shared.accepting_peers.load(Ordering::Acquire))
    {
        return Err(RelayError::NoRoute);
    }
    let _mesh_session = Arc::clone(&shared.peer_sessions)
        .try_acquire_owned()
        .map_err(|_| RelayError::HandshakeLimited)?;
    let token = shared.tasks.token();
    let cancel = shared.cancel.clone();
    let result = tokio::select! {
        () = cancel.cancelled() => Ok(()),
        result = async {
            if backbone {
                // KK handshake has a strict timeout; the host permit is released
                // by the prefaced acceptor after authentication, not at session end.
                run_incoming_backbone_host(socket, Arc::clone(&shared), preface, handshake, ip).await
            } else {
                run_peer_session(socket, Arc::clone(&shared.local_private), Arc::clone(&shared), ip, Some(preface), Some(handshake)).await
            }
        } => result,
    };
    drop(token);
    result
}
