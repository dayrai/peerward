/// Sends one request to the local protected daemon socket.
#[cfg(unix)]
pub async fn client(socket_path: &Path, request: &Request) -> Result<Response, ServiceError> {
    let bytes = serde_json::to_vec(request)?;
    if bytes.len() >= LOCAL_MESSAGE_LIMIT {
        return Err(ServiceError::Invalid);
    }
    tokio::time::timeout(Duration::from_secs(15), async {
        let stream = UnixStream::connect(socket_path).await?;
        let (reader, mut writer) = stream.into_split();
        writer.write_all(&bytes).await?;
        writer.write_all(b"\n").await?;
        let limited = tokio::io::AsyncReadExt::take(reader, LOCAL_MESSAGE_LIMIT as u64 + 1);
        let mut line = String::new();
        let length = BufReader::new(limited).read_line(&mut line).await?;
        if length == 0 || length > LOCAL_MESSAGE_LIMIT {
            return Err(ServiceError::Invalid);
        }
        Ok(serde_json::from_str(&line)?)
    })
    .await
    .map_err(|_| std::io::Error::from(std::io::ErrorKind::TimedOut))?
}

/// Proxies one TCP stream to a loopback target; `copy_bidirectional` propagates half-closes.
pub async fn forward_tcp(
    mut mesh_stream: TcpStream,
    target: SocketAddr,
) -> Result<(), ServiceError> {
    if !target.ip().is_loopback() || target.port() == 0 {
        return Err(ServiceError::Invalid);
    }
    let mut local = TcpStream::connect(target).await?;
    tokio::io::copy_bidirectional(&mut mesh_stream, &mut local).await?;
    Ok(())
}

/// Bounded UDP association metadata.
pub struct UdpAssociations {
    entries: HashMap<SocketAddr, u64>,
    capacity: usize,
    timeout: u64,
}

impl UdpAssociations {
    /// Creates a fixed-capacity expiry table.
    pub fn new(capacity: usize, timeout: u64) -> Result<Self, ServiceError> {
        if capacity == 0 || timeout == 0 {
            return Err(ServiceError::Invalid);
        }
        Ok(Self {
            entries: HashMap::new(),
            capacity,
            timeout,
        })
    }

    /// Refreshes one association after expiring stale entries.
    pub fn touch(&mut self, remote: SocketAddr, now: u64) -> Result<(), ServiceError> {
        self.expire(now);
        if !self.entries.contains_key(&remote) && self.entries.len() == self.capacity {
            return Err(ServiceError::Capacity);
        }
        self.entries.insert(remote, now.saturating_add(self.timeout));
        Ok(())
    }

    /// Removes expired associations with no packet-dependent allocations.
    pub fn expire(&mut self, now: u64) {
        self.entries.retain(|_, deadline| *deadline > now);
    }

    /// Current bounded association count.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether there are no live associations.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Forwards UDP request/response datagrams to one loopback target with expiry and capacity.
pub async fn forward_udp(
    mesh_socket: UdpSocket,
    target: SocketAddr,
    capacity: usize,
    idle_timeout: Duration,
    shutdown: watch::Receiver<bool>,
) -> Result<(), ServiceError> {
    forward_udp_counted(
        mesh_socket,
        target,
        capacity,
        idle_timeout,
        shutdown,
        None,
    )
    .await
}

async fn forward_udp_counted(
    mesh_socket: UdpSocket,
    target: SocketAddr,
    capacity: usize,
    idle_timeout: Duration,
    mut shutdown: watch::Receiver<bool>,
    metrics: Option<Arc<Metrics>>,
) -> Result<(), ServiceError> {
    if !target.ip().is_loopback() || target.port() == 0 || capacity == 0 || idle_timeout.is_zero() {
        return Err(ServiceError::Invalid);
    }
    let mesh_socket = Arc::new(mesh_socket);
    let mut associations: HashMap<SocketAddr, mpsc::Sender<Vec<u8>>> = HashMap::new();
    let mut tasks = tokio::task::JoinSet::new();
    let mut packet = vec![0_u8; 65_535];
    while !*shutdown.borrow() {
        tokio::select! {
            received = mesh_socket.recv_from(&mut packet) => {
                let (length, remote) = received?;
                if let Some(metrics) = &metrics {
                    metrics.udp_datagrams.fetch_add(1, Ordering::Relaxed);
                }
                // Drain completed workers before admitting replacements, even
                // when ingress remains continuously ready.
                while tasks.try_join_next().is_some() {}
                associations.retain(|_, sender| !sender.is_closed());
                if !associations.contains_key(&remote) && associations.len() == capacity {
                    continue;
                }
                if let std::collections::hash_map::Entry::Vacant(entry) = associations.entry(remote) {
                    let socket = UdpSocket::bind(loopback_bind_address(target)).await?;
                    socket.connect(target).await?;
                    let (sender, requests) = mpsc::channel(64);
                    entry.insert(sender);
                    tasks.spawn(run_udp_association(
                        Arc::clone(&mesh_socket), socket, remote, requests,
                        idle_timeout, shutdown.clone(),
                    ));
                }
                enqueue_udp_request(&mut associations, remote, &packet[..length]);
            }
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
        }
    }
    tasks.shutdown().await;
    Ok(())
}

fn loopback_bind_address(target: SocketAddr) -> SocketAddr {
    match target {
        SocketAddr::V4(_) => (std::net::Ipv4Addr::LOCALHOST, 0).into(),
        SocketAddr::V6(_) => (std::net::Ipv6Addr::LOCALHOST, 0).into(),
    }
}

fn enqueue_udp_request(
    associations: &mut HashMap<SocketAddr, mpsc::Sender<Vec<u8>>>,
    remote: SocketAddr,
    packet: &[u8],
) {
    // A full queue drops only this datagram. Keep the live association counted
    // against capacity and avoid allocating a payload that cannot be queued.
    let closed = match associations[&remote].try_reserve() {
        Ok(permit) => {
            permit.send(packet.to_vec());
            false
        }
        Err(mpsc::error::TrySendError::Full(())) => false,
        Err(mpsc::error::TrySendError::Closed(())) => true,
    };
    if closed {
        associations.remove(&remote);
    }
}

async fn run_udp_association(
    mesh_socket: Arc<UdpSocket>,
    local_socket: UdpSocket,
    remote: SocketAddr,
    mut requests: mpsc::Receiver<Vec<u8>>,
    idle_timeout: Duration,
    mut shutdown: watch::Receiver<bool>,
) {
    let deadline = tokio::time::sleep(idle_timeout);
    tokio::pin!(deadline);
    let mut response = vec![0_u8; 65_535];
    while !*shutdown.borrow() {
        tokio::select! {
            request = requests.recv() => {
                let Some(request) = request else { return; };
                if local_socket.send(&request).await.is_err() { return; }
                deadline.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
            }
            received = local_socket.recv(&mut response) => {
                let Ok(length) = received else { return; };
                if mesh_socket.send_to(&response[..length], remote).await.is_err() { return; }
                deadline.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
            }
            () = &mut deadline => return,
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() { return; }
            }
        }
    }
}

fn valid_label(value: &str) -> bool {
    value.len() <= 63
        && !value.is_empty()
        && !value.starts_with('-')
        && !value.ends_with('-')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}
