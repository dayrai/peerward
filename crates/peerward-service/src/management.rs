const LOCAL_MESSAGE_LIMIT: usize = 65_536;
const TCP_PUBLICATION_CONNECTION_LIMIT: usize = 256;

/// Local service management or forwarding failure.
#[derive(Debug, Error)]
pub enum ServiceError {
    /// Request, alias, port, or target is invalid.
    #[error("invalid service request")]
    Invalid,
    /// Service resource does not exist.
    #[error("service does not exist")]
    NotFound,
    /// Caller is not the peer daemon's operating-system user.
    #[error("local service caller is unauthorized")]
    Unauthorized,
    /// Bounded mapping or request capacity is exhausted.
    #[error("local service capacity is exhausted")]
    Capacity,
    /// Socket operation failed.
    #[error("local service socket failed")]
    Io(#[from] std::io::Error),
    /// Durable state update failed.
    #[error("local service persistence failed")]
    State(#[from] PlatformError),
    /// Local protocol encoding failed.
    #[error("local service protocol failed")]
    Encoding(#[from] serde_json::Error),
}

/// One durable loopback publication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceRecord {
    /// Stable service identifier.
    pub id: ServiceId,
    /// Canonical nonempty transport set.
    pub protocols: Vec<ServiceProtocol>,
    /// Mesh-visible port, independent from the loopback target port.
    pub listen_port: u16,
    /// Loopback-only target.
    pub target: SocketAddr,
    /// Optional mesh DNS label.
    pub alias: Option<String>,
}

/// Local registry mutation that must commit through the authenticated Peer session.
pub enum ServiceChange {
    /// Publish or idempotently restore one service.
    Publish(ServiceRecord, oneshot::Sender<bool>),
    /// Withdraw one exact owned service.
    Remove(ServiceId, oneshot::Sender<bool>),
}

/// Newline-delimited, local-only management request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    /// Get or version-check an explicit local preference update.
    ClientPreferences { request: ClientPreferenceRequest },
    /// Publish one loopback port.
    Publish {
        /// Mesh-visible port.
        listen_port: u16,
        /// Loopback-only destination, never sent to Control.
        target: SocketAddr,
        /// TCP, UDP, or canonical TCP+UDP.
        protocols: Vec<ServiceProtocol>,
        /// Optional DNS alias.
        alias: Option<String>,
    },
    /// List current publications.
    List,
    /// Remove one exact service.
    Remove {
        /// Service identity.
        service_id: ServiceId,
    },
    /// Return daemon health and queue counters.
    Health,
    /// Return detailed secret-free runtime status.
    Status,
    /// Return monotonic process counters.
    Metrics,
}

/// Stable local response envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    /// Whether the operation succeeded.
    pub ok: bool,
    /// Machine-readable failure when `ok` is false.
    pub error: Option<String>,
    /// Affected service.
    pub service: Option<ServiceRecord>,
    /// Current services for list operations.
    pub services: Vec<ServiceRecord>,
    /// Status or metrics JSON without secrets.
    pub detail: serde_json::Value,
}

impl Response {
    fn success() -> Self {
        Self {
            ok: true,
            error: None,
            service: None,
            services: Vec::new(),
            detail: serde_json::Value::Null,
        }
    }

    fn failure(code: &str) -> Self {
        Self {
            ok: false,
            error: Some(code.into()),
            ..Self::success()
        }
    }
}

#[derive(Default)]
struct Metrics {
    requests: AtomicU64,
    failures: AtomicU64,
    tcp_connections: AtomicU64,
    udp_datagrams: AtomicU64,
}

struct PublicationSet {
    mesh_address: IpAddr,
    tasks: HashMap<ServiceId, (watch::Sender<bool>, Vec<tokio::task::JoinHandle<()>>)>,
    metrics: Arc<Metrics>,
}

impl PublicationSet {
    fn new(mesh_address: IpAddr, metrics: Arc<Metrics>) -> Result<Self, ServiceError> {
        if mesh_address.is_unspecified() {
            return Err(ServiceError::Invalid);
        }
        Ok(Self {
            mesh_address,
            tasks: HashMap::new(),
            metrics,
        })
    }

    async fn activate(&mut self, service: &ServiceRecord) -> Result<(), ServiceError> {
        self.deactivate(service.id).await;
        let bind = SocketAddr::new(self.mesh_address, service.listen_port);
        let tcp = service
            .protocols
            .contains(&ServiceProtocol::Tcp)
            .then(|| TcpListener::bind(bind));
        let udp = service
            .protocols
            .contains(&ServiceProtocol::Udp)
            .then(|| UdpSocket::bind(bind));
        let tcp = match tcp {
            Some(listener) => Some(listener.await?),
            None => None,
        };
        let udp = match udp {
            Some(socket) => Some(socket.await?),
            None => None,
        };
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let mut tasks = Vec::with_capacity(service.protocols.len());
        if let Some(listener) = tcp {
            let target = service.target;
            let shutdown = shutdown_rx.clone();
            let metrics = Arc::clone(&self.metrics);
            tasks.push(tokio::spawn(async move {
                run_tcp_publication(
                    listener,
                    target,
                    TCP_PUBLICATION_CONNECTION_LIMIT,
                    metrics,
                    shutdown,
                )
                .await;
            }));
        }
        if let Some(socket) = udp {
            let target = service.target;
            let metrics = Arc::clone(&self.metrics);
            tasks.push(tokio::spawn(async move {
                if let Err(error) = forward_udp_counted(
                    socket,
                    target,
                    256,
                    Duration::from_secs(30),
                    shutdown_rx,
                    Some(metrics),
                )
                .await
                {
                    tracing::warn!(%target, ?error, "Published UDP service stopped");
                }
            }));
        }
        self.tasks.insert(service.id, (shutdown_tx, tasks));
        Ok(())
    }

    async fn deactivate(&mut self, id: ServiceId) {
        if let Some((shutdown, tasks)) = self.tasks.remove(&id) {
            let _ = shutdown.send(true);
            for task in tasks {
                let _ = task.await;
            }
        }
    }

    async fn shutdown(&mut self) {
        let ids: Vec<_> = self.tasks.keys().copied().collect();
        for id in ids {
            self.deactivate(id).await;
        }
    }
}

async fn run_tcp_publication(
    listener: TcpListener,
    target: SocketAddr,
    capacity: usize,
    metrics: Arc<Metrics>,
    mut shutdown: watch::Receiver<bool>,
) {
    let clients = Arc::new(tokio::sync::Semaphore::new(capacity));
    let mut tasks = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let Ok((stream, source)) = accepted else { break; };
                let Ok(permit) = Arc::clone(&clients).try_acquire_owned() else {
                    drop(stream);
                    continue;
                };
                metrics.tcp_connections.fetch_add(1, Ordering::Relaxed);
                tasks.spawn(async move {
                    let _permit = permit;
                    if let Err(error) = forward_tcp(stream, target).await {
                        tracing::debug!(%source, %target, ?error, "Published TCP service connection failed");
                    }
                });
            }
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() { break; }
            }
        }
    }
    tasks.shutdown().await;
}

/// Runs the protected local management socket until shutdown.
#[cfg(unix)]
pub async fn serve(
    socket_path: &Path,
    state_path: PathBuf,
    shutdown: watch::Receiver<bool>,
) -> Result<(), ServiceError> {
    serve_inner(socket_path, state_path, None, None, None, shutdown).await
}

/// Runs the protected API and activates publications on the peer's TUN address.
#[cfg(unix)]
pub async fn serve_with_address(
    socket_path: &Path,
    state_path: PathBuf,
    mesh_address: IpAddr,
    shutdown: watch::Receiver<bool>,
) -> Result<(), ServiceError> {
    serve_inner(
        socket_path,
        state_path,
        Some(mesh_address),
        None,
        None,
        shutdown,
    )
    .await
}

/// Runs the complete local Peer management endpoint with live runtime observability.
#[cfg(unix)]
pub async fn serve_peer_management(
    socket_path: &Path,
    state_path: PathBuf,
    mesh_address: IpAddr,
    changes: mpsc::Sender<ServiceChange>,
    observability: PeerObservability,
    shutdown: watch::Receiver<bool>,
) -> Result<(), ServiceError> {
    serve_inner(
        socket_path,
        state_path,
        Some(mesh_address),
        Some(changes),
        Some(observability),
        shutdown,
    )
    .await
}

#[cfg(unix)]
async fn serve_inner(
    socket_path: &Path,
    state_path: PathBuf,
    mesh_address: Option<IpAddr>,
    changes: Option<mpsc::Sender<ServiceChange>>,
    observability: Option<PeerObservability>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), ServiceError> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};

    let current_uid = std::fs::metadata("/proc/self")?.uid();
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if let Ok(metadata) = std::fs::symlink_metadata(socket_path) {
        if !metadata.file_type().is_socket() || metadata.uid() != current_uid {
            return Err(ServiceError::Unauthorized);
        }
        std::fs::remove_file(socket_path)?;
    }
    let listener = UnixListener::bind(socket_path)?;
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))?;
    let socket_cleanup = BoundUnixSocket(Some(socket_path.to_path_buf()));
    let registry = Arc::new(Mutex::new(Registry::load(state_path)?));
    let metrics = Arc::new(Metrics::default());
    let publications = if let Some(address) = mesh_address {
        let mut active = PublicationSet::new(address, Arc::clone(&metrics))?;
        for service in &registry.lock().await.state.services {
            if let Err(error) = active.activate(service).await {
                active.shutdown().await;
                return Err(error);
            }
        }
        Some(Arc::new(Mutex::new(active)))
    } else {
        None
    };
    if let Some(changes) = &changes {
        let existing = registry.lock().await.state.services.clone();
        for service in existing {
            if !commit_change(changes, |reply| ServiceChange::Publish(service, reply)).await {
                if let Some(publications) = &publications {
                    publications.lock().await.shutdown().await;
                }
                return Err(ServiceError::Capacity);
            }
        }
    }
    let clients = Arc::new(tokio::sync::Semaphore::new(128));
    let mut client_tasks = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                let Ok(permit)=Arc::clone(&clients).try_acquire_owned() else {drop(stream);continue;};
                let registry = Arc::clone(&registry);
                let metrics = Arc::clone(&metrics);
                let publications = publications.clone();
                let changes = changes.clone();
                let observability = observability.clone();
                client_tasks.spawn(async move {
                    let _permit=permit;
                    if let Err(error) = handle_client(
                        stream,
                        current_uid,
                        registry,
                        publications,
                        changes,
                        observability,
                        metrics.clone(),
                    ).await {
                        metrics.failures.fetch_add(1, Ordering::Relaxed);
                        tracing::warn!(?error, "Peer local management request failed");
                    }
                });
            }
            Some(result) = client_tasks.join_next(), if !client_tasks.is_empty() => {
                if let Err(error) = result {
                    tracing::debug!(?error, "Peer local management client task failed");
                }
            }
            shutdown_change = shutdown.changed() => {
                if shutdown_change.is_err() || *shutdown.borrow() {
                    break;
                }
            }
        }
    }
    client_tasks.shutdown().await;
    if let Some(publications) = publications {
        publications.lock().await.shutdown().await;
    }
    drop(listener);
    socket_cleanup.remove()?;
    Ok(())
}

#[cfg(unix)]
async fn handle_client(
    stream: UnixStream,
    current_uid: u32,
    registry: Arc<Mutex<Registry>>,
    publications: Option<Arc<Mutex<PublicationSet>>>,
    changes: Option<mpsc::Sender<ServiceChange>>,
    observability: Option<PeerObservability>,
    metrics: Arc<Metrics>,
) -> Result<(), ServiceError> {
    if stream.peer_cred()?.uid() != current_uid {
        return Err(ServiceError::Unauthorized);
    }
    metrics.requests.fetch_add(1, Ordering::Relaxed);
    let (reader, mut writer) = stream.into_split();
    let mut line = String::new();
    let limited = tokio::io::AsyncReadExt::take(reader, LOCAL_MESSAGE_LIMIT as u64 + 1);
    let length = tokio::time::timeout(
        Duration::from_secs(10),
        BufReader::new(limited).read_line(&mut line),
    )
    .await
    .map_err(|_| std::io::Error::from(std::io::ErrorKind::TimedOut))??;
    if length == 0 || length > LOCAL_MESSAGE_LIMIT {
        return Err(ServiceError::Invalid);
    }
    let request: Request = serde_json::from_str(&line)?;
    let response = process_request(
        request,
        &registry,
        publications.as_deref(),
        changes.as_ref(),
        observability.as_ref(),
        &metrics,
    )
    .await;
    writer.write_all(&serde_json::to_vec(&response)?).await?;
    writer.write_all(b"\n").await?;
    writer.shutdown().await?;
    Ok(())
}

async fn process_request(
    request: Request,
    registry: &Mutex<Registry>,
    publications: Option<&Mutex<PublicationSet>>,
    changes: Option<&mpsc::Sender<ServiceChange>>,
    observability: Option<&PeerObservability>,
    metrics: &Metrics,
) -> Response {
    if let Request::ClientPreferences { request } = request {
        return match observability {
            Some(observed) => observed.client_preferences(request).await,
            None => Response::failure("client_runtime_unavailable"),
        };
    }
    let mut registry = registry.lock().await;
    match request {
        Request::ClientPreferences { .. } => unreachable!("handled before registry lock"),
        Request::Publish {
            listen_port,
            target,
            protocols,
            alias,
        } => match registry.publish(listen_port, target, protocols, alias) {
            Ok(service) => {
                if let Some(active) = publications
                    && active.lock().await.activate(&service).await.is_err()
                {
                    let _ = registry.remove(service.id);
                    return Response::failure("service_bind_failed");
                }
                if let Some(changes) = changes
                    && !commit_change(changes, |reply| {
                        ServiceChange::Publish(service.clone(), reply)
                    })
                    .await
                {
                    if let Some(active) = publications {
                        active.lock().await.deactivate(service.id).await;
                    }
                    let _ = registry.remove(service.id);
                    return Response::failure("control_registration_failed");
                }
                if let Some(observability) = observability {
                    observability.record_service_mutation();
                }
                Response {
                    service: Some(service),
                    ..Response::success()
                }
            }
            Err(_) => Response::failure("invalid_service"),
        },
        Request::List => Response {
            services: registry.state.services.clone(),
            ..Response::success()
        },
        Request::Remove { service_id } => {
            if !registry
                .state
                .services
                .iter()
                .any(|service| service.id == service_id)
            {
                return Response::failure("service_not_found");
            }
            if let Some(changes) = changes
                && !commit_change(changes, |reply| ServiceChange::Remove(service_id, reply)).await
            {
                return Response::failure("control_registration_failed");
            }
            match registry.remove(service_id) {
                Ok(service) => {
                    if let Some(active) = publications {
                        active.lock().await.deactivate(service_id).await;
                    }
                    if let Some(observability) = observability {
                        observability.record_service_mutation();
                    }
                    Response {
                        service: Some(service),
                        ..Response::success()
                    }
                }
                Err(_) => Response::failure("service_not_found"),
            }
        }
        Request::Health => Response {
            detail: observability.map_or_else(
                || serde_json::json!({"status":"degraded","reason":"runtime_unavailable"}),
                PeerObservability::health_json,
            ),
            ..Response::success()
        },
        Request::Status => {
            let mut detail = observability.map_or_else(
                || serde_json::json!({"status":"degraded","reason":"runtime_unavailable"}),
                PeerObservability::status_json,
            );
            if let Some(detail) = detail.as_object_mut() {
                detail.insert(
                    "published_services".into(),
                    registry.state.services.len().into(),
                );
            }
            Response {
                detail,
                ..Response::success()
            }
        }
        Request::Metrics => Response {
            detail: merge_metrics(
                observability,
                serde_json::json!({
                    "peerward_service_requests_total": metrics.requests.load(Ordering::Relaxed),
                    "peerward_service_failures_total": metrics.failures.load(Ordering::Relaxed),
                    "peerward_service_tcp_connections_total": metrics.tcp_connections.load(Ordering::Relaxed),
                    "peerward_service_udp_datagrams_total": metrics.udp_datagrams.load(Ordering::Relaxed),
                }),
            ),
            ..Response::success()
        },
    }
}

async fn commit_change<F>(changes: &mpsc::Sender<ServiceChange>, make: F) -> bool
where
    F: FnOnce(oneshot::Sender<bool>) -> ServiceChange,
{
    let (reply, result) = oneshot::channel();
    if changes.send(make(reply)).await.is_err() {
        return false;
    }
    matches!(
        tokio::time::timeout(Duration::from_secs(10), result).await,
        Ok(Ok(true))
    )
}

fn valid_protocols(protocols: &[ServiceProtocol]) -> bool {
    matches!(
        protocols,
        [ServiceProtocol::Tcp | ServiceProtocol::Udp]
            | [ServiceProtocol::Tcp, ServiceProtocol::Udp]
    )
}
