use super::*;
use futures_util::{StreamExt, stream};
use peerward_api::{
    RelayHostAcknowledgement, RelayHostAssignment, RelayHostAssignments, RelayHostPublicKey,
};
use peerward_credentials::{
    AuthorityCertificate, RootPublicKey,
    private_files::{
        private_dir, read_bounded_regular_file, read_private, remove_private, write_private_atomic,
    },
};
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

include!("host_wss.rs");
include!("host_config.rs");
include!("host_dispatch.rs");
include!("host_quic.rs");
include!("host_health.rs");
include!("host_capacity.rs");
type Registry = Arc<AsyncRwLock<BTreeMap<MeshId, Arc<RelayShared>>>>;
type Terminals = Arc<AsyncRwLock<BTreeMap<MeshId, (RelayId, Vec<u8>)>>>;

/// Runs fixed listeners even when no Mesh is configured. One database pool and
/// notification subscription are shared by every Mesh in this process.
pub async fn serve_host(
    config: RelayHostConfig,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), RelayError> {
    private_dir(&config.state_directory)?;
    let store = Store::connect(
        config
            .database_url
            .as_deref()
            .ok_or(RelayError::InvalidConfig)?,
        8,
    )
    .await?;
    let client = config.client()?;
    let peers = TcpListener::bind(config.peer_address).await?;
    let backbone = TcpListener::bind(config.backbone_address).await?;
    let health = TcpListener::bind(config.health_address).await?;
    let wss = open_wss_listener(config.wss.as_ref()).await?;
    let quic = open_quic_listener(config.quic.as_ref(), false)?;
    let quic_additional = open_quic_listener(config.quic.as_ref(), true)?;
    let mut stun_sockets = Vec::new();
    for address in &config.stun_addresses {
        // Explicit IPV6_V6ONLY avoids stealing the independent IPv4 listener.
        let socket = if address.is_ipv4() {
            socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None)?
        } else {
            let socket = socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::DGRAM, None)?;
            socket.set_only_v6(true)?;
            socket
        };
        socket.set_nonblocking(true)?;
        socket.bind(&(*address).into())?;
        stun_sockets.push(tokio::net::UdpSocket::from_std(socket.into())?);
    }
    let registry: Registry = Arc::new(AsyncRwLock::new(BTreeMap::new()));
    let terminals: Terminals = Arc::new(AsyncRwLock::new(BTreeMap::new()));
    let sessions = Arc::new(Semaphore::new(config.max_peer_sessions));
    let handshakes = Arc::new(Semaphore::new(config.max_pending_handshakes));
    let ips = Arc::new(IpHandshakeLimiter::new(
        config.max_pending_handshakes_per_ip,
    ));
    let host_tasks = tokio_util::task::TaskTracker::new();
    let cancel = tokio_util::sync::CancellationToken::new();
    let sync_ok = Arc::new(AtomicU64::new(0));
    let traffic = Arc::new(TrafficCounters::default());
    let (stop, stop_rx) = watch::channel(false);
    for socket in stun_sockets {
        let stop_rx = stop.subscribe();
        host_tasks.spawn(async move {
            if let Err(error) = peerward_p2p::serve_stun(socket, stop_rx).await {
                tracing::warn!(%error, "Shared STUN listener stopped");
            }
        });
    }
    host_tasks.spawn(observe_host_capacity(
        config.clone(),
        client.clone(),
        Arc::clone(&registry),
        Arc::clone(&traffic),
        stop.subscribe(),
    ));
    let reconcile = tokio::spawn(reconcile_host(
        config.clone(),
        client,
        store.clone(),
        Arc::clone(&registry),
        Arc::clone(&terminals),
        Arc::clone(&sync_ok),
        Arc::clone(&traffic),
        stop_rx,
    ));
    loop {
        tokio::select! {
            accepted = peers.accept() => {
                if let Ok((socket, remote)) = accepted {
                    admit_socket(socket, remote.ip(), IncomingCarrier::Tcp(false), &registry, &terminals, &sessions, &handshakes, &ips, &host_tasks, &cancel);
                }
            }
            accepted = backbone.accept() => {
                if let Ok((socket, remote)) = accepted {
                    admit_socket(socket, remote.ip(), IncomingCarrier::Tcp(true), &registry, &terminals, &sessions, &handshakes, &ips, &host_tasks, &cancel);
                }
            }
            accepted = accept_wss(wss.as_ref()) => {
                if let Ok((socket, remote, carrier)) = accepted {
                    admit_socket(socket, remote.ip(), carrier, &registry, &terminals, &sessions, &handshakes, &ips, &host_tasks, &cancel);
                }
            }
            incoming = accept_quic(quic.as_ref()) => {
                if let Some(incoming) = incoming {
                    admit_quic(incoming, Arc::clone(quic.as_ref().expect("enabled listener")), &registry, &terminals, &sessions, &handshakes, &ips, &host_tasks, &cancel);
                }
            }
            incoming = accept_quic(quic_additional.as_ref()) => {
                if let Some(incoming) = incoming {
                    admit_quic(incoming, Arc::clone(quic_additional.as_ref().expect("enabled additional listener")), &registry, &terminals, &sessions, &handshakes, &ips, &host_tasks, &cancel);
                }
            }
            accepted = health.accept() => {
                if let Ok((socket, _)) = accepted {
                    let Ok(permit) = Arc::clone(&handshakes).try_acquire_owned() else { continue; };
                    let registry = Arc::clone(&registry);
                    let store = store.clone();
                    let sync_ok = Arc::clone(&sync_ok);
                    let traffic = Arc::clone(&traffic);
                    host_tasks.spawn(async move {
                        let _permit = permit;
                        let _ = tokio::time::timeout(Duration::from_secs(4), respond_host_health(socket, &registry, &store, &sync_ok, &traffic)).await;
                    });
                }
            }
            _ = shutdown.changed() => { if *shutdown.borrow() { break; } }
        }
    }
    let _ = stop.send(true);
    cancel.cancel();
    host_tasks.close();
    host_tasks.wait().await;
    let _ = reconcile.await;
    Ok(())
}

async fn reconcile_host(
    config: RelayHostConfig,
    client: reqwest::Client,
    store: Store,
    registry: Registry,
    terminals: Terminals,
    sync_ok: Arc<AtomicU64>,
    traffic: Arc<TrafficCounters>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut runtimes: BTreeMap<MeshId, (i64, MeshRuntime)> = BTreeMap::new();
    let mut removed = BTreeMap::new();
    let mut cursor: Option<uuid::Uuid> = None;
    let mut scan_revision = 0;
    let database = config.database_url.as_deref().unwrap_or_default();
    let mut dispatcher = store.dispatcher(database).await.ok();
    let mut interval = tokio::time::interval(Duration::from_secs(2));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let version_path = config.state_directory.join("configuration.version");
    let mut last_revision = match read_private(&version_path, 8) {
        Ok(bytes) => match <[u8; 8]>::try_from(bytes) {
            Ok(bytes) if i64::from_be_bytes(bytes) >= 0 => i64::from_be_bytes(bytes),
            _ => {
                tracing::error!("Invalid persisted Relay configuration revision");
                return;
            }
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
        Err(_) => {
            tracing::error!("Cannot read persisted Relay configuration revision");
            return;
        }
    };
    loop {
        tokio::select! {
            _ = shutdown.changed() => { if *shutdown.borrow() { break; } }
            _ = interval.tick() => {},
            () = async {
                match dispatcher.as_mut() {
                    Some(listener) => { if listener.next_cursor().await.is_err() { dispatcher = None; } },
                    None => std::future::pending::<()>().await,
                }
            } => {},
        }
        if dispatcher.is_none() {
            dispatcher = store.dispatcher(database).await.ok();
        }
        let endpoint = format!(
            "{}/internal/v1/relay-host/assignments",
            config.control_url.trim_end_matches('/')
        );
        let fetched = async {
            let mut request = client.get(&endpoint);
            if let Some(after) = cursor {
                request = request.query(&[
                    ("after", after.to_string()),
                    ("revision", scan_revision.to_string()),
                ]);
            }
            let response = request.send().await?.error_for_status()?;
            response.json::<RelayHostAssignments>().await
        }
        .await;
        match fetched {
            Ok(snapshot)
                if snapshot.host_id == config.host_id && snapshot.revision >= last_revision =>
            {
                if snapshot.revision != last_revision
                    && write_private_atomic(&version_path, &snapshot.revision.to_be_bytes())
                        .is_err()
                {
                    continue;
                }
                last_revision = snapshot.revision;
                scan_revision = snapshot.revision;
                cursor = snapshot.next_mesh;
                sync_ok.store(unix_time().0, Ordering::Relaxed);
                if cursor.is_some() {
                    interval.reset_immediately();
                }
                for assignment in snapshot.assignments {
                    if removed
                        .get(&assignment.mesh_id)
                        .is_some_and(|revision| *revision >= assignment.revision)
                    {
                        continue;
                    }
                    if assignment.desired == "removed"
                        && let Some(record) = &assignment.termination
                        && record.len() == 228
                    {
                        terminals
                            .write()
                            .await
                            .insert(assignment.mesh_id, (assignment.relay_id, record.clone()));
                    }
                    if let Err(error) = apply_assignment(
                        &config,
                        &client,
                        &store,
                        &registry,
                        &mut runtimes,
                        &assignment,
                        &traffic,
                        shutdown.clone(),
                    )
                    .await
                    {
                        tracing::warn!(mesh_id = %assignment.mesh_id, ?error, "Relay assignment deferred");
                        if matches!(
                            assignment.desired.as_str(),
                            "active" | "draining" | "suspended"
                        ) {
                            let _ =
                                acknowledge(&config, &client, &assignment, "failed", None).await;
                        }
                    } else if assignment.desired == "removed" {
                        removed.insert(assignment.mesh_id, assignment.revision);
                    }
                }
            }
            _ => {
                cursor = None;
                tracing::debug!("Relay configuration synchronization deferred");
            }
        }
        let mut pending = Vec::new();
        for (mesh, (_, runtime)) in &runtimes {
            pending.push(async move { (*mesh, refresh_runtime(runtime).await) });
        }
        let refreshed = stream::iter(pending)
            .buffer_unordered(8)
            .collect::<Vec<_>>()
            .await;
        for (mesh, result) in refreshed {
            if let Err(error) = result {
                tracing::warn!(%mesh, ?error, "Relay Mesh runtime stopped");
                registry.write().await.remove(&mesh);
                if let Some((_, runtime)) = runtimes.remove(&mesh) {
                    runtime.stop().await;
                }
            }
        }
    }
    registry.write().await.clear();
    for (_, (_, runtime)) in runtimes {
        runtime.stop().await;
    }
}

async fn refresh_runtime(runtime: &MeshRuntime) -> Result<(), RelayError> {
    let shared = &runtime.shared;
    if shared.cancel.is_cancelled() {
        return Err(RelayError::NoRoute);
    }
    if let Err(error) = catch_up_state(shared, runtime.directory_verifier).await {
        if !database_allows_existing_sessions(shared) {
            return Err(error);
        }
        return Ok(());
    }
    reconcile_backbones(shared).await;
    let health = shared
        .backbone_health
        .lock()
        .await
        .values()
        .cloned()
        .collect::<Vec<_>>();
    shared
        .store
        .renew_relay_runtime_with_health(
            shared.config.mesh_id,
            shared.config.relay_id,
            runtime.instance_id,
            runtime.runtime_generation,
            OffsetDateTime::now_utc() + time::Duration::seconds(30),
            &health,
        )
        .await?;
    Ok(())
}

async fn acknowledge(
    config: &RelayHostConfig,
    client: &reqwest::Client,
    assignment: &RelayHostAssignment,
    state: &str,
    active_sessions: Option<u64>,
) -> Result<(), RelayError> {
    client
        .post(format!(
            "{}/internal/v1/relay-host/ack",
            config.control_url.trim_end_matches('/')
        ))
        .json(&RelayHostAcknowledgement {
            mesh_id: assignment.mesh_id,
            relay_id: assignment.relay_id,
            revision: assignment.revision,
            state: state.into(),
            error_code: (state == "failed").then(|| "assignment_not_applied".into()),
            active_sessions,
        })
        .send()
        .await
        .map_err(|_| RelayError::NoRoute)?
        .error_for_status()
        .map_err(|_| RelayError::NoRoute)?;
    Ok(())
}

async fn apply_assignment(
    config: &RelayHostConfig,
    client: &reqwest::Client,
    store: &Store,
    registry: &Registry,
    runtimes: &mut BTreeMap<MeshId, (i64, MeshRuntime)>,
    assignment: &RelayHostAssignment,
    traffic: &Arc<TrafficCounters>,
    shutdown: watch::Receiver<bool>,
) -> Result<(), RelayError> {
    let directory = config.state_directory.join(assignment.mesh_id.to_string());
    private_dir(&directory)?;
    let key_file = directory.join("noise.key");
    let terminal_file = directory.join("terminated.bin");
    if assignment.desired == "suspended" {
        registry.write().await.remove(&assignment.mesh_id);
        if let Some((_, runtime)) = runtimes.remove(&assignment.mesh_id) {
            runtime.stop().await;
        }
        // Retain keys and trust. Suspension is a recoverable host operation,
        // never a signed Mesh termination and never a key deletion.
        acknowledge(config, client, assignment, "suspended", Some(0)).await?;
        return Ok(());
    }
    if assignment.desired == "removed" {
        let terminal = assignment
            .termination
            .as_ref()
            .ok_or(RelayError::InvalidConfig)?;
        let root_path = directory.join("root.pub");
        if root_path.exists() {
            let root: [u8; 32] = read_private(&root_path, 32)?
                .try_into()
                .map_err(|_| RelayError::InvalidConfig)?;
            peerward_credentials::MeshTermination::decode(terminal)?.verify(
                RootPublicKey::from_bytes(&root)?,
                assignment.mesh_id,
                0,
                unix_time(),
            )?;
        }
        write_private_atomic(&terminal_file, terminal)?;
        registry.write().await.remove(&assignment.mesh_id);
        if let Some((_, runtime)) = runtimes.remove(&assignment.mesh_id) {
            runtime
                .shared
                .termination
                .send_replace(Some(terminal.clone()));
            // Terminal flush is bounded; stalled sockets cannot prevent cleanup.
            let _ = tokio::time::timeout(Duration::from_secs(2), async {
                while runtime.shared.authenticated_peers.load(Ordering::Relaxed) != 0 {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await;
            runtime.stop().await;
        }
        remove_private(&key_file)?;
        acknowledge(config, client, assignment, "removed", Some(0)).await?;
        return Ok(());
    }
    if !matches!(assignment.desired.as_str(), "active" | "draining") || terminal_file.exists() {
        return Err(RelayError::NoRoute);
    }
    let draining = assignment.desired == "draining";
    if let Some((revision, runtime)) = runtimes.get_mut(&assignment.mesh_id)
        && *revision <= assignment.revision
        && draining
    {
        let admission = runtime.shared.admission_lock.lock().await;
        runtime
            .shared
            .accepting_peers
            .store(false, Ordering::Release);
        drop(admission);
        *revision = assignment.revision;
        return acknowledge(
            config,
            client,
            assignment,
            "draining",
            Some(runtime.shared.authenticated_peers.load(Ordering::Relaxed)),
        )
        .await;
    }
    if let Some((revision, runtime)) = runtimes.get(&assignment.mesh_id) {
        if *revision > assignment.revision {
            return Err(RelayError::NoRoute);
        }
        if *revision == assignment.revision {
            return acknowledge(
                config,
                client,
                assignment,
                "ready",
                Some(runtime.shared.authenticated_peers.load(Ordering::Relaxed)),
            )
            .await;
        }
    }
    if !runtimes.contains_key(&assignment.mesh_id) && runtimes.len() >= config.max_mesh_contexts {
        return Err(RelayError::NoRoute);
    }
    if !key_file.exists() {
        let key = StaticSecret::random_from_rng(OsRng);
        write_private_atomic(&key_file, &key.to_bytes())?;
    }
    let key = Zeroizing::new(
        <[u8; 32]>::try_from(read_private(&key_file, 32)?)
            .map_err(|_| RelayError::InvalidConfig)?,
    );
    let public = PublicKey::from(&StaticSecret::from(*key)).to_bytes();
    let Some(material) = &assignment.material else {
        client
            .post(format!(
                "{}/internal/v1/relay-host/public-key",
                config.control_url.trim_end_matches('/')
            ))
            .json(&RelayHostPublicKey {
                mesh_id: assignment.mesh_id,
                relay_id: assignment.relay_id,
                revision: assignment.revision,
                public_key: public.to_vec(),
            })
            .send()
            .await
            .map_err(|_| RelayError::NoRoute)?
            .error_for_status()
            .map_err(|_| RelayError::NoRoute)?;
        return Ok(());
    };
    let root: [u8; 32] = material
        .root_public_key
        .as_slice()
        .try_into()
        .map_err(|_| RelayError::InvalidConfig)?;
    let root_path = directory.join("root.pub");
    if root_path.exists() && read_private(&root_path, 32)? != root {
        return Err(RelayError::InvalidConfig);
    }
    let mut trust = TrustSet::new(RootPublicKey::from_bytes(&root)?, assignment.mesh_id);
    trust.add_authority(
        AuthorityCertificate::decode(&material.authority_certificate)?,
        unix_time(),
    )?;
    let credential = SubjectCredential::decode(&material.credential)?;
    trust.verify_subject(&credential, unix_time())?;
    if credential.subject != SubjectId::Relay(assignment.relay_id)
        || credential.public_noise_key != public
    {
        return Err(RelayError::InvalidConfig);
    }
    let distribution = DistributionCertificate::decode(&material.distribution_certificate)?;
    trust.verify_distribution(&distribution, unix_time())?;
    write_private_atomic(&root_path, &root)?;
    let mesh_config = RelayConfig {
        relay_transport: config.relay_transport.clone(),
        config_version: 1,
        relay_id: assignment.relay_id,
        mesh_id: assignment.mesh_id,
        peer_address: config.peer_address,
        backbone_address: config.backbone_address,
        health_address: None,
        database_url: config.database_url.clone(),
        private_key_file: key_file,
        credential_file: PathBuf::new(),
        root_public_key_file: root_path,
        authority_certificate_file: PathBuf::new(),
        distribution_certificate_file: PathBuf::new(),
        queue_capacity: default_queue_capacity(),
        lease_seconds: default_lease_seconds(),
        keepalive_seconds: default_keepalive_seconds(),
        max_peer_sessions: config.max_peer_sessions.min(1024),
        max_pending_handshakes: config.max_pending_handshakes.min(64),
        max_pending_handshakes_per_ip: config.max_pending_handshakes_per_ip,
        handshake_timeout_seconds: default_handshake_timeout_seconds(),
    };
    if let Some((_, previous)) = runtimes.remove(&assignment.mesh_id) {
        registry.write().await.remove(&assignment.mesh_id);
        previous.stop().await;
    }
    let runtime = initialize_mesh_runtime(
        mesh_config,
        *key,
        material.credential.clone(),
        distribution,
        Arc::new(CredentialGate::new(trust)),
        store.clone(),
        shutdown,
        RelayDatabasePolicy::production(),
        true,
        Arc::clone(traffic),
    )
    .await?;
    runtime
        .shared
        .accepting_peers
        .store(!draining, Ordering::Release);
    registry
        .write()
        .await
        .insert(assignment.mesh_id, Arc::clone(&runtime.shared));
    let active_sessions = runtime.shared.authenticated_peers.load(Ordering::Relaxed);
    runtimes.insert(assignment.mesh_id, (assignment.revision, runtime));
    acknowledge(
        config,
        client,
        assignment,
        if draining { "draining" } else { "ready" },
        Some(active_sessions),
    )
    .await
}
