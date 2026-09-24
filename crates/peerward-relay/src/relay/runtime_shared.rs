struct RelayShared {
    traffic: Arc<TrafficCounters>,
    authenticated_peers: AtomicU64,
    routed: bool,
    accepting_peers: std::sync::atomic::AtomicBool,
    admission_lock: Mutex<()>,
    cancel: tokio_util::sync::CancellationToken,
    tasks: tokio_util::task::TaskTracker,
    termination: watch::Sender<Option<Vec<u8>>>,
    config: RelayConfig,
    store: Store,
    gate: Arc<CredentialGate>,
    router: Mutex<OpaqueRouter>,
    services: Mutex<RemoteServiceTable>,
    presence: Mutex<PresenceCache>,
    distributions: AsyncRwLock<RelayDistributions>,
    backbones: Mutex<BTreeMap<RelayId, mpsc::Sender<BackbonePayload>>>,
    backbone_health: Mutex<BTreeMap<RelayId, RelayNeighborHealth>>,
    local_private: Arc<zeroize::Zeroizing<[u8; 32]>>,
    local_credential: Arc<Vec<u8>>,
    last_database_success: AtomicU64,
    event_sequence: AtomicU64,
    database_policy: RelayDatabasePolicy,
    peer_sessions: Arc<Semaphore>,
    handshakes: Arc<Semaphore>,
    pending_routes: Semaphore,
    ip_handshakes: Arc<IpHandshakeLimiter>,
    audit_sender: mpsc::Sender<RelayAuditIngress>,
    audit_queued: Arc<AtomicU64>,
    audit_dropped: Arc<AtomicU64>,
    link_rekeys: AtomicU64,
    invalid_forwarded_frames: Arc<AtomicU64>,
    no_route: Arc<AtomicU64>,
    queue_full: Arc<AtomicU64>,
    backbone_ttl_drops: AtomicU64,
    backbone_loop_drops: AtomicU64,
    backbone_forwarded_hops: AtomicU64,
    topology_revision: AtomicU64,
}

struct RelayAuditIngress {
    source_peer: PeerId,
    envelope: Vec<u8>,
}

struct MeshRuntime {
    shared: Arc<RelayShared>,
    directory_verifier: DirectoryPublicKey,
    instance_id: uuid::Uuid,
    runtime_generation: i64,
    audit_task: tokio::task::JoinHandle<()>,
}

impl Drop for MeshRuntime {
    fn drop(&mut self) {
        self.shared.cancel.cancel();
        self.shared.tasks.close();
        self.audit_task.abort();
    }
}

impl MeshRuntime {
    async fn stop(&self) {
        self.shared.cancel.cancel();
        self.shared.tasks.close();
        self.shared.tasks.wait().await;
        let _ = self
            .shared
            .store
            .release_relay_runtime(
                self.shared.config.mesh_id,
                self.shared.config.relay_id,
                self.instance_id,
                self.runtime_generation,
            )
            .await;
    }
}

fn spawn_mesh_task<F>(shared: &Arc<RelayShared>, future: F) -> tokio::task::JoinHandle<()>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    let cancel = shared.cancel.clone();
    shared.tasks.spawn(async move {
        tokio::select! { biased; () = cancel.cancelled() => {}, () = future => {} }
    })
}
