const fn default_join_validity() -> u64 {
    86_400
}

fn default_http_address() -> SocketAddr {
    "127.0.0.1:8080".parse().expect("fixed socket address")
}

fn default_management_address() -> SocketAddr {
    "127.0.0.1:9090".parse().expect("fixed socket address")
}

const fn default_connections() -> u32 {
    16
}

#[derive(Clone)]
struct AppState {
    store: Store,
    public_url: Option<Url>,
    auth: AuthState,
    join_issuers: IssuerRegistry,
    metrics: Arc<ControlMetrics>,
    event_signal: watch::Receiver<u64>,
    sse_connections: Arc<Semaphore>,
}

#[derive(Default)]
struct ControlMetrics {
    protected_requests: AtomicU64,
    auth_rejections: AtomicU64,
    join_claims: AtomicU64,
    join_replays: AtomicU64,
    join_completions: AtomicU64,
    policy_validations: AtomicU64,
    policy_validation_failures: AtomicU64,
    publisher_last_success: AtomicU64,
    publisher_failures: AtomicU64,
    publisher_builds: AtomicU64,
    publisher_skips: AtomicU64,
    lifecycle_expirations: AtomicU64,
    audit_batches_processed: AtomicU64,
    audit_batches_replayed: AtomicU64,
    audit_batches_rejected: AtomicU64,
    maintenance_last_success: AtomicU64,
    maintenance_failures: AtomicU64,
    maintenance_deleted_rows: AtomicU64,
    maintenance_backlog_tables: AtomicU64,
    sse_capacity_rejections: AtomicU64,
    sse_cursor_resets: AtomicU64,
    audit_log_rows: AtomicU64,
    audit_log_bytes: AtomicU64,
    audit_log_growth_rows_per_hour: AtomicU64,
    audit_log_last_sample_seconds: AtomicU64,
    audit_storage_available: AtomicU64,
    audit_growth_available: AtomicU64,
    audit_capacity: tokio::sync::Mutex<AuditCapacityState>,
}

#[derive(Clone)]
struct AuthState {
    oidc: Option<OidcConfig>,
    development_digest: Option<[u8; 32]>,
    bootstrap_digest: Option<[u8; 32]>,
}
