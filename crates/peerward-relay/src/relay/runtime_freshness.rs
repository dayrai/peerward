/// Fixed production database outage policy. The public constructor exists so
/// integration tests can exercise all phases without waiting fifteen minutes.
#[doc(hidden)]
#[derive(Debug, Clone, Copy)]
pub struct RelayDatabasePolicy {
    new_session_seconds: u64,
    existing_session_seconds: u64,
}

impl RelayDatabasePolicy {
    const fn production() -> Self {
        Self {
            new_session_seconds: 60,
            existing_session_seconds: 15 * 60,
        }
    }

    /// Creates an accelerated policy for a fault-injection test.
    #[doc(hidden)]
    pub fn for_test(new_session_seconds: u64, existing_session_seconds: u64) -> Option<Self> {
        (new_session_seconds > 0 && existing_session_seconds > new_session_seconds).then_some(
            Self {
                new_session_seconds,
                existing_session_seconds,
            },
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DatabaseFreshness {
    Fresh,
    Cached,
    Expired,
}

fn database_freshness_at(
    policy: RelayDatabasePolicy,
    last_success: u64,
    now: u64,
) -> DatabaseFreshness {
    match now.saturating_sub(last_success) {
        stale if stale <= policy.new_session_seconds => DatabaseFreshness::Fresh,
        stale if stale <= policy.existing_session_seconds => DatabaseFreshness::Cached,
        _ => DatabaseFreshness::Expired,
    }
}

fn database_freshness(shared: &RelayShared) -> DatabaseFreshness {
    database_freshness_at(
        shared.database_policy,
        shared.last_database_success.load(Ordering::Relaxed),
        unix_time().0,
    )
}

fn database_stale_for(shared: &RelayShared) -> u64 {
    unix_time()
        .0
        .saturating_sub(shared.last_database_success.load(Ordering::Relaxed))
}

fn database_accepts_new_sessions(shared: &RelayShared) -> bool {
    database_freshness(shared) == DatabaseFreshness::Fresh
}

fn database_allows_existing_sessions(shared: &RelayShared) -> bool {
    database_freshness(shared) != DatabaseFreshness::Expired
}

fn watch_database_expiry(shared: &Arc<RelayShared>) {
    let state = Arc::clone(shared);
    spawn_mesh_task(shared, async move {
        let mut tick = tokio::time::interval(Duration::from_millis(250));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            if !database_allows_existing_sessions(&state) {
                state.cancel.cancel();
                return;
            }
        }
    });
}
