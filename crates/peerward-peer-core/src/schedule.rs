/// Runtime facts used only to detect privacy-safe health changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeHealthFingerprint {
    pub state_generation: u64,
    pub primary_relay_authenticated: bool,
    pub standby_relay_count: u16,
    pub direct_path_count: u32,
    pub signed_state_complete: bool,
    pub signed_state_revision: u64,
    pub degraded_reason_mask: u32,
}

/// One bounded scheduling decision for a platform adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeSchedule {
    pub observe_status: bool,
    pub send_keepalive: bool,
    pub report_health: bool,
    pub next_poll_millis: u64,
}

/// Platform-neutral owner for runtime observation, keepalive and health-report cadence.
#[derive(Debug, Default)]
pub struct RuntimeScheduler {
    polled_at_millis: Option<u64>,
    keepalive_at_millis: Option<u64>,
    health_at_millis: Option<u64>,
    health_fingerprint: Option<RuntimeHealthFingerprint>,
}

impl RuntimeScheduler {
    pub const OBSERVATION_INTERVAL_MILLIS: u64 = 1_000;
    pub const KEEPALIVE_INTERVAL_MILLIS: u64 = 10_000;
    pub const HEALTH_INTERVAL_MILLIS: u64 = 30_000;

    /// Selects due work from monotonic time. Backwards time fails closed by
    /// resetting deadlines without emitting overdue network actions.
    #[must_use]
    pub fn poll(&mut self, now_millis: u64, health: RuntimeHealthFingerprint) -> RuntimeSchedule {
        if self
            .polled_at_millis
            .is_some_and(|previous| now_millis < previous)
        {
            *self = Self::default();
        }
        self.polled_at_millis = Some(now_millis);

        let send_keepalive = self
            .keepalive_at_millis
            .is_some_and(|last| now_millis.saturating_sub(last) >= Self::KEEPALIVE_INTERVAL_MILLIS);
        if self.keepalive_at_millis.is_none() || send_keepalive {
            self.keepalive_at_millis = Some(now_millis);
        }

        let health_changed = self.health_fingerprint.is_none_or(|last| last != health);
        let health_expired = self
            .health_at_millis
            .is_some_and(|last| now_millis.saturating_sub(last) >= Self::HEALTH_INTERVAL_MILLIS);
        let report_health = health_changed || health_expired;
        if report_health {
            self.health_fingerprint = Some(health);
            self.health_at_millis = Some(now_millis);
        }

        RuntimeSchedule {
            observe_status: true,
            send_keepalive,
            report_health,
            next_poll_millis: Self::OBSERVATION_INTERVAL_MILLIS,
        }
    }

    /// Makes a failed health send due on the next poll without disturbing
    /// keepalive or observation deadlines.
    pub fn retry_health(&mut self) {
        self.health_at_millis = None;
        self.health_fingerprint = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn health(revision: u64) -> RuntimeHealthFingerprint {
        RuntimeHealthFingerprint {
            state_generation: 0,
            primary_relay_authenticated: true,
            standby_relay_count: 1,
            direct_path_count: 0,
            signed_state_complete: revision > 0,
            signed_state_revision: revision,
            degraded_reason_mask: u32::from(revision == 0),
        }
    }

    #[test]
    fn state_change_and_intervals_produce_exact_bounded_actions() {
        let mut scheduler = RuntimeScheduler::default();
        assert_eq!(
            scheduler.poll(100, health(0)),
            RuntimeSchedule {
                observe_status: true,
                send_keepalive: false,
                report_health: true,
                next_poll_millis: 1_000,
            }
        );
        assert!(!scheduler.poll(1_100, health(0)).report_health);
        assert!(scheduler.poll(2_100, health(7)).report_health);
        assert!(scheduler.poll(10_100, health(7)).send_keepalive);
        assert!(!scheduler.poll(20_099, health(7)).send_keepalive);
        assert!(scheduler.poll(20_100, health(7)).send_keepalive);
        assert!(scheduler.poll(32_100, health(7)).report_health);
        scheduler.retry_health();
        assert!(scheduler.poll(32_101, health(7)).report_health);
    }

    #[test]
    fn backwards_clock_resets_without_keepalive_burst() {
        let mut scheduler = RuntimeScheduler::default();
        let _ = scheduler.poll(20_000, health(3));
        let reset = scheduler.poll(1_000, health(3));
        assert!(!reset.send_keepalive);
        assert!(reset.report_health);
    }
}
