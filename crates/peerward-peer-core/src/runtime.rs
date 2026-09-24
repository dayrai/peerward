use std::time::Duration;

/// Stable connection phases shared by Linux, Android, and the mobile UI contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RuntimePhase {
    Stopped = 0,
    PermissionRequired = 1,
    Starting = 2,
    Connecting = 3,
    Healthy = 4,
    Degraded = 5,
    Reconnecting = 6,
    Stopping = 7,
    Failed = 8,
}

/// Privacy-safe, platform-neutral runtime facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct RuntimeView {
    pub sequence: u64,
    pub phase: RuntimePhase,
    pub rust_runtime_running: bool,
    pub tun_open: bool,
    pub packet_pump_running: bool,
    pub underlay_available: bool,
    pub primary_relay_authenticated: bool,
    pub standby_relay_count: u16,
    pub direct_path_count: u32,
    pub signed_state_complete: bool,
    pub signed_state_revision: u64,
}

/// Events supplied by a narrow platform adapter. Policy lives in the state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeEvent {
    Reset,
    PermissionRequired,
    StartRequested,
    TunOpened,
    Connecting,
    TransportObserved {
        primary_relay_authenticated: bool,
        standby_relay_count: u16,
        direct_path_count: u32,
        signed_state_complete: bool,
        signed_state_revision: u64,
    },
    UnderlayLost,
    UnderlayRestored,
    TransportLost,
    StopRequested,
    Stopped,
    Failed,
}

/// Single owner for lifecycle truth used by every platform adapter.
#[derive(Debug)]
pub struct RuntimeOrchestrator {
    view: RuntimeView,
    was_authenticated: bool,
}

impl Default for RuntimeOrchestrator {
    fn default() -> Self {
        Self {
            view: RuntimeView {
                sequence: 0,
                phase: RuntimePhase::Stopped,
                rust_runtime_running: false,
                tun_open: false,
                packet_pump_running: false,
                underlay_available: false,
                primary_relay_authenticated: false,
                standby_relay_count: 0,
                direct_path_count: 0,
                signed_state_complete: false,
                signed_state_revision: 0,
            },
            was_authenticated: false,
        }
    }
}

impl RuntimeOrchestrator {
    /// Applies one observed platform/runtime event and returns the authoritative projection.
    pub fn transition(&mut self, event: RuntimeEvent) -> RuntimeView {
        self.view.sequence = self.view.sequence.saturating_add(1);
        // Platform callbacks can arrive after stop, permission revocation or failure.
        // Only an explicit start may reopen the lifecycle from these phases.
        if matches!(
            self.view.phase,
            RuntimePhase::Stopped
                | RuntimePhase::Stopping
                | RuntimePhase::PermissionRequired
                | RuntimePhase::Failed
        ) && matches!(
            event,
            RuntimeEvent::TunOpened
                | RuntimeEvent::Connecting
                | RuntimeEvent::TransportObserved { .. }
                | RuntimeEvent::UnderlayLost
                | RuntimeEvent::UnderlayRestored
                | RuntimeEvent::TransportLost
        ) {
            return self.view;
        }
        match event {
            RuntimeEvent::Reset | RuntimeEvent::Stopped => self.reset_runtime(),
            RuntimeEvent::PermissionRequired => {
                self.reset_runtime();
                self.view.phase = RuntimePhase::PermissionRequired;
            }
            RuntimeEvent::StartRequested => {
                self.reset_runtime();
                self.view.rust_runtime_running = true;
                self.view.phase = RuntimePhase::Starting;
            }
            RuntimeEvent::TunOpened => {
                self.view.rust_runtime_running = true;
                self.view.tun_open = true;
                self.view.packet_pump_running = true;
                self.view.underlay_available = true;
                self.view.phase = if self.was_authenticated {
                    RuntimePhase::Reconnecting
                } else {
                    RuntimePhase::Connecting
                };
            }
            RuntimeEvent::Connecting => {
                self.view.rust_runtime_running = true;
                self.view.phase = if self.was_authenticated {
                    RuntimePhase::Reconnecting
                } else {
                    RuntimePhase::Connecting
                };
            }
            RuntimeEvent::TransportObserved {
                primary_relay_authenticated,
                standby_relay_count,
                direct_path_count,
                signed_state_complete,
                signed_state_revision,
            } => {
                self.view.primary_relay_authenticated = primary_relay_authenticated;
                self.view.standby_relay_count = standby_relay_count;
                self.view.direct_path_count = direct_path_count;
                self.view.signed_state_complete = signed_state_complete;
                self.view.signed_state_revision = if signed_state_complete {
                    signed_state_revision
                } else {
                    0
                };
                self.was_authenticated |= primary_relay_authenticated;
                self.recompute_health();
            }
            RuntimeEvent::UnderlayLost => {
                self.clear_transport();
                // Network loss does not close the persistent TUN reader/packet pump.
                self.view.underlay_available = false;
                self.view.phase = RuntimePhase::Reconnecting;
            }
            RuntimeEvent::UnderlayRestored => {
                self.clear_transport();
                self.view.underlay_available = true;
                self.recompute_health();
            }
            RuntimeEvent::TransportLost => {
                self.clear_transport();
                self.view.phase = if self.view.tun_open {
                    RuntimePhase::Reconnecting
                } else {
                    RuntimePhase::Connecting
                };
            }
            RuntimeEvent::StopRequested => self.view.phase = RuntimePhase::Stopping,
            RuntimeEvent::Failed => {
                self.reset_runtime();
                self.view.phase = RuntimePhase::Failed;
            }
        }
        self.view
    }

    /// Current immutable projection.
    pub const fn view(&self) -> RuntimeView {
        self.view
    }

    /// Shared bounded exponential reconnect delay with deterministic identity jitter.
    pub fn reconnect_delay(attempt: u8, entropy: u64) -> Duration {
        let exponent = u32::from(attempt.min(6));
        let base = 250_u64.saturating_mul(1_u64 << exponent).min(10_000);
        Duration::from_millis(base + entropy % 251)
    }

    fn reset_runtime(&mut self) {
        let sequence = self.view.sequence;
        self.view = Self::default().view;
        self.view.sequence = sequence;
        self.was_authenticated = false;
    }

    fn clear_transport(&mut self) {
        self.view.primary_relay_authenticated = false;
        self.view.standby_relay_count = 0;
        self.view.direct_path_count = 0;
        self.view.signed_state_complete = false;
        self.view.signed_state_revision = 0;
    }

    fn recompute_health(&mut self) {
        self.view.phase = if !self.view.tun_open
            || !self.view.packet_pump_running
            || !self.view.underlay_available
        {
            if self.was_authenticated {
                RuntimePhase::Reconnecting
            } else {
                RuntimePhase::Connecting
            }
        } else if !self.view.primary_relay_authenticated {
            RuntimePhase::Reconnecting
        } else if self.view.signed_state_complete && self.view.signed_state_revision > 0 {
            RuntimePhase::Healthy
        } else {
            RuntimePhase::Degraded
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_fault_trace_never_reports_healthy_without_all_proofs() {
        let mut runtime = RuntimeOrchestrator::default();
        let phases = [
            RuntimeEvent::PermissionRequired,
            RuntimeEvent::StartRequested,
            RuntimeEvent::TunOpened,
            RuntimeEvent::TransportObserved {
                primary_relay_authenticated: true,
                standby_relay_count: 1,
                direct_path_count: 0,
                signed_state_complete: false,
                signed_state_revision: 0,
            },
            RuntimeEvent::TransportObserved {
                primary_relay_authenticated: true,
                standby_relay_count: 1,
                direct_path_count: 2,
                signed_state_complete: true,
                signed_state_revision: 7,
            },
            RuntimeEvent::UnderlayLost,
            RuntimeEvent::TunOpened,
            RuntimeEvent::TransportObserved {
                primary_relay_authenticated: true,
                standby_relay_count: 0,
                direct_path_count: 0,
                signed_state_complete: true,
                signed_state_revision: 8,
            },
            RuntimeEvent::StopRequested,
            RuntimeEvent::Stopped,
        ]
        .map(|event| runtime.transition(event).phase);
        assert_eq!(
            phases,
            [
                RuntimePhase::PermissionRequired,
                RuntimePhase::Starting,
                RuntimePhase::Connecting,
                RuntimePhase::Degraded,
                RuntimePhase::Healthy,
                RuntimePhase::Reconnecting,
                RuntimePhase::Reconnecting,
                RuntimePhase::Healthy,
                RuntimePhase::Stopping,
                RuntimePhase::Stopped,
            ]
        );
        assert_eq!(runtime.view().sequence, 10);
    }

    #[test]
    fn signed_revision_is_hidden_until_the_complete_set_is_verified() {
        let mut runtime = RuntimeOrchestrator::default();
        runtime.transition(RuntimeEvent::StartRequested);
        runtime.transition(RuntimeEvent::TunOpened);
        let view = runtime.transition(RuntimeEvent::TransportObserved {
            primary_relay_authenticated: true,
            standby_relay_count: 0,
            direct_path_count: 0,
            signed_state_complete: false,
            signed_state_revision: 99,
        });
        assert_eq!(view.phase, RuntimePhase::Degraded);
        assert_eq!(view.signed_state_revision, 0);
    }

    #[test]
    fn underlay_recovery_preserves_the_tunnel_and_requires_new_authenticated_state() {
        let mut runtime = RuntimeOrchestrator::default();
        runtime.transition(RuntimeEvent::StartRequested);
        runtime.transition(RuntimeEvent::TunOpened);
        let connected = RuntimeEvent::TransportObserved {
            primary_relay_authenticated: true,
            standby_relay_count: 0,
            direct_path_count: 0,
            signed_state_complete: true,
            signed_state_revision: 7,
        };
        runtime.transition(connected);
        let lost = runtime.transition(RuntimeEvent::UnderlayLost);
        assert!(lost.tun_open && lost.packet_pump_running && !lost.underlay_available);
        assert_eq!(
            runtime.transition(connected).phase,
            RuntimePhase::Reconnecting
        );
        let restored = runtime.transition(RuntimeEvent::UnderlayRestored);
        assert!(restored.tun_open && restored.packet_pump_running && restored.underlay_available);
        assert!(!restored.primary_relay_authenticated && !restored.signed_state_complete);
        assert_eq!(restored.phase, RuntimePhase::Reconnecting);
        assert_eq!(runtime.transition(connected).phase, RuntimePhase::Healthy);
    }

    #[test]
    fn reconnect_delay_is_bounded_and_stable() {
        assert!(
            RuntimeOrchestrator::reconnect_delay(3, 17)
                < RuntimeOrchestrator::reconnect_delay(4, 17)
        );
        assert_eq!(
            RuntimeOrchestrator::reconnect_delay(6, 17),
            RuntimeOrchestrator::reconnect_delay(40, 17)
        );
        assert!(RuntimeOrchestrator::reconnect_delay(40, u64::MAX).as_millis() <= 10_250);
    }

    #[test]
    fn delayed_platform_observations_cannot_reopen_a_stopped_or_revoked_runtime() {
        let connected = RuntimeEvent::TransportObserved {
            primary_relay_authenticated: true,
            standby_relay_count: 1,
            direct_path_count: 2,
            signed_state_complete: true,
            signed_state_revision: 8,
        };
        for terminal in [
            RuntimeEvent::Reset,
            RuntimeEvent::StopRequested,
            RuntimeEvent::Stopped,
            RuntimeEvent::PermissionRequired,
            RuntimeEvent::Failed,
        ] {
            let mut runtime = RuntimeOrchestrator::default();
            runtime.transition(RuntimeEvent::StartRequested);
            runtime.transition(RuntimeEvent::TunOpened);
            assert_eq!(runtime.transition(connected).phase, RuntimePhase::Healthy);
            let mut expected = runtime.transition(terminal);
            for delayed in [
                connected,
                RuntimeEvent::TunOpened,
                RuntimeEvent::Connecting,
                RuntimeEvent::UnderlayLost,
                RuntimeEvent::UnderlayRestored,
                RuntimeEvent::TransportLost,
            ] {
                expected.sequence += 1;
                assert_eq!(runtime.transition(delayed), expected);
            }
            runtime.transition(RuntimeEvent::StartRequested);
            runtime.transition(RuntimeEvent::TunOpened);
            assert_eq!(runtime.transition(connected).phase, RuntimePhase::Healthy);
        }
    }
}
