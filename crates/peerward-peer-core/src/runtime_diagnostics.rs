use peerward_types::{DiagnosticCode, RuntimeDiagnostic};

use crate::{RuntimePhase, RuntimeView};

impl RuntimeView {
    /// Projects facts already observed by the shared state machine. A zero direct-path
    /// count alone is not a failure, and stopped runtimes ignore late transport errors.
    #[must_use]
    pub fn diagnostics(
        self,
        observed_at: u64,
        error: Option<DiagnosticCode>,
    ) -> Vec<RuntimeDiagnostic> {
        let mut codes = Vec::new();
        match self.phase {
            RuntimePhase::Stopped | RuntimePhase::Stopping => return Vec::new(),
            RuntimePhase::PermissionRequired => codes.push(DiagnosticCode::VpnPermissionRequired),
            RuntimePhase::Failed => codes.push(error.unwrap_or(DiagnosticCode::RuntimeFailed)),
            _ => {
                if let Some(code) = error {
                    codes.push(code);
                }
                if self.phase == RuntimePhase::Reconnecting && !self.underlay_available {
                    codes.push(DiagnosticCode::UnderlayUnavailable);
                }
                if self.phase == RuntimePhase::Reconnecting && !self.primary_relay_authenticated {
                    codes.push(DiagnosticCode::RelayUnavailable);
                }
                if self.primary_relay_authenticated && !self.signed_state_complete {
                    codes.push(DiagnosticCode::SignedStateIncomplete);
                }
            }
        }
        let mut observations = Vec::new();
        for code in codes {
            if !observations
                .iter()
                .any(|item: &RuntimeDiagnostic| item.code == code)
            {
                observations.push(RuntimeDiagnostic::new(code, Some(observed_at)));
            }
        }
        observations
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RuntimeEvent, RuntimeOrchestrator};

    #[test]
    fn lifecycle_diagnostics_distinguish_permission_reconnection_and_incomplete_state() {
        let mut runtime = RuntimeOrchestrator::default();
        assert!(
            runtime
                .view()
                .diagnostics(1, Some(DiagnosticCode::RelayUnavailable))
                .is_empty()
        );
        let view = runtime.transition(RuntimeEvent::PermissionRequired);
        assert_eq!(
            view.diagnostics(2, None),
            vec![RuntimeDiagnostic::new(
                DiagnosticCode::VpnPermissionRequired,
                Some(2)
            )]
        );
        runtime.transition(RuntimeEvent::StartRequested);
        runtime.transition(RuntimeEvent::TunOpened);
        let event = RuntimeEvent::TransportObserved {
            primary_relay_authenticated: true,
            standby_relay_count: 0,
            direct_path_count: 0,
            signed_state_complete: false,
            signed_state_revision: 0,
        };
        assert_eq!(
            runtime.transition(event).diagnostics(3, None)[0].code,
            DiagnosticCode::SignedStateIncomplete
        );
        let lost = runtime
            .transition(RuntimeEvent::UnderlayLost)
            .diagnostics(4, Some(DiagnosticCode::UnderlayUnavailable));
        assert_eq!(lost.len(), 2);
        assert_eq!(lost[1].code, DiagnosticCode::RelayUnavailable);
        let failed = runtime
            .transition(RuntimeEvent::Failed)
            .diagnostics(5, Some(DiagnosticCode::AuthenticationFailed));
        assert_eq!(failed[0].code, DiagnosticCode::AuthenticationFailed);
        assert_eq!(failed[0].observed_at, Some(5));
    }
}
