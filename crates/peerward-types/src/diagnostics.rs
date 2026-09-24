//! Stable, privacy-safe observations shared by local and remote diagnostics.
use serde::{Deserialize, Serialize};

/// An observed failure category, never inferred by parsing human error messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticCode {
    DeviceOffline,
    AuthenticationFailed,
    PolicyDenied,
    DnsDegraded,
    TargetUnreachable,
    RelayUnavailable,
    DirectPathUnavailable,
    SignedStateIncomplete,
    UnderlayUnavailable,
    PacketPumpUnavailable,
    CredentialRotation,
    VpnPermissionRequired,
    RuntimeFailed,
    /// No fresh observation is available; this is not evidence of healthy operation.
    ObservationUnavailable,
    /// A newer producer supplied a category this consumer does not understand.
    #[serde(other)]
    Unknown,
}

/// Action identifier for localized clients. It does not authorize an automatic mutation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetryHint {
    CheckNetwork,
    CheckIdentity,
    CheckPolicy,
    CheckDnsConfiguration,
    CheckTarget,
    CheckUdpOrUseRelay,
    WaitForSignedState,
    RestartPeer,
    WaitForCredentialRotation,
    GrantVpnPermission,
    RefreshObservation,
    ExportDiagnostics,
    #[serde(other)]
    Unknown,
}

/// One timestamped fact, without device identity, addresses, packet contents or secrets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeDiagnostic {
    pub code: DiagnosticCode,
    /// Unix seconds of the observation, not the time at which a UI renders it.
    /// None explicitly means the source has never supplied an observation.
    pub observed_at: Option<u64>,
    pub retry_hint: RetryHint,
}

impl RuntimeDiagnostic {
    #[must_use]
    pub const fn new(code: DiagnosticCode, observed_at: Option<u64>) -> Self {
        Self {
            code,
            observed_at,
            retry_hint: code.retry_hint(),
        }
    }
}

impl DiagnosticCode {
    #[must_use]
    pub const fn retry_hint(self) -> RetryHint {
        match self {
            Self::DeviceOffline | Self::RelayUnavailable | Self::UnderlayUnavailable => {
                RetryHint::CheckNetwork
            }
            Self::AuthenticationFailed => RetryHint::CheckIdentity,
            Self::PolicyDenied => RetryHint::CheckPolicy,
            Self::DnsDegraded => RetryHint::CheckDnsConfiguration,
            Self::TargetUnreachable => RetryHint::CheckTarget,
            Self::DirectPathUnavailable => RetryHint::CheckUdpOrUseRelay,
            Self::SignedStateIncomplete => RetryHint::WaitForSignedState,
            Self::PacketPumpUnavailable | Self::RuntimeFailed => RetryHint::RestartPeer,
            Self::CredentialRotation => RetryHint::WaitForCredentialRotation,
            Self::VpnPermissionRequired => RetryHint::GrantVpnPermission,
            Self::ObservationUnavailable => RetryHint::RefreshObservation,
            Self::Unknown => RetryHint::ExportDiagnostics,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observation_time_and_unknown_codes_survive_json_boundaries() {
        let value = RuntimeDiagnostic::new(DiagnosticCode::PolicyDenied, Some(123));
        let json = serde_json::to_value(value).unwrap();
        assert_eq!(
            json,
            serde_json::json!({"code":"policy_denied","observed_at":123,"retry_hint":"check_policy"})
        );
        assert_eq!(
            serde_json::from_value::<RuntimeDiagnostic>(json).unwrap(),
            value
        );
        let unknown: RuntimeDiagnostic = serde_json::from_value(serde_json::json!({
            "code":"future_reason","observed_at":null,"retry_hint":"future_action"
        }))
        .unwrap();
        assert_eq!(unknown.code, DiagnosticCode::Unknown);
        assert_eq!(unknown.observed_at, None);
        assert_eq!(unknown.retry_hint, RetryHint::Unknown);
    }
}
