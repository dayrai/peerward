use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::ManagementError;

/// Exactly one admission mechanism applies to an invitation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum JoinMode {
    #[default]
    Bearer,
    Prebound {
        identity_fingerprint: String,
    },
    Approval,
}

/// Administrator-controlled attributes, never accepted from device self-report.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoinSettings {
    #[serde(default)]
    pub name: Option<String>,
    /// Human-readable name, independent of the DNS name and policy selectors.
    #[serde(default)]
    pub display_name: String,
    /// Existing device collections to join atomically on successful enrollment.
    #[serde(default)]
    pub device_groups: BTreeSet<Uuid>,
    /// Selects enrollment instructions; never overrides the device's reported platform.
    #[serde(default)]
    pub platform_hint: Option<EnrollmentPlatform>,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    #[serde(default)]
    pub mode: JoinMode,
    #[serde(default)]
    pub lifecycle: DeviceLifecycle,
}

impl JoinSettings {
    pub fn validate(&self) -> Result<(), ManagementError> {
        self.lifecycle.validate()?;
        if self.device_groups.len() > 64
            || self
                .device_groups
                .iter()
                .any(|id| id.get_version_num() != 4)
        {
            return Err(ManagementError::Invalid("invitation.device_groups"));
        }
        if self.display_name.chars().count() > 128
            || self.display_name.chars().any(char::is_control)
            || self.display_name.trim() != self.display_name
        {
            return Err(ManagementError::Invalid("invitation.display_name"));
        }
        if self.name.as_ref().is_some_and(|name| {
            name.is_empty()
                || name.len() > 63
                || name.starts_with('-')
                || name.ends_with('-')
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        }) {
            return Err(ManagementError::Invalid("invitation.name"));
        }
        if self.labels.len() > 32
            || self.labels.iter().any(|(key, value)| {
                !crate::name_valid(key)
                    || key.len() > 64
                    || !crate::name_valid(value)
                    || matches!(
                        key.as_str(),
                        "device_model" | "platform" | "platform_version"
                    )
            })
        {
            return Err(ManagementError::Invalid("invitation.labels"));
        }
        if let JoinMode::Prebound {
            identity_fingerprint,
        } = &self.mode
            && !valid_identity_fingerprint(identity_fingerprint)
        {
            return Err(ManagementError::Invalid("invitation.identity_fingerprint"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnrollmentPlatform {
    Linux,
    Android,
}

/// Device access duration is independent from submission and approval deadlines.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DeviceLifecycle {
    #[default]
    LongLived,
    Ephemeral,
    Expiring {
        valid_until: u64,
    },
}
impl DeviceLifecycle {
    pub fn validate(self) -> Result<(), ManagementError> {
        if let Self::Expiring { valid_until } = self
            && !(1..=253_402_300_799).contains(&valid_until)
        {
            return Err(ManagementError::Invalid("lifecycle.valid_until"));
        }
        Ok(())
    }
    pub const fn deadline(self) -> Option<u64> {
        match self {
            Self::Expiring { valid_until } => Some(valid_until),
            _ => None,
        }
    }
    pub const fn kind(self) -> &'static str {
        match self {
            Self::LongLived => "long_lived",
            Self::Ephemeral => "ephemeral",
            Self::Expiring { .. } => "expiring",
        }
    }
}

pub fn valid_identity_fingerprint(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JoinApplicationStatus {
    Pending,
    Approved,
    Rejected,
    Cancelled,
    Expired,
}

/// Public admission status contains no network credential, address, or topology.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoinApplication {
    pub id: Uuid,
    pub mesh_id: peerward_types::MeshId,
    pub ticket_id: Uuid,
    pub version: u64,
    pub claim_id: Uuid,
    pub name: String,
    pub identity_fingerprint: String,
    pub status: JoinApplicationStatus,
    pub created_at: u64,
    pub expires_at: u64,
    pub peer_id: Option<peerward_types::PeerId>,
}

/// The caller must obtain this fingerprint through a trusted independent channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoinApprovalRequest {
    pub identity_fingerprint: String,
}

/// HTTP 202; resend the exact signed claim to retrieve the eventual response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingJoinResponse {
    pub application: JoinApplication,
    pub retry_after_seconds: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invitation_groups_reject_invalid_ids_and_excessive_selections() {
        for device_groups in [
            [Uuid::nil()].into(),
            (0..65).map(|_| Uuid::new_v4()).collect(),
        ] {
            let settings = JoinSettings {
                device_groups,
                ..Default::default()
            };
            assert_eq!(
                settings.validate(),
                Err(ManagementError::Invalid("invitation.device_groups"))
            );
        }
    }

    #[test]
    fn device_information_preserves_unicode_and_keeps_old_invitations_valid() {
        let old: JoinSettings = serde_json::from_str(r#"{"name":"home-laptop"}"#).unwrap();
        assert!(old.validate().is_ok());
        assert!(old.device_groups.is_empty());
        let mut settings = JoinSettings {
            display_name: "小明的笔记本 💻".into(),
            device_groups: [Uuid::new_v4(), Uuid::new_v4()].into(),
            platform_hint: Some(EnrollmentPlatform::Android),
            ..Default::default()
        };
        assert!(settings.validate().is_ok());
        assert!(settings.labels.is_empty());
        for invalid in [" hidden".to_owned(), "bad\nname".into(), "界".repeat(129)] {
            settings.display_name = invalid;
            assert_eq!(
                settings.validate(),
                Err(ManagementError::Invalid("invitation.display_name"))
            );
        }
        for invalid in [
            r#"{"purpose":"administrator"}"#,
            r#"{"platform_hint":"unknown"}"#,
        ] {
            assert!(serde_json::from_str::<JoinSettings>(invalid).is_err());
        }
    }
}
