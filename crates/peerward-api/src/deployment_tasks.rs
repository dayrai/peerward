use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentRunnerCreate {
    pub id: Uuid,
    pub name: String,
    pub profile_digest: String,
    pub ttl_seconds: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentPreview {
    pub digest: String,
    pub services_to_pause: Vec<String>,
    pub online_files: u32,
    pub meshes: u32,
    pub relay_hosts: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upgrade: Option<NativeUpgradePreview>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentTaskCreate {
    pub id: Uuid,
    pub runner_id: Uuid,
    pub preview_digest: String,
    #[serde(default, skip_serializing_if = "DeploymentOperation::is_backup")]
    pub operation: DeploymentOperation,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentTaskStatus {
    Running,
    Succeeded,
    Failed,
    RecoveryRequired,
}
impl DeploymentTaskStatus {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::RecoveryRequired => "recovery_required",
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentArtifact {
    pub sha256: String,
    pub bytes: u64,
    pub files: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentTaskReport {
    pub task_id: Uuid,
    pub local_version: u64,
    pub status: DeploymentTaskStatus,
    pub stage: String,
    pub error_code: Option<String>,
    pub artifact: Option<DeploymentArtifact>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upgrade: Option<NativeUpgradeResult>,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentOperation {
    #[default]
    InstallationBackup,
    NativeUpgrade,
}
impl DeploymentOperation {
    pub const fn is_backup(&self) -> bool {
        matches!(self, Self::InstallationBackup)
    }
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InstallationBackup => "installation_backup",
            Self::NativeUpgrade => "native_upgrade",
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NativeUpgradeRole {
    Control,
    Relay,
    Peer,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeUpgradePreview {
    pub role: NativeUpgradeRole,
    pub current_version: String,
    pub version: String,
    pub manifest_sha256: String,
    pub artifact_sha256: String,
    pub artifact_bytes: u64,
    pub rollback_floor: String,
    pub repair: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NativeUpgradeState {
    Succeeded,
    RolledBack,
    RecoveryRequired,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeUpgradeResult {
    pub role: NativeUpgradeRole,
    pub version: String,
    pub manifest_sha256: String,
    pub current_sha256: String,
    pub state: NativeUpgradeState,
    pub runtime_checked: bool,
}

/// Narrow runner credential can call only its own exchange endpoint.
/// No commands, paths, credentials or database contents cross this interface.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentExchange {
    pub sequence: u64,
    pub profile_digest: String,
    pub preview: Option<DeploymentPreview>,
    pub reports: Vec<DeploymentTaskReport>,
}
