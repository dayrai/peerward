use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Fixed operations only. This contract never accepts commands, scripts or paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MaintenanceOperation {
    RelayDrain,
    RelayResume,
}
impl MaintenanceOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RelayDrain => "relay_drain",
            Self::RelayResume => "relay_resume",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MaintenancePlanRequest {
    pub operation: MaintenanceOperation,
    pub host_id: Uuid,
    pub replacement_host_id: Option<Uuid>,
    #[serde(default = "default_grace")]
    pub grace_seconds: u32,
}
const fn default_grace() -> u32 {
    60
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MaintenanceTaskCreateRequest {
    pub id: Uuid,
    pub plan: MaintenancePlanRequest,
    pub preview_digest: String,
}
