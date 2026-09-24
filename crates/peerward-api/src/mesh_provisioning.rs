use peerward_types::MeshId;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Idempotent request to initialize a Mesh on the bootstrap host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeshProvisioningCreateRequest {
    pub request_id: Uuid,
    pub name: String,
    /// Optional immutable, installation-unique, human-readable network identifier.
    #[serde(default)]
    pub network_identifier: Option<String>,
    #[serde(default)]
    pub existing_mesh_id: Option<MeshId>,
}

/// Durable initialization progress; private identity material is never exposed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeshProvisioningResource {
    pub id: Uuid,
    #[serde(default = "create_operation")]
    pub operation: String,
    pub mesh_id: MeshId,
    pub name: String,
    pub existing_mesh: bool,
    /// `queued`, `running`, `failed`, or `succeeded`.
    pub status: String,
    /// Last persisted initialization stage.
    pub stage: String,
    pub error_code: Option<String>,
    pub relay_endpoint: Option<String>,
    /// RFC3339 timestamp.
    pub created_at: String,
    /// RFC3339 timestamp.
    pub updated_at: String,
}

fn create_operation() -> String {
    "create".into()
}

/// Lowercase ASCII slug, 1–63 characters, with no leading/trailing hyphen.
pub fn valid_network_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && value.as_bytes()[0] != b'-'
        && !value.ends_with('-')
}
