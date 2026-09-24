use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigurationOwnershipRequest {
    /// None returns to interactive capability-checked management. A repository must
    /// be explicitly assigned its machine credential before declarative apply.
    pub owner_machine_id: Option<Uuid>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigurationOwnershipView {
    pub version: u64,
    pub owner_machine_id: Option<Uuid>,
    pub owner_name: Option<String>,
    pub owner_active: bool,
}

/// A complete declaration of network intent for an existing Mesh. This is not
/// a database backup: identities, secrets, live advertisements and leases are absent.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigurationDocument {
    pub schema_version: u32,
    pub wire_version: u32,
    pub mesh_id: Uuid,
    pub resources: Vec<crate::NetworkResourceCreateRequest>,
    pub bindings: Vec<ConfigurationBinding>,
    pub collections: Vec<crate::CollectionCreateRequest>,
    pub auto_approval_rules: Vec<crate::AutoApprovalCreateRequest>,
    #[serde(default)]
    pub device_conditions: peerward_management::DeviceConditions,
    pub dns_profiles: Vec<peerward_management::DnsProfile>,
    pub peer_policy: ConfigurationPeerPolicy,
    pub resource_policy: crate::ResourcePolicyDocument,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigurationPeerPolicy {
    pub default_action: String,
    pub rules: Vec<crate::PolicyRuleRequest>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigurationBinding {
    pub id: Uuid,
    pub resource_id: Uuid,
    pub peer_id: peerward_types::PeerId,
    pub priority: u32,
    pub forwarding: peerward_management::ForwardingMode,
    pub return_route_confirmed: bool,
    pub approval: ConfigurationApproval,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ConfigurationApproval {
    Manual { approved: bool },
    Automatic,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigurationSnapshot {
    pub version: u64,
    pub document: ConfigurationDocument,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigurationApplyRequest {
    pub request_id: Uuid,
    pub document: ConfigurationDocument,
    pub preview_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigurationChange {
    pub kind: String,
    pub id: Uuid,
    pub change: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigurationPreview {
    pub version: u64,
    pub document_digest: String,
    pub preview_digest: String,
    pub changes: Vec<ConfigurationChange>,
    pub failed_tests: Vec<Uuid>,
    pub only_removes_grants: bool,
    pub can_apply: bool,
    /// Database commit only. Client application requires a separate receipt.
    pub applied: bool,
}
