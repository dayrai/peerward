//! Strict transport contracts for network resources and grants.
use peerward_management::{ForwardingMode, ResourceDefinition};
use peerward_types::PeerId;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The client-generated UUID is also the resource identity for exact creation retries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkResourceCreateRequest {
    pub id: Uuid,
    pub definition: ResourceDefinition,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayBindingCreateRequest {
    pub id: Uuid,
    pub resource_id: Uuid,
    pub peer_id: PeerId,
    pub priority: u32,
    #[serde(default)]
    pub forwarding: ForwardingMode,
    #[serde(default)]
    pub return_route_confirmed: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayPriorityRequest {
    pub priority: u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutoApprovalCreateRequest {
    pub id: Uuid,
    pub definition: peerward_management::AutoApprovalDefinition,
}
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutomaticGatewayRequest {}

/// Approval is one versioned administrative grant, never duplicated on advertisements.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayApprovalRequest {
    pub approved: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsProfileResponse {
    pub version: u64,
    pub profile: peerward_management::DnsProfile,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsPreviewRequest {
    pub peer_id: PeerId,
    #[serde(default)]
    pub draft_profiles: Option<Vec<peerward_management::DnsProfile>>,
}

/// Packet simulation keeps an addressable target separate from its tunnel provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PacketSimulationTarget {
    Peer {
        peer_id: PeerId,
    },
    Resource {
        resource_id: Uuid,
        address: std::net::IpAddr,
        provider_peer_id: PeerId,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketSimulationRequest {
    pub source_peer_id: PeerId,
    pub target: PacketSimulationTarget,
    pub protocol: u8,
    pub destination_port: Option<u16>,
    #[serde(default)]
    pub draft_policy: Option<crate::PolicyPutRequest>,
    #[serde(default)]
    pub draft_resource_rules: Option<Vec<peerward_management::ResourceRule>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PolicySimulationInput {
    Service(crate::PolicySimulationRequest),
    Packet(PacketSimulationRequest),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourcePolicyTest {
    pub id: Uuid,
    pub name: String,
    pub source_peer_id: PeerId,
    pub resource_id: Uuid,
    pub provider_peer_id: PeerId,
    pub address: std::net::IpAddr,
    pub protocol: u8,
    pub destination_port: Option<u16>,
    pub expected: peerward_management::ResourceAction,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourcePolicyDocument {
    pub rules: Vec<peerward_management::ResourceRule>,
    pub tests: Vec<ResourcePolicyTest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourcePolicyResponse {
    pub version: u64,
    pub document: ResourcePolicyDocument,
    /// Positive assertions never prevent a policy which provably only removes grants.
    pub failed_tests: Vec<Uuid>,
    pub tests_evaluated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectionCreateRequest {
    pub id: Uuid,
    pub definition: peerward_management::CollectionDefinition,
}

/// Mesh-scoped automation credential, returned once at creation; trust management is excluded.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineCredentialCreateRequest {
    pub id: Uuid,
    pub name: String,
    pub capabilities: Vec<String>,
    pub ttl_seconds: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineCredentialResource {
    pub id: Uuid,
    pub mesh_id: Uuid,
    pub name: String,
    pub version: u64,
    pub capabilities: Vec<String>,
    pub created_at: String,
    pub expires_at: String,
    pub revoked_at: Option<String>,
}
