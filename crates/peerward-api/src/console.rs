//! Bounded read models for the task-oriented operations console.
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsoleOverview {
    pub observed_at: u64,
    pub devices: u64,
    pub online_devices: u64,
    pub services: u64,
    pub networks: u64,
    pub exits: u64,
    pub credential_warnings: u64,
    pub pending_applications: u64,
    pub issues: Vec<ConsoleIssue>,
    pub issue_count: u64,
    #[serde(default)]
    pub open_issue_count: u64,
    #[serde(default)]
    pub unread_notice_count: u64,
}

/// Counts cover the complete scope, independently of the cursor and page size.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsoleIssuePage {
    /// Server-side completion marker for this evaluation pass.
    pub checked_at: String,
    pub items: Vec<ConsoleIssue>,
    pub next_cursor: Option<String>,
    pub total: u64,
    pub all_count: u64,
    pub open_count: u64,
    pub unread_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsoleIssue {
    pub id: String,
    pub fingerprint: String,
    pub mesh_id: Uuid,
    pub kind: String,
    pub severity: String,
    pub name: String,
    pub resource_id: Uuid,
    pub href: String,
    pub observed_at: Option<String>,
    pub known: bool,
    pub read: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsoleNoticeUpdate {
    pub id: String,
    pub fingerprint: String,
    pub known: Option<bool>,
    pub read: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsoleSearchItem {
    pub id: Uuid,
    pub mesh_id: Uuid,
    pub mesh_name: String,
    pub kind: String,
    pub name: String,
    pub href: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsoleEvidence {
    /// ready, blocked, unknown, pending, or paused. Never inferred from another layer.
    pub state: String,
    pub reason: String,
    pub observed_at: Option<String>,
    #[serde(default)]
    pub diagnostic: Option<peerward_types::RuntimeDiagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsoleSharingResource {
    pub id: Uuid,
    pub version: u64,
    pub kind: String,
    pub name: String,
    pub provider: String,
    pub target: String,
    pub configuration: ConsoleEvidence,
    pub authorization: ConsoleEvidence,
    pub path: ConsoleEvidence,
    pub reachability: ConsoleEvidence,
    pub service: Option<crate::ServiceResource>,
    pub network: Option<peerward_management::NetworkResource>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsoleDevicePage {
    pub items: Vec<crate::PeerResource>,
    pub next_cursor: Option<String>,
    pub total: u64,
    /// Mesh-scoped, observed facts for the device list. Missing facts stay unknown.
    #[serde(default)]
    pub summaries: std::collections::BTreeMap<String, ConsoleDeviceSummary>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsoleDeviceSummary {
    /// Latest retained relay presence observation; never inferred from edits or leases.
    pub last_connected_at: Option<String>,
    pub provided_services: u64,
    pub forwarded_resources: u64,
    /// Timestamp of the fresh, signed runtime report; absence is not healthy evidence.
    #[serde(default)]
    pub runtime_observed_at: Option<u64>,
    #[serde(default)]
    pub diagnostics: Vec<peerward_types::RuntimeDiagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsoleServiceEdit {
    pub display_name: String,
    pub alias: Option<String>,
    pub protocols: Vec<peerward_types::ServiceProtocol>,
    pub listen_port: u16,
    pub paused: bool,
    #[serde(default)]
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsoleResourceState {
    pub paused: bool,
    #[serde(default)]
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsoleNetworkEdit {
    pub request_id: Uuid,
    pub resource_version: u64,
    pub definition: peerward_management::ResourceDefinition,
    pub reason: String,
    #[serde(default)]
    pub gateways: Vec<ConsoleGatewayChange>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsoleGateway {
    pub binding: peerward_management::GatewayBinding,
    pub peer_name: String,
    pub online: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsoleGatewayChange {
    pub id: Uuid,
    pub version: u64,
    pub priority: u32,
    pub approved: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsoleNetworkEditApply {
    pub draft: ConsoleNetworkEdit,
    pub preview_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsoleNetworkEditPreview {
    pub version: u64,
    pub digest: String,
    pub resource_id: Uuid,
    pub previous_target: peerward_management::ResourceTarget,
    pub target_changed: bool,
    pub gateways_requiring_approval: u64,
    pub gateways_changed: u64,
    pub overlapping_resources: Vec<String>,
    pub applied: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ConsoleGrantSource {
    None,
    Peer { id: peerward_types::PeerId },
    Collection { id: Uuid },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ConsoleSharingTarget {
    Service {
        protocols: Vec<peerward_types::ServiceProtocol>,
        port: u16,
        alias: Option<String>,
    },
    Network {
        definition: peerward_management::ResourceDefinition,
        dns_name: Option<String>,
        dns_address: Option<std::net::IpAddr>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsoleSharingDraft {
    pub request_id: Uuid,
    pub name: String,
    pub provider: peerward_types::PeerId,
    pub target: ConsoleSharingTarget,
    pub source: ConsoleGrantSource,
    /// Network grant predicate. 0 permits all protocols; ports only apply to TCP/UDP.
    pub protocol: u8,
    pub port: Option<u16>,
    #[serde(default)]
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsoleSharingPreview {
    pub version: u64,
    pub digest: String,
    pub resource_id: Uuid,
    pub affected_sources: u64,
    pub overlapping_resources: Vec<String>,
    pub warnings: Vec<String>,
    pub applied: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsoleSharingApply {
    pub draft: ConsoleSharingDraft,
    pub preview_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsoleSharingImpact {
    pub version: u64,
    pub resource_name: String,
    pub overlapping_resources: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ConsoleMatrixTarget {
    Service {
        id: Uuid,
        #[serde(default)]
        address: Option<std::net::IpAddr>,
        #[serde(default)]
        protocol: Option<u8>,
    },
    Network {
        id: Uuid,
        address: Option<std::net::IpAddr>,
        provider: Option<peerward_types::PeerId>,
        protocol: Option<u8>,
        port: Option<u16>,
    },
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsoleMatrixQuery {
    pub source: ConsoleGrantSource,
    pub targets: Vec<ConsoleMatrixTarget>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsoleMatrixCell {
    pub id: Uuid,
    /// allowed, denied, partial, conditions, unknown. Applies only to stated predicates.
    pub outcome: String,
    pub sources: u64,
    pub allowed_sources: u64,
    pub unknown_sources: u64,
    pub matched_rules: Vec<Uuid>,
    pub reasons: Vec<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsoleMatrix {
    pub observed_at: u64,
    pub cells: Vec<ConsoleMatrixCell>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsoleGrantDraft {
    pub request_id: Uuid,
    pub resource_id: Uuid,
    pub service: bool,
    pub source: ConsoleGrantSource,
    pub protocol: u8,
    pub port: Option<u16>,
    pub reason: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsoleGrantApply {
    pub draft: ConsoleGrantDraft,
    pub preview_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsoleRenewalRequest {
    pub request_id: Uuid,
    pub current_serial: peerward_types::CredentialSerial,
    pub valid_for_seconds: u32,
    pub reason: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsoleRenewal {
    pub id: Uuid,
    pub peer_id: peerward_types::PeerId,
    pub current_serial: peerward_types::CredentialSerial,
    pub state: String,
    pub created_at: String,
    pub expires_at: String,
    pub delivered_at: Option<String>,
    pub completed_at: Option<String>,
    pub completed_serial: Option<peerward_types::CredentialSerial>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsoleServiceGrant {
    pub id: Uuid,
    pub version: u64,
    pub enabled: bool,
    pub source: peerward_management::DeviceSelector,
    pub source_collections: Vec<Uuid>,
    pub source_names: Vec<String>,
    #[serde(default)]
    pub protocol: u8,
    #[serde(default)]
    pub destination_ports: Vec<(u16, u16)>,
    #[serde(default)]
    pub advanced: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsoleServiceGrantState {
    pub enabled: bool,
    pub reason: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsoleDeviceRetire {
    pub name: String,
    pub reason: String,
}
/// Current, explicitly group-targeted grants, not a connectivity prediction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsoleEnrollmentGroup {
    pub id: Uuid,
    pub name: String,
    pub grants: Vec<ConsoleEnrollmentGrant>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsoleEnrollmentGrant {
    pub name: String,
    pub protocol: u8,
    pub destination_ports: Vec<(u16, u16)>,
    pub conditional: bool,
}
