use std::{collections::BTreeMap, net::IpAddr};

use ipnet::IpNet;
use peerward_types::{
    CredentialSerial, MeshId, NetworkEndpoint, PeerId, PolicyProtocol, RelayId, ServiceId,
    ServiceProtocol, TicketId,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::ResourceSummary;

/// Administrative availability of a Peer or Relay.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AdministrativeState {
    /// New sessions and forwarding are allowed.
    Enabled,
    /// Credentials are revoked and the resource cannot be re-enabled through deletion.
    Disabled,
}

/// Credential or Authority lifecycle projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CredentialLifecycle {
    /// Issued but not yet authenticated.
    Staged,
    /// Current credential.
    Active,
    /// Previous credential accepted during a bounded transition.
    Overlap,
    /// Explicitly rejected serial.
    Revoked,
}

/// Mesh creation document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeshCreateRequest {
    /// Stable idempotency key for retries.
    #[serde(default)]
    pub request_id: Option<Uuid>,
    /// Mutable display name.
    pub name: String,
    /// Private mesh prefix.
    pub address_cidr: IpNet,
    /// Reserved in-mesh DNS gateway.
    pub gateway: IpAddr,
    /// Split-DNS suffix.
    pub dns_suffix: String,
    /// Distributed packet MTU.
    pub mtu: u16,
    /// Addresses excluded from allocation.
    #[serde(default)]
    pub reserved: Vec<IpAddr>,
    /// `allow` or `deny` for unmatched traffic.
    pub default_policy: String,
    /// Released-address quarantine.
    pub quarantine_seconds: u64,
    /// Maximum credential overlap.
    pub rotation_overlap_seconds: u64,
}

/// Confirmation for permanently deleting an empty Mesh.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeshDeleteRequest {
    /// Exact current display name, including case and whitespace.
    pub confirmation_name: String,
}

/// Mutable Mesh fields.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeshPatchRequest {
    /// Replacement display name.
    pub name: Option<String>,
    /// Replacement split-DNS suffix.
    pub dns_suffix: Option<String>,
    /// Offline authorization duration: 300, 900 or 3600 seconds.
    pub lease_seconds: Option<u32>,
}

/// Root-signed Authority staging document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityStageRequest {
    /// Unpadded base64url Root-signed Authority certificate.
    pub certificate: String,
    /// Authority relation replaced by this certificate.
    pub replaces: Option<Uuid>,
}

/// Complete Mesh response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeshResource {
    /// Offline authorization limit. Changing it requires trust management authority.
    #[serde(default = "default_lease_seconds")]
    pub lease_seconds: u32,
    #[serde(default = "active_mesh_lifecycle")]
    pub lifecycle: String,
    #[serde(default)]
    pub lifecycle_job: Option<Uuid>,
    /// Monotonic resource version used by `ETag` preconditions.
    pub version: u64,
    /// Stable Mesh identity.
    pub id: MeshId,
    /// Immutable human-readable identifier; absent on legacy networks.
    #[serde(default)]
    pub network_identifier: Option<String>,
    /// Mutable display name.
    pub name: String,
    /// Allocatable prefix.
    pub address_cidr: IpNet,
    /// Allocated pool in the opposite family.
    pub secondary_cidr: IpNet,
    /// Reserved secondary gateway.
    pub secondary_gateway: IpAddr,
    /// Mesh DNS gateway.
    pub gateway: IpAddr,
    /// Split-DNS suffix.
    pub dns_suffix: String,
    /// Distributed packet MTU.
    pub mtu: u16,
    /// Unmatched policy decision.
    pub default_policy: String,
    /// Current ordered policy revision.
    pub policy_revision: u64,
    /// Current Root-anchored Authority revision.
    pub authority_revision: u64,
    /// Current Peer directory revision.
    pub directory_revision: u64,
    /// Current Relay directory revision.
    pub relay_revision: u64,
    /// Current service snapshot revision.
    pub service_revision: u64,
    /// Current exact-revocation revision.
    pub revocation_revision: u64,
}

const fn default_lease_seconds() -> u32 {
    900
}

/// One live Relay attachment for a Peer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PresenceResource {
    /// Owning Relay.
    pub relay_id: RelayId,
    /// `primary` or `standby`.
    pub role: String,
    /// Monotonic attachment fence.
    pub generation: i64,
    /// RFC 3339 lease deadline.
    pub lease_deadline: String,
}

/// Credential fields embedded in a Peer or Relay projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialBrief {
    /// Exact revocation serial.
    pub serial: CredentialSerial,
    /// Credential expiry for active/staged credentials.
    #[serde(default)]
    pub not_after: Option<String>,
    /// Bounded acceptance deadline for overlap credentials.
    #[serde(default)]
    pub overlap_deadline: Option<String>,
}

/// Active, staged, and overlap credentials embedded in a resource response.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialProjection {
    /// Current credential, if issued.
    pub active: Option<CredentialBrief>,
    /// Staged replacement, if present.
    pub pending: Option<CredentialBrief>,
    /// Previous credentials inside their overlap windows.
    #[serde(default)]
    pub overlap: Vec<CredentialBrief>,
}

/// Complete Peer response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerResource {
    /// Monotonic resource version used by `ETag` preconditions.
    pub version: u64,
    /// Stable Peer identity.
    pub id: PeerId,
    /// Mutable DNS-safe network name.
    pub name: String,
    /// Human-readable device name; independent of the DNS name and policy labels.
    #[serde(default)]
    pub display_name: String,
    /// Administrator-provided location, not inferred geolocation.
    #[serde(default)]
    pub location: String,
    /// Currently allocated Mesh addresses, including when the device is offline.
    #[serde(default)]
    pub mesh_addresses: Vec<IpAddr>,
    /// Policy selector labels.
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    /// Irreversible administrative state.
    pub administrative_state: AdministrativeState,
    /// True only with enabled Peer/Relay and current runtime/presence leases.
    pub online: bool,
    /// Immutable admission mode chosen at enrollment, independent from credential rotation.
    #[serde(default)]
    pub admission: peerward_management::DeviceLifecycle,
    /// Automatic retirement timestamp; absent until expiration or healthy offline cleanup.
    #[serde(default)]
    pub admission_ended_at: Option<String>,
    /// Bounded automatic retirement reason.
    #[serde(default)]
    pub admission_end_reason: Option<String>,
    /// Current, fully live attachments.
    #[serde(default)]
    pub presence: Vec<PresenceResource>,
    /// Credential lifecycle summary.
    pub credentials: CredentialProjection,
}

/// Complete Relay response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayResource {
    /// Monotonic resource version used by `ETag` preconditions.
    pub version: u64,
    /// Stable Relay identity.
    pub id: RelayId,
    /// Mutable display name.
    pub name: String,
    /// Ordered peer-facing endpoints.
    pub peer_endpoints: Vec<NetworkEndpoint>,
    /// Ordered Relay-backbone endpoints.
    pub backbone_endpoints: Vec<NetworkEndpoint>,
    /// Scheduling region used by the sparse Relay backbone.
    pub region: String,
    /// Relative routing preference in the inclusive range `1..=1000`.
    pub routing_weight: u16,
    /// Irreversible administrative state.
    pub administrative_state: AdministrativeState,
    /// True only while the enabled Relay runtime lease is current.
    pub online: bool,
    /// Live Peer attachments on this Relay.
    pub presence_count: u64,
    /// Credential lifecycle summary.
    pub credentials: CredentialProjection,
}

/// Root-anchored Authority response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityResource {
    /// Monotonic resource version used by `ETag` preconditions.
    pub version: u64,
    /// Database relation identity.
    pub id: Uuid,
    /// Certificate serial.
    pub serial: CredentialSerial,
    /// Ed25519 public key as lowercase hexadecimal.
    pub public_key: String,
    /// RFC 3339 validity start.
    pub not_before: String,
    /// RFC 3339 validity end.
    pub not_after: String,
    /// Current lifecycle.
    pub lifecycle: CredentialLifecycle,
    /// Replaced Authority relation, if any.
    pub replacement_id: Option<Uuid>,
    /// Bounded overlap deadline.
    pub overlap_deadline: Option<String>,
}

/// Metadata-only Join Ticket response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoinTicketResource {
    /// Monotonic resource version used by `ETag` preconditions.
    pub version: u64,
    /// Stable ticket identity.
    pub id: TicketId,
    /// RFC 3339 expiry.
    pub expires_at: String,
    /// Whether the single claim committed.
    pub consumed: bool,
    /// Effective retained status: unused, pending, approved, rejected, cancelled or expired.
    pub status: String,
    /// Immutable administrator-issued settings.
    pub settings: peerward_management::JoinSettings,
    /// Committed Peer, when enrolled.
    pub claimed_peer_id: Option<PeerId>,
    /// Creation timestamp for invitation history.
    pub created_at: String,
}

/// Service creation document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceCreateRequest {
    /// Publishing Peer.
    pub peer_id: PeerId,
    /// Canonical nonempty transport set.
    pub protocols: Vec<ServiceProtocol>,
    /// Mesh-visible service port.
    pub listen_port: u16,
    /// Optional Mesh DNS alias.
    pub alias: Option<String>,
    /// Policy-visible service labels.
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
}

/// Inclusive destination port span in an ordered policy rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyPortSpan {
    /// First included port.
    pub first: u16,
    /// Last included port.
    pub last: u16,
}

/// Conjunctive policy selector with alternatives inside each dimension.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySelectorRequest {
    /// Exact Peer alternatives; empty means no Peer-ID restriction.
    #[serde(default)]
    pub peer_ids: Vec<PeerId>,
    /// Required label key/value pairs.
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    /// CIDR alternatives; empty means no address restriction.
    #[serde(default)]
    pub cidrs: Vec<IpNet>,
}

/// One ordered policy rule replacement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRuleRequest {
    /// Stable rule UUID.
    pub id: Uuid,
    /// Ascending evaluation priority.
    pub priority: u32,
    /// `allow` or `deny`.
    pub action: String,
    /// Whether this rule participates in evaluation.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Emit a bounded structured decision event when matched.
    #[serde(default)]
    pub log: bool,
    /// Initiator selector.
    #[serde(default)]
    pub source: PolicySelectorRequest,
    /// Destination selector.
    #[serde(default)]
    pub destination: PolicySelectorRequest,
    /// Any, TCP, UDP, or ICMP selector.
    pub protocol: PolicyProtocol,
    /// Optional bounded spans for TCP/UDP; empty means every port.
    #[serde(default)]
    pub destination_ports: Vec<PolicyPortSpan>,
}

const fn default_true() -> bool {
    true
}

/// Atomic policy replacement document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyPutRequest {
    /// Strictly increasing revision.
    pub revision: u64,
    /// `allow` or `deny` for unmatched initiations.
    pub default_action: String,
    /// Ordered policy rules.
    #[serde(default)]
    pub rules: Vec<PolicyRuleRequest>,
}

/// Side-effect-free policy editor validation result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyValidationResponse {
    /// Whether the document can be submitted as an authoritative replacement.
    pub valid: bool,
    /// Deterministically ordered equivalent document when validation succeeds.
    pub normalized: Option<PolicyPutRequest>,
    /// SHA-256 of the canonical compiled policy bytes when valid.
    pub canonical_sha256: Option<String>,
    /// Stable field paths mapped to safe validation messages.
    #[serde(default)]
    pub field_errors: BTreeMap<String, String>,
    /// Non-blocking operational cautions.
    #[serde(default)]
    pub warnings: Vec<String>,
}

/// One side-effect-free policy question against a real source Peer and target Service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySimulationRequest {
    pub source_peer_id: PeerId,
    pub target_service_id: ServiceId,
    pub protocol: ServiceProtocol,
    /// Operator/Admin-only unsaved document. Viewers may simulate only current policy.
    #[serde(default)]
    pub draft_policy: Option<PolicyPutRequest>,
}

/// Explainable result produced by the canonical `peerward-policy` evaluator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySimulationResponse {
    pub allowed: bool,
    pub action: String,
    pub matched_rule_id: Option<Uuid>,
    pub default_action_used: bool,
    pub policy_revision: u64,
    pub canonical_sha256: String,
    #[serde(default)]
    pub warnings: Vec<String>,
}

/// Complete service response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceResource {
    /// Monotonic resource version used by `ETag` preconditions.
    pub version: u64,
    /// Stable service identity.
    pub id: ServiceId,
    /// Publishing Peer.
    pub peer_id: PeerId,
    /// Canonical nonempty transport set.
    pub protocols: Vec<ServiceProtocol>,
    /// Published Mesh port.
    pub listen_port: u16,
    /// Optional Mesh DNS alias.
    pub alias: Option<String>,
    /// Policy-visible labels.
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    /// `enabled` or `disabled`.
    pub state: String,
}

/// One credential lifecycle row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialResource {
    /// Database relation identity.
    pub id: Uuid,
    /// Exact revocation serial.
    pub serial: CredentialSerial,
    /// Issuing Authority relation.
    pub authority_id: Uuid,
    /// X25519 public key as lowercase hexadecimal.
    pub public_key: String,
    /// RFC 3339 validity start.
    pub not_before: String,
    /// RFC 3339 validity end.
    pub not_after: String,
    /// Current lifecycle.
    pub lifecycle: CredentialLifecycle,
    /// Replaced credential relation, if any.
    pub replacement_id: Option<Uuid>,
    /// Bounded overlap deadline.
    pub overlap_deadline: Option<String>,
}

/// Metadata-only audit response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditResource {
    /// Time-ordered record identity.
    pub id: Uuid,
    /// Sanitized actor.
    pub actor: String,
    /// Stable action name.
    pub action: String,
    /// Target resource family.
    pub target_type: String,
    /// Target identity, when applicable.
    pub target_id: Option<Uuid>,
    /// RFC 3339 occurrence time.
    pub timestamp: String,
    /// `success`, `denied`, or `failure`.
    pub result: String,
    /// Sanitized non-secret metadata.
    #[serde(default)]
    pub metadata: Value,
}

fn summary<T: Serialize>(id: String, name: String, value: &T) -> ResourceSummary {
    let mut details = serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_object().cloned())
        .map_or_else(BTreeMap::new, |object| object.into_iter().collect());
    details.remove("id");
    details.remove("name");
    details.remove("alias");
    ResourceSummary { id, name, details }
}

macro_rules! named_summary {
    ($resource:ty) => {
        impl From<$resource> for ResourceSummary {
            fn from(value: $resource) -> Self {
                summary(value.id.to_string(), value.name.clone(), &value)
            }
        }
    };
}

named_summary!(MeshResource);
named_summary!(PeerResource);
named_summary!(RelayResource);

impl From<AuthorityResource> for ResourceSummary {
    fn from(value: AuthorityResource) -> Self {
        summary(value.id.to_string(), value.serial.to_string(), &value)
    }
}

impl From<JoinTicketResource> for ResourceSummary {
    fn from(value: JoinTicketResource) -> Self {
        summary(
            value.id.to_string(),
            value
                .settings
                .name
                .clone()
                .unwrap_or_else(|| "Join ticket".into()),
            &value,
        )
    }
}

impl From<ServiceResource> for ResourceSummary {
    fn from(value: ServiceResource) -> Self {
        let name = value
            .alias
            .clone()
            .unwrap_or_else(|| format!("service-{}", value.id));
        summary(value.id.to_string(), name, &value)
    }
}

impl From<CredentialResource> for ResourceSummary {
    fn from(value: CredentialResource) -> Self {
        summary(value.id.to_string(), value.serial.to_string(), &value)
    }
}

impl From<AuditResource> for ResourceSummary {
    fn from(value: AuditResource) -> Self {
        summary(value.id.to_string(), value.action.clone(), &value)
    }
}

fn active_mesh_lifecycle() -> String {
    "active".into()
}
