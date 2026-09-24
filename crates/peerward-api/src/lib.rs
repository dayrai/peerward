//! Shared, versioned `/api/v1` transport contracts.

mod console;
pub use console::*;

mod mesh_provisioning;
mod relay_hosts;
pub use relay_hosts::*;
mod maintenance_tasks;
pub use maintenance_tasks::*;
mod configuration_management;
mod network_management;
pub use configuration_management::*;
mod resources;
pub use network_management::*;
mod topology_bulk;

pub use mesh_provisioning::*;
pub use resources::*;
pub use topology_bulk::*;

use std::collections::BTreeMap;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use peerward_types::{
    MAX_LABELS, MAX_POLICY_RULES, MAX_PORT_SPANS, MAX_SELECTOR_CIDRS, MAX_SELECTOR_PEERS, MeshId,
    NetworkEndpoint, PeerId, RelayId,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

/// Maximum JSON request body accepted by Control.
pub const MAX_REQUEST_BYTES: usize = 2 * 1024 * 1024;
/// Maximum serialized SSE event block.
pub const MAX_SSE_EVENT_BYTES: usize = peerward_types::MAX_SSE_EVENT_BYTES;

/// Versioned stable keyset cursor ordered by a database timestamp and UUID tie-breaker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageCursor {
    /// Timestamp rounded down to microseconds, matching `PostgreSQL` precision.
    pub timestamp: OffsetDateTime,
    /// Unique ordering tie-breaker.
    pub id: Uuid,
}

/// Encodes a keyset cursor as unpadded `Base64URL`.
pub fn encode_page_cursor(cursor: PageCursor) -> String {
    let micros = cursor.timestamp.unix_timestamp_nanos().div_euclid(1_000);
    let micros = i64::try_from(micros).expect("supported timestamps fit cursor precision");
    let mut bytes = [0_u8; 25];
    bytes[0] = 1;
    bytes[1..9].copy_from_slice(&micros.to_be_bytes());
    bytes[9..].copy_from_slice(cursor.id.as_bytes());
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Strictly decodes the current keyset cursor version.
pub fn decode_page_cursor(encoded: &str) -> Option<PageCursor> {
    if encoded.len() != 34 {
        return None;
    }
    let bytes = URL_SAFE_NO_PAD.decode(encoded).ok()?;
    let bytes: [u8; 25] = bytes.try_into().ok()?;
    if bytes[0] != 1 || bytes[15] >> 4 != 4 || bytes[17] & 0xc0 != 0x80 {
        return None;
    }
    let micros = i64::from_be_bytes(bytes[1..9].try_into().ok()?);
    let timestamp = OffsetDateTime::from_unix_timestamp_nanos(i128::from(micros) * 1_000).ok()?;
    Some(PageCursor {
        timestamp,
        id: Uuid::from_bytes(bytes[9..].try_into().ok()?),
    })
}
/// Validates the shared bounded label shape used by Peers, Services, and policies.
pub fn valid_labels(labels: &BTreeMap<String, String>) -> bool {
    labels.len() <= MAX_LABELS
        && labels.iter().all(|(key, value)| {
            !key.is_empty() && key.len() <= 64 && !value.is_empty() && value.len() <= 256
        })
}

impl PolicyPutRequest {
    /// Enforces collection bounds before policy compilation or persistence.
    pub fn within_limits(&self) -> bool {
        self.rules.len() <= MAX_POLICY_RULES
            && self.rules.iter().all(|rule| {
                rule.destination_ports.len() <= MAX_PORT_SPANS
                    && [(&rule.source), (&rule.destination)]
                        .into_iter()
                        .all(|selector| {
                            selector.peer_ids.len() <= MAX_SELECTOR_PEERS
                                && selector.cidrs.len() <= MAX_SELECTOR_CIDRS
                                && valid_labels(&selector.labels)
                        })
            })
    }
}

/// Stable cursor-paginated success envelope.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Page<T> {
    /// Current page items.
    pub items: Vec<T>,
    /// Opaque cursor for the next page.
    pub next_cursor: Option<String>,
}

/// Stable machine-readable error body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiErrorBody {
    /// Stable machine code.
    pub code: String,
    /// Safe human description.
    pub message: String,
    /// Request correlation UUID.
    pub request_id: String,
    /// Per-field validation failures keyed by request field name.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub field_errors: BTreeMap<String, String>,
    /// Whether retrying the same semantic operation can succeed later.
    #[serde(default)]
    pub retryable: bool,
}

/// Error response envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorEnvelope {
    /// Structured error details.
    pub error: ApiErrorBody,
}

/// Authenticated browser session projection.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthSession {
    /// Whether a server-side session is active.
    #[serde(default)]
    pub authenticated: bool,
    /// Stable audit actor associated with this session.
    #[serde(default)]
    pub actor: String,
    /// Effective auditor/viewer/operator/admin role.
    #[serde(default)]
    pub role: String,
    /// Stable capabilities used by the Console to render allowed routes and actions.
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// Separate CSRF value used only for mutations.
    #[serde(default)]
    pub csrf_token: Option<String>,
}

/// Stable table projection used by generic management screens.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceSummary {
    /// Typed UUID serialized by the Control API.
    pub id: String,
    /// Human-readable mutable name or alias.
    #[serde(default, alias = "alias")]
    pub name: String,
    /// Additional non-secret resource fields.
    #[serde(flatten)]
    pub details: BTreeMap<String, Value>,
}

/// New Peer request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerCreateRequest {
    /// DNS-safe network name.
    pub name: String,
    /// Optional human-readable device name.
    #[serde(default)]
    pub display_name: String,
    /// Optional administrator-provided location.
    #[serde(default)]
    pub location: String,
    /// Deterministic string labels used by policy selectors.
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
}

/// Confirmed soft deletion of an already disabled Peer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerDeleteRequest {
    /// Exact current resource name, entered to confirm deletion.
    pub name: String,
}

/// Mutable Peer fields.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerPatchRequest {
    /// Replacement DNS-safe network name.
    pub name: Option<String>,
    /// Human-readable device name; an empty string clears it.
    pub display_name: Option<String>,
    /// Administrator-provided location; an empty string clears it.
    pub location: Option<String>,
    /// Replacement label set.
    pub labels: Option<BTreeMap<String, String>>,
    /// Replacement administrative state.
    pub administrative_state: Option<AdministrativeState>,
}

/// New Relay request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayCreateRequest {
    /// Display name.
    pub name: String,
    /// One through sixteen peer-facing endpoints.
    pub peer_endpoints: Vec<NetworkEndpoint>,
    /// One through sixteen Relay-backbone endpoints.
    pub backbone_endpoints: Vec<NetworkEndpoint>,
    /// Scheduling region used by sparse-backbone construction.
    #[serde(default = "default_relay_region")]
    pub region: String,
    /// Relative routing preference in the inclusive range `1..=1000`.
    #[serde(default = "default_relay_routing_weight")]
    pub routing_weight: u16,
}

/// Mutable Relay fields.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayPatchRequest {
    /// Replacement display name.
    pub name: Option<String>,
    /// Replacement Peer endpoints.
    pub peer_endpoints: Option<Vec<NetworkEndpoint>>,
    /// Replacement backbone endpoints.
    pub backbone_endpoints: Option<Vec<NetworkEndpoint>>,
    /// Replacement scheduling region.
    pub region: Option<String>,
    /// Replacement relative routing preference.
    pub routing_weight: Option<u16>,
    /// Replacement administrative state.
    pub administrative_state: Option<AdministrativeState>,
}

fn default_relay_region() -> String {
    "default".to_owned()
}

const fn default_relay_routing_weight() -> u16 {
    100
}

/// Rotation request containing only locally generated public material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialRotationRequest {
    /// New X25519 Noise public key encoded as lowercase hexadecimal.
    pub public_key: String,
}

/// Bounded one-time Join Ticket creation request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoinTicketCreateRequest {
    /// Ticket lifetime in seconds.
    pub expires_in_seconds: u64,
    /// Controlled name, labels and one admission mode.
    #[serde(default)]
    pub settings: peerward_management::JoinSettings,
}

/// Secret-bearing Join Ticket response returned exactly once at creation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoinTicketCreateResponse {
    /// Initial monotonic resource version.
    pub version: u64,
    /// Ticket resource identifier.
    pub id: Uuid,
    /// Mesh trust boundary.
    pub mesh_id: MeshId,
    /// RFC 3339 expiry for display.
    pub expires_at: String,
    /// Unix expiry used in the mobile bundle.
    pub expires_at_unix: u64,
    /// Unpadded base64url secret returned only once.
    pub token: String,
    /// Device-reachable claim URL from Control's explicit public origin, when configured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_url: Option<String>,
    /// SHA-256 fingerprint of the pinned offline Root public key.
    pub root_fingerprint: String,
}

/// Join claim body. Private device material is never transported.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoinClaimRequest {
    /// Must equal two; old clients must rejoin using Wire 5 software.
    pub schema_version: u32,
    /// Client-generated `UUIDv4` used for exact idempotent replay.
    pub claim_id: Uuid,
    /// Device-generated Ed25519 identity verifier.
    pub identity_public_key: String,
    /// Device-generated X25519 session public key.
    pub session_public_key: String,
    /// Independent device-generated `WireGuard` data key.
    pub wireguard_public_key: String,
    /// Exact Peerward client version.
    pub client_version: String,
    /// The only Wire major supported by this clean-install client.
    pub supported_wire_major: u32,
    /// Client nonce proving this request was freshly constructed.
    pub nonce: String,
    /// Human-readable device name.
    pub device_name: String,
    /// Bounded device model label.
    pub device_model: String,
    /// Operating-system family.
    pub platform: String,
    /// Operating-system version.
    pub platform_version: String,
    /// Ed25519 signature over the canonical ticket-bound claim transcript.
    pub signature: String,
}

/// One-time enrollment response shared by CLI and Android enrollment adapters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoinResponse {
    /// Profile identifier, equal to the enrolled Peer identifier in v1.
    pub profile_id: PeerId,
    /// Mesh trust boundary.
    pub mesh_id: MeshId,
    /// Enrolled Peer identifier.
    pub peer_id: PeerId,
    /// Human-readable Mesh name.
    pub mesh_name: String,
    /// Assigned address with prefix.
    pub address: String,
    /// Exact assignment with host prefix in the other address family.
    pub secondary_address: Option<String>,
    /// Mesh route set.
    pub routes: Vec<String>,
    /// Mesh DNS resolver addresses.
    pub dns_servers: Vec<String>,
    /// Tunnel MTU.
    pub mtu: u16,
    /// Optional STUN endpoints.
    #[serde(default)]
    pub stun_servers: Vec<String>,
    /// Split-DNS suffix.
    pub dns_suffix: String,
    /// Authority-signed Peer credential.
    pub credential: String,
    /// Typed Relay identity and endpoint choices.
    pub relays: Vec<JoinRelayTarget>,
    /// Pinned offline Root public key.
    pub root_public_key: String,
    /// Current active and overlap Authority certificates.
    pub authority_certificates: Vec<String>,
    /// Monotonic Authority lifecycle revision.
    pub authority_revision: u64,
    /// Directory signing public key.
    pub distribution_public_key: String,
    /// Service snapshot signing public key.
    pub service_public_key: String,
    /// X25519 HPKE recipient public key for payload-free security audit batches.
    pub audit_public_key: String,
    /// Rooted distribution-key binding certificate.
    pub distribution_certificate: String,
}

/// One Relay choice returned in a Join profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoinRelayTarget {
    /// Stable Relay identity.
    pub relay_id: RelayId,
    /// Ordered peer-facing endpoints.
    pub endpoints: Vec<NetworkEndpoint>,
    /// X25519 Noise public key encoded as unpadded base64url.
    pub public_key: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_cursor_is_strict_versioned_base64url() {
        let cursor = PageCursor {
            timestamp: OffsetDateTime::from_unix_timestamp_nanos(1_725_000_000_123_456_000)
                .unwrap(),
            id: Uuid::parse_str("12345678-1234-4abc-8def-1234567890ab").unwrap(),
        };
        let encoded = encode_page_cursor(cursor);
        assert!(!encoded.contains('='));
        assert_eq!(decode_page_cursor(&encoded), Some(cursor));
        assert_eq!(decode_page_cursor("not-a-cursor"), None);
        assert_eq!(decode_page_cursor(&"A".repeat(1_000_000)), None);
        let mut bytes = URL_SAFE_NO_PAD.decode(encoded).unwrap();
        bytes[0] = 2;
        assert_eq!(decode_page_cursor(&URL_SAFE_NO_PAD.encode(bytes)), None);
    }
}

mod webhooks;
pub use webhooks::*;
mod deployment_tasks;
pub use deployment_tasks::*;
mod relay_capacity;
pub use relay_capacity::*;
