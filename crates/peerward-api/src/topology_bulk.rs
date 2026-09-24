use std::collections::BTreeMap;

use peerward_types::{PeerId, RelayId};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::AdministrativeState;

/// Privacy-safe current Mesh topology. It intentionally has no Peer-to-Peer edge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TopologyResource {
    /// Peer nodes visible to the authenticated operator.
    pub peers: Vec<TopologyPeerNode>,
    /// Relay nodes visible to the authenticated operator.
    pub relays: Vec<TopologyRelayNode>,
    /// Current Peer-to-Relay presence only.
    pub presence: Vec<TopologyPresenceEdge>,
}

/// Peer node in the privacy-safe topology projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TopologyPeerNode {
    pub id: PeerId,
    pub name: String,
    pub online: bool,
    pub administrative_state: AdministrativeState,
    /// `healthy`, `warning_30d`, `warning_7d`, `expired`, or `missing`.
    pub credential_status: String,
    /// Current report only; absent after its 90-second TTL.
    pub runtime_health: Option<RuntimeHealthSummary>,
}

/// Privacy-safe current runtime aggregate with no remote identities or network metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeHealthSummary {
    pub direct_path_count: u32,
    /// Relay packet share in basis points (0..=10,000), avoiding floating-point ambiguity.
    pub relay_packet_share_bps: u16,
    pub degraded_reasons: Vec<String>,
    pub signed_revision: u64,
    pub observed_at: String,
}

/// Relay node in the privacy-safe topology projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TopologyRelayNode {
    pub id: RelayId,
    pub name: String,
    pub online: bool,
    pub administrative_state: AdministrativeState,
    pub presence_count: u64,
    /// Relay scheduling region.
    #[serde(default = "default_region")]
    pub region: String,
    /// Relative routing preference.
    #[serde(default = "default_routing_weight")]
    pub routing_weight: u16,
    /// `healthy`, `warning_30d`, `warning_7d`, `expired`, or `missing`.
    pub credential_status: String,
}

fn default_region() -> String {
    "default".into()
}

const fn default_routing_weight() -> u16 {
    100
}

/// Database-aggregated topology overview; no full Peer collection is loaded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TopologySummary {
    pub peer_count: u64,
    pub online_peer_count: u64,
    pub relay_count: u64,
    pub online_relay_count: u64,
    pub presence_count: u64,
    pub regions: Vec<TopologyRegionSummary>,
    pub backbone_revision: Option<u64>,
    pub backbone_mode: Option<String>,
    pub backbone_edge_count: u64,
}

/// One region aggregate used by the console topology graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TopologyRegionSummary {
    pub region: String,
    pub relay_count: u64,
    pub online_relay_count: u64,
    pub presence_count: u64,
}

/// A bounded node row for topology drill-down.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TopologyNodeItem {
    /// `peer` or `relay`.
    pub kind: String,
    pub id: Uuid,
    pub name: String,
    pub online: bool,
    pub administrative_state: AdministrativeState,
    pub credential_status: String,
    pub region: Option<String>,
    pub routing_weight: Option<u16>,
    pub presence_count: Option<u64>,
}

/// A bounded current topology edge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TopologyEdgeItem {
    /// `presence` or `backbone`.
    pub kind: String,
    pub source_id: Uuid,
    pub target_id: Uuid,
    /// Presence role; absent for backbone edges.
    pub role: Option<String>,
    /// Signed topology revision; absent for presence edges.
    pub revision: Option<u64>,
}

/// Current presence edge; no endpoint, IP, DNS, or direct-path identity is included.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TopologyPresenceEdge {
    pub peer_id: PeerId,
    pub relay_id: RelayId,
    pub role: String,
}

/// Resource family accepted by atomic bulk operations. Authorities are deliberately excluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BulkResourceFamily {
    Peer,
    Relay,
    JoinTicket,
    Service,
}

/// One resource and the exact version captured by a bulk preview.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BulkResourceItem {
    pub id: Uuid,
    pub version: u64,
}

/// Bounded, same-family bulk disable/cancel request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BulkRequest {
    pub family: BulkResourceFamily,
    pub items: Vec<BulkResourceItem>,
}

/// Per-item result produced without mutation by bulk preview.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BulkPreviewItem {
    pub id: Uuid,
    pub version: u64,
    pub current_state: String,
    pub ready: bool,
    pub error_code: Option<String>,
}

/// Preview proving all versions and states that a later commit must revalidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BulkPreviewResponse {
    pub family: BulkResourceFamily,
    pub valid: bool,
    pub items: Vec<BulkPreviewItem>,
}

/// Successful all-or-nothing bulk commit response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BulkCommitResponse {
    pub family: BulkResourceFamily,
    pub committed: usize,
    pub versions: BTreeMap<Uuid, u64>,
}
