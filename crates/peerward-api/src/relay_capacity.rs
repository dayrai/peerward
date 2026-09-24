use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Short-lived server challenge. A replay cannot refresh observation age.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayObservationChallenge {
    pub nonce: Uuid,
}

/// Aggregated host-process observations, with no Peer/IP/Mesh labels.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayCapacityReport {
    pub nonce: Uuid,
    pub process_id: Uuid,
    pub uptime_millis: u64,
    pub received_bytes: u64,
    pub accepted_bytes: u64,
    pub authenticated_peer_sessions: u64,
    pub authenticated_backbone_sessions: u64,
    pub session_limit: u64,
    pub mesh_contexts: u64,
    pub router_queued_messages: u64,
    pub router_queued_encoded_bytes: u64,
    pub backbone_pending_slots: u64,
    pub audit_pending_slots: u64,
    pub no_route_total: u64,
    pub queue_full_total: u64,
    pub invalid_forwarded_frames_total: u64,
    pub audit_queued_total: u64,
    pub audit_dropped_total: u64,
}
