use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookCreateRequest {
    pub id: Uuid,
    pub name: String,
    pub endpoint: String,
    #[serde(default)]
    pub enabled: bool,
    pub event_types: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookUpdateRequest {
    pub name: String,
    pub endpoint: String,
    pub enabled: bool,
    pub event_types: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookResource {
    pub id: Uuid,
    pub version: u64,
    pub mesh_id: Uuid,
    pub name: String,
    pub endpoint: String,
    pub enabled: bool,
    pub event_types: Vec<String>,
    /// Pin this distribution public key through an authenticated management channel.
    pub signing_public_key: Option<String>,
    pub pending_deliveries: u64,
    pub dead_deliveries: u64,
    pub dropped_events: u64,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookDeliveryResource {
    pub id: Uuid,
    pub webhook_id: Uuid,
    pub webhook_version: u64,
    pub version: u64,
    pub event: peerward_management::WebhookEvent,
    /// queued / sending / succeeded / failed / cancelled.
    pub status: String,
    pub attempts: u32,
    pub next_attempt_at: String,
    pub result_code: Option<String>,
    pub http_status: Option<u16>,
    pub created_at: String,
    pub completed_at: Option<String>,
}
