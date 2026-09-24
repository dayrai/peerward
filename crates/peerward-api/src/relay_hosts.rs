use peerward_types::{MeshId, NetworkEndpoint, RelayId};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Versioned public trust material. Never contains a private key.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayTrustMaterial {
    pub root_public_key: Vec<u8>,
    pub authority_certificate: Vec<u8>,
    pub distribution_certificate: Vec<u8>,
    pub credential: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayHostAssignment {
    pub mesh_id: MeshId,
    pub relay_id: RelayId,
    pub revision: i64,
    pub desired: String,
    pub material: Option<RelayTrustMaterial>,
    pub termination: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayHostAssignments {
    pub host_id: Uuid,
    pub revision: i64,
    pub peer_endpoints: Vec<NetworkEndpoint>,
    pub backbone_endpoints: Vec<NetworkEndpoint>,
    pub assignments: Vec<RelayHostAssignment>,
    pub next_mesh: Option<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayHostPublicKey {
    pub mesh_id: MeshId,
    pub relay_id: RelayId,
    pub revision: i64,
    pub public_key: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayHostAcknowledgement {
    pub mesh_id: MeshId,
    pub relay_id: RelayId,
    pub revision: i64,
    pub state: String,
    pub error_code: Option<String>,
    #[serde(default)]
    pub active_sessions: Option<u64>,
}
