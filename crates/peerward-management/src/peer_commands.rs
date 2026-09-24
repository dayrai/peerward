use crate::ManagementError;
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use peerward_types::{CredentialSerial, MeshId, PeerId};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A signed Core rejection requests a newer lease without changing configuration.
pub const FRESH_AUTHORIZATION_REQUIRED: &str = "fresh_authorization_required";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PeerOperation {
    DeviceEvidence {
        evidence: crate::DeviceEvidence,
    },
    TargetHealth {
        binding_id: Uuid,
        binding_version: u64,
        resource_version: u64,
        result: crate::TargetProbeResult,
    },
    Advertise {
        binding_id: Uuid,
        binding_version: u64,
        published: bool,
        forwarding_ready: bool,
    },
    Applied {
        category: ApplicationCategory,
        configuration_version: u64,
        configuration_digest: [u8; 32],
        lease_sequence: u64,
        result: ApplicationResult,
        reason: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationResult {
    Applied,
    Rejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationCategory {
    Core,
    Routes,
    Dns,
    Firewall,
}
impl ApplicationCategory {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Core => "core",
            Self::Routes => "routes",
            Self::Dns => "dns",
            Self::Firewall => "firewall",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerCommand {
    pub mesh_id: MeshId,
    pub peer_id: PeerId,
    pub credential_serial: CredentialSerial,
    pub request_id: Uuid,
    /// Persistently increasing per-device operation number, independent of lease sequence.
    pub sequence: u64,
    pub issued_at: u64,
    pub operation: PeerOperation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPeerCommand {
    pub command: PeerCommand,
    pub signature: Vec<u8>,
}

fn command_bytes(command: &PeerCommand) -> Result<Vec<u8>, ManagementError> {
    if let PeerOperation::DeviceEvidence { evidence } = &command.operation {
        evidence.validate()?;
    }
    if command.request_id.get_version_num() != 4
        || command.sequence == 0
        || matches!(&command.operation,PeerOperation::Applied{reason:Some(reason),..} if reason.len()>256 || reason.chars().any(char::is_control))
    {
        return Err(ManagementError::Invalid("peer_command"));
    }
    let mut bytes = b"peerward/peer-management-command/v1\0".to_vec();
    bytes
        .extend(serde_json::to_vec(command).map_err(|_| ManagementError::Invalid("peer_command"))?);
    Ok(bytes)
}

impl SignedPeerCommand {
    pub fn sign(command: PeerCommand, key: &SigningKey) -> Result<Self, ManagementError> {
        let signature = key.sign(&command_bytes(&command)?).to_bytes().to_vec();
        Ok(Self { command, signature })
    }
    pub fn verify(&self, key: &[u8; 32], now: u64) -> Result<(), ManagementError> {
        if now.abs_diff(self.command.issued_at) > 300 {
            return Err(ManagementError::Expired);
        }
        VerifyingKey::from_bytes(key)
            .map_err(|_| ManagementError::Signature)?
            .verify_strict(
                &command_bytes(&self.command)?,
                &Signature::from_slice(&self.signature).map_err(|_| ManagementError::Signature)?,
            )
            .map_err(|_| ManagementError::Signature)
    }
}

impl PeerCommand {
    /// Exact domain-separated transcript for a protected external identity signer.
    pub fn signing_transcript(&self) -> Result<Vec<u8>, ManagementError> {
        command_bytes(self)
    }
}
