use crate::ClientPreferences;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Durable local intent. A saved change never claims that platform application succeeded.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedClientPreferences {
    pub schema_version: u32,
    pub mesh_id: peerward_types::MeshId,
    pub peer_id: peerward_types::PeerId,
    pub version: u64,
    pub preferences: ClientPreferences,
    pub last_change: Option<PreferenceChange>,
}
impl SavedClientPreferences {
    pub fn new(mesh_id: peerward_types::MeshId, peer_id: peerward_types::PeerId) -> Self {
        Self {
            schema_version: 4,
            mesh_id,
            peer_id,
            version: 0,
            preferences: ClientPreferences::default(),
            last_change: None,
        }
    }
    pub fn validate(
        &self,
        mesh: peerward_types::MeshId,
        peer: peerward_types::PeerId,
    ) -> Result<(), crate::ManagementError> {
        self.preferences.validate()?;
        if self.schema_version != 4
            || self.mesh_id != mesh
            || self.peer_id != peer
            || self.last_change.as_ref().is_some_and(|change| {
                change.request_id.get_version_num() != 4
                    || change.expected_version.checked_add(1) != Some(self.version)
                    || change.preferences != self.preferences
            })
            || (self.version == 0) != self.last_change.is_none()
        {
            return Err(crate::ManagementError::Conflict(
                "client_preferences.identity_or_version",
            ));
        }
        Ok(())
    }
    pub fn validate_change(
        &self,
        change: &PreferenceChange,
    ) -> Result<bool, crate::ManagementError> {
        change.preferences.validate()?;
        if change.request_id.get_version_num() != 4 {
            return Err(crate::ManagementError::Invalid("request_id"));
        }
        if self.last_change.as_ref() == Some(change) {
            return Ok(false);
        }
        if self
            .last_change
            .as_ref()
            .is_some_and(|last| last.request_id == change.request_id)
            || change.expected_version != self.version
            || self.version == u64::MAX
        {
            return Err(crate::ManagementError::Conflict(
                "client_preferences.version",
            ));
        }
        Ok(true)
    }
    pub fn changed(&self, change: PreferenceChange) -> Result<Self, crate::ManagementError> {
        if !self.validate_change(&change)? {
            return Ok(self.clone());
        }
        Ok(Self {
            version: self.version + 1,
            preferences: change.preferences.clone(),
            last_change: Some(change),
            ..self.clone()
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreferenceChange {
    pub request_id: Uuid,
    pub expected_version: u64,
    pub preferences: ClientPreferences,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum ClientPreferenceRequest {
    Get {},
    Set { change: PreferenceChange },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreferenceApplication {
    Pending,
    Applied,
    Rejected,
    Unknown,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExitChoice {
    pub resource_id: Uuid,
    pub name: String,
    pub ipv4: bool,
    pub ipv6: bool,
    pub providers: usize,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientPreferenceView {
    pub version: u64,
    pub preferences: ClientPreferences,
    pub application: PreferenceApplication,
    pub reason: Option<String>,
    pub exits: Vec<ExitChoice>,
    pub local_lan: Vec<ipnet::IpNet>,
    pub gateway_paths: Vec<crate::GatewayPathObservation>,
}
