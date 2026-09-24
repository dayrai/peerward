use super::*;
use peerward_credentials::private_files::{read_private, write_private_atomic};
use peerward_management::{
    ClientPreferenceRequest, ClientPreferenceView, ExitChoice, PreferenceApplication,
    ResourceTarget, SavedClientPreferences,
};
use std::path::{Path, PathBuf};

pub(super) struct MobilePreferences {
    path: PathBuf,
    saved: SavedClientPreferences,
}

impl MobileWireguard {
    /// Called only after the checkpoint has acquired this Mesh/Peer's exclusive owner lock.
    pub fn load_preferences(&mut self, directory: &Path) -> Result<(), MobileError> {
        if self.preferences.is_some() {
            return Err(MobileError::InvalidState);
        }
        let path = directory.join("preferences.json");
        let saved = match read_private(&path, 65_536) {
            Ok(bytes) => serde_json::from_slice::<SavedClientPreferences>(&bytes)
                .map_err(|_| MobileError::InvalidInput)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                SavedClientPreferences::new(self.mesh, self.peer)
            }
            Err(_) => return Err(MobileError::InvalidState),
        };
        saved
            .validate(self.mesh, self.peer)
            .map_err(|_| MobileError::InvalidInput)?;
        self.core.set_preferences(saved.preferences.clone())?;
        self.preferences = Some(MobilePreferences { path, saved });
        Ok(())
    }

    pub fn client_preferences(
        &mut self,
        request: ClientPreferenceRequest,
        now: UnixTime,
    ) -> Result<ClientPreferenceView, MobileError> {
        if let ClientPreferenceRequest::Set { change } = request {
            let store = self.preferences.as_ref().ok_or(MobileError::InvalidState)?;
            if store
                .saved
                .validate_change(&change)
                .map_err(|_| MobileError::InvalidInput)?
            {
                if let Some(selected) = change.preferences.exit_resource {
                    let (resources, _) = self
                        .core
                        .resource_network_configuration(now)
                        .ok_or(MobileError::PolicyDenied)?;
                    if !resources.resources.iter().any(|resource| {
                        resource.id == selected
                            && matches!(resource.definition.target, ResourceTarget::Internet { .. })
                    }) || !resources.bindings.iter().any(|binding| {
                        binding.resource_id == selected
                            && binding.peer_id != self.peer
                            && binding.approved
                    }) {
                        return Err(MobileError::PolicyDenied);
                    }
                }
                let next = store
                    .saved
                    .changed(change)
                    .map_err(|_| MobileError::InvalidInput)?;
                // Platform update follows this durable intent. A crash restores capture from
                // these preferences before starting packet processing, never a stale UI value.
                write_private_atomic(
                    &store.path,
                    &serde_json::to_vec(&next).map_err(|_| MobileError::InvalidState)?,
                )
                .map_err(|_| MobileError::InvalidState)?;
                self.core.set_preferences(next.preferences.clone())?;
                self.outputs.clear();
                self.output_bytes = 0;
                self.network_applied = None;
                self.network_observation = None;
                self.preferences
                    .as_mut()
                    .ok_or(MobileError::InvalidState)?
                    .saved = next;
            }
        }
        let view = self.core.resource_network_configuration(now);
        let exits = view
            .as_ref()
            .map(|(resources, _)| {
                resources
                    .resources
                    .iter()
                    .filter_map(|resource| {
                        let ResourceTarget::Internet { ipv4, ipv6 } = resource.definition.target
                        else {
                            return None;
                        };
                        Some(ExitChoice {
                            resource_id: resource.id,
                            name: resource.definition.name.clone(),
                            ipv4,
                            ipv6,
                            providers: resources
                                .bindings
                                .iter()
                                .filter(|binding| {
                                    binding.resource_id == resource.id
                                        && binding.peer_id != self.peer
                                        && binding.approved
                                })
                                .count(),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        let application = if view.is_none() {
            PreferenceApplication::Unknown
        } else if self.core.resource_platform_ready() {
            PreferenceApplication::Applied
        } else if self
            .network_observation
            .as_ref()
            .is_some_and(|observation| {
                observation.result == peerward_management::ApplicationResult::Rejected
            })
        {
            PreferenceApplication::Rejected
        } else {
            PreferenceApplication::Pending
        };
        Ok(ClientPreferenceView {
            version: self.preference_version(),
            preferences: self.core.preferences().clone(),
            application,
            reason: self
                .network_observation
                .as_ref()
                .and_then(|observation| observation.reason.clone()),
            exits,
            local_lan: vec![],
            gateway_paths: self
                .core
                .gateway_path_observations(std::time::Instant::now()),
        })
    }

    pub(super) fn preference_version(&self) -> u64 {
        self.preferences
            .as_ref()
            .map_or(0, |store| store.saved.version)
    }
}
