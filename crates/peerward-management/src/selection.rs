use crate::{GatewayBinding, RouteAdvertisement};
use peerward_types::PeerId;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};
use uuid::Uuid;

/// Local preferences never confer remote authorization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)] // Independent opt-in preferences, not mutually exclusive runtime states.
pub struct ClientPreferences {
    pub accept_private_routes: bool,
    pub accept_dns: bool,
    pub allow_inbound: bool,
    pub exit_resource: Option<Uuid>,
    pub allow_local_lan: bool,
}
impl Default for ClientPreferences {
    fn default() -> Self {
        Self {
            accept_private_routes: true,
            accept_dns: true,
            allow_inbound: true,
            exit_resource: None,
            allow_local_lan: false,
        }
    }
}

impl ClientPreferences {
    pub fn validate(&self) -> Result<(), crate::ManagementError> {
        if self
            .exit_resource
            .is_some_and(|id| id.get_version_num() != 4)
        {
            return Err(crate::ManagementError::Invalid("preferences.exit_resource"));
        }
        if self.exit_resource.is_some() && !self.accept_dns {
            return Err(crate::ManagementError::Invalid(
                "preferences.exit_requires_dns",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathHealth {
    Unknown,
    Healthy,
    Unhealthy,
}

/// A consumer-side path observation; it does not assert target application health.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayPathObservation {
    pub binding_id: Uuid,
    pub peer_id: PeerId,
    pub health: PathHealth,
}

#[derive(Debug, Clone)]
struct Observation {
    health: PathHealth,
    failures: u8,
    successes: u8,
    stable_since: Instant,
    checked: Instant,
}

/// Provider selection for NEW connections. Existing flows retain their healthy provider.
#[derive(Default)]
pub struct GatewaySelector {
    observations: BTreeMap<Uuid, Observation>,
    selected: BTreeMap<Uuid, Uuid>,
}

impl GatewaySelector {
    /// A fresh approved path has one bounded discovery window, never inferred healthy.
    pub fn register(&mut self, binding: Uuid, now: Instant) {
        self.observations.entry(binding).or_insert(Observation {
            health: PathHealth::Unknown,
            failures: 0,
            successes: 0,
            stable_since: now,
            checked: now,
        });
    }
    pub fn retain(&mut self, mut keep: impl FnMut(Uuid) -> bool) {
        self.observations.retain(|id, _| keep(*id));
        self.selected
            .retain(|_, id| self.observations.contains_key(id));
    }
    pub fn eligible(&self, binding: Uuid, now: Instant) -> bool {
        self.health(binding, now) == PathHealth::Healthy
            || self.observations.get(&binding).is_some_and(|state| {
                state.health == PathHealth::Unknown
                    && state.failures < 3
                    && now.saturating_duration_since(state.stable_since) < Duration::from_secs(15)
            })
    }
    pub fn observe(&mut self, binding: Uuid, success: bool, now: Instant) {
        let observation = self.observations.entry(binding).or_insert(Observation {
            health: PathHealth::Unknown,
            failures: 0,
            successes: 0,
            stable_since: now,
            checked: now,
        });
        observation.checked = now;
        if success {
            if observation.successes == 0 {
                observation.stable_since = now;
            }
            observation.failures = 0;
            observation.successes = observation.successes.saturating_add(1);
            if observation.health == PathHealth::Unknown || observation.successes >= 3 {
                observation.health = PathHealth::Healthy;
            }
        } else {
            observation.successes = 0;
            observation.failures = observation.failures.saturating_add(1);
            if observation.failures >= 3 {
                observation.health = PathHealth::Unhealthy;
            }
        }
    }
    pub fn health(&self, binding: Uuid, now: Instant) -> PathHealth {
        self.observations
            .get(&binding)
            .filter(|observation| {
                now.saturating_duration_since(observation.checked) <= Duration::from_secs(15)
            })
            .map_or(PathHealth::Unknown, |observation| observation.health)
    }
    pub fn select(
        &mut self,
        resource: Uuid,
        bindings: &[GatewayBinding],
        advertisements: &[RouteAdvertisement],
        wall: u64,
        now: Instant,
    ) -> Option<PeerId> {
        self.select_aliases(resource, &[resource], bindings, advertisements, wall, now)
    }

    pub fn select_aliases(
        &mut self,
        resource: Uuid,
        aliases: &[Uuid],
        bindings: &[GatewayBinding],
        advertisements: &[RouteAdvertisement],
        wall: u64,
        now: Instant,
    ) -> Option<PeerId> {
        let mut candidates: Vec<_> = bindings
            .iter()
            .filter(|binding| {
                aliases.contains(&binding.resource_id)
                    && binding.approved
                    && binding.validate().is_ok()
                    && self.eligible(binding.id, now)
                    && advertisements.iter().any(|ad| {
                        ad.binding_id == binding.id
                            && ad.binding_version == binding.version
                            && ad.peer_id == binding.peer_id
                            && ad.published
                            && ad.forwarding_ready
                            && ad.valid_until > wall
                    })
            })
            .collect();
        candidates.sort_by_key(|binding| (binding.priority, binding.peer_id, binding.id));
        let preferred = *candidates.first()?;
        let current = self
            .selected
            .get(&resource)
            .and_then(|id| candidates.iter().find(|binding| binding.id == *id))
            .copied();
        let selected = match current {
            Some(current)
                if current.id != preferred.id
                    && self.observations.get(&preferred.id).is_none_or(|state| {
                        now.saturating_duration_since(state.stable_since) < Duration::from_secs(30)
                    }) =>
            {
                current
            }
            _ => preferred,
        };
        self.selected.insert(resource, selected.id);
        Some(selected.peer_id)
    }
}
