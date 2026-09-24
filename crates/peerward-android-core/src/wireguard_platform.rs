use super::*;
use peerward_management::{ApplicationCategory, ApplicationResult, PeerOperation};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MobileNetworkConfiguration {
    pub configuration_version: u64,
    pub preferences_version: u64,
    pub routes: Vec<ipnet::IpNet>,
    pub search_domains: Vec<String>,
    pub accept_dns: bool,
    pub exit_selected: bool,
    pub allow_local_lan: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MobileNetworkObservation {
    pub configuration_version: u64,
    pub preferences_version: u64,
    pub source: IpAddr,
    pub result: ApplicationResult,
    pub reason: Option<String>,
}

impl MobileWireguard {
    pub fn managed_network(
        &mut self,
        source: IpAddr,
        now: UnixTime,
    ) -> Result<MobileNetworkConfiguration, MobileError> {
        if !self.core.local_source_authorized(source, now) {
            return Err(MobileError::PolicyDenied);
        }
        let (resources, preferences) = self
            .core
            .resource_network_configuration(now)
            .ok_or(MobileError::PolicyDenied)?;
        let routes: Vec<_> = resources
            .capture_routes(self.core.local_peer(), &preferences)
            .into_iter()
            .collect();
        if routes.len() > 128 {
            return Err(MobileError::InvalidInput);
        }
        let search_domains = if preferences.accept_dns {
            self.core
                .effective_dns(source, now)?
                .1
                .search_domains
                .clone()
        } else {
            vec![]
        };
        Ok(MobileNetworkConfiguration {
            preferences_version: self.preference_version(),
            accept_dns: preferences.accept_dns,
            exit_selected: preferences.exit_resource.is_some(),
            allow_local_lan: preferences.allow_local_lan,
            configuration_version: self
                .core
                .configuration_status()
                .ok_or(MobileError::InvalidState)?
                .0,
            routes,
            search_domains,
        })
    }

    pub fn observe_network(
        &mut self,
        observation: MobileNetworkObservation,
        now: UnixTime,
    ) -> Result<(), MobileError> {
        let current = self.managed_network(observation.source, now)?;
        if current.configuration_version != observation.configuration_version
            || current.preferences_version != observation.preferences_version
            || observation
                .reason
                .as_ref()
                .is_some_and(|reason| reason.len() > 256 || reason.chars().any(char::is_control))
        {
            return Err(MobileError::InvalidInput);
        }
        self.network_applied =
            (observation.result == ApplicationResult::Applied).then_some(current);
        self.core
            .set_resource_platform_ready(self.network_applied.is_some());
        self.network_observation = Some(observation);
        Ok(())
    }

    pub(crate) fn reconcile_platform(&mut self, now: UnixTime) {
        let current = self
            .network_observation
            .as_ref()
            .map(|value| value.source)
            .and_then(|source| self.managed_network(source, now).ok());
        let ready = current
            .as_ref()
            .zip(self.network_applied.as_ref())
            .is_some_and(|(current, applied)| {
                current.routes == applied.routes
                    && current.search_domains == applied.search_domains
                    && current.preferences_version == applied.preferences_version
                    && current.accept_dns == applied.accept_dns
                    && current.exit_selected == applied.exit_selected
                    && current.allow_local_lan == applied.allow_local_lan
            });
        if ready && let (Some(current), Some(observed)) = (current, &mut self.network_observation) {
            observed.configuration_version = current.configuration_version;
            self.network_applied = Some(current);
        }
        self.core.set_resource_platform_ready(ready);
    }

    pub(crate) fn application_receipts(&mut self, now: UnixTime) -> Vec<PeerOperation> {
        let Some(core) = self.core.core_management_receipt(now) else {
            return vec![];
        };
        let PeerOperation::Applied {
            configuration_version,
            result: ApplicationResult::Applied,
            ..
        } = &core
        else {
            return vec![core];
        };
        let mut operations = vec![core.clone()];
        if let Some(observed) = &self.network_observation
            && observed.configuration_version == *configuration_version
        {
            for category in [ApplicationCategory::Routes, ApplicationCategory::Dns] {
                let mut operation = core.clone();
                if let PeerOperation::Applied {
                    category: part,
                    result,
                    reason,
                    ..
                } = &mut operation
                {
                    *part = category;
                    *result = observed.result;
                    reason.clone_from(&observed.reason);
                }
                operations.push(operation);
            }
        }
        operations
    }
}
