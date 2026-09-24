use crate::{ClientPreferences, ResourceConfiguration, ResourceTarget};
use ipnet::IpNet;
use peerward_types::PeerId;
use std::collections::BTreeSet;

impl ResourceConfiguration {
    /// Exit selection captures both families, including an unsupported one.
    /// Unsupported, revoked or unavailable egress is dropped by the core instead
    /// of disappearing from the host route table and silently using local Internet.
    pub fn capture_routes(
        &self,
        local: PeerId,
        preferences: &ClientPreferences,
    ) -> BTreeSet<IpNet> {
        let mut routes = self.private_capture_routes(local, preferences);
        if preferences.exit_resource.is_some() {
            routes.insert(IpNet::V4(ipnet::Ipv4Net::default()));
            routes.insert(IpNet::V6(ipnet::Ipv6Net::default()));
        }
        routes
    }

    /// Capture target addresses independently of a provider's current health or
    /// approval. The core decides authorization. Removing an unhealthy path from
    /// the OS would leak packets to its default route instead of denying them.
    pub fn private_capture_routes(
        &self,
        local: PeerId,
        preferences: &ClientPreferences,
    ) -> BTreeSet<IpNet> {
        if !preferences.accept_private_routes {
            return BTreeSet::new();
        }
        let mut prefixes = BTreeSet::new();
        for resource in &self.resources {
            if let ResourceTarget::Subnet { prefix, .. } = resource.definition.target
                && !self
                    .bindings
                    .iter()
                    .any(|binding| binding.resource_id == resource.id && binding.peer_id == local)
                && !self.former_provider_captures_locally(prefix, local)
            {
                prefixes.insert(prefix);
            }
        }
        for withdrawal in &self.withdrawals {
            if let ResourceTarget::Subnet { prefix, .. } = &withdrawal.target
                && !withdrawal.providers.contains(&local)
                && !self.former_provider_captures_locally(*prefix, local)
            {
                prefixes.insert(*prefix);
            }
        }
        prefixes
    }

    fn former_provider_captures_locally(&self, prefix: IpNet, local: PeerId) -> bool {
        self.capture_exclusions.iter().any(|exclusion| {
            exclusion.providers.contains(&local)
                && matches!(exclusion.target, ResourceTarget::Subnet { prefix: prior, .. }
                    if prior.prefix_len()<=prefix.prefix_len() && prior.contains(&prefix.network()))
        })
    }
}
