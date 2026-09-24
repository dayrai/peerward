use super::*;
use peerward_dataplane::{Firewall, FlowKey};
use peerward_management::{
    ResourceAccess, ResourceAction, ResourceTarget, decide_resource_aliases,
};
use std::{collections::HashMap, net::IpAddr};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum PlatformState {
    Unmanaged,
    Pending,
    Applied,
}

#[derive(Clone)]
pub(super) struct ResourceFlow {
    source: PeerId,
    provider: PeerId,
    resource: uuid::Uuid,
    valid_until: u64,
}

pub(super) struct ResourceTraffic {
    flows: HashMap<FlowKey, ResourceFlow>,
    firewall: Firewall,
}

impl ResourceTraffic {
    pub(super) fn new() -> Self {
        Self {
            flows: HashMap::new(),
            firewall: Firewall::new(1, Action::Deny, vec![], 4096, 8),
        }
    }
    pub(super) fn clear(&mut self) {
        self.flows.clear();
        self.firewall.invalidate_state();
    }
    fn locate(&self, packet: &ParsedPacket) -> Option<(ResourceFlow, bool)> {
        if let Some(related) = &packet.related_flow {
            return self.flows.get(related).cloned().map(|flow| (flow, true));
        }
        let key = FlowKey::from_packet(packet)?;
        self.flows
            .get(&key)
            .cloned()
            .map(|flow| (flow, false))
            .or_else(|| {
                self.flows
                    .get(&key.reverse())
                    .cloned()
                    .map(|flow| (flow, true))
            })
    }
}

impl WireguardRuntime {
    pub(super) fn flush_packet_queues(&mut self) {
        if let Some(next) = self.authorization.checked_add(1) {
            self.authorization = next;
        } else {
            self.closed = true;
        }
        self.pending.clear();
        for slot in &mut self.slots {
            slot.engine.clear_pending();
        }
        self.egress_fragments = fragments();
        self.ingress_fragments = fragments();
    }

    /// Platform adapters fence resource traffic until their OS transaction is applied.
    pub fn set_resource_platform_ready(&mut self, ready: bool) {
        let state = if ready {
            PlatformState::Applied
        } else {
            PlatformState::Pending
        };
        if self.resource_platform != state {
            self.clear_pending();
        }
        self.resource_platform = state;
    }

    pub(super) fn expire_resource_flows(&mut self, wall: UnixTime) {
        let expired: Vec<_> = self
            .resource_traffic
            .flows
            .iter()
            .filter(|(_, flow)| !self.resource_flow_current(flow, wall))
            .map(|(key, _)| key.clone())
            .collect();
        if !expired.is_empty() {
            for key in expired {
                self.resource_traffic.flows.remove(&key);
                self.resource_traffic.firewall.forget_flow(&key);
            }
            // Already encrypted output cannot be reclassified by flow; fence that bounded queue.
            // Healthy connection tracking and WireGuard sessions remain intact.
            self.flush_packet_queues();
        }
    }
    /// Local preferences constrain already approved traffic; they never create a grant.
    pub fn set_preferences(
        &mut self,
        preferences: peerward_management::ClientPreferences,
    ) -> Result<(), PeerError> {
        preferences
            .validate()
            .map_err(|_| PeerError::InvalidConfig)?;
        if preferences != self.preferences {
            self.clear_pending();
            self.dns_cache = None;
            if self.resource_platform != PlatformState::Unmanaged {
                self.resource_platform = PlatformState::Pending;
            }
            self.preferences = preferences;
        }
        Ok(())
    }
    pub fn preferences(&self) -> &peerward_management::ClientPreferences {
        &self.preferences
    }
    pub fn resource_platform_ready(&self) -> bool {
        self.resource_platform == resources::PlatformState::Applied
    }

    pub(super) fn resource_path_current(
        &self,
        packet: &ParsedPacket,
        local: &Key,
        remote: &Key,
        wall: UnixTime,
    ) -> bool {
        let Some((flow, reverse)) = self.resource_traffic.locate(packet) else {
            return false;
        };
        if !self.resource_flow_current(&flow, wall) {
            return false;
        }
        let (source, provider) = if reverse {
            (remote, local)
        } else {
            (local, remote)
        };
        self.directory
            .get(source, wall)
            .is_some_and(|peer| peer.peer_id == flow.source)
            && self
                .directory
                .get(provider, wall)
                .is_some_and(|peer| peer.peer_id == flow.provider)
    }

    fn resource_flow_current(&self, flow: &ResourceFlow, wall: UnixTime) -> bool {
        if self.resource_platform == PlatformState::Pending
            || !self.device_admitted(flow.source, wall)
            || !self.device_admitted(flow.provider, wall)
            || wall.0 >= flow.valid_until
            || !self.state_ready()
        {
            return false;
        }
        let Some(delivery) = &self.configuration else {
            return false;
        };
        delivery.resources.bindings.iter().any(|binding| {
            binding.resource_id == flow.resource
                && binding.peer_id == flow.provider
                && binding.approved
                && (flow.source != self.local
                    || self
                        .gateway_health
                        .selector
                        .eligible(binding.id, Instant::now()))
                && delivery.resources.advertisements.iter().any(|ad| {
                    ad.binding_id == binding.id
                        && ad.binding_version == binding.version
                        && ad.peer_id == flow.provider
                        && ad.published
                        && ad.forwarding_ready
                        && ad.valid_until > wall.0
                })
        })
    }

    pub(super) fn resource_return_candidate(
        &self,
        provider: PeerId,
        destination: IpAddr,
        wall: UnixTime,
    ) -> bool {
        // Fragment prefilter only. Reassembly and the exact flow check are mandatory below.
        self.directory
            .active(self.local, wall)
            .is_some_and(|local| local.owns(destination))
            && self.resource_traffic.flows.values().any(|flow| {
                flow.source == self.local
                    && flow.provider == provider
                    && self.resource_flow_current(flow, wall)
            })
    }

    pub(super) fn resource_destination(
        &mut self,
        packet: &ParsedPacket,
        source: PeerId,
        provider: Option<PeerId>,
        wall: UnixTime,
        now: Instant,
    ) -> Result<Key, PeerError> {
        if self.resource_platform == PlatformState::Pending
            || !self.device_admitted(source, wall)
            || provider.is_some_and(|peer| !self.device_admitted(peer, wall))
        {
            return Err(PeerError::PolicyDenied);
        }
        if let Some(delivery) = &self.configuration {
            self.gateway_health.sync(
                &delivery.resources,
                self.local,
                delivery.manifest.manifest.version,
                now,
            );
        }
        if let Some((flow, reverse)) = self.resource_traffic.locate(packet) {
            let expected = if reverse { flow.provider } else { flow.source };
            if source != expected
                || provider.is_some_and(|peer| {
                    if reverse {
                        peer != flow.source
                    } else {
                        peer != flow.provider
                    }
                })
                || !self.resource_flow_current(&flow, wall)
            {
                return Err(PeerError::PolicyDenied);
            }
            let result = self.resource_traffic.firewall.evaluate_with_policy(
                packet,
                self.seconds(now),
                |_| (Action::Deny, None),
            );
            if result.action != Action::Allow {
                return Err(PeerError::PolicyDenied);
            }
            let target = if reverse { flow.source } else { flow.provider };
            return self
                .directory
                .active(target, wall)
                .map(|peer| peer.credential.wireguard_public_key)
                .ok_or(PeerError::NoRoute);
        }
        let delivery = self.configuration.as_ref().ok_or(PeerError::NoRoute)?;
        let descriptor = self
            .policy
            .descriptor(packet.source)
            .filter(|peer| peer.id == source)
            .ok_or(PeerError::InvalidPacket)?;
        // Packet addresses resolve all equally specific aliases before grant checks.
        let exit = if source == self.local {
            self.preferences.exit_resource
        } else {
            delivery
                .resources
                .resources
                .iter()
                .find(|resource| {
                    matches!(resource.definition.target, ResourceTarget::Internet { .. })
                        && provider.is_some_and(|peer| {
                            delivery.resources.bindings.iter().any(|binding| {
                                binding.resource_id == resource.id
                                    && binding.peer_id == peer
                                    && binding.approved
                            })
                        })
                })
                .map(|resource| resource.id)
        };
        let aliases = peerward_management::packet_resource_aliases(
            &delivery.resources.resources,
            packet.destination,
            exit,
        );
        let resource = delivery
            .resources
            .resources
            .iter()
            .find(|resource| aliases.first() == Some(&resource.id))
            .ok_or(PeerError::NoRoute)?;
        if delivery.resources.withdrawals.iter().any(|withdrawal| {
            matches!(withdrawal.target, ResourceTarget::Subnet { .. })
                && withdrawal.target.contains(packet.destination)
                && withdrawal.target.specificity() >= resource.definition.target.specificity()
        }) {
            return Err(PeerError::PolicyDenied);
        }
        if source == self.local {
            match resource.definition.target {
                ResourceTarget::Subnet { .. } if !self.preferences.accept_private_routes => {
                    return Err(PeerError::PolicyDenied);
                }
                ResourceTarget::Internet { .. }
                    if self.preferences.exit_resource != Some(resource.id) =>
                {
                    return Err(PeerError::PolicyDenied);
                }
                _ => {}
            }
        }
        let candidates: Vec<_> = delivery
            .resources
            .bindings
            .iter()
            .filter(|binding| {
                aliases.contains(&binding.resource_id)
                    && binding.approved
                    && binding.peer_id != source
                    && self.device_admitted(binding.peer_id, wall)
                    && provider.is_none_or(|peer| peer == binding.peer_id)
                    && self.directory.active(binding.peer_id, wall).is_some()
                    && {
                        let (action, _, target) = decide_resource_aliases(
                            &delivery.resources.rules,
                            &delivery.resources.collections,
                            &aliases,
                            &delivery.resources.bindings,
                            &ResourceAccess {
                                source_peer: source,
                                source_address: packet.source,
                                source_labels: &descriptor.labels,
                                resource: resource.id,
                                provider: binding.peer_id,
                                protocol: packet.protocol,
                                destination_port: packet.destination_port,
                                now: wall.0,
                            },
                        );
                        action == ResourceAction::Allow && target == Some(binding.resource_id)
                    }
                    && delivery.resources.advertisements.iter().any(|ad| {
                        ad.binding_id == binding.id
                            && ad.binding_version == binding.version
                            && ad.peer_id == binding.peer_id
                            && ad.published
                            && ad.forwarding_ready
                            && ad.valid_until > wall.0
                    })
            })
            .cloned()
            .collect();
        let selected = if source == self.local {
            self.gateway_health.selector.select_aliases(
                resource.id,
                &aliases,
                &candidates,
                &delivery.resources.advertisements,
                wall.0,
                now,
            )
        } else {
            provider
        }
        .ok_or(PeerError::NoRoute)?;
        let binding = candidates
            .iter()
            .find(|binding| binding.peer_id == selected)
            .ok_or(PeerError::PolicyDenied)?;
        let (action, rule, _) = decide_resource_aliases(
            &delivery.resources.rules,
            &delivery.resources.collections,
            &aliases,
            &delivery.resources.bindings,
            &ResourceAccess {
                source_peer: source,
                source_address: packet.source,
                source_labels: &descriptor.labels,
                resource: resource.id,
                provider: binding.peer_id,
                protocol: packet.protocol,
                destination_port: packet.destination_port,
                now: wall.0,
            },
        );
        if action != ResourceAction::Allow {
            return Err(PeerError::PolicyDenied);
        }
        self.resource_traffic
            .flows
            .retain(|_, flow| wall.0 < flow.valid_until);
        if self.resource_traffic.flows.len() >= 4096 {
            return Err(PeerError::QueueFull);
        }
        let key = FlowKey::from_packet(packet).ok_or(PeerError::InvalidPacket)?;
        let result =
            self.resource_traffic
                .firewall
                .evaluate_with_policy(packet, self.seconds(now), |_| (Action::Allow, None));
        if result.action != Action::Allow {
            return Err(PeerError::PolicyDenied);
        }
        let until = delivery
            .resources
            .rules
            .iter()
            .find(|item| Some(item.id) == rule)
            .and_then(|rule| rule.not_after)
            .unwrap_or(u64::MAX)
            .min(wall.0.saturating_add(600));
        self.resource_traffic.flows.insert(
            key,
            ResourceFlow {
                source,
                provider: binding.peer_id,
                resource: binding.resource_id,
                valid_until: until,
            },
        );
        self.directory
            .active(binding.peer_id, wall)
            .map(|peer| peer.credential.wireguard_public_key)
            .ok_or(PeerError::NoRoute)
    }

    pub(super) fn outbound_target(
        &mut self,
        packet: &ParsedPacket,
        local: Key,
        wall: UnixTime,
        now: Instant,
    ) -> Result<Key, PeerError> {
        if self.directory.owns_source(&local, packet.source, wall) {
            if let Some(remote) = self.directory.destination(packet.destination, wall) {
                if remote.peer_id == self.local
                    || !self.device_admitted(remote.peer_id, wall)
                    || self.policy.evaluate(packet, self.seconds(now)) != Action::Allow
                {
                    return Err(PeerError::PolicyDenied);
                }
                return Ok(remote.credential.wireguard_public_key);
            }
            self.resource_destination(packet, self.local, None, wall, now)
        } else {
            // Host forwarding is only a return path for a previously authorized resource flow.
            let Some((flow, true)) = self.resource_traffic.locate(packet) else {
                return Err(PeerError::InvalidPacket);
            };
            if flow.provider != self.local {
                return Err(PeerError::InvalidPacket);
            }
            self.resource_destination(packet, self.local, Some(flow.source), wall, now)
        }
    }

    pub(super) fn inbound_allowed(
        &mut self,
        packet: &ParsedPacket,
        remote: Key,
        local: Key,
        wall: UnixTime,
        now: Instant,
    ) -> Result<(), PeerError> {
        let provider = self
            .directory
            .get(&remote, wall)
            .ok_or(PeerError::Revoked)?
            .peer_id;
        if !self.device_admitted(provider, wall) || !self.device_admitted(self.local, wall) {
            return Err(PeerError::PolicyDenied);
        }
        if self.directory.owns_source(&remote, packet.source, wall) {
            if self.directory.owns_source(&local, packet.destination, wall) {
                if self.policy.evaluate_inbound(
                    packet,
                    self.seconds(now),
                    self.preferences.allow_inbound,
                ) != Action::Allow
                {
                    return Err(PeerError::PolicyDenied);
                }
            } else {
                if self
                    .directory
                    .destination(packet.destination, wall)
                    .is_some()
                {
                    return Err(PeerError::InvalidPacket);
                }
                self.resource_destination(packet, provider, Some(self.local), wall, now)?;
            }
        } else {
            if !self.directory.owns_source(&local, packet.destination, wall) {
                return Err(PeerError::InvalidPacket);
            }
            let Some((flow, true)) = self.resource_traffic.locate(packet) else {
                return Err(PeerError::InvalidPacket);
            };
            if flow.provider != provider || flow.source != self.local {
                return Err(PeerError::InvalidPacket);
            }
            self.resource_destination(packet, provider, Some(self.local), wall, now)?;
        }
        Ok(())
    }
}
