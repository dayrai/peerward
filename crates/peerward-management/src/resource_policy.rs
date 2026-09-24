use crate::{DeviceSelector, ManagementError};
use peerward_types::PeerId;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceAction {
    Deny,
    Allow,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceRule {
    pub id: Uuid,
    pub priority: u32,
    pub enabled: bool,
    pub action: ResourceAction,
    pub source: DeviceSelector,
    pub resources: BTreeSet<Uuid>,
    /// Additional source restriction; a device must belong to at least one selected collection.
    #[serde(default)]
    pub source_collections: BTreeSet<Uuid>,
    /// Alternative target membership, unioned with explicit resource IDs.
    #[serde(default)]
    pub resource_collections: BTreeSet<Uuid>,
    /// Empty allows any currently approved provider for this real resource.
    pub providers: BTreeSet<PeerId>,
    /// IP protocol number; zero means any. Port predicates require TCP or UDP.
    pub protocol: u8,
    pub destination_ports: Vec<(u16, u16)>,
    pub not_after: Option<u64>,
}

impl ResourceRule {
    pub fn validate(&self) -> Result<(), ManagementError> {
        self.source.validate()?;
        if self.providers.len() > 4096 {
            return Err(ManagementError::Invalid("resource_rule.providers"));
        }
        if self.id.get_version_num() != 4
            || (self.resources.is_empty() && self.resource_collections.is_empty())
            || self.source_collections.len() > 64
            || self.resource_collections.len() > 64
            || self.resources.len() > 4096
            || self.destination_ports.len() > 64
            || ![0, 1, 6, 17, 58].contains(&self.protocol)
            || (!self.destination_ports.is_empty() && ![6, 17].contains(&self.protocol))
            || self
                .destination_ports
                .iter()
                .any(|(first, last)| *first == 0 || first > last)
        {
            return Err(ManagementError::Invalid("resource_rule"));
        }
        Ok(())
    }
}

/// The provider identity is an independent predicate, never a target selector.
#[derive(Clone, Copy)]
pub struct ResourceAccess<'a> {
    pub source_peer: PeerId,
    pub source_address: IpAddr,
    pub source_labels: &'a BTreeMap<String, String>,
    pub resource: Uuid,
    pub provider: PeerId,
    pub protocol: u8,
    pub destination_port: Option<u16>,
    pub now: u64,
}

pub fn decide_resource(
    rules: &[ResourceRule],
    access: &ResourceAccess<'_>,
) -> (ResourceAction, Option<Uuid>) {
    decide_resource_with_collections(rules, &[], access)
}

pub fn decide_resource_with_collections(
    rules: &[ResourceRule],
    collections: &[crate::ResolvedCollection],
    access: &ResourceAccess<'_>,
) -> (ResourceAction, Option<Uuid>) {
    let selected = rules
        .iter()
        .filter(|rule| resource_rule_matches(rule, collections, access))
        .min_by_key(|rule| (rule.priority, rule.action, rule.id));
    selected.map_or((ResourceAction::Deny, None), |rule| {
        (rule.action, Some(rule.id))
    })
}

fn resource_rule_matches(
    rule: &ResourceRule,
    collections: &[crate::ResolvedCollection],
    access: &ResourceAccess<'_>,
) -> bool {
    rule.enabled
        && rule.validate().is_ok()
        && rule.not_after.is_none_or(|until| access.now < until)
        && (rule.resources.contains(&access.resource)
            || crate::collection_contains(
                collections,
                &rule.resource_collections,
                crate::CollectionKind::Resources,
                access.resource,
            ))
        && (rule.source_collections.is_empty()
            || crate::collection_contains(
                collections,
                &rule.source_collections,
                crate::CollectionKind::Devices,
                access.source_peer.into_uuid(),
            ))
        && (rule.providers.is_empty() || rule.providers.contains(&access.provider))
        && rule.source.matches(
            access.source_peer,
            access.source_address,
            access.source_labels,
        )
        && (rule.protocol == 0 || rule.protocol == access.protocol)
        && (rule.destination_ports.is_empty()
            || access.destination_port.is_some_and(|port| {
                rule.destination_ports
                    .iter()
                    .any(|(first, last)| *first <= port && port <= *last)
            }))
}

/// Select aliases by actual packet address before evaluating any grant. An
/// explicitly selected exit is considered only when no more specific LAN exists.
pub fn packet_resource_aliases(
    resources: &[crate::NetworkResource],
    address: IpAddr,
    exit: Option<Uuid>,
) -> Vec<Uuid> {
    let matching: Vec<_> = resources
        .iter()
        .filter(|resource| {
            resource.definition.target.contains(address)
                && match resource.definition.target {
                    crate::ResourceTarget::Subnet { .. } => true,
                    crate::ResourceTarget::Internet { .. } => Some(resource.id) == exit,
                }
        })
        .collect();
    let Some(specificity) = matching
        .iter()
        .map(|r| r.definition.target.specificity())
        .max()
    else {
        return vec![];
    };
    let mut aliases: Vec<_> = matching
        .into_iter()
        .filter(|r| r.definition.target.specificity() == specificity)
        .map(|r| r.id)
        .collect();
    aliases.sort_unstable();
    aliases
}

/// A packet has no resource-name field. Rules for all equally specific aliases
/// therefore share one deterministic priority order. A matching Deny cannot be
/// bypassed by choosing a second alias; an Allow still requires its own approved
/// resource/provider binding. No broader prefix is considered on rejection.
pub fn decide_resource_aliases(
    rules: &[ResourceRule],
    collections: &[crate::ResolvedCollection],
    aliases: &[Uuid],
    bindings: &[crate::GatewayBinding],
    access: &ResourceAccess<'_>,
) -> (ResourceAction, Option<Uuid>, Option<Uuid>) {
    let selected = rules
        .iter()
        .filter_map(|rule| {
            let resource = aliases
                .iter()
                .copied()
                .filter(|resource| {
                    resource_rule_matches(
                        rule,
                        collections,
                        &ResourceAccess {
                            resource: *resource,
                            ..*access
                        },
                    ) && (rule.action == ResourceAction::Deny
                        || bindings.iter().any(|binding| {
                            binding.resource_id == *resource
                                && binding.peer_id == access.provider
                                && binding.approved
                        }))
                })
                .min()?;
            Some((rule, resource))
        })
        .min_by_key(|(rule, resource)| (rule.priority, rule.action, rule.id, *resource));
    selected.map_or((ResourceAction::Deny, None, None), |(rule, resource)| {
        (rule.action, Some(rule.id), Some(resource))
    })
}
