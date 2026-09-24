use crate::{ManagementError, name_valid};
use ipnet::IpNet;
use peerward_types::{MeshId, PeerId};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};
use uuid::Uuid;

/// Business target; tunnel identity belongs only to the approved provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ResourceTarget {
    Subnet { prefix: IpNet, site_id: Uuid },
    Internet { ipv4: bool, ipv6: bool },
}

impl ResourceTarget {
    pub fn specificity(&self) -> u8 {
        match self {
            Self::Subnet { prefix, .. } => prefix.prefix_len(),
            Self::Internet { .. } => 0,
        }
    }

    pub fn contains(&self, address: IpAddr) -> bool {
        match self {
            Self::Subnet { prefix, .. } => prefix.contains(&address),
            Self::Internet { ipv4, ipv6 } => {
                let family = if address.is_ipv4() { *ipv4 } else { *ipv6 };
                family && crate::internet_destination(address)
            }
        }
    }

    pub fn validate(&self) -> Result<(), ManagementError> {
        match self {
            Self::Subnet { prefix, site_id } => {
                if site_id.is_nil()
                    || prefix.prefix_len() == 0
                    || prefix.addr() != prefix.network()
                    || prefix.addr().is_unspecified()
                    || prefix.addr().is_multicast()
                    || prefix.addr().is_loopback()
                {
                    return Err(ManagementError::Invalid("target.prefix"));
                }
            }
            Self::Internet {
                ipv4: false,
                ipv6: false,
            } => return Err(ManagementError::Invalid("target.address_families")),
            Self::Internet { .. } => {}
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceDefinition {
    pub name: String,
    pub target: ResourceTarget,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health_probe: Option<crate::TargetProbe>,
}

impl ResourceDefinition {
    pub fn validate(&self) -> Result<(), ManagementError> {
        if !name_valid(&self.name) {
            return Err(ManagementError::Invalid("name"));
        }
        if self.labels.len() > 32
            || self.labels.iter().any(|(key, value)| {
                !name_valid(key)
                    || value.is_empty()
                    || value.len() > 256
                    || value.chars().any(char::is_control)
            })
        {
            return Err(ManagementError::Invalid("labels"));
        }
        self.target.validate()?;
        if let Some(probe) = &self.health_probe {
            probe.validate(&self.target)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkResource {
    pub id: Uuid,
    pub mesh_id: MeshId,
    pub version: u64,
    pub definition: ResourceDefinition,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForwardingMode {
    #[default]
    Snat,
    PreserveSource,
}

/// Administrator-owned grant. Advertisements cannot change approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayBinding {
    pub id: Uuid,
    pub resource_id: Uuid,
    pub peer_id: PeerId,
    pub version: u64,
    pub approved: bool,
    pub priority: u32,
    pub forwarding: ForwardingMode,
    pub return_route_confirmed: bool,
    pub approval_source: ApprovalSource,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ApprovalSource {
    Manual,
    Automatic { rule_id: Uuid, rule_version: u64 },
}

impl GatewayBinding {
    pub fn validate(&self) -> Result<(), ManagementError> {
        if self.id.get_version_num() != 4 || self.resource_id.is_nil() || self.version == 0 {
            return Err(ManagementError::Invalid("binding"));
        }
        if let ApprovalSource::Automatic {
            rule_id,
            rule_version,
        } = self.approval_source
            && (rule_id.get_version_num() != 4 || rule_version == 0)
        {
            return Err(ManagementError::Invalid("approval_source"));
        }
        if self.approved
            && self.forwarding == ForwardingMode::PreserveSource
            && !self.return_route_confirmed
        {
            return Err(ManagementError::Invalid("return_route_confirmed"));
        }
        Ok(())
    }
}

/// Authenticated provider observation, distinct from an administrator grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteAdvertisement {
    pub binding_version: u64,
    pub binding_id: Uuid,
    pub peer_id: PeerId,
    pub sequence: u64,
    pub published: bool,
    pub valid_until: u64,
    pub forwarding_ready: bool,
}

/// Explicit membership plus an optional simple conjunction of controlled labels.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceSelector {
    #[serde(default)]
    pub peers: BTreeSet<PeerId>,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    #[serde(default)]
    pub cidrs: Vec<IpNet>,
}

impl DeviceSelector {
    pub fn validate(&self) -> Result<(), ManagementError> {
        if self.peers.len() > 4096
            || self.labels.len() > 32
            || self.cidrs.len() > 64
            || self.labels.iter().any(|(key, value)| {
                key.is_empty()
                    || key.len() > 64
                    || value.len() > 128
                    || key.chars().chain(value.chars()).any(char::is_control)
            })
            || self
                .cidrs
                .iter()
                .any(|prefix| prefix.network() != prefix.addr())
        {
            return Err(ManagementError::Invalid("selector"));
        }
        Ok(())
    }

    pub fn matches(
        &self,
        peer: PeerId,
        address: IpAddr,
        labels: &BTreeMap<String, String>,
    ) -> bool {
        (self.peers.is_empty() || self.peers.contains(&peer))
            && self
                .labels
                .iter()
                .all(|(key, value)| labels.get(key) == Some(value))
            && (self.cidrs.is_empty() || self.cidrs.iter().any(|cidr| cidr.contains(&address)))
    }
}

/// Reject address ambiguity across sites, while permitting overlapping descriptions at one site.
pub fn validate_resource_conflicts<'a>(
    resource: &ResourceTarget,
    others: impl IntoIterator<Item = &'a ResourceTarget>,
    virtual_pools: &[IpNet],
) -> Result<(), ManagementError> {
    resource.validate()?;
    let ResourceTarget::Subnet { prefix, site_id } = resource else {
        return Ok(());
    };
    if virtual_pools.iter().any(|pool| overlaps(*prefix, *pool)) {
        return Err(ManagementError::Conflict("virtual_pool"));
    }
    for target in others {
        if let ResourceTarget::Subnet {
            prefix: other,
            site_id: other_site,
        } = target
            && site_id != other_site
            && overlaps(*prefix, *other)
        {
            return Err(ManagementError::Conflict("site_address_ambiguity"));
        }
    }
    Ok(())
}

pub fn overlaps(left: IpNet, right: IpNet) -> bool {
    left.contains(&right.network()) || right.contains(&left.network())
}
