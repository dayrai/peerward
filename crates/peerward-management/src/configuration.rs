use crate::{
    ConfigurationPart, DnsProfile, GatewayBinding, ManagementError, NetworkResource, ResourceRule,
    RouteAdvertisement, SignedLease, SignedManifest, content_digest,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceWithdrawal {
    pub target: crate::ResourceTarget,
    /// Capture exclusion only. This never grants a gateway packet authorization.
    pub providers: std::collections::BTreeSet<peerward_types::PeerId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderCaptureExclusion {
    pub target: crate::ResourceTarget,
    pub providers: std::collections::BTreeSet<peerward_types::PeerId>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceConfiguration {
    #[serde(default)]
    pub admission: crate::AdmissionConfiguration,
    #[serde(default)]
    pub collections: Vec<crate::ResolvedCollection>,
    /// Address shadows survive target replacement/deletion until an explicit matching approval.
    pub withdrawals: Vec<ResourceWithdrawal>,
    /// Former providers retain their directly connected LAN. No access is granted.
    pub capture_exclusions: Vec<ProviderCaptureExclusion>,
    pub resources: Vec<NetworkResource>,
    pub bindings: Vec<GatewayBinding>,
    pub advertisements: Vec<RouteAdvertisement>,
    pub rules: Vec<ResourceRule>,
}

impl ResourceConfiguration {
    /// Grants and forwarding intent exclude refreshed provider observations.
    pub fn same_grants(&self, other: &Self) -> bool {
        self.admission.same_requirements(&other.admission)
            && self.collections == other.collections
            && self.withdrawals == other.withdrawals
            && self.capture_exclusions == other.capture_exclusions
            && self.resources == other.resources
            && self.bindings == other.bindings
            && self.rules == other.rules
    }
    pub fn validate(&self) -> Result<(), ManagementError> {
        self.admission.validate()?;
        if self.collections.len() > 64
            || self
                .resources
                .iter()
                .filter(|r| r.definition.health_probe.is_some())
                .count()
                > 64
            || self.withdrawals.len() > 4096
            || self.capture_exclusions.len() > 4096
            || self.resources.len() > 4096
            || self.bindings.len() > 8192
            || self.advertisements.len() > 8192
            || self.rules.len() > 4096
        {
            return Err(ManagementError::Invalid("resource_configuration.bounds"));
        }
        for withdrawal in &self.withdrawals {
            withdrawal.target.validate()?;
            if withdrawal.providers.len() > 4096 {
                return Err(ManagementError::Invalid("withdrawal.providers"));
            }
        }
        for exclusion in &self.capture_exclusions {
            exclusion.target.validate()?;
            if !matches!(exclusion.target, crate::ResourceTarget::Subnet { .. })
                || exclusion.providers.len() > 4096
            {
                return Err(ManagementError::Invalid("capture_exclusion.providers"));
            }
        }
        let mut ids = std::collections::BTreeSet::new();
        for resource in &self.resources {
            resource.definition.validate()?;
            if resource.version == 0 || resource.id.is_nil() || !ids.insert(resource.id) {
                return Err(ManagementError::Invalid("resource_configuration.identity"));
            }
        }
        let mut collection_ids = std::collections::BTreeMap::new();
        for collection in &self.collections {
            if collection.id.get_version_num() != 4
                || collection.members.len() > 4096
                || collection
                    .members
                    .iter()
                    .any(|id| id.get_version_num() != 4)
                || (collection.kind == crate::CollectionKind::Resources
                    && !collection.members.is_subset(&ids))
                || collection_ids
                    .insert(collection.id, collection.kind)
                    .is_some()
            {
                return Err(ManagementError::Invalid(
                    "resource_configuration.collection",
                ));
            }
        }
        let mut bindings = std::collections::BTreeMap::new();
        let mut exit_providers = std::collections::BTreeMap::new();
        for binding in &self.bindings {
            binding.validate()?;
            if !ids.contains(&binding.resource_id) || bindings.insert(binding.id, binding).is_some()
            {
                return Err(ManagementError::Invalid("resource_configuration.binding"));
            }
            if binding.approved
                && self.resources.iter().any(|resource| {
                    resource.id == binding.resource_id
                        && matches!(
                            resource.definition.target,
                            crate::ResourceTarget::Internet { .. }
                        )
                })
                && exit_providers
                    .insert(binding.peer_id, binding.resource_id)
                    .is_some_and(|previous| previous != binding.resource_id)
            {
                return Err(ManagementError::Conflict("exit.provider_resource"));
            }
        }
        let mut advertisements = std::collections::BTreeSet::new();
        for ad in &self.advertisements {
            if ad.sequence == 0
                || ad.binding_version == 0
                || !advertisements.insert(ad.binding_id)
                || bindings
                    .get(&ad.binding_id)
                    .is_none_or(|binding| binding.peer_id != ad.peer_id)
            {
                return Err(ManagementError::Invalid(
                    "resource_configuration.advertisement",
                ));
            }
        }
        let mut rules = std::collections::BTreeSet::new();
        for rule in &self.rules {
            rule.validate()?;
            if !rules.insert(rule.id)
                || rule.resources.iter().any(|id| !ids.contains(id))
                || rule
                    .source_collections
                    .iter()
                    .any(|id| collection_ids.get(id) != Some(&crate::CollectionKind::Devices))
                || rule
                    .resource_collections
                    .iter()
                    .any(|id| collection_ids.get(id) != Some(&crate::CollectionKind::Resources))
            {
                return Err(ManagementError::Invalid("resource_configuration.rule"));
            }
        }
        Ok(())
    }
}

/// One bounded delivery; large unchanged identity/rule components travel via existing chunks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigurationDelivery {
    pub manifest: SignedManifest,
    pub lease: SignedLease,
    pub resources: ResourceConfiguration,
    pub dns: Vec<DnsProfile>,
}

impl ConfigurationDelivery {
    pub fn validate_payload(&self) -> Result<(), ManagementError> {
        self.resources.validate()?;
        if self.dns.len() > 256 {
            return Err(ManagementError::Invalid("dns.profiles"));
        }
        for profile in &self.dns {
            profile.validate()?;
        }
        if self
            .resources
            .resources
            .iter()
            .any(|resource| resource.mesh_id != self.manifest.manifest.mesh_id)
        {
            return Err(ManagementError::Invalid("resource.mesh_id"));
        }
        for (part, digest) in [
            (
                ConfigurationPart::Resources,
                content_digest(&self.resources)?,
            ),
            (ConfigurationPart::Dns, content_digest(&self.dns)?),
        ] {
            if self
                .manifest
                .manifest
                .parts
                .get(&part)
                .is_none_or(|reference| reference.digest != digest)
            {
                return Err(ManagementError::Incomplete);
            }
        }
        Ok(())
    }
}
