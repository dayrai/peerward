use crate::{ManagementError, ResourceTarget, name_valid};
use ipnet::IpNet;
use peerward_types::MeshId;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use uuid::Uuid;

/// A bounded approval authority, separate from permission to access a resource.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutoApprovalDefinition {
    pub name: String,
    #[serde(default)]
    pub enabled: bool,
    pub device_collection: Uuid,
    pub site_id: Uuid,
    pub prefixes: Vec<IpNet>,
}
impl AutoApprovalDefinition {
    pub fn validate(&self) -> Result<(), ManagementError> {
        if !name_valid(&self.name)
            || self.device_collection.get_version_num() != 4
            || self.site_id.get_version_num() != 4
            || self.prefixes.is_empty()
            || self.prefixes.len() > 32
        {
            return Err(ManagementError::Invalid("auto_approval"));
        }
        let mut unique = BTreeSet::new();
        for prefix in &self.prefixes {
            ResourceTarget::Subnet {
                prefix: *prefix,
                site_id: self.site_id,
            }
            .validate()?;
            if !unique.insert(*prefix) {
                return Err(ManagementError::Invalid("auto_approval.prefixes"));
            }
        }
        Ok(())
    }
    pub fn covers(&self, target: &ResourceTarget) -> bool {
        match target {
            ResourceTarget::Subnet { prefix, site_id } => {
                self.enabled
                    && *site_id == self.site_id
                    && self.prefixes.iter().any(|allowed| {
                        allowed.prefix_len() <= prefix.prefix_len()
                            && allowed.contains(&prefix.network())
                            && allowed.contains(&prefix.broadcast())
                    })
            }
            ResourceTarget::Internet { .. } => false,
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutoApprovalRule {
    pub id: Uuid,
    pub mesh_id: MeshId,
    pub version: u64,
    pub definition: AutoApprovalDefinition,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn approval_requires_an_explicit_site_prefix_and_never_includes_an_exit() {
        let mut rule = AutoApprovalDefinition {
            name: "Office gateways".into(),
            enabled: true,
            device_collection: Uuid::new_v4(),
            site_id: Uuid::new_v4(),
            prefixes: vec!["192.168.20.0/24".parse().unwrap()],
        };
        rule.validate().unwrap();
        let target = ResourceTarget::Subnet {
            prefix: "192.168.20.50/32".parse().unwrap(),
            site_id: rule.site_id,
        };
        assert!(rule.covers(&target));
        assert!(!rule.covers(&ResourceTarget::Subnet {
            prefix: "192.168.20.0/23".parse().unwrap(),
            site_id: rule.site_id
        }));
        assert!(!rule.covers(&ResourceTarget::Subnet {
            prefix: "192.168.20.50/32".parse().unwrap(),
            site_id: Uuid::new_v4()
        }));
        assert!(!rule.covers(&ResourceTarget::Internet {
            ipv4: true,
            ipv6: true
        }));
        rule.enabled = false;
        assert!(!rule.covers(&target));
        rule.prefixes = vec!["0.0.0.0/0".parse().unwrap()];
        assert!(rule.validate().is_err());
    }
}
