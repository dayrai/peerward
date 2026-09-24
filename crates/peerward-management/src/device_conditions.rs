use crate::{DeviceSelector, ManagementError};
use peerward_types::PeerId;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DevicePlatform {
    Linux,
    Android,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceCapability {
    ManagedDns,
    ResourceConsumer,
    ExitConsumer,
    SubnetGateway,
    ExitGateway,
}

/// Device-signed software statements, never hardware attestation or antivirus evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceEvidence {
    pub version: String,
    pub platform: DevicePlatform,
    pub capabilities: BTreeSet<DeviceCapability>,
}
impl DeviceEvidence {
    pub fn current(platform: DevicePlatform) -> Self {
        use DeviceCapability::{
            ExitConsumer, ExitGateway, ManagedDns, ResourceConsumer, SubnetGateway,
        };
        let mut capabilities = BTreeSet::from([ManagedDns, ResourceConsumer, ExitConsumer]);
        if platform == DevicePlatform::Linux {
            capabilities.extend([SubnetGateway, ExitGateway]);
        }
        Self {
            version: env!("CARGO_PKG_VERSION").into(),
            platform,
            capabilities,
        }
    }
    pub fn validate(&self) -> Result<(), ManagementError> {
        canonical_device_version(&self.version)?;
        if self.platform == DevicePlatform::Android
            && self.capabilities.iter().any(|c| {
                matches!(
                    c,
                    DeviceCapability::SubnetGateway | DeviceCapability::ExitGateway
                )
            })
        {
            return Err(ManagementError::Invalid("device_evidence.capabilities"));
        }
        Ok(())
    }
}
fn canonical_device_version(value: &str) -> Result<semver::Version, ManagementError> {
    if value.len() > 128 {
        return Err(ManagementError::Invalid("device_version"));
    }
    let parsed =
        semver::Version::parse(value).map_err(|_| ManagementError::Invalid("device_version"))?;
    if parsed.to_string() != value {
        return Err(ManagementError::Invalid("device_version"));
    }
    Ok(parsed)
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceConditions {
    pub enabled: bool,
    #[serde(default)]
    pub scope: DeviceSelector,
    pub minimum_version: Option<String>,
    #[serde(default)]
    pub platforms: BTreeSet<DevicePlatform>,
    #[serde(default)]
    pub required_capabilities: BTreeSet<DeviceCapability>,
    #[serde(default)]
    pub minimum_credential_seconds: u32,
}
impl DeviceConditions {
    /// Conservative symbolic proof used to let emergency restrictions pass even
    /// if previously saved positive traffic assertions no longer succeed.
    pub fn only_restricts(&self, old: &Self) -> bool {
        if self == old || !old.enabled {
            return true;
        }
        if !self.enabled || self.scope != old.scope {
            return false;
        }
        (old.platforms.is_empty()
            || (!self.platforms.is_empty() && self.platforms.is_subset(&old.platforms)))
            && old
                .required_capabilities
                .is_subset(&self.required_capabilities)
            && self.minimum_credential_seconds >= old.minimum_credential_seconds
            && old.minimum_version.as_ref().is_none_or(|old| {
                self.minimum_version.as_ref().is_some_and(|new| {
                    match (canonical_device_version(new), canonical_device_version(old)) {
                        (Ok(new), Ok(old)) => !new.cmp_precedence(&old).is_lt(),
                        _ => false,
                    }
                })
            })
    }
    pub fn validate(&self) -> Result<(), ManagementError> {
        self.scope.validate()?;
        if let Some(version) = &self.minimum_version {
            canonical_device_version(version)?;
        }
        if self.minimum_credential_seconds > 86400 {
            return Err(ManagementError::Invalid("minimum_credential_seconds"));
        }
        Ok(())
    }
    /// Called only after the server verifies evidence identity, signature and credential.
    pub fn evaluate(
        &self,
        evidence: Option<&DeviceEvidence>,
        evidence_until: u64,
        credential_until: u64,
        now: u64,
    ) -> AdmissionDecision {
        let mut reasons = Vec::new();
        let valid_until = evidence_until
            .min(credential_until.saturating_sub(u64::from(self.minimum_credential_seconds)));
        match evidence {
            Some(evidence) if evidence.validate().is_ok() && evidence_until > now => {
                if !self.platforms.is_empty() && !self.platforms.contains(&evidence.platform) {
                    reasons.push(AdmissionReason::Platform);
                }
                if !self.required_capabilities.is_subset(&evidence.capabilities) {
                    reasons.push(AdmissionReason::Capabilities);
                }
                if self.minimum_version.as_ref().is_some_and(|min| {
                    match (
                        canonical_device_version(&evidence.version),
                        canonical_device_version(min),
                    ) {
                        (Ok(actual), Ok(minimum)) => actual.cmp_precedence(&minimum).is_lt(),
                        _ => true,
                    }
                }) {
                    reasons.push(AdmissionReason::Version);
                }
            }
            _ => reasons.push(AdmissionReason::EvidenceUnavailable),
        }
        if credential_until.saturating_sub(u64::from(self.minimum_credential_seconds)) <= now {
            reasons.push(AdmissionReason::Credential);
        }
        AdmissionDecision {
            allowed: reasons.is_empty(),
            valid_until: Some(valid_until),
            reasons,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionReason {
    EvidenceUnavailable,
    Version,
    Platform,
    Capabilities,
    Credential,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionDecision {
    pub allowed: bool,
    /// None only for devices outside the condition scope.
    pub valid_until: Option<u64>,
    pub reasons: Vec<AdmissionReason>,
}
impl AdmissionDecision {
    pub const fn unrestricted() -> Self {
        Self {
            allowed: true,
            valid_until: None,
            reasons: Vec::new(),
        }
    }
    pub fn permits(&self, now: u64) -> bool {
        self.allowed && self.valid_until.is_none_or(|until| now < until)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionConfiguration {
    pub enabled: bool,
    pub peers: std::collections::BTreeMap<PeerId, AdmissionDecision>,
}
impl AdmissionConfiguration {
    /// A refresh which only extends unchanged evidence does not tear down flows.
    pub fn same_requirements(&self, next: &Self) -> bool {
        self.enabled == next.enabled
            && self.peers.len() == next.peers.len()
            && self.peers.iter().all(|(peer, old)| {
                next.peers.get(peer).is_some_and(|new| {
                    old.allowed == new.allowed
                        && old.reasons == new.reasons
                        && match (old.valid_until, new.valid_until) {
                            (Some(old), Some(new)) => new >= old,
                            (None, None) => true,
                            _ => false,
                        }
                })
            })
    }
    pub fn permits(&self, peer: PeerId, now: u64) -> bool {
        !self.enabled
            || self
                .peers
                .get(&peer)
                .is_some_and(|decision| decision.permits(now))
    }
    pub fn validate(&self) -> Result<(), ManagementError> {
        if self.peers.len() > 4096
            || self
                .peers
                .values()
                .any(|d| d.reasons.len() > 5 || (d.allowed && !d.reasons.is_empty()))
        {
            return Err(ManagementError::Invalid("admission_configuration"));
        }
        Ok(())
    }
}
