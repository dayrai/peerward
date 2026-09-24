use crate::{ManagementError, ResourceTarget};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Explicit TCP connect only; no application payload, URL, DNS, or credentials.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetProbe {
    pub address: IpAddr,
    pub port: u16,
}
impl TargetProbe {
    pub fn validate(&self, target: &ResourceTarget) -> Result<(), ManagementError> {
        if self.port == 0
            || !target.contains(self.address)
            || self.address.is_loopback()
            || self.address.is_multicast()
            || self.address.is_unspecified()
            || match self.address {
                IpAddr::V4(ip) => ip.is_link_local() || ip.is_broadcast(),
                IpAddr::V6(ip) => ip.is_unicast_link_local() || ip.to_ipv4_mapped().is_some(),
            }
        {
            return Err(ManagementError::Invalid("health_probe"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetProbeResult {
    Reachable,
    Refused,
    Timeout,
    Unavailable,
}
impl TargetProbeResult {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Reachable => "reachable",
            Self::Refused => "refused",
            Self::Timeout => "timeout",
            Self::Unavailable => "unavailable",
        }
    }
}
