use crate::{DeviceSelector, ManagementError};
use peerward_types::PeerId;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, SocketAddr},
};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", deny_unknown_fields)]
pub enum DnsRecord {
    A(std::net::Ipv4Addr),
    AAAA(std::net::Ipv6Addr),
    CNAME(String),
}

/// Every upstream in one group must serve the same namespace; no public fallback.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsRoute {
    pub suffix: String,
    pub upstreams: Vec<SocketAddr>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsProfile {
    pub id: Uuid,
    pub scope: DeviceSelector,
    pub search_domains: Vec<String>,
    pub routes: Vec<DnsRoute>,
    pub records: BTreeMap<String, Vec<DnsRecord>>,
}

/// Effective DNS configuration after scope resolution and equal-specificity conflict checking.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectiveDns {
    pub search_domains: Vec<String>,
    pub routes: Vec<DnsRoute>,
    pub records: BTreeMap<String, Vec<DnsRecord>>,
}

pub fn valid_dns_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name == name.to_ascii_lowercase()
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

impl DnsProfile {
    pub fn validate(&self) -> Result<(), ManagementError> {
        self.scope.validate()?;
        if self.id.get_version_num() != 4
            || self.search_domains.len() > 6
            || self.routes.len() > 64
            || self.records.len() > 4096
        {
            return Err(ManagementError::Invalid("dns.bounds"));
        }
        if self.search_domains.iter().any(|name| !valid_dns_name(name)) {
            return Err(ManagementError::Invalid("dns.search_domains"));
        }
        let mut suffixes = BTreeSet::new();
        for route in &self.routes {
            if !(route.suffix == "." || valid_dns_name(&route.suffix))
                || !suffixes.insert(&route.suffix)
                || route.upstreams.is_empty()
                || route.upstreams.len() > 4
                || route.upstreams.iter().any(|server| {
                    server.port() == 0 || server.ip().is_unspecified() || server.ip().is_multicast()
                })
            {
                return Err(ManagementError::Invalid("dns.routes"));
            }
        }
        validate_records(&self.records)
    }
}

fn validate_records(records: &BTreeMap<String, Vec<DnsRecord>>) -> Result<(), ManagementError> {
    for (name, values) in records {
        if !valid_dns_name(name) || values.is_empty() || values.len() > 16 {
            return Err(ManagementError::Invalid("dns.records"));
        }
        for value in values {
            if let DnsRecord::CNAME(target) = value
                && (values.len() != 1 || !valid_dns_name(target))
            {
                return Err(ManagementError::Invalid("dns.cname"));
            }
        }
        let mut visited = BTreeSet::new();
        let mut current = name;
        while let Some(values) = records.get(current) {
            if !visited.insert(current) {
                return Err(ManagementError::Conflict("dns.cname_cycle"));
            }
            match values.first() {
                Some(DnsRecord::CNAME(next)) => current = next,
                _ => break,
            }
        }
    }
    Ok(())
}

impl EffectiveDns {
    /// Bounded local answer chain shared by Linux and Android DNS packet adapters.
    /// An existing name with no matching type yields NODATA, never upstream fallback.
    pub fn answer_records(
        &self,
        name: &str,
        qtype: u16,
    ) -> Result<Vec<(String, DnsRecord)>, ManagementError> {
        let mut current = name;
        let mut output = Vec::new();
        for _ in 0..16 {
            let Some(records) = self.records.get(current) else {
                return Ok(output);
            };
            if let Some(DnsRecord::CNAME(target)) = records.first() {
                output.push((current.to_owned(), DnsRecord::CNAME(target.clone())));
                if qtype == 5 {
                    return Ok(output);
                }
                current = target;
            } else {
                output.extend(
                    records
                        .iter()
                        .filter(|record| {
                            matches!(
                                (qtype, record),
                                (1, DnsRecord::A(_)) | (28, DnsRecord::AAAA(_))
                            )
                        })
                        .cloned()
                        .map(|record| (current.to_owned(), record)),
                );
                return Ok(output);
            }
        }
        Err(ManagementError::Invalid("dns.cname_depth"))
    }

    pub fn for_peer(
        profiles: &[DnsProfile],
        peer: PeerId,
        address: IpAddr,
        labels: &BTreeMap<String, String>,
    ) -> Result<Self, ManagementError> {
        let mut result = Self::default();
        let mut routes = BTreeMap::<String, Vec<SocketAddr>>::new();
        for profile in profiles {
            profile.validate()?;
            if !profile.scope.matches(peer, address, labels) {
                continue;
            }
            for route in &profile.routes {
                let mut servers = route.upstreams.clone();
                servers.sort_unstable();
                servers.dedup();
                if let Some(existing) = routes.insert(route.suffix.clone(), servers.clone())
                    && existing != servers
                {
                    return Err(ManagementError::Conflict("dns.equal_suffix"));
                }
            }
            for (name, records) in &profile.records {
                if let Some(existing) = result.records.insert(name.clone(), records.clone())
                    && &existing != records
                {
                    return Err(ManagementError::Conflict("dns.record"));
                }
            }
            for domain in &profile.search_domains {
                if !result.search_domains.contains(domain) {
                    result.search_domains.push(domain.clone());
                }
            }
        }
        if result.search_domains.len() > 6 {
            return Err(ManagementError::Conflict("dns.search_domains"));
        }
        result.routes = routes
            .into_iter()
            .map(|(suffix, upstreams)| DnsRoute { suffix, upstreams })
            .collect();
        result
            .routes
            .sort_by_key(|route| (std::cmp::Reverse(route.suffix.len()), route.suffix.clone()));
        validate_records(&result.records)?;
        Ok(result)
    }

    /// A selected private route is terminal, even if every server fails.
    pub fn route(&self, name: &str) -> Option<&DnsRoute> {
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        self.routes.iter().find(|route| {
            route.suffix == "."
                || name == route.suffix
                || name
                    .strip_suffix(&route.suffix)
                    .is_some_and(|prefix| prefix.ends_with('.'))
        })
    }

    /// An explicit child namespace overrides the implicit Mesh authority.
    /// The Mesh suffix itself and the public default must not shadow Peer names.
    pub fn delegates_mesh_child(&self, name: &str, mesh_suffix: &str) -> bool {
        let suffix = mesh_suffix.trim_end_matches('.').to_ascii_lowercase();
        self.route(name).is_some_and(|route| {
            route
                .suffix
                .strip_suffix(&suffix)
                .is_some_and(|prefix| prefix.ends_with('.'))
        })
    }
}
