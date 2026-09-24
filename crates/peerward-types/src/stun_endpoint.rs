use std::{fmt, net::SocketAddr, str::FromStr};

use serde::{Deserialize, Serialize};

use crate::NetworkEndpoint;

/// Maximum configured discovery servers and resolved destinations per address family.
pub const MAX_STUN_SERVERS: usize = 8;

/// A STUN destination must be an ASCII DNS name or canonical IP, with an explicit UDP port.
#[derive(Debug, Clone, Copy, thiserror::Error, PartialEq, Eq)]
#[error("STUN endpoint must be host:port or [IPv6]:port with a non-zero port")]
pub struct StunEndpointError;

/// Validated STUN destination. DNS resolution belongs to the current underlay network.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct StunEndpoint(NetworkEndpoint);

impl StunEndpoint {
    /// Host without IPv6 brackets; no resolution is performed.
    pub fn host(&self) -> String {
        self.0.host()
    }

    /// Non-zero UDP port.
    pub const fn port(&self) -> u16 {
        self.0.port()
    }

    /// Numeric destination, if configured without DNS.
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        self.0.authority().parse().ok()
    }
}

/// Rejects non-unicast destinations, including DNS answers unsuitable for discovery.
pub fn valid_stun_destination(address: SocketAddr) -> bool {
    address.port() != 0
        && !address.ip().is_unspecified()
        && !address.ip().is_multicast()
        && match address {
            SocketAddr::V4(value) => !value.ip().is_broadcast(),
            SocketAddr::V6(value) => !value.ip().is_unicast_link_local() && value.scope_id() == 0,
        }
}

/// Empty lists are valid; repeated canonical names and oversized lists are rejected.
pub fn validate_stun_servers(servers: &[StunEndpoint]) -> Result<(), StunEndpointError> {
    let mut seen = std::collections::BTreeSet::new();
    if servers.len() <= MAX_STUN_SERVERS && servers.iter().all(|server| seen.insert(server)) {
        Ok(())
    } else {
        Err(StunEndpointError)
    }
}

impl FromStr for StunEndpoint {
    type Err = StunEndpointError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() > 261 {
            return Err(StunEndpointError);
        }
        let endpoint = format!("tcp://{value}")
            .parse::<NetworkEndpoint>()
            .map_err(|_| StunEndpointError)?;
        let address = endpoint.authority().parse::<SocketAddr>().ok();
        if (address.is_none()
            && endpoint
                .host()
                .bytes()
                .all(|byte| byte.is_ascii_digit() || byte == b'.'))
            || address.is_some_and(|address| !valid_stun_destination(address))
        {
            return Err(StunEndpointError);
        }
        Ok(Self(endpoint))
    }
}

impl TryFrom<String> for StunEndpoint {
    type Error = StunEndpointError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl From<StunEndpoint> for String {
    fn from(value: StunEndpoint) -> Self {
        value.to_string()
    }
}

impl fmt::Display for StunEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0.authority())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_and_dual_stack_literals_roundtrip_without_resolution() {
        for (input, canonical) in [
            ("STUN.Example:3478", "stun.example:3478"),
            ("127.0.0.1:3478", "127.0.0.1:3478"),
            ("[2001:db8::1]:443", "[2001:db8::1]:443"),
        ] {
            let endpoint: StunEndpoint = input.parse().unwrap();
            assert_eq!(endpoint.to_string(), canonical);
            let json = serde_json::to_string(&endpoint).unwrap();
            assert_eq!(json, format!("\"{canonical}\""));
            assert_eq!(
                serde_json::from_str::<StunEndpoint>(&json).unwrap(),
                endpoint
            );
        }
        assert!(
            "stun.example:3478"
                .parse::<StunEndpoint>()
                .unwrap()
                .socket_addr()
                .is_none()
        );
    }

    #[test]
    fn destinations_and_lists_reject_ambiguous_or_unsafe_values() {
        for input in [
            "stun.example",
            "stun.example:0",
            "udp://stun.example:3478",
            "u@stun.example:3478",
            "stun.example:3478/path",
            "stun.example:3478?x",
            " stun.example:3478",
            "0.0.0.0:3478",
            "255.255.255.255:3478",
            "224.0.0.1:3478",
            "[::]:3478",
            "[fe80::1]:3478",
            "[fe80::1%2]:3478",
            "[ff02::1]:3478",
            "2001:db8::1:3478",
        ] {
            assert!(input.parse::<StunEndpoint>().is_err(), "{input}");
        }
        let server: StunEndpoint = "stun.example:3478".parse().unwrap();
        assert!(validate_stun_servers(&[]).is_ok());
        assert!(validate_stun_servers(std::slice::from_ref(&server)).is_ok());
        assert!(
            validate_stun_servers(&[server.clone(), "STUN.EXAMPLE:3478".parse().unwrap()]).is_err()
        );
        assert!(validate_stun_servers(&vec![server; MAX_STUN_SERVERS + 1]).is_err());
    }
}
