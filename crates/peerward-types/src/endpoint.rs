use std::{fmt, net::IpAddr, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use thiserror::Error;
use url::{Host, Url};

/// Maximum endpoint count published for one Relay transport.
pub const MAX_RELAY_ENDPOINTS: usize = 16;

/// A Relay endpoint failed strict canonical validation.
#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
#[error(
    "endpoint must be canonical tcp://host:port or quic://host:port or wss://host:port/peerward"
)]
pub struct EndpointError;

/// Validates a canonical, duplicate-free Relay endpoint list.
pub fn validate_endpoint_list(endpoints: &[NetworkEndpoint]) -> Result<(), EndpointError> {
    if endpoints.is_empty() || endpoints.len() > MAX_RELAY_ENDPOINTS {
        return Err(EndpointError);
    }
    let mut canonical = std::collections::BTreeSet::new();
    if endpoints
        .iter()
        .all(|endpoint| canonical.insert(endpoint.as_str()))
    {
        Ok(())
    } else {
        Err(EndpointError)
    }
}

/// Canonical Relay endpoint containing an IP address or ASCII DNS name.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NetworkEndpoint {
    canonical: String,
    host: EndpointHost,
    port: u16,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum EndpointHost {
    Ip(IpAddr),
    Dns(String),
}

impl NetworkEndpoint {
    /// TLS WebSocket carrier, using the fixed shared-host upgrade path.
    pub fn is_wss(&self) -> bool {
        self.canonical.starts_with("wss://")
    }
    /// QUIC DATAGRAM with a reliable authenticated control stream.
    pub fn is_quic(&self) -> bool {
        self.canonical.starts_with("quic://")
    }
    pub fn is_tcp(&self) -> bool {
        self.canonical.starts_with("tcp://")
    }
    pub fn carrier_priority(&self) -> u8 {
        if self.is_quic() {
            0
        } else if self.is_wss() {
            1
        } else {
            2
        }
    }
    /// Returns the canonical signed and serialized representation.
    pub fn as_str(&self) -> &str {
        &self.canonical
    }

    /// Returns the host without IPv6 URI brackets.
    pub fn host(&self) -> String {
        match &self.host {
            EndpointHost::Ip(address) => address.to_string(),
            EndpointHost::Dns(name) => name.clone(),
        }
    }

    /// Returns the non-zero TCP port.
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// Returns an IP socket directly when the host is not a DNS name.
    pub fn socket_addr(&self) -> Option<std::net::SocketAddr> {
        match self.host {
            EndpointHost::Ip(address) => Some(std::net::SocketAddr::new(address, self.port)),
            EndpointHost::Dns(_) => None,
        }
    }

    /// Returns a resolver input that correctly brackets IPv6 literals.
    pub fn authority(&self) -> String {
        match &self.host {
            EndpointHost::Ip(IpAddr::V6(address)) => format!("[{address}]:{}", self.port),
            EndpointHost::Ip(address) => format!("{address}:{}", self.port),
            EndpointHost::Dns(name) => format!("{name}:{}", self.port),
        }
    }
}

impl FromStr for NetworkEndpoint {
    type Err = EndpointError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.trim() != value || !value.is_ascii() {
            return Err(EndpointError);
        }
        let parsed = Url::parse(value).map_err(|_| EndpointError)?;
        let wss = parsed.scheme() == "wss";
        if !(parsed.scheme() == "tcp" || parsed.scheme() == "quic" || wss)
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || if wss {
                parsed.path() != "/peerward"
            } else {
                !parsed.path().is_empty()
            }
        {
            return Err(EndpointError);
        }
        let port = parsed
            .port_or_known_default()
            .filter(|port| *port != 0)
            .ok_or(EndpointError)?;
        let host = match parsed.host().ok_or(EndpointError)? {
            Host::Ipv4(address) => checked_ip(IpAddr::V4(address))?,
            Host::Ipv6(address) => checked_ip(IpAddr::V6(address))?,
            Host::Domain(name) => {
                let name = name.to_ascii_lowercase();
                if let Ok(address) = name.parse::<IpAddr>() {
                    checked_ip(address)?
                } else {
                    if name
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || byte == b'.')
                    {
                        return Err(EndpointError);
                    }
                    validate_dns_name(&name)?;
                    EndpointHost::Dns(name)
                }
            }
        };
        let scheme = parsed.scheme();
        let path = if wss { "/peerward" } else { "" };
        let canonical = match &host {
            EndpointHost::Ip(IpAddr::V6(address)) => format!("{scheme}://[{address}]:{port}{path}"),
            EndpointHost::Ip(address) => format!("{scheme}://{address}:{port}{path}"),
            EndpointHost::Dns(name) => format!("{scheme}://{name}:{port}{path}"),
        };
        if !value.eq_ignore_ascii_case(&canonical) || (wss && !value.ends_with("/peerward")) {
            return Err(EndpointError);
        }
        Ok(Self {
            canonical,
            host,
            port,
        })
    }
}

fn checked_ip(address: IpAddr) -> Result<EndpointHost, EndpointError> {
    if address.is_unspecified() || address.is_multicast() {
        Err(EndpointError)
    } else {
        Ok(EndpointHost::Ip(address))
    }
}

fn validate_dns_name(name: &str) -> Result<(), EndpointError> {
    if name.is_empty()
        || name.len() > 253
        || name.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
    {
        Err(EndpointError)
    } else {
        Ok(())
    }
}

impl fmt::Display for NetworkEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.canonical)
    }
}

impl fmt::Debug for NetworkEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("NetworkEndpoint")
            .field(&self.canonical)
            .finish()
    }
}

impl Serialize for NetworkEndpoint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.canonical)
    }
}

impl<'de> Deserialize<'de> for NetworkEndpoint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_canonical_network_endpoints() {
        let dns: NetworkEndpoint = "tcp://Relay.Example:7777".parse().unwrap();
        assert_eq!(dns.authority(), "relay.example:7777");
        assert_eq!(dns.as_str(), "tcp://relay.example:7777");
        let ipv6: NetworkEndpoint = "tcp://[2001:db8::1]:7778".parse().unwrap();
        assert_eq!(ipv6.authority(), "[2001:db8::1]:7778");
        for invalid in [
            "relay.example:7777",
            "tcp://relay.example:0",
            "tcp://relay.example:7777/path",
            "tcp://user@relay.example:7777",
            "tcp://-relay.example:7777",
        ] {
            assert!(invalid.parse::<NetworkEndpoint>().is_err(), "{invalid}");
        }
    }

    #[test]
    fn serde_is_a_transparent_string() {
        let endpoint: NetworkEndpoint = "tcp://127.0.0.1:7777".parse().unwrap();
        let encoded = serde_json::to_string(&endpoint).unwrap();
        assert_eq!(encoded, "\"tcp://127.0.0.1:7777\"");
        assert_eq!(
            serde_json::from_str::<NetworkEndpoint>(&encoded).unwrap(),
            endpoint
        );
    }

    #[test]
    fn wss_requires_explicit_port_and_fixed_case_sensitive_path() {
        let endpoint: NetworkEndpoint = "wss://Relay.Example:443/peerward".parse().unwrap();
        assert!(endpoint.is_wss());
        assert_eq!(endpoint.as_str(), "wss://relay.example:443/peerward");
        assert_eq!(endpoint.port(), 443);
        for invalid in [
            "wss://relay.example/peerward",
            "ws://relay.example:443/peerward",
            "wss://relay.example:443/Peerward",
            "wss://relay.example:443/peerward?x=y",
            "wss://relay.example:443/peerward/",
            "wss://relay.example:443/a/../peerward",
            "tcp://0.0.0.0:7777",
            "tcp://224.0.0.1:7777",
            "tcp://127.1:7777",
        ] {
            assert!(invalid.parse::<NetworkEndpoint>().is_err(), "{invalid}");
        }
        let ipv4: NetworkEndpoint = "tcp://127.0.0.1:7777".parse().unwrap();
        assert_eq!(ipv4.socket_addr(), Some("127.0.0.1:7777".parse().unwrap()));
    }

    #[test]
    fn list_is_nonempty_bounded_and_unique() {
        let endpoint: NetworkEndpoint = "tcp://127.0.0.1:7777".parse().unwrap();
        assert!(validate_endpoint_list(std::slice::from_ref(&endpoint)).is_ok());
        assert!(validate_endpoint_list(&[]).is_err());
        assert!(validate_endpoint_list(&[endpoint.clone(), endpoint]).is_err());
        let lower: NetworkEndpoint = "tcp://relay.example:7777".parse().unwrap();
        let upper: NetworkEndpoint = "tcp://RELAY.EXAMPLE:7777".parse().unwrap();
        assert!(validate_endpoint_list(&[lower, upper]).is_err());
    }
}
