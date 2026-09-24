//! Strong identifiers and shared domain values.

mod correlation;
mod diagnostics;
mod endpoint;
mod protocol;
mod stun_endpoint;

pub use correlation::{CorrelationContext, CorrelationError};
pub use diagnostics::{DiagnosticCode, RetryHint, RuntimeDiagnostic};
pub use endpoint::{EndpointError, MAX_RELAY_ENDPOINTS, NetworkEndpoint, validate_endpoint_list};
pub use protocol::{IpProtocol, PolicyProtocol, ServiceProtocol};
pub use stun_endpoint::{
    MAX_STUN_SERVERS, StunEndpoint, StunEndpointError, valid_stun_destination,
    validate_stun_servers,
};

use core::{fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use thiserror::Error;
use uuid::{Uuid, Variant, Version};

/// Maximum labels carried by a resource or policy selector.
pub const MAX_LABELS: usize = 64;
/// Maximum ordered rules in a policy document.
pub const MAX_POLICY_RULES: usize = 1024;
/// Maximum exact Peer alternatives in a policy selector.
pub const MAX_SELECTOR_PEERS: usize = 1024;
/// Maximum CIDR alternatives in a policy selector.
pub const MAX_SELECTOR_CIDRS: usize = 256;
/// Maximum destination-port intervals in one policy rule.
pub const MAX_PORT_SPANS: usize = 256;
/// Maximum explicitly reserved addresses in one Mesh.
pub const MAX_RESERVED_ADDRESSES: usize = 4096;
/// Maximum serialized event block accepted by SSE consumers.
pub const MAX_SSE_EVENT_BYTES: usize = 256 * 1024;
/// Maximum complete signed distribution state accepted from bounded wire chunks.
pub const MAX_SIGNED_STATE_BYTES: usize = 32 * 1024 * 1024;
/// Maximum independently bounded chunks in one signed distribution state.
pub const MAX_SIGNED_STATE_CHUNKS: u32 = 1024;

/// A supplied identifier was not a UUID version 4 value.
#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
#[error("identifier must be a UUIDv4")]
pub struct InvalidId;

macro_rules! domain_id {
    ($name:ident) => {
        #[doc = concat!("Persistent `UUIDv4` identifier for a `", stringify!($name), "` resource.")]
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(Uuid);

        impl $name {
            /// Creates a fresh random identifier.
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }

            /// Validates and wraps a `UUIDv4`.
            pub fn from_uuid(value: Uuid) -> Result<Self, InvalidId> {
                if value.get_version() == Some(Version::Random)
                    && value.get_variant() == Variant::RFC4122
                {
                    Ok(Self(value))
                } else {
                    Err(InvalidId)
                }
            }

            /// Returns the canonical 16 UUID bytes.
            pub const fn as_bytes(&self) -> &[u8; 16] {
                self.0.as_bytes()
            }

            /// Returns the underlying UUID.
            pub const fn into_uuid(self) -> Uuid {
                self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.0)
                    .finish()
            }
        }

        impl FromStr for $name {
            type Err = InvalidId;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Uuid::parse_str(value)
                    .map_err(|_| InvalidId)
                    .and_then(Self::from_uuid)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.0.hyphenated().to_string())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                value.parse().map_err(de::Error::custom)
            }
        }
    };
}

domain_id!(MeshId);
domain_id!(PeerId);
domain_id!(RelayId);
domain_id!(TicketId);
domain_id!(ServiceId);
domain_id!(AttachmentId);
domain_id!(EventId);
domain_id!(RuleId);
domain_id!(CredentialSerial);
domain_id!(RotationId);

/// Seconds since the Unix epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct UnixTime(pub u64);

/// The identity role bound into a subject credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectRole {
    /// A mesh peer.
    Peer,
    /// A packet relay.
    Relay,
}

impl SubjectRole {
    /// Stable transcript tag.
    pub const fn transcript_tag(self) -> u8 {
        match self {
            Self::Peer => 1,
            Self::Relay => 2,
        }
    }
}

/// Layer-4 protocols available to services and policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransportProtocol {
    /// Transmission Control Protocol.
    Tcp,
    /// User Datagram Protocol.
    Udp,
    /// Internet Control Message Protocol.
    Icmp,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_rejects_non_v4_uuid() {
        let nil = Uuid::nil();
        assert_eq!(MeshId::from_uuid(nil), Err(InvalidId));
    }

    #[test]
    fn identifiers_are_domain_separated_at_compile_time() {
        let raw = Uuid::parse_str("970a3f18-1c6f-4da6-a223-f9623958a928").unwrap();
        let mesh = MeshId::from_uuid(raw).unwrap();
        let peer = PeerId::from_uuid(raw).unwrap();
        assert_eq!(mesh.as_bytes(), peer.as_bytes());
        assert_eq!(mesh.to_string(), raw.to_string());
    }

    #[test]
    fn credential_serial_is_a_uuidv4() {
        let serial = CredentialSerial::new();
        assert_eq!(serial.into_uuid().get_version(), Some(Version::Random));
        assert_eq!(CredentialSerial::from_uuid(Uuid::nil()), Err(InvalidId));
    }

    #[test]
    fn domain_ids_reject_non_rfc_variants_with_version_four_bits() {
        for variant in [0x00, 0x40, 0xc0, 0xe0] {
            let mut bytes = *Uuid::new_v4().as_bytes();
            bytes[8] = variant;
            let raw = Uuid::from_bytes(bytes);
            // The UUID crate's version accessor does not validate the variant.
            assert_eq!(raw.get_version(), Some(Version::Random));
            assert_eq!(MeshId::from_uuid(raw), Err(InvalidId));
            assert_eq!(PeerId::from_uuid(raw), Err(InvalidId));
            assert_eq!(CredentialSerial::from_uuid(raw), Err(InvalidId));
            assert!(raw.to_string().parse::<MeshId>().is_err());
            assert!(serde_json::from_str::<MeshId>(&format!("\"{raw}\"")).is_err());
        }
    }
}
