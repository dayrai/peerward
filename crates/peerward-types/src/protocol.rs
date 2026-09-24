use serde::{Deserialize, Serialize};

/// Service transports represented in signed service directories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ServiceProtocol {
    /// Transmission Control Protocol.
    Tcp,
    /// User Datagram Protocol.
    Udp,
}

/// Protocol selector used by ordered policy rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyProtocol {
    /// Match every IP protocol number.
    Any,
    /// Match TCP.
    Tcp,
    /// Match UDP.
    Udp,
    /// Match `ICMPv4` or `ICMPv6`.
    Icmp,
}

/// An exact IP protocol or IPv6 next-header number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IpProtocol(u8);

impl IpProtocol {
    /// ICMP for IPv4.
    pub const ICMPV4: Self = Self(1);
    /// TCP.
    pub const TCP: Self = Self(6);
    /// UDP.
    pub const UDP: Self = Self(17);
    /// ICMP for IPv6.
    pub const ICMPV6: Self = Self(58);

    /// Preserves any protocol number, including unknown values.
    pub const fn new(value: u8) -> Self {
        Self(value)
    }

    /// Returns the exact wire value.
    pub const fn get(self) -> u8 {
        self.0
    }

    /// Returns whether the protocol is either ICMP family.
    pub const fn is_icmp(self) -> bool {
        self.0 == Self::ICMPV4.0 || self.0 == Self::ICMPV6.0
    }
}

impl PolicyProtocol {
    /// Matches a parsed IP protocol without discarding unknown numbers.
    pub const fn matches(self, actual: IpProtocol) -> bool {
        match self {
            Self::Any => true,
            Self::Tcp => actual.0 == IpProtocol::TCP.0,
            Self::Udp => actual.0 == IpProtocol::UDP.0,
            Self::Icmp => actual.is_icmp(),
        }
    }
}
