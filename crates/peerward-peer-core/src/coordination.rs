//! Strict, bounded coordination carried exclusively inside authenticated `WireGuard` IP packets.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::PeerError;

pub const PORT: u16 = 51821;
pub const MAX_CANDIDATES: usize = 32;
const HEADER: usize = 28;
pub const MAX_PROBE_PADDING: u16 = 9000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    Candidates(Vec<SocketAddr>),
    CandidatesAck,
    Probe,
    ProbeAck,
    /// Authenticated path check with this many zero padding bytes.
    MtuProbe(u16),
    /// Checks one approved gateway binding over the existing authenticated carrier.
    GatewayProbe(uuid::Uuid),
    GatewayAck(uuid::Uuid, bool),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Coordination {
    pub generation: u64,
    pub transaction: [u8; 16],
    pub message: Message,
}

pub fn valid_endpoint(endpoint: SocketAddr) -> bool {
    endpoint.port() != 0
        && !endpoint.ip().is_unspecified()
        && !endpoint.ip().is_loopback()
        && !endpoint.ip().is_multicast()
        && match endpoint {
            SocketAddr::V4(address) => !address.ip().is_broadcast(),
            SocketAddr::V6(address) => {
                !address.ip().is_unicast_link_local() && address.scope_id() == 0
            }
        }
}

impl Coordination {
    pub fn encode(&self) -> Result<Vec<u8>, PeerError> {
        let kind = match &self.message {
            Message::Candidates(_) => 1,
            Message::CandidatesAck => 2,
            Message::Probe => 3,
            Message::ProbeAck => 4,
            Message::MtuProbe(_) => 5,
            Message::GatewayProbe(_) => 6,
            Message::GatewayAck(_, _) => 7,
        };
        let mut bytes = vec![1, kind, 0, 0];
        bytes.extend_from_slice(&self.generation.to_be_bytes());
        bytes.extend_from_slice(&self.transaction);
        match self.message {
            Message::GatewayProbe(id) | Message::GatewayAck(id, _) => {
                if id.get_version_num() != 4 || self.generation == 0 {
                    return Err(PeerError::InvalidPacket);
                }
                bytes.extend_from_slice(id.as_bytes());
                if let Message::GatewayAck(_, ready) = self.message {
                    bytes.push(u8::from(ready));
                }
            }
            _ => {}
        }
        if let Message::Candidates(candidates) = &self.message {
            validate_candidates(candidates)?;
            bytes.push(u8::try_from(candidates.len()).map_err(|_| PeerError::InvalidPacket)?);
            for endpoint in candidates {
                match endpoint.ip() {
                    IpAddr::V4(ip) => {
                        bytes.push(4);
                        bytes.extend_from_slice(&ip.octets());
                    }
                    IpAddr::V6(ip) => {
                        bytes.push(6);
                        bytes.extend_from_slice(&ip.octets());
                    }
                }
                bytes.extend_from_slice(&endpoint.port().to_be_bytes());
            }
        }
        if let Message::MtuProbe(padding) = self.message {
            if padding == 0 || padding > MAX_PROBE_PADDING {
                return Err(PeerError::InvalidPacket);
            }
            bytes.resize(HEADER + usize::from(padding), 0);
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, PeerError> {
        if bytes.len() < HEADER
            || bytes.len() > HEADER + usize::from(MAX_PROBE_PADDING)
            || bytes[0] != 1
            || bytes[2..4] != [0, 0]
        {
            return Err(PeerError::InvalidPacket);
        }
        let generation = u64::from_be_bytes(
            bytes[4..12]
                .try_into()
                .map_err(|_| PeerError::InvalidPacket)?,
        );
        let transaction = bytes[12..28]
            .try_into()
            .map_err(|_| PeerError::InvalidPacket)?;
        let mut body = &bytes[HEADER..];
        let message = match bytes[1] {
            1 => {
                let count = usize::from(*body.first().ok_or(PeerError::InvalidPacket)?);
                body = &body[1..];
                if count > MAX_CANDIDATES {
                    return Err(PeerError::InvalidPacket);
                }
                let mut candidates = Vec::with_capacity(count);
                for _ in 0..count {
                    let family = take::<1>(&mut body)?[0];
                    let ip = match family {
                        4 => IpAddr::V4(Ipv4Addr::from(take::<4>(&mut body)?)),
                        6 => IpAddr::V6(Ipv6Addr::from(take::<16>(&mut body)?)),
                        _ => return Err(PeerError::InvalidPacket),
                    };
                    candidates.push(SocketAddr::new(
                        ip,
                        u16::from_be_bytes(take::<2>(&mut body)?),
                    ));
                }
                validate_candidates(&candidates)?;
                Message::Candidates(candidates)
            }
            2 => Message::CandidatesAck,
            3 => Message::Probe,
            4 => Message::ProbeAck,
            kind @ (6 | 7) => {
                let id = uuid::Uuid::from_bytes(take::<16>(&mut body)?);
                if id.get_version_num() != 4 || generation == 0 {
                    return Err(PeerError::InvalidPacket);
                }
                if kind == 6 {
                    Message::GatewayProbe(id)
                } else {
                    let ready = match take::<1>(&mut body)?[0] {
                        0 => false,
                        1 => true,
                        _ => return Err(PeerError::InvalidPacket),
                    };
                    Message::GatewayAck(id, ready)
                }
            }
            5 if !body.is_empty() && body.iter().all(|byte| *byte == 0) => {
                let padding = u16::try_from(body.len()).map_err(|_| PeerError::InvalidPacket)?;
                body = &[];
                Message::MtuProbe(padding)
            }
            _ => return Err(PeerError::InvalidPacket),
        };
        if !body.is_empty() {
            return Err(PeerError::InvalidPacket);
        }
        Ok(Self {
            generation,
            transaction,
            message,
        })
    }
}

pub fn validate_candidates(candidates: &[SocketAddr]) -> Result<(), PeerError> {
    let mut unique = std::collections::BTreeSet::new();
    if candidates.len() > MAX_CANDIDATES
        || candidates
            .iter()
            .any(|candidate| !valid_endpoint(*candidate) || !unique.insert(*candidate))
    {
        return Err(PeerError::InvalidPacket);
    }
    Ok(())
}

/// Filters local discovery observations before advertising them. Remote coordination
/// messages must still use strict validation; a STUN mapping alone is not a usable path.
pub fn filter_wireguard_candidates(
    endpoints: impl IntoIterator<Item = SocketAddr>,
) -> Vec<SocketAddr> {
    let mut unique = std::collections::BTreeSet::new();
    endpoints
        .into_iter()
        .filter(|endpoint| valid_endpoint(*endpoint) && unique.insert(*endpoint))
        .take(MAX_CANDIDATES)
        .collect()
}

/// No IP options, extension headers or fragmentation are allowed on the internal channel.
pub fn decode_ip(packet: &[u8]) -> Result<Coordination, PeerError> {
    let parsed = peerward_dataplane::parse_packet(packet).map_err(|_| PeerError::InvalidPacket)?;
    let header = match packet.first() {
        Some(0x45) => 20,
        Some(0x60) if packet.get(6) == Some(&17) => 40,
        _ => return Err(PeerError::InvalidPacket),
    };
    if parsed.protocol != 17
        || parsed.source_port != Some(PORT)
        || parsed.destination_port != Some(PORT)
        || parsed.fragment.is_some()
    {
        return Err(PeerError::InvalidPacket);
    }
    Coordination::decode(packet.get(header + 8..).ok_or(PeerError::InvalidPacket)?)
}

pub fn encode_ip(
    source: IpAddr,
    destination: IpAddr,
    coordination: &Coordination,
) -> Result<Vec<u8>, PeerError> {
    let body = coordination.encode()?;
    let udp_len = u16::try_from(body.len() + 8).map_err(|_| PeerError::InvalidPacket)?;
    let mut pseudo = Vec::new();
    let mut packet = match (source, destination) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            let mut header = vec![0; 20];
            header[0] = 0x45;
            header[8] = 64;
            header[9] = 17;
            header[2..4].copy_from_slice(&(udp_len + 20).to_be_bytes());
            header[12..16].copy_from_slice(&source.octets());
            header[16..20].copy_from_slice(&destination.octets());
            let sum = checksum(&header);
            header[10..12].copy_from_slice(&sum.to_be_bytes());
            pseudo.extend_from_slice(&header[12..20]);
            pseudo.extend_from_slice(&[0, 17]);
            pseudo.extend_from_slice(&udp_len.to_be_bytes());
            header
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            let mut header = vec![0; 40];
            header[0] = 0x60;
            header[6] = 17;
            header[7] = 64;
            header[4..6].copy_from_slice(&udp_len.to_be_bytes());
            header[8..24].copy_from_slice(&source.octets());
            header[24..40].copy_from_slice(&destination.octets());
            pseudo.extend_from_slice(&header[8..40]);
            pseudo.extend_from_slice(&u32::from(udp_len).to_be_bytes());
            pseudo.extend_from_slice(&[0, 0, 0, 17]);
            header
        }
        _ => return Err(PeerError::NoRoute),
    };
    let mut udp = Vec::from(PORT.to_be_bytes());
    udp.extend_from_slice(&PORT.to_be_bytes());
    udp.extend_from_slice(&udp_len.to_be_bytes());
    udp.extend_from_slice(&[0, 0]);
    udp.extend_from_slice(&body);
    pseudo.extend_from_slice(&udp);
    let sum = checksum(&pseudo);
    udp[6..8].copy_from_slice(&(if sum == 0 { u16::MAX } else { sum }).to_be_bytes());
    packet.extend(udp);
    Ok(packet)
}

fn take<const N: usize>(bytes: &mut &[u8]) -> Result<[u8; N], PeerError> {
    let value = bytes
        .get(..N)
        .ok_or(PeerError::InvalidPacket)?
        .try_into()
        .map_err(|_| PeerError::InvalidPacket)?;
    *bytes = &bytes[N..];
    Ok(value)
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = bytes
        .chunks(2)
        .map(|pair| u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)])))
        .sum();
    while sum > u32::from(u16::MAX) {
        sum = (sum & 65535) + (sum >> 16);
    }
    !u16::try_from(sum).expect("folded checksum")
}

#[cfg(test)]
#[path = "coordination_tests.rs"]
mod tests;
