use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use rand::{RngCore, rngs::OsRng};
use tokio::net::UdpSocket;

use crate::P2pError;

/// RFC 5389 magic cookie used to distinguish STUN from Peerward datagrams.
pub const STUN_MAGIC: u32 = 0x2112_a442;
const STUN_BINDING_REQUEST: u16 = 0x0001;
pub(crate) const STUN_BINDING_SUCCESS: u16 = 0x0101;
pub(crate) const XOR_MAPPED_ADDRESS: u16 = 0x0020;

/// One RFC 5389 transaction identity and request bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StunRequest {
    /// Random 96-bit transaction identifier.
    pub transaction: [u8; 12],
    /// Complete binding request.
    pub bytes: [u8; 20],
}

impl StunRequest {
    /// Creates a binding request with an OS-random transaction.
    pub fn random() -> Self {
        let mut transaction = [0_u8; 12];
        OsRng.fill_bytes(&mut transaction);
        Self::from_transaction(transaction)
    }

    /// Creates a deterministic request for tests and golden vectors.
    pub fn from_transaction(transaction: [u8; 12]) -> Self {
        let mut bytes = [0_u8; 20];
        bytes[..2].copy_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());
        bytes[4..8].copy_from_slice(&STUN_MAGIC.to_be_bytes());
        bytes[8..20].copy_from_slice(&transaction);
        Self { transaction, bytes }
    }

    /// Parses the XOR-MAPPED-ADDRESS from the matching success response.
    pub fn parse_response(&self, bytes: &[u8]) -> Result<SocketAddr, P2pError> {
        if !(20..=1024).contains(&bytes.len())
            || u16::from_be_bytes([bytes[0], bytes[1]]) != STUN_BINDING_SUCCESS
            || u32::from_be_bytes(bytes[4..8].try_into().map_err(|_| P2pError::Stun)?) != STUN_MAGIC
            || bytes[8..20] != self.transaction
        {
            return Err(P2pError::Stun);
        }
        let declared = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
        if declared.checked_add(20) != Some(bytes.len()) || !declared.is_multiple_of(4) {
            return Err(P2pError::Stun);
        }
        let mut cursor = 20;
        let mut mapped = None;
        while cursor < bytes.len() {
            if cursor + 4 > bytes.len() {
                return Err(P2pError::Stun);
            }
            let kind = u16::from_be_bytes([bytes[cursor], bytes[cursor + 1]]);
            let length = usize::from(u16::from_be_bytes([bytes[cursor + 2], bytes[cursor + 3]]));
            let start = cursor + 4;
            let end = start.checked_add(length).ok_or(P2pError::Stun)?;
            if end > bytes.len() {
                return Err(P2pError::Stun);
            }
            if kind == XOR_MAPPED_ADDRESS {
                if mapped.is_some() {
                    return Err(P2pError::Stun);
                }
                let address = decode_xor_address(&bytes[start..end], &self.transaction)?;
                if address.port() == 0
                    || address.ip().is_unspecified()
                    || address.ip().is_multicast()
                {
                    return Err(P2pError::Stun);
                }
                mapped = Some(address);
            }
            cursor = end
                .checked_add((4 - length % 4) % 4)
                .ok_or(P2pError::Stun)?;
            if cursor > bytes.len() {
                return Err(P2pError::Stun);
            }
        }
        mapped.ok_or(P2pError::Stun)
    }
}

fn decode_xor_address(value: &[u8], transaction: &[u8; 12]) -> Result<SocketAddr, P2pError> {
    if value.len() < 4 || value[0] != 0 {
        return Err(P2pError::Stun);
    }
    let port = u16::from_be_bytes([value[2], value[3]]) ^ (STUN_MAGIC >> 16) as u16;
    match value[1] {
        1 if value.len() == 8 => {
            let mask = STUN_MAGIC.to_be_bytes();
            let mut address = [0_u8; 4];
            for index in 0..4 {
                address[index] = value[4 + index] ^ mask[index];
            }
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(address)), port))
        }
        2 if value.len() == 20 => {
            let mut mask = [0_u8; 16];
            mask[..4].copy_from_slice(&STUN_MAGIC.to_be_bytes());
            mask[4..].copy_from_slice(transaction);
            let mut address = [0_u8; 16];
            for index in 0..16 {
                address[index] = value[4 + index] ^ mask[index];
            }
            Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(address)), port))
        }
        _ => Err(P2pError::Stun),
    }
}

/// Retransmits a binding transaction and accepts only a matching response.
/// Requires exclusive receive ownership; shared data sockets must use a demux.
pub async fn discover_mapping(
    socket: &UdpSocket,
    server: SocketAddr,
    timeout: Duration,
) -> Result<SocketAddr, P2pError> {
    let request = StunRequest::random();
    let deadline = tokio::time::Instant::now() + timeout;
    let mut retry = tokio::time::Instant::now();
    let mut backoff = Duration::from_millis(250);
    let mut response = [0_u8; 1024];
    loop {
        tokio::select! {
            biased;
            () = tokio::time::sleep_until(deadline) => return Err(P2pError::Timeout),
            () = tokio::time::sleep_until(retry) => {
                socket.send_to(&request.bytes, server).await?;
                retry = tokio::time::Instant::now() + backoff;
                backoff = (backoff * 2).min(Duration::from_secs(1));
            }
            received = socket.recv_from(&mut response) => {
                let (length, source) = received?;
                if source == server && let Ok(mapping) = request.parse_response(&response[..length]) {
                    return Ok(mapping);
                }
            }
        }
    }
}

/// Coarse NAT mapping behavior inferred from multiple STUN destinations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatBehavior {
    /// Every server observed the same external endpoint.
    EndpointIndependent,
    /// Mapping changed across destinations; simultaneous probing remains possible.
    EndpointDependent,
    /// No matching STUN observation exists.
    Unknown,
}

/// Classifies mapping observations without guessing filtering behavior.
pub fn classify_nat(observations: &[SocketAddr]) -> NatBehavior {
    let Some(first) = observations.first() else {
        return NatBehavior::Unknown;
    };
    if observations.iter().all(|endpoint| endpoint == first) {
        NatBehavior::EndpointIndependent
    } else {
        NatBehavior::EndpointDependent
    }
}
