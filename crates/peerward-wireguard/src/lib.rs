//! Standard `WireGuard` sessions, independent of the platform and the carrier.
//!
//! This boundary receives keys only after credential and directory validation.
//! IP ownership and ACL enforcement remain the caller's responsibility.

use std::{net::SocketAddr, time::Duration};

use thiserror::Error;

mod engine;
mod queue;

pub use engine::Engine;

pub type Key = [u8; 32];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ingress {
    Direct(SocketAddr),
    /// Public key selected from the authenticated Relay source's credentials.
    Relay {
        peer: Key,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub enum Event {
    /// An unmodified WG datagram, including handshake/cookie/timer traffic.
    Network { peer: Option<Key>, packet: Vec<u8> },
    /// Authenticated IP packet; still subject to source ownership and ACL.
    Plaintext { peer: Key, packet: Vec<u8> },
}

#[derive(Clone, Debug)]
pub struct Limits {
    pub peers: usize,
    pub mtu: usize,
    pub queued_packets: usize,
    pub queued_bytes: usize,
    pub total_queued_bytes: usize,
    pub queue_lifetime: Duration,
    pub handshakes_per_second: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            peers: 20_000,
            mtu: DEFAULT_MTU,
            queued_packets: 64,
            queued_bytes: 256 * 1024,
            total_queued_bytes: 16 * 1024 * 1024,
            queue_lifetime: Duration::from_secs(3),
            handshakes_per_second: 100,
        }
    }
}

impl Limits {
    fn validate(&self) -> Result<(), Error> {
        if self.peers == 0
            || self.peers > 20_000
            || !(1280..=9000).contains(&self.mtu)
            || self.queued_packets == 0
            || self.queued_packets > 512
            || self.queued_bytes < self.mtu
            || self.queued_bytes > 4 * 1024 * 1024
            || self.total_queued_bytes < self.queued_bytes
            || self.total_queued_bytes > 64 * 1024 * 1024
            || self.queue_lifetime.is_zero()
            || self.queue_lifetime > Duration::from_secs(10)
            || self.handshakes_per_second == 0
            || self.handshakes_per_second > 1000
        {
            return Err(Error::InvalidLimits);
        }
        Ok(())
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    #[error("WireGuard credential engine is closed")]
    Closed,
    #[error("invalid WireGuard resource limits")]
    InvalidLimits,
    #[error("WireGuard peer limit reached")]
    PeerLimit,
    #[error("invalid WireGuard public key")]
    InvalidKey,
    #[error("unknown WireGuard peer")]
    UnknownPeer,
    #[error("unknown WireGuard receiver index")]
    UnknownIndex,
    #[error("WireGuard authentication failed")]
    Authentication,
    #[error("packet is not authorized")]
    Unauthorized,
    #[error("WireGuard plaintext queue is full")]
    QueueFull,
    #[error("invalid inner IP packet")]
    InvalidPacket,
    #[error("packet exceeds tunnel MTU")]
    PacketTooLarge,
}

/// Conservative default inner IP MTU shared by Linux and Android.
pub const DEFAULT_MTU: usize = 1280;

#[cfg(test)]
mod tests;
