use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Instant};

use gotatun::{
    noise::{
        Tunn, TunnResult, handshake::parse_handshake_anon, index_table::IndexTable,
        rate_limiter::RateLimiter,
    },
    packet::{Packet, WgKind},
};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::{Error, Event, Ingress, Key, Limits, queue::Queue};

struct Peer {
    tunnel: Tunn,
    pending: Queue,
}

/// One local credential's `WireGuard` device. Paths never own cryptographic state.
///
/// The owner must remove keys on expiry, exact revocation or directory deletion.
/// Each Mesh owns its own engine; credential overlap uses at most two engines.
pub struct Engine {
    private: StaticSecret,
    public: PublicKey,
    indices: IndexTable,
    owners: HashMap<u32, Key>,
    peers: HashMap<Key, Peer>,
    queued_bytes: usize,
    limiter: Arc<RateLimiter>,
    limits: Limits,
    closed: bool,
}

impl Engine {
    pub fn new(private: StaticSecret, limits: Limits) -> Result<Self, Error> {
        Self::with_indices(private, limits, IndexTable::from_os_rng())
    }

    fn with_indices(
        private: StaticSecret,
        limits: Limits,
        indices: IndexTable,
    ) -> Result<Self, Error> {
        limits.validate()?;
        let public = PublicKey::from(&private);
        Ok(Self {
            private,
            public,
            indices,
            owners: HashMap::new(),
            peers: HashMap::new(),
            queued_bytes: 0,
            limiter: Arc::new(RateLimiter::new(&public, limits.handshakes_per_second)),
            limits,
            closed: false,
        })
    }

    /// A new local credential sharing the collision-free receiver-index space.
    /// The runtime must bound credential overlap and authenticate the new key.
    pub fn replacement(&self, private: StaticSecret) -> Result<Self, Error> {
        if self.closed {
            return Err(Error::Closed);
        }
        Self::with_indices(private, self.limits.clone(), self.indices.clone())
    }

    /// Constant-time map lookup for non-initial packets during local key overlap.
    pub fn owns_receiver(&self, datagram: &[u8]) -> bool {
        let index = match datagram.get(..4) {
            Some([2, 0, 0, 0]) => datagram.get(8..12),
            Some([3 | 4, 0, 0, 0]) => datagram.get(4..8),
            _ => None,
        };
        index
            .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
            .is_some_and(|bytes| self.owner(u32::from_le_bytes(bytes)).is_ok())
    }

    pub fn public_key(&self) -> Key {
        self.public.to_bytes()
    }

    /// Install only a key from an authenticated, current signed directory.
    /// Installing an existing key preserves the session and its indices.
    pub fn install(&mut self, public: Key) -> Result<(), Error> {
        if self.closed {
            return Err(Error::Closed);
        }
        if self.peers.contains_key(&public) {
            return Ok(());
        }
        if self.peers.len() >= self.limits.peers {
            return Err(Error::PeerLimit);
        }
        let key = PublicKey::from(public);
        if public == self.public_key() || !self.private.diffie_hellman(&key).was_contributory() {
            return Err(Error::InvalidKey);
        }
        self.peers.insert(
            public,
            Peer {
                tunnel: Tunn::new(
                    self.private.clone(),
                    key,
                    None,
                    Some(25),
                    self.indices.clone(),
                    self.limiter.clone(),
                ),
                pending: Queue::default(),
            },
        );
        Ok(())
    }

    /// Drop exactly this credential's tunnel, plaintext and receiver indices.
    pub fn remove(&mut self, public: &Key) {
        if let Some(mut peer) = self.peers.remove(public) {
            self.queued_bytes -= peer.pending.bytes();
            peer.pending.clear();
            peer.tunnel.reset();
        }
        self.owners.retain(|_, owner| owner != public);
    }

    /// Policy replacement must discard plaintext accepted under the old policy.
    pub fn clear_pending(&mut self) {
        for peer in self.peers.values_mut() {
            peer.pending.clear();
        }
        self.queued_bytes = 0;
    }

    /// Resume with fresh handshakes: `GotaTun`'s monotonic timers exclude system suspend.
    /// Keeps authorized static keys but destroys transport keys, indices and queued plaintext.
    pub fn reset_sessions(&mut self) {
        self.clear_pending();
        for peer in self.peers.values_mut() {
            peer.tunnel.reset();
        }
        self.owners.clear();
    }

    /// Snapshot installed public keys for exact authorization reconciliation.
    pub fn peer_keys(&self) -> Vec<Key> {
        self.peers.keys().copied().collect()
    }

    pub fn peer_capacity(&self) -> usize {
        self.limits.peers
    }

    /// Permanently destroys this local credential's sessions, indices and private key.
    pub fn close(&mut self) {
        if self.closed {
            return;
        }
        self.clear_pending();
        for peer in self.peers.values_mut() {
            peer.tunnel.reset();
        }
        self.peers.clear();
        self.owners.clear();
        // Replacing StaticSecret runs its zeroizing Drop immediately.
        self.private = StaticSecret::from([0; 32]);
        self.closed = true;
    }

    pub fn pending_bytes(&self) -> usize {
        self.queued_bytes
    }

    /// Bootstrap the encrypted coordination channel over an authenticated Relay.
    pub fn initiate(&mut self, public: &Key) -> Result<Vec<Event>, Error> {
        if self.closed {
            return Err(Error::Closed);
        }
        let peer = self.peers.get_mut(public).ok_or(Error::UnknownPeer)?;
        let packet = peer.tunnel.format_handshake_initiation(false);
        Ok(packet
            .into_iter()
            .map(|p| self.network(Some(*public), p.into()))
            .collect())
    }

    /// Encrypts an internal path check only if a session is ready now. A delayed
    /// check must never be mistaken for a round trip on its originally selected path.
    pub fn send_ready(&mut self, public: &Key, packet: &[u8]) -> Result<Option<Event>, Error> {
        if self.closed {
            return Err(Error::Closed);
        }
        validate_ip(packet, self.limits.mtu)?;
        let peer = self.peers.get_mut(public).ok_or(Error::UnknownPeer)?;
        match peer
            .tunnel
            .encapsulate_with_session(padded(packet, self.limits.mtu))
        {
            Ok(ciphertext) => Ok(Some(self.network(Some(*public), ciphertext.into()))),
            Err(mut original) => {
                original.buf_mut().fill(0);
                Ok(None)
            }
        }
    }

    /// Encrypt or retain one already validated IP packet under bounded limits.
    /// `authorized` is evaluated on every send, including a later queue drain.
    pub fn send(
        &mut self,
        public: &Key,
        packet: &[u8],
        now: Instant,
        authorized: impl FnOnce(&Key, &[u8]) -> bool,
    ) -> Result<Vec<Event>, Error> {
        self.send_tagged(public, packet, now, 0, authorized)
            .map(|(events, _)| events)
    }

    /// Retains an opaque local authorization ID with queued plaintext. The ID
    /// never enters a `WireGuard` packet; it lets a runtime recheck a reassembled
    /// fragment's complete flow before draining the original MTU-sized fragments.
    pub fn send_tagged(
        &mut self,
        public: &Key,
        packet: &[u8],
        now: Instant,
        authorization: u64,
        authorized: impl FnOnce(&Key, &[u8]) -> bool,
    ) -> Result<(Vec<Event>, bool), Error> {
        if self.closed {
            return Err(Error::Closed);
        }
        validate_ip(packet, self.limits.mtu)?;
        if !authorized(public, packet) {
            return Err(Error::Unauthorized);
        }
        let available = self
            .limits
            .total_queued_bytes
            .saturating_sub(self.pending_bytes());
        let peer = self.peers.get_mut(public).ok_or(Error::UnknownPeer)?;
        match peer
            .tunnel
            .encapsulate_with_session(padded(packet, self.limits.mtu))
        {
            Ok(ciphertext) => Ok((vec![self.network(Some(*public), ciphertext.into())], false)),
            Err(mut original) => {
                // The library's private queue cannot be revoked by policy. Keep
                // plaintext here, with byte, count and lifetime bounds instead.
                original.buf_mut().fill(0);
                if packet.len() > available {
                    return Err(Error::QueueFull);
                }
                let before = peer.pending.bytes();
                let queued = peer.pending.push(packet, now, &self.limits, authorization);
                self.queued_bytes = self.queued_bytes - before + peer.pending.bytes();
                queued?;
                let handshake = peer.tunnel.format_handshake_initiation(false);
                Ok((
                    handshake
                        .into_iter()
                        .map(|p| self.network(Some(*public), p.into()))
                        .collect(),
                    true,
                ))
            }
        }
    }

    /// Decode one standard WG datagram. Authentication never changes a path.
    /// The caller routes immediate responses back over this exact ingress.
    pub fn receive(&mut self, ingress: Ingress, datagram: &[u8]) -> Result<Vec<Event>, Error> {
        if let Ingress::Relay { peer } = ingress
            && !self.peers.contains_key(&peer)
        {
            return Err(Error::UnknownPeer);
        }
        self.receive_checked(ingress.cookie_address(), datagram, |owner| match ingress {
            Ingress::Direct(_) => true,
            Ingress::Relay { peer } => owner == &peer,
        })
    }

    /// Checks recovered/indexed keys against the authenticated Relay's Peer ID.
    /// The predicate runs after MAC validation, before mutating replay/session state.
    pub fn receive_relay(
        &mut self,
        source: [u8; 16],
        datagram: &[u8],
        authorized: impl FnOnce(&Key) -> bool,
    ) -> Result<Vec<Event>, Error> {
        self.receive_checked(
            SocketAddr::new(std::net::Ipv6Addr::from(source).into(), 1),
            datagram,
            authorized,
        )
    }

    /// Direct reception with exact current credential authorization before replay acceptance.
    pub fn receive_direct(
        &mut self,
        source: SocketAddr,
        datagram: &[u8],
        authorized: impl FnOnce(&Key) -> bool,
    ) -> Result<Vec<Event>, Error> {
        self.receive_checked(source, datagram, authorized)
    }

    fn receive_checked(
        &mut self,
        cookie_address: SocketAddr,
        datagram: &[u8],
        authorized: impl FnOnce(&Key) -> bool,
    ) -> Result<Vec<Event>, Error> {
        if self.closed {
            return Err(Error::Closed);
        }
        if datagram.len() > self.limits.mtu + 32 {
            return Err(Error::PacketTooLarge);
        }
        // MAC1 and cookie limits precede anonymous static-key recovery (DH).
        let packet = match self
            .limiter
            .verify_packet(cookie_address, Packet::copy_from(datagram))
        {
            Ok(packet) => packet,
            Err(TunnResult::WriteToNetwork(packet)) => return Ok(vec![self.network(None, packet)]),
            Err(_) => return Err(Error::Authentication),
        };
        let owner = match &packet {
            WgKind::HandshakeInit(init) => {
                parse_handshake_anon(&self.private, &self.public, init)
                    .map_err(|_| Error::Authentication)?
                    .peer_static_public
            }
            WgKind::HandshakeResp(response) => self.owner(response.receiver_idx.get())?,
            WgKind::CookieReply(cookie) => self.owner(cookie.receiver_idx.get())?,
            WgKind::Data(data) => self.owner(data.header.receiver_idx.get())?,
        };
        if !authorized(&owner) {
            return Err(Error::Unauthorized);
        }
        let peer = self.peers.get_mut(&owner).ok_or(Error::UnknownPeer)?;
        match peer.tunnel.handle_incoming_packet(packet) {
            TunnResult::Done => Ok(Vec::new()),
            TunnResult::Err(_) => Err(Error::Authentication),
            TunnResult::WriteToNetwork(packet) => Ok(vec![self.network(Some(owner), packet)]),
            TunnResult::WriteToTunnel(mut packet) => {
                if packet.is_empty() {
                    return Ok(Vec::new());
                }
                // The session API returns plaintext including standard padding.
                // Truncate according to the authenticated inner IP length.
                let length = ip_length(&packet)?;
                if length > packet.len()
                    || packet.len() - length > 15
                    || packet[length..].iter().any(|byte| *byte != 0)
                {
                    return Err(Error::InvalidPacket);
                }
                packet.truncate(length);
                validate_ip(&packet, self.limits.mtu)?;
                Ok(vec![Event::Plaintext {
                    peer: owner,
                    packet: packet.to_vec(),
                }])
            }
        }
    }

    /// Call frequently (at most 250 ms apart while active), even without TUN
    /// traffic or a Relay. `WireGuard` timers continue on direct-only connections.
    pub fn tick(&mut self, now: Instant, authorized: impl Fn(&Key, &[u8]) -> bool) -> Vec<Event> {
        self.tick_tagged(now, |key, packet, _| authorized(key, packet))
    }

    pub fn tick_tagged(
        &mut self,
        now: Instant,
        authorized: impl Fn(&Key, &[u8], u64) -> bool,
    ) -> Vec<Event> {
        if self.closed {
            return Vec::new();
        }
        self.limiter.try_reset_count();
        self.owners.retain(|index, _| self.indices.in_use(*index));
        let mut output = Vec::new();
        let keys: Vec<_> = self.peers.keys().copied().collect();
        for key in keys {
            let peer = self.peers.get_mut(&key).expect("installed peer");
            let before = peer.pending.bytes();
            peer.pending.expire(now);
            let mut packets = Vec::new();
            if let Ok(Some(packet)) = peer.tunnel.update_timers() {
                packets.push(packet);
            }
            while let Some(pending) = peer.pending.pop() {
                if !authorized(&key, &pending.packet, pending.authorization) {
                    continue;
                }
                match peer
                    .tunnel
                    .encapsulate_with_session(padded(&pending.packet, self.limits.mtu))
                {
                    Ok(packet) => packets.push(packet.into()),
                    Err(mut original) => {
                        original.buf_mut().fill(0);
                        peer.pending.restore(pending);
                        break;
                    }
                }
            }
            self.queued_bytes = self.queued_bytes - before + peer.pending.bytes();
            output.extend(packets.into_iter().map(|p| self.network(Some(key), p)));
        }
        output
    }

    fn owner(&self, index: u32) -> Result<Key, Error> {
        if !self.indices.in_use(index) {
            return Err(Error::UnknownIndex);
        }
        self.owners.get(&index).copied().ok_or(Error::UnknownIndex)
    }

    fn network(&mut self, peer: Option<Key>, packet: WgKind) -> Event {
        if let Some(peer) = peer {
            let index = match &packet {
                WgKind::HandshakeInit(p) => Some(p.sender_idx.get()),
                WgKind::HandshakeResp(p) => Some(p.sender_idx.get()),
                _ => None,
            };
            if let Some(index) = index {
                self.owners.insert(index, peer);
            }
        }
        let packet: Packet = packet.into();
        Event::Network {
            peer,
            packet: packet.to_vec(),
        }
    }
}

#[cfg(test)]
#[path = "engine_tests.rs"]
mod tests;

impl Drop for Engine {
    fn drop(&mut self) {
        self.close();
    }
}

fn padded(packet: &[u8], mtu: usize) -> Packet {
    let mut padded = Packet::copy_from(packet);
    padded
        .buf_mut()
        .resize(packet.len().next_multiple_of(16).min(mtu), 0);
    padded
}

fn validate_ip(packet: &[u8], mtu: usize) -> Result<(), Error> {
    if packet.len() > mtu {
        return Err(Error::PacketTooLarge);
    }
    if ip_length(packet)? != packet.len() {
        return Err(Error::InvalidPacket);
    }
    Ok(())
}

fn ip_length(packet: &[u8]) -> Result<usize, Error> {
    let length = match packet.first().map(|byte| byte >> 4) {
        Some(4) if packet.len() >= 20 => {
            let header = usize::from(packet[0] & 15) * 4;
            if header < 20 || header > packet.len() {
                return Err(Error::InvalidPacket);
            }
            let length = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
            if length < header {
                return Err(Error::InvalidPacket);
            }
            length
        }
        Some(6) if packet.len() >= 40 => {
            40 + usize::from(u16::from_be_bytes([packet[4], packet[5]]))
        }
        _ => return Err(Error::InvalidPacket),
    };
    Ok(length)
}

impl Ingress {
    fn cookie_address(self) -> SocketAddr {
        match self {
            Self::Direct(address) => address,
            // Authenticated Relay identity, never an observed direct endpoint.
            Self::Relay { peer } => SocketAddr::new(
                std::net::Ipv6Addr::from(
                    <[u8; 16]>::try_from(&peer[..16]).expect("fixed key length"),
                )
                .into(),
                1,
            ),
        }
    }
}
