//! Bounded path checks independent of `WireGuard` handshake/key generations.
use crate::{
    PeerError,
    coordination::{Coordination, Message, validate_candidates},
};
use peerward_wireguard::Key;
use rand::{RngCore, rngs::OsRng};
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, Instant},
};

const MAX_PEERS: usize = 256;
const MESH_CHECKS: usize = 64;
const PROCESS_CHECKS: usize = 256;
// Leave 500 ms within the end-to-end 3 s failover target for the platform
// polling loop, relay delivery and the application's next transmission.
const ACTIVE_HEALTH_LIFETIME: Duration = Duration::from_millis(2_500);
static CHECKS: AtomicUsize = AtomicUsize::new(0);
static MESSAGES: std::sync::OnceLock<std::sync::Mutex<Rate>> = std::sync::OnceLock::new();

struct Rate {
    since: Instant,
    count: usize,
}
impl Rate {
    fn allow(&mut self, now: Instant, maximum: usize) -> bool {
        if now.saturating_duration_since(self.since) >= Duration::from_secs(1) {
            self.since = now;
            self.count = 0;
        }
        if self.count >= maximum {
            return false;
        }
        self.count += 1;
        true
    }
}

struct Permit;
impl Permit {
    fn acquire() -> Option<Self> {
        CHECKS
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                (count < PROCESS_CHECKS).then_some(count + 1)
            })
            .ok()
            .map(|_| Self)
    }
}
impl Drop for Permit {
    fn drop(&mut self) {
        CHECKS.fetch_sub(1, Ordering::Relaxed);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Route {
    pub endpoint: SocketAddr,
    pub source: Option<SocketAddr>,
}

struct Check {
    route: Route,
    sent: Instant,
    ciphertext_limit: Option<usize>,
    _permit: Permit,
}
struct Verified {
    route: Route,
    confirmed: Instant,
    selected: Instant,
    mtu: mtu::Mtu,
}
struct Track {
    local: Key,
    candidates: Vec<SocketAddr>,
    pairs: Vec<Route>,
    advertised: Vec<SocketAddr>,
    remote_generation: Option<u64>,
    next: usize,
    pending: BTreeMap<[u8; 16], Check>,
    verified: Option<Verified>,
    quality: BTreeMap<Route, quality::Quality>,
    last_alternative: Option<Instant>,
    candidate_tx: [u8; 16],
    candidate_ack: bool,
    candidate_sent: Option<Instant>,
    last_check: Option<Instant>,
    last_activity: Instant,
    rate_since: Instant,
    rate_count: u16,
}

pub struct Connectivity {
    generation: u64,
    generation_ceiling: u64,
    candidates: Vec<SocketAddr>,
    local_paths: Option<Vec<SocketAddr>>,
    peers: BTreeMap<Key, Track>,
    cursor: usize,
    messages: Rate,
}

pub struct Send {
    pub local: Key,
    pub remote: Key,
    pub endpoint: Option<SocketAddr>,
    pub source: Option<SocketAddr>,
    pub coordination: Coordination,
}

impl Connectivity {
    pub fn new(generation: u64) -> Self {
        Self {
            generation,
            generation_ceiling: u64::MAX,
            candidates: Vec::new(),
            local_paths: None,
            peers: BTreeMap::new(),
            cursor: 0,
            messages: Rate {
                since: Instant::now(),
                count: 0,
            },
        }
    }

    pub(crate) fn reserve_generation(&mut self, start: u64, ceiling: u64) {
        self.generation = start;
        self.generation_ceiling = ceiling;
    }

    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    pub fn update_paths(
        &mut self,
        local: Vec<SocketAddr>,
        candidates: Vec<SocketAddr>,
    ) -> Result<(), PeerError> {
        validate_candidates(&local)?;
        if local.len() > 8 {
            return Err(PeerError::QueueFull);
        }
        validate_candidates(&candidates)?;
        // Commit only after the generation lease and both collections validate.
        self.update(candidates)?;
        self.local_paths = Some(local);
        for track in self.peers.values_mut() {
            track.pairs = pairs(self.local_paths.as_deref(), &track.candidates);
        }
        Ok(())
    }

    pub fn update(&mut self, candidates: Vec<SocketAddr>) -> Result<(), PeerError> {
        validate_candidates(&candidates)?;
        if self.generation >= self.generation_ceiling {
            return Err(PeerError::Checkpoint(
                "path generation lease exhausted; restart runtime",
            ));
        }
        self.generation = self.generation.checked_add(1).ok_or(PeerError::Closed)?;
        self.candidates = candidates;
        for track in self.peers.values_mut() {
            track.pairs = pairs(self.local_paths.as_deref(), &track.candidates);
            track.quality.clear();
            track.last_alternative = None;
            track.pending.clear();
            track.verified = None;
            track.next = 0;
            track.last_check = None;
            track.candidate_tx = transaction();
            track.candidate_ack = false;
            track.candidate_sent = None;
        }
        Ok(())
    }

    pub fn resume(&mut self) -> Result<(), PeerError> {
        self.update(self.candidates.clone())
    }

    pub fn touch(&mut self, local: Key, remote: Key, now: Instant) {
        if let Some(track) = self.peers.get_mut(&remote) {
            if track.local == local {
                track.last_activity = now;
                return;
            }
            self.peers.remove(&remote);
        }
        // Eviction is confined to idle discovery state, never the encryption engine.
        if self.peers.len() >= MAX_PEERS {
            let oldest = self
                .peers
                .iter()
                .filter(|(_, track)| {
                    now.saturating_duration_since(track.last_activity) > Duration::from_mins(1)
                })
                .min_by_key(|(_, track)| track.last_activity)
                .map(|(key, _)| *key);
            if let Some(key) = oldest {
                self.peers.remove(&key);
            } else {
                return;
            }
        }
        self.peers.insert(
            remote,
            Track {
                local,
                candidates: Vec::new(),
                pairs: Vec::new(),
                advertised: Vec::new(),
                remote_generation: None,
                next: 0,
                pending: BTreeMap::new(),
                verified: None,
                quality: BTreeMap::new(),
                last_alternative: None,
                candidate_tx: transaction(),
                candidate_ack: false,
                candidate_sent: None,
                last_check: None,
                last_activity: now,
                rate_since: now,
                rate_count: 0,
            },
        );
    }

    pub fn retain(&mut self, authorized: impl Fn(&Key, &Key) -> bool) {
        self.peers
            .retain(|remote, track| authorized(&track.local, remote));
    }

    pub fn clear(&mut self) {
        self.peers.clear();
    }

    pub fn verified(&self, now: Instant) -> Vec<Key> {
        self.peers
            .keys()
            .filter(|key| self.endpoint(key, now, 32).is_some())
            .copied()
            .collect()
    }

    pub fn endpoint(
        &self,
        remote: &Key,
        now: Instant,
        ciphertext_len: usize,
    ) -> Option<SocketAddr> {
        self.route(remote, now, ciphertext_len)
            .map(|route| route.endpoint)
    }

    pub(super) fn route(&self, remote: &Key, now: Instant, ciphertext_len: usize) -> Option<Route> {
        let track = self.peers.get(remote)?;
        let verified = track.verified.as_ref()?;
        let lifetime = health_lifetime(track, now);
        (now.saturating_duration_since(verified.confirmed) < lifetime
            && ciphertext_len <= verified.mtu.limit(now, lifetime, 96))
        .then_some(verified.route)
    }

    #[cfg(test)]
    pub fn receive(
        &mut self,
        local: Key,
        remote: Key,
        message: Coordination,
        source: Option<SocketAddr>,
        now: Instant,
    ) -> Result<Vec<Send>, PeerError> {
        self.receive_on(local, remote, message, source, None, now)
    }

    pub fn receive_on(
        &mut self,
        local: Key,
        remote: Key,
        message: Coordination,
        source: Option<SocketAddr>,
        local_endpoint: Option<SocketAddr>,
        now: Instant,
    ) -> Result<Vec<Send>, PeerError> {
        if local_endpoint.is_some_and(|local| {
            self.local_paths
                .as_ref()
                .is_none_or(|paths| !paths.contains(&local))
        }) {
            return Err(PeerError::InvalidPacket);
        }
        if !self.messages.allow(now, 1024)
            || !MESSAGES
                .get_or_init(|| {
                    std::sync::Mutex::new(Rate {
                        since: now,
                        count: 0,
                    })
                })
                .lock()
                .map_err(|_| PeerError::Closed)?
                .allow(now, 4096)
        {
            return Err(PeerError::QueueFull);
        }
        if self
            .peers
            .get(&remote)
            .is_none_or(|track| track.local != local)
        {
            self.touch(local, remote, now);
        }
        let track = self.peers.get_mut(&remote).ok_or(PeerError::QueueFull)?;
        if now.saturating_duration_since(track.rate_since) >= Duration::from_secs(1) {
            track.rate_since = now;
            track.rate_count = 0;
        }
        track.rate_count = track.rate_count.saturating_add(1);
        if track.rate_count > 32 {
            return Err(PeerError::QueueFull);
        }
        let reply = match message.message {
            Message::GatewayProbe(_) | Message::GatewayAck(_, _) => {
                return Err(PeerError::InvalidPacket);
            }
            Message::Candidates(candidates) => {
                if source.is_some()
                    || track
                        .remote_generation
                        .is_some_and(|generation| message.generation < generation)
                    || (track.remote_generation == Some(message.generation)
                        && track.advertised != candidates)
                {
                    return Err(PeerError::InvalidPacket);
                }
                if track.remote_generation != Some(message.generation) {
                    track.remote_generation = Some(message.generation);
                    track.advertised.clone_from(&candidates);
                    track.candidates = candidates;
                    track.pairs = pairs(self.local_paths.as_deref(), &track.candidates);
                    track.quality.retain(|route, _| track.pairs.contains(route));
                    track.last_alternative = None;
                    track.pending.clear();
                    track.verified = None;
                    track.next = 0;
                    track.last_check = None;
                }
                Some(Message::CandidatesAck)
            }
            Message::CandidatesAck => {
                if source.is_some()
                    || message.generation != self.generation
                    || message.transaction != track.candidate_tx
                {
                    return Err(PeerError::InvalidPacket);
                }
                track.candidate_ack = true;
                None
            }
            Message::Probe | Message::MtuProbe(_) => {
                let endpoint = source
                    .filter(|endpoint| crate::coordination::valid_endpoint(*endpoint))
                    .ok_or(PeerError::InvalidPacket)?;
                // An authenticated incoming check creates a bounded triggered check, not a healthy path.
                if !track.candidates.contains(&endpoint) && track.candidates.len() < 32 {
                    track.candidates.insert(0, endpoint);
                    track.next = 0;
                    track.last_check = None;
                }
                let route = Route {
                    endpoint,
                    source: local_endpoint,
                };
                if track.candidates.contains(&endpoint)
                    && !track.pairs.contains(&route)
                    && track.pairs.len() < 128
                {
                    track.pairs.insert(0, route);
                    track.next = 0;
                    track.last_check = None;
                }
                Some(Message::ProbeAck)
            }
            Message::ProbeAck => {
                let endpoint = source.ok_or(PeerError::InvalidPacket)?;
                if message.generation != self.generation {
                    return Err(PeerError::InvalidPacket);
                }
                let pending = track
                    .pending
                    .get(&message.transaction)
                    .ok_or(PeerError::InvalidPacket)?;
                let route = Route {
                    endpoint,
                    source: local_endpoint,
                };
                if pending.route != route
                    || now.saturating_duration_since(pending.sent) >= Duration::from_secs(1)
                {
                    return Err(PeerError::InvalidPacket);
                }
                let pending = track
                    .pending
                    .remove(&message.transaction)
                    .expect("checked transaction");
                let rtt = now.saturating_duration_since(pending.sent);
                let quality = track.quality.entry(route).or_default();
                // An oversized MTU probe failure must not penalize small-packet health.
                if pending.ciphertext_limit.is_none() {
                    quality.success(rtt, now);
                }
                let score = quality.score();
                let replace = track.verified.as_ref().is_none_or(|old| {
                    old.route == route
                        || now.saturating_duration_since(old.confirmed) >= ACTIVE_HEALTH_LIFETIME
                        || (now.saturating_duration_since(old.selected) >= Duration::from_secs(5)
                            && track.quality.get(&old.route).is_some_and(|old_quality| {
                                score + Duration::from_millis(5) < old_quality.score().mul_f32(0.8)
                            }))
                });
                if replace {
                    let selected = track
                        .verified
                        .as_ref()
                        .filter(|old| old.route == route)
                        .map_or(now, |old| old.selected);
                    let mut mtu = track
                        .verified
                        .take()
                        .filter(|old| old.route == route)
                        .map_or_else(mtu::Mtu::default, |old| old.mtu);
                    if let Some(limit) = pending.ciphertext_limit {
                        mtu.confirm(limit, now);
                    }
                    track.verified = Some(Verified {
                        route,
                        confirmed: now,
                        selected,
                        mtu,
                    });
                }
                None
            }
        };
        Ok(reply
            .into_iter()
            .map(|reply| Send {
                local,
                remote,
                endpoint: source,
                source: local_endpoint,
                coordination: Coordination {
                    generation: message.generation,
                    transaction: message.transaction,
                    message: reply,
                },
            })
            .collect())
    }
}

fn health_lifetime(track: &Track, now: Instant) -> Duration {
    if now.saturating_duration_since(track.last_activity) > Duration::from_secs(30) {
        Duration::from_secs(30)
    } else {
        ACTIVE_HEALTH_LIFETIME
    }
}
fn transaction() -> [u8; 16] {
    let mut bytes = [0; 16];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

#[cfg(test)]
#[path = "wireguard_connectivity_tests.rs"]
mod tests;

#[path = "wireguard_checks.rs"]
mod checks;
#[path = "wireguard_mtu.rs"]
mod mtu;

#[cfg(test)]
#[path = "wireguard_mtu_tests.rs"]
mod mtu_tests;

#[path = "wireguard_quality.rs"]
mod quality;

fn pairs(local: Option<&[SocketAddr]>, remote: &[SocketAddr]) -> Vec<Route> {
    let Some(local) = local else {
        return remote
            .iter()
            .map(|endpoint| Route {
                endpoint: *endpoint,
                source: None,
            })
            .collect();
    };
    let mut output = Vec::new();
    // Diagonal order covers every remote before adding second/third local choices.
    for offset in 0..local.len() {
        for (index, endpoint) in remote.iter().enumerate() {
            let source = local[(index + offset) % local.len()];
            if source.is_ipv4() == endpoint.is_ipv4() {
                output.push(Route {
                    endpoint: *endpoint,
                    source: Some(source),
                });
                if output.len() == 128 {
                    return output;
                }
            }
        }
    }
    output
}
