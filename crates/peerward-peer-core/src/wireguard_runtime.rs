//! Common authenticated IP pipeline; carriers never own `WireGuard` sessions.
use std::{collections::BTreeMap, net::SocketAddr, sync::Arc, time::Instant};

use crate::{PeerError, PolicyEngine, WireguardDirectory};
use peerward_credentials::{
    DistributionCertificate, SignedAuthorityBundle, SubjectCredential, SubjectId, TrustSet,
};
use peerward_dataplane::{
    Action, FragmentReassembler, ParsedPacket, ReassemblyStatus, parse_packet,
};
use peerward_directory::{
    DirectoryPublicKey, SignedPeerDirectory, SignedPolicyBundle, SignedRevocationBundle,
};
use peerward_types::{MeshId, PeerId, UnixTime};
use peerward_wireguard::{Engine, Event, Key, Limits};
use x25519_dalek::{PublicKey, StaticSecret};

/// A Relay identity is authenticated by the outer transport, not asserted by ciphertext.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireguardIngress {
    Direct(SocketAddr),
    DirectPath {
        local: SocketAddr,
        remote: SocketAddr,
    },
    Relay(PeerId),
}

#[derive(Debug)]
pub enum WireguardOutput {
    /// Immediate replies use the exact ingress; scheduled sends use path selection.
    Network {
        local_key: Key,
        peer: Option<PeerId>,
        packet: Vec<u8>,
        reply_to: Option<WireguardIngress>,
        /// Direct coordination must never fall back onto Relay.
        path_probe: bool,
        authorization: u64,
        expires: Instant,
    },
    /// Source ownership and inbound ACL have both succeeded.
    Tunnel {
        peer: PeerId,
        packet: Vec<u8>,
        ingress: WireguardIngress,
        authorization: u64,
        expires: Instant,
    },
}

struct LocalCredential {
    credential: SubjectCredential,
    engine: Engine,
    published: bool,
}
struct PendingAuthorization {
    local: Key,
    remote: Key,
    parsed: ParsedPacket,
    expires: Instant,
}

/// One Mesh's packet and key lifecycle, shared by Linux and Android.
/// Drive `tick` at least every 250 ms independently of Relay availability.
pub struct WireguardRuntime {
    mesh: MeshId,
    local: PeerId,
    directory: WireguardDirectory,
    policy: Arc<PolicyEngine>,
    slots: Vec<LocalCredential>,
    limits: Limits,
    started: Instant,
    pending: BTreeMap<u64, PendingAuthorization>,
    next_authorization: u64,
    egress_fragments: FragmentReassembler,
    ingress_fragments: FragmentReassembler,
    closed: bool,
    last_validation: Option<UnixTime>,
    admission_floor: u64,
    admission_anchor: (u64, Instant),
    admission_permitted: Option<std::collections::BTreeSet<PeerId>>,
    connectivity: crate::wireguard_connectivity::Connectivity,
    authorization: u64,
    suspend_clock: suspend::SuspendClock,
    root: [u8; 32],
    updates_started: bool,
    checkpoint: Option<crate::checkpoint::Checkpoint>,
    configuration_clock: peerward_management::LeaseClock,
    configuration_active: bool,
    resource_platform: resources::PlatformState,
    configuration_parts:
        BTreeMap<peerward_management::ConfigurationPart, peerward_management::ComponentReference>,
    configuration_key: [u8; 32],
    configuration: Option<peerward_management::ConfigurationDelivery>,
    pending_configuration: Option<peerward_management::ConfigurationDelivery>,
    preferences: peerward_management::ClientPreferences,
    dns_cache: Option<(
        u64,
        std::net::IpAddr,
        Arc<peerward_management::EffectiveDns>,
    )>,
    resource_traffic: resources::ResourceTraffic,
    gateway_health: gateways::GatewayHealth,
    management_sequence: u64,
    management_ceiling: u64,
}

impl WireguardRuntime {
    pub fn new(
        mesh: MeshId,
        local: PeerId,
        trust: TrustSet,
        distribution: &DistributionCertificate,
        credential: SubjectCredential,
        private: StaticSecret,
        mtu: usize,
        state_limit: usize,
        shards: usize,
        now: UnixTime,
    ) -> Result<Self, PeerError> {
        let root = trust.root_public_key().to_bytes();
        let directory = WireguardDirectory::new(mesh, trust, distribution, now)?;
        let policy = Arc::new(PolicyEngine::new(
            mesh,
            local,
            DirectoryPublicKey::from_bytes(&distribution.directory_public_key)?,
            state_limit,
            shards,
        )?);
        // Two local generations share an aggregate 16 MiB plaintext budget.
        let limits = Limits {
            mtu,
            total_queued_bytes: 8 * 1024 * 1024,
            ..Limits::default()
        };
        let mut runtime = Self {
            mesh,
            local,
            root,
            updates_started: false,
            checkpoint: None,
            configuration_clock: peerward_management::LeaseClock::new(
                peerward_management::AuthorizationFloor::default(),
            ),
            configuration_active: false,
            resource_platform: resources::PlatformState::Unmanaged,
            configuration_parts: BTreeMap::new(),
            configuration_key: distribution.directory_public_key,
            configuration: None,
            pending_configuration: None,
            preferences: peerward_management::ClientPreferences::default(),
            dns_cache: None,
            resource_traffic: resources::ResourceTraffic::new(),
            gateway_health: gateways::GatewayHealth::default(),
            management_sequence: 0,
            management_ceiling: 0,
            directory,
            policy,
            slots: Vec::new(),
            limits,
            started: Instant::now(),
            suspend_clock: suspend::SuspendClock::new(),
            pending: BTreeMap::new(),
            next_authorization: 0,
            egress_fragments: fragments(),
            ingress_fragments: fragments(),
            closed: false,
            last_validation: None,
            admission_floor: now.0,
            admission_anchor: (now.0, Instant::now()),
            admission_permitted: None,
            authorization: 0,
            connectivity: crate::wireguard_connectivity::Connectivity::new(
                u64::try_from(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_err(|_| PeerError::InvalidConfig)?
                        .as_nanos(),
                )
                .map_err(|_| PeerError::InvalidConfig)?,
            ),
        };
        runtime.stage(credential, private, now)?;
        Ok(runtime)
    }

    /// Shared policy view for DNS/service visibility. Install updates through this runtime.
    pub fn policy(&self) -> Arc<PolicyEngine> {
        Arc::clone(&self.policy)
    }

    /// DNS and other local runtime services obey the same credential/source lifetime as TUN data.
    pub fn local_source_authorized(&mut self, source: std::net::IpAddr, now: UnixTime) -> bool {
        self.prune(now);
        !self.closed
            && self
                .active_local(now)
                .is_ok_and(|key| self.directory.owns_source(&key, source, now))
    }

    /// Authenticates new local material; staged keys carry no traffic before directory activation.
    pub fn stage(
        &mut self,
        credential: SubjectCredential,
        private: StaticSecret,
        now: UnixTime,
    ) -> Result<(), PeerError> {
        if self.closed {
            return Err(PeerError::Closed);
        }
        self.directory.verify_credential(&credential, now)?;
        if credential.mesh_id != self.mesh
            || credential.subject != SubjectId::Peer(self.local)
            || credential.wireguard_public_key != PublicKey::from(&private).to_bytes()
        {
            return Err(PeerError::InvalidConfig);
        }
        if let Some(existing) = self
            .slots
            .iter()
            .find(|slot| slot.engine.public_key() == credential.wireguard_public_key)
        {
            return if existing.credential == credential {
                Ok(())
            } else {
                Err(PeerError::InvalidConfig)
            };
        }
        self.prune(now);
        if self.slots.len() == 2 {
            let previous = self.slots.iter().position(|slot| {
                slot.published
                    && self
                        .directory
                        .get(&slot.engine.public_key(), now)
                        .is_some_and(|key| !key.active)
            });
            if let Some(index) = previous {
                self.slots.remove(index);
                self.clear_pending();
            } else {
                return Err(PeerError::QueueFull);
            }
        }
        let engine = match self.slots.first() {
            Some(slot) => slot.engine.replacement(private),
            None => Engine::new(private, self.limits.clone()),
        }
        .map_err(wg_error)?;
        self.slots.push(LocalCredential {
            credential,
            engine,
            published: false,
        });
        self.reconcile(now)
    }

    /// Validates source, reassembles for ACL, then sends the original MTU-sized fragments.
    pub fn send_tunnel(
        &mut self,
        packet: &[u8],
        wall: UnixTime,
        now: Instant,
    ) -> Result<Vec<WireguardOutput>, PeerError> {
        if self.closed {
            return Err(PeerError::Closed);
        }
        self.prune(wall);
        parse_packet(packet).map_err(|_| PeerError::InvalidPacket)?;
        let local_key = self.active_local(wall)?;
        // Resource returns can carry a LAN source. Validate the complete flow after reassembly.
        if packet.len() > self.limits.mtu {
            return Err(PeerError::InvalidPacket);
        }
        let seconds = self.seconds(now);
        let ReassemblyStatus::Complete(datagram) = self
            .egress_fragments
            .push(packet, seconds)
            .map_err(|_| PeerError::InvalidPacket)?
        else {
            return Ok(Vec::new());
        };
        let parsed = parse_packet(&datagram.packet).map_err(|_| PeerError::InvalidPacket)?;
        if reserved(&parsed) {
            return Err(PeerError::InvalidPacket);
        }
        let remote_key = self.outbound_target(&parsed, local_key, wall, now)?;
        self.connectivity.touch(local_key, remote_key, now);
        self.pending.retain(|_, context| context.expires > now);
        if self.pending.len() >= 4096 {
            return Err(PeerError::QueueFull);
        }
        self.next_authorization = self
            .next_authorization
            .checked_add(1)
            .ok_or(PeerError::Closed)?;
        let id = self.next_authorization;
        let slot = self
            .slots
            .iter_mut()
            .find(|slot| slot.engine.public_key() == local_key)
            .ok_or(PeerError::Revoked)?;
        let mut events = Vec::new();
        let mut queued = false;
        // At most 64 original fragments fit one Peer queue; reject partial oversized batches.
        if datagram.original_fragments.len() > self.limits.queued_packets {
            return Err(PeerError::QueueFull);
        }
        for fragment in &datagram.original_fragments {
            let result = slot
                .engine
                .send_tagged(&remote_key, fragment, now, id, |_, _| true);
            match result {
                Ok((output, retained)) => {
                    events.extend(output);
                    queued |= retained;
                }
                Err(error) => {
                    slot.engine.clear_pending();
                    self.pending.clear();
                    return Err(wg_error(error));
                }
            }
        }
        if queued {
            self.pending.insert(
                id,
                PendingAuthorization {
                    local: local_key,
                    remote: remote_key,
                    parsed,
                    expires: now + self.limits.queue_lifetime,
                },
            );
        }
        self.output(local_key, events, None, wall, now)
    }

    /// Source binding is checked before the engine mutates handshake/replay state.
    pub fn receive(
        &mut self,
        ingress: WireguardIngress,
        packet: &[u8],
        wall: UnixTime,
        now: Instant,
    ) -> Result<Vec<WireguardOutput>, PeerError> {
        if self.closed {
            return Err(PeerError::Closed);
        }
        self.prune(wall);
        if !self.state_ready() {
            return Err(PeerError::NoRoute);
        }
        if let WireguardIngress::Relay(peer) = ingress
            && self.directory.keys_for_peer(peer, wall).next().is_none()
        {
            return Err(PeerError::NoRoute);
        }
        let initiation = packet.get(..4) == Some(&[1, 0, 0, 0]);
        let mut result = None;
        for slot in &mut self.slots {
            let local_key = slot.engine.public_key();
            if self.directory.get(&local_key, wall).is_none()
                || (!initiation && !slot.engine.owns_receiver(packet))
            {
                continue;
            }
            let authorized = |key: &Key| {
                self.directory.get(key, wall).is_some_and(|remote| {
                    remote.peer_id != self.local
                        && match ingress {
                            WireguardIngress::Relay(peer) => remote.peer_id == peer,
                            WireguardIngress::Direct(_) | WireguardIngress::DirectPath { .. } => {
                                true
                            }
                        }
                })
            };
            let received = match ingress {
                WireguardIngress::Direct(endpoint)
                | WireguardIngress::DirectPath {
                    remote: endpoint, ..
                } => slot.engine.receive_direct(endpoint, packet, authorized),
                WireguardIngress::Relay(peer) => {
                    slot.engine
                        .receive_relay(*peer.as_bytes(), packet, authorized)
                }
            };
            match received {
                Ok(events) => {
                    result = Some((local_key, events));
                    break;
                }
                // Only the two local MAC keys are tried; never iterate remote Peers.
                Err(peerward_wireguard::Error::Authentication) if initiation => {}
                Err(error) => return Err(wg_error(error)),
            }
        }
        let (local_key, events) = result.ok_or(PeerError::InvalidPacket)?;
        let mut output = self.output(local_key, events, Some(ingress), wall, now)?;
        output.extend(self.tick(wall, now)?);
        Ok(output)
    }

    pub fn tick(
        &mut self,
        wall: UnixTime,
        now: Instant,
    ) -> Result<Vec<WireguardOutput>, PeerError> {
        if self.closed {
            return Err(PeerError::Closed);
        }
        self.prune(wall);
        if !self.state_ready() {
            return Ok(Vec::new());
        }
        self.pending.retain(|_, context| context.expires > now);
        let seconds = self.seconds(now);
        let eligible: std::collections::BTreeSet<u64> = self
            .pending
            .iter()
            .filter_map(|(id, context)| {
                let ordinary =
                    self.directory
                        .owns_source(&context.local, context.parsed.source, wall)
                        && self.directory.owns_source(
                            &context.remote,
                            context.parsed.destination,
                            wall,
                        )
                        && self.policy.evaluate(&context.parsed, seconds) == Action::Allow;
                (ordinary
                    || self.resource_path_current(
                        &context.parsed,
                        &context.local,
                        &context.remote,
                        wall,
                    ))
                .then_some(*id)
            })
            .collect();
        let mut collected = Vec::new();
        for slot in &mut self.slots {
            let local = slot.engine.public_key();
            if self.directory.get(&local, wall).is_none() {
                continue;
            }
            let events = slot.engine.tick_tagged(now, |remote, _, id| {
                eligible.contains(&id)
                    && self
                        .pending
                        .get(&id)
                        .is_some_and(|context| context.local == local && &context.remote == remote)
            });
            collected.push((local, events));
        }
        if self
            .slots
            .iter()
            .all(|slot| slot.engine.pending_bytes() == 0)
        {
            self.pending.clear();
        }
        let mut output = Vec::new();
        for (local, events) in collected {
            output.extend(self.output(local, events, None, wall, now)?);
        }
        let coordination = self
            .connectivity
            .poll_with_mtu(now, self.limits.mtu, |key| {
                self.directory.get(key, wall).map(|entry| entry.address)
            });
        output.extend(self.send_coordination(coordination, wall)?);
        output.extend(self.poll_gateways(wall, now)?);
        Ok(output)
    }

    pub fn clear_pending(&mut self) {
        self.resource_traffic.clear();
        if self.policy.clear_connections().is_err() {
            self.closed = true;
        }
        self.flush_packet_queues();
    }

    pub fn close(&mut self) {
        self.clear_pending();
        self.connectivity.clear();
        self.slots.clear();
        self.closed = true;
        self.policy.set_ready(false);
        self.checkpoint = None;
    }
    pub fn pending_bytes(&self) -> usize {
        self.slots
            .iter()
            .map(|slot| slot.engine.pending_bytes())
            .sum()
    }
    pub fn credential_count(&self) -> usize {
        self.slots.len()
    }
    pub fn directory_revision(&self) -> Option<u64> {
        self.directory.revision()
    }

    /// Rechecks a decrypted delivery immediately before TUN write. Policy updates,
    /// expiry and exact revocations invalidate data already handed to a platform queue.
    pub fn delivery_current(&mut self, authorization: u64, wall: UnixTime) -> bool {
        self.prune(wall);
        self.state_ready() && self.authorization == authorization
    }

    /// Privacy-safe status derived solely from authenticated direct round trips.
    pub fn direct_peers(&mut self, wall: UnixTime, now: Instant) -> Vec<PeerId> {
        self.prune(wall);
        self.connectivity
            .verified(now)
            .iter()
            .filter_map(|key| self.directory.get(key, wall).map(|peer| peer.peer_id))
            .collect()
    }
    fn seconds(&self, now: Instant) -> u64 {
        now.saturating_duration_since(self.started).as_secs()
    }

    fn active_local(&self, wall: UnixTime) -> Result<Key, PeerError> {
        if !self.state_ready() || !self.device_admitted(self.local, wall) {
            return Err(PeerError::NoRoute);
        }
        let key = self
            .directory
            .active(self.local, wall)
            .ok_or(PeerError::Revoked)?
            .credential
            .wireguard_public_key;
        self.slots
            .iter()
            .any(|slot| slot.engine.public_key() == key)
            .then_some(key)
            .ok_or(PeerError::Revoked)
    }

    fn reconcile(&mut self, now: UnixTime) -> Result<(), PeerError> {
        self.last_validation = None;
        self.prune(now);
        for slot in &mut self.slots {
            if self.directory.get(&slot.engine.public_key(), now).is_some() {
                self.directory
                    .reconcile_engine(&mut slot.engine, self.local, now)?;
                slot.published = true;
            }
        }
        Ok(())
    }
}

#[path = "wireguard_coordination.rs"]
mod channel;

fn reserved(packet: &ParsedPacket) -> bool {
    packet.protocol == 17
        && (packet.source_port == Some(51821) || packet.destination_port == Some(51821))
}
fn fragments() -> FragmentReassembler {
    FragmentReassembler::new(256 * 1024, 4 * 1024 * 1024, 3).expect("fixed fragment bounds")
}
fn wg_error(error: peerward_wireguard::Error) -> PeerError {
    match error {
        peerward_wireguard::Error::Closed => PeerError::Closed,
        peerward_wireguard::Error::QueueFull => PeerError::QueueFull,
        peerward_wireguard::Error::Unauthorized => PeerError::Revoked,
        _ => PeerError::PacketRuntime(Box::new(error)),
    }
}

#[path = "wireguard_local.rs"]
mod local;
#[path = "wireguard_output.rs"]
mod output;
#[path = "wireguard_suspend.rs"]
mod suspend;

#[path = "wireguard_updates.rs"]
mod updates;

#[path = "wireguard_configuration.rs"]
mod configuration;

#[path = "wireguard_gateways.rs"]
mod gateways;
#[path = "wireguard_resources.rs"]
mod resources;

#[path = "wireguard_device_conditions.rs"]
mod device_conditions;
