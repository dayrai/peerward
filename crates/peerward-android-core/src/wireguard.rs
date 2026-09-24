//! Mesh-owned Android data state. Relay attachments only carry opaque datagrams.
use std::{collections::BTreeMap, net::SocketAddr, sync::Mutex, time::Instant};

use peerward_peer_core::{WireguardIngress, WireguardOutput, WireguardRuntime};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::*;

pub type SharedMobileWireguard = Arc<Mutex<MobileWireguard>>;

/// An output ticket contains no plaintext. It expires with its authorization decision.
#[derive(Clone, Debug)]
pub struct MobileWireguardTicket {
    pub id: u64,
    pub tunnel: bool,
    pub endpoint: Option<SocketAddr>,
    pub local_endpoint: Option<SocketAddr>,
}

struct PendingOutput {
    value: WireguardOutput,
    offered: bool,
}

impl Drop for PendingOutput {
    fn drop(&mut self) {
        if let WireguardOutput::Tunnel { packet, .. } = &mut self.value {
            packet.zeroize();
        }
    }
}

/// One owner survives all Relay replacements; explicit Mesh shutdown destroys it.
pub struct MobileWireguard {
    pub(crate) core: WireguardRuntime,
    pub(crate) services: RemoteServiceTable,
    pub(crate) audit_counts: BTreeMap<(i32, i32), u32>,
    mesh: MeshId,
    peer: PeerId,
    distribution: [u8; 32],
    accepted: BTreeMap<u8, (u64, [u8; 32])>,
    outputs: BTreeMap<u64, PendingOutput>,
    output_bytes: usize,
    next_ticket: u64,
    network_observation: Option<platform::MobileNetworkObservation>,
    network_applied: Option<platform::MobileNetworkConfiguration>,
    preferences: Option<preferences::MobilePreferences>,
}

impl MobileWireguard {
    /// Builds the same Root-authorized packet pipeline used by Linux.
    ///
    /// # Errors
    /// Rejects invalid trust, credentials, private/public binding or resource bounds.
    pub fn new(
        trust: &MobileTrust,
        credential: SubjectCredential,
        private: StaticSecret,
        mtu: usize,
        now: UnixTime,
    ) -> Result<Self, MobileError> {
        let SubjectId::Peer(peer) = credential.subject else {
            return Err(MobileError::InvalidInput);
        };
        let mut owner = Self {
            core: WireguardRuntime::new(
                trust.mesh_id,
                peer,
                trust.credentials.clone(),
                &trust.binding,
                credential,
                private,
                mtu,
                65_536,
                16,
                now,
            )?,
            services: RemoteServiceTable::new(trust.mesh_id, trust.services),
            audit_counts: BTreeMap::new(),
            mesh: trust.mesh_id,
            peer,
            distribution: trust.distribution.to_bytes(),
            accepted: BTreeMap::new(),
            outputs: BTreeMap::new(),
            output_bytes: 0,
            next_ticket: 0,
            network_observation: None,
            network_applied: None,
            preferences: None,
        };
        owner.core.set_resource_platform_ready(false);
        Ok(owner)
    }

    pub(crate) fn accept_update(
        &mut self,
        kind: u8,
        revision: u64,
        canonical: &[u8],
        apply: impl FnOnce(&mut Self) -> Result<(), MobileError>,
    ) -> Result<(), MobileError> {
        let digest: [u8; 32] = Sha256::digest(canonical).into();
        if let Some((previous, hash)) = self.accepted.get(&kind) {
            if revision == *previous && digest == *hash {
                return Ok(());
            }
            if revision <= *previous {
                return Err(MobileError::InvalidInput);
            }
        }
        // Remember only updates that the shared Root/directory verifier accepted.
        apply(self)?;
        self.reconcile_platform(UnixTime(crate::wall_clock_seconds()));
        self.accepted.insert(kind, (revision, digest));
        self.clear_outputs();
        Ok(())
    }

    /// Drives handshakes, timers and encrypted path checks independently of Relay health.
    ///
    /// # Errors
    /// Fails if this Mesh has closed or its trust is no longer valid.
    pub fn tick(&mut self, now: UnixTime, clock: Instant) -> Result<(), MobileError> {
        self.expire(now, clock);
        let output = self.core.tick(now, clock)?;
        self.enqueue(output)
    }

    /// Queues policy-approved TUN traffic until a standard `WireGuard` handshake completes.
    ///
    /// # Errors
    /// Rejects malformed, unauthorized or over-budget packets.
    pub fn send(
        &mut self,
        packet: &[u8],
        now: UnixTime,
        clock: Instant,
    ) -> Result<(), MobileError> {
        let output = self.core.send_tunnel(packet, now, clock).map_err(|error| {
            let error = MobileError::from(error);
            crate::accumulate_audit(
                &mut self.audit_counts,
                peerward_wire::AuditDirectionV1::Egress,
                &error,
            );
            error
        })?;
        self.enqueue(output)
    }

    /// Processes a datagram whose carrier source has been authenticated or observed locally.
    ///
    /// # Errors
    /// Rejects unauthorized keys, replayed packets, forged sources and malformed traffic.
    pub fn receive(
        &mut self,
        ingress: WireguardIngress,
        packet: &[u8],
        now: UnixTime,
        clock: Instant,
    ) -> Result<(), MobileError> {
        let output = self
            .core
            .receive(ingress, packet, now, clock)
            .map_err(|error| {
                let error = MobileError::from(error);
                crate::accumulate_audit(
                    &mut self.audit_counts,
                    peerward_wire::AuditDirectionV1::Ingress,
                    &error,
                );
                error
            })?;
        self.enqueue(output)
    }

    fn enqueue(&mut self, outputs: Vec<WireguardOutput>) -> Result<(), MobileError> {
        for value in outputs {
            let pending = PendingOutput {
                value,
                offered: false,
            };
            let size = packet_length(&pending.value);
            if self.outputs.len() >= 512 || self.output_bytes.saturating_add(size) > 4 * 1024 * 1024
            {
                // Drop both ciphertext and zeroizing plaintext without blocking the timer.
                continue;
            }
            self.next_ticket = self
                .next_ticket
                .checked_add(1)
                .filter(|value| i64::try_from(*value).is_ok())
                .ok_or(MobileError::InvalidState)?;
            self.outputs.insert(self.next_ticket, pending);
            self.output_bytes += size;
        }
        Ok(())
    }

    /// Offers at most 64 tickets. No plaintext leaves the Rust queue.
    pub fn poll(&mut self, now: UnixTime, clock: Instant) -> Vec<MobileWireguardTicket> {
        self.expire(now, clock);
        self.outputs
            .iter_mut()
            .filter(|(_, output)| !output.offered)
            .take(64)
            .map(|(id, output)| {
                output.offered = true;
                MobileWireguardTicket {
                    id: *id,
                    tunnel: matches!(output.value, WireguardOutput::Tunnel { .. }),
                    local_endpoint: match &output.value {
                        WireguardOutput::Network {
                            reply_to: Some(WireguardIngress::DirectPath { local, .. }),
                            ..
                        } => Some(*local),
                        _ => None,
                    },
                    endpoint: match &output.value {
                        WireguardOutput::Network {
                            reply_to:
                                Some(
                                    WireguardIngress::Direct(endpoint)
                                    | WireguardIngress::DirectPath {
                                        remote: endpoint, ..
                                    },
                                ),
                            ..
                        } => Some(*endpoint),
                        _ => None,
                    },
                }
            })
            .collect()
    }

    /// Consumes a ticket only at the actual platform writer, under the Mesh lock.
    ///
    /// # Errors
    /// Propagates the writer error; a failed writer cannot reuse the ticket.
    pub fn deliver(
        &mut self,
        id: u64,
        now: UnixTime,
        clock: Instant,
        write: impl FnOnce(&WireguardOutput) -> Result<(), MobileError>,
    ) -> Result<bool, MobileError> {
        let Some(output) = self.outputs.remove(&id) else {
            return Ok(false);
        };
        self.output_bytes -= packet_length(&output.value);
        if !self.current(&output.value, now, clock) {
            return Ok(false);
        }
        write(&output.value)?;
        Ok(true)
    }

    fn current(&mut self, output: &WireguardOutput, now: UnixTime, clock: Instant) -> bool {
        let (authorization, expires) = match output {
            WireguardOutput::Network {
                authorization,
                expires,
                ..
            }
            | WireguardOutput::Tunnel {
                authorization,
                expires,
                ..
            } => (*authorization, *expires),
        };
        expires > clock && self.core.delivery_current(authorization, now)
    }

    fn expire(&mut self, now: UnixTime, clock: Instant) {
        self.outputs.retain(|_, output| {
            let (authorization, expires) = match &output.value {
                WireguardOutput::Network {
                    authorization,
                    expires,
                    ..
                }
                | WireguardOutput::Tunnel {
                    authorization,
                    expires,
                    ..
                } => (*authorization, *expires),
            };
            let valid = expires > clock && self.core.delivery_current(authorization, now);
            if !valid {
                self.output_bytes -= packet_length(&output.value);
            }
            valid
        });
    }

    /// Retains the same ciphertext for Relay when the selected UDP writer is unavailable.
    pub fn fallback(&mut self, id: u64) {
        if self.outputs.get(&id).is_some_and(|output| {
            matches!(
                output.value,
                WireguardOutput::Network {
                    path_probe: true,
                    ..
                }
            )
        }) {
            if let Some(output) = self.outputs.remove(&id) {
                self.output_bytes -= packet_length(&output.value);
            }
            return;
        }
        if let Some(output) = self.outputs.get_mut(&id)
            && let WireguardOutput::Network {
                peer: Some(peer),
                reply_to,
                ..
            } = &mut output.value
        {
            *reply_to = Some(WireguardIngress::Relay(*peer));
            output.offered = false;
        }
    }

    /// Sends a direct datagram while the authorization lock is held, falling back without resealing.
    ///
    /// # Errors
    /// Rejects a ticket that was not addressed to a direct endpoint.
    pub fn deliver_direct(
        &mut self,
        id: u64,
        now: UnixTime,
        clock: Instant,
        send: impl FnOnce(SocketAddr, &[u8]) -> bool,
    ) -> Result<bool, MobileError> {
        self.deliver_direct_on(id, None, now, clock, send)
    }

    pub fn deliver_direct_on(
        &mut self,
        id: u64,
        local: Option<SocketAddr>,
        now: UnixTime,
        clock: Instant,
        send: impl FnOnce(SocketAddr, &[u8]) -> bool,
    ) -> Result<bool, MobileError> {
        self.expire(now, clock);
        let Some(output) = self.outputs.get(&id) else {
            return Ok(false);
        };
        let WireguardOutput::Network {
            packet,
            reply_to: Some(route),
            ..
        } = &output.value
        else {
            return Err(MobileError::InvalidInput);
        };
        let endpoint = match *route {
            WireguardIngress::Direct(remote) => remote,
            WireguardIngress::DirectPath {
                local: source,
                remote,
            } if local == Some(source) => remote,
            _ => return Err(MobileError::InvalidInput),
        };
        if send(endpoint, packet) {
            self.output_bytes -= packet.len();
            self.outputs.remove(&id);
            Ok(true)
        } else {
            self.fallback(id);
            Ok(false)
        }
    }

    fn clear_outputs(&mut self) {
        self.outputs.clear();
        self.output_bytes = 0;
    }

    /// Drops this Mesh's key material and pending packets, regardless of live attachments.
    pub fn close(&mut self) {
        self.core.close();
        self.clear_outputs();
        self.audit_counts.clear();
    }

    pub(crate) fn resolve_dns(
        &mut self,
        query: &[u8],
        source: std::net::IpAddr,
        suffix: &str,
        now: UnixTime,
    ) -> Result<Vec<u8>, MobileError> {
        if !self.core.local_source_authorized(source, now) {
            return Err(MobileError::PolicyDenied);
        }
        let (_, dns) = self.core.effective_dns(source, now)?;
        let question = crate::parse_question(query)?;
        if dns.delegates_mesh_child(&question.name, suffix) {
            // A static record can answer locally; otherwise the platform forwards
            // only to this signed private namespace's configured upstream group.
            return crate::resolve_managed_dns(&dns, query);
        }
        let local =
            crate::resolve_mesh_dns(&self.core.policy(), &self.services, query, source, suffix)?;
        if !local.is_empty() && local.get(3).is_some_and(|flags| flags & 15 != 3) {
            return Ok(local);
        }
        let managed = crate::resolve_managed_dns(&dns, query)?;
        if !managed.is_empty() {
            return Ok(managed);
        }
        if !local.is_empty() {
            return Ok(local);
        }
        Ok(Vec::new())
    }
}

fn packet_length(output: &WireguardOutput) -> usize {
    match output {
        WireguardOutput::Network { packet, .. } | WireguardOutput::Tunnel { packet, .. } => {
            packet.len()
        }
    }
}

impl NativeSession {
    /// Binds a Relay carrier to its Mesh owner. Closing the carrier does not close the owner.
    ///
    /// # Errors
    /// Rejects an owner for another Mesh, Peer or signed distribution key.
    pub fn attach_wireguard(&mut self, owner: SharedMobileWireguard) -> Result<(), MobileError> {
        {
            let shared = owner.lock().map_err(|_| MobileError::InvalidState)?;
            if shared.mesh != self.trust.mesh_id
                || shared.peer != self.local_peer
                || shared.distribution != self.trust.distribution.to_bytes()
                || !shared
                    .core
                    .accepts_carrier(&self.current_credential, UnixTime(wall_clock_seconds()))
            {
                return Err(MobileError::InvalidInput);
            }
            shared
                .core
                .restore_carrier_trust(&mut self.trust.credentials)?;
            self.policy = shared.core.policy();
        }
        self.wireguard = Some(owner);
        Ok(())
    }

    pub(crate) fn shared_update(
        &mut self,
        kind: u8,
        revision: u64,
        bytes: &[u8],
        apply: impl FnOnce(&mut WireguardRuntime) -> Result<(), PeerError>,
    ) -> Result<(), MobileError> {
        if let Some(owner) = &self.wireguard {
            owner
                .lock()
                .map_err(|_| MobileError::InvalidState)?
                .accept_update(kind, revision, bytes, |owner| {
                    apply(&mut owner.core).map_err(Into::into)
                })?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "wireguard_queue_tests.rs"]
mod queue_tests;

#[path = "wireguard_platform.rs"]
mod platform;
#[path = "wireguard_preferences.rs"]
mod preferences;
pub use platform::{MobileNetworkConfiguration, MobileNetworkObservation};
