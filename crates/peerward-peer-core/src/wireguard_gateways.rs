//! Authenticated gateway path checks share `WireGuard` sessions and carrier selection.
use super::*;
use crate::coordination::{Coordination, Message};
use crate::wireguard_connectivity::Send;
use peerward_management::{GatewayPathObservation, GatewaySelector, ResourceConfiguration};
use std::time::Duration;
use uuid::Uuid;

const INTERVAL: Duration = Duration::from_secs(5);

struct PendingProbe {
    transaction: [u8; 16],
    local: Key,
    remote: Key,
    ingress: WireguardIngress,
}
struct Track {
    bindings: BTreeMap<Uuid, u64>,
    last: Option<Instant>,
    pending: Option<PendingProbe>,
}
impl Track {
    fn accept_ack(
        &mut self,
        local: Key,
        remote: Key,
        message: &Coordination,
        ingress: WireguardIngress,
        now: Instant,
    ) -> bool {
        let Message::GatewayAck(id, _) = message.message else {
            return false;
        };
        let valid = self.bindings.first_key_value() == Some((&id, &message.generation))
            && self
                .last
                .is_some_and(|sent| now.saturating_duration_since(sent) < INTERVAL)
            && self.pending.as_ref().is_some_and(|pending| {
                pending.transaction == message.transaction
                    && pending.local == local
                    && pending.remote == remote
                    && pending.ingress == ingress
            });
        if valid {
            self.pending = None;
        }
        valid
    }
}
#[derive(Default)]
pub(super) struct GatewayHealth {
    pub selector: GatewaySelector,
    version: Option<u64>,
    tracks: BTreeMap<PeerId, Track>,
    response_window: Option<Instant>,
    responses: u16,
}

impl GatewayHealth {
    pub fn sync(
        &mut self,
        resources: &ResourceConfiguration,
        local: PeerId,
        version: u64,
        now: Instant,
    ) {
        if self.version == Some(version) {
            return;
        }
        self.version = Some(version);
        let mut desired: BTreeMap<PeerId, BTreeMap<Uuid, u64>> = BTreeMap::new();
        for binding in &resources.bindings {
            if binding.approved && binding.peer_id != local {
                desired
                    .entry(binding.peer_id)
                    .or_default()
                    .insert(binding.id, binding.version);
            }
        }
        self.tracks
            .retain(|peer, track| desired.get(peer) == Some(&track.bindings));
        self.selector.retain(|id| {
            self.tracks
                .values()
                .any(|track| track.bindings.contains_key(&id))
        });
        for (peer, bindings) in desired {
            for id in bindings.keys() {
                self.selector.register(*id, now);
            }
            self.tracks.entry(peer).or_insert(Track {
                bindings,
                last: None,
                pending: None,
            });
        }
    }
    fn allow_response(&mut self, now: Instant) -> bool {
        if self
            .response_window
            .is_none_or(|since| now.saturating_duration_since(since) >= Duration::from_secs(1))
        {
            self.response_window = Some(now);
            self.responses = 0;
        }
        self.responses = self.responses.saturating_add(1);
        self.responses <= 512
    }
}

impl WireguardRuntime {
    pub fn gateway_path_observations(&self, now: Instant) -> Vec<GatewayPathObservation> {
        self.gateway_health
            .tracks
            .iter()
            .flat_map(|(peer, track)| {
                track.bindings.keys().map(|id| GatewayPathObservation {
                    binding_id: *id,
                    peer_id: *peer,
                    health: if self.state_ready() {
                        self.gateway_health.selector.health(*id, now)
                    } else {
                        peerward_management::PathHealth::Unknown
                    },
                })
            })
            .collect()
    }

    pub(super) fn poll_gateways(
        &mut self,
        wall: UnixTime,
        now: Instant,
    ) -> Result<Vec<WireguardOutput>, PeerError> {
        let Some(delivery) = &self.configuration else {
            return Ok(vec![]);
        };
        self.gateway_health.sync(
            &delivery.resources,
            self.local,
            delivery.manifest.manifest.version,
            now,
        );
        let Ok(local) = self.active_local(wall) else {
            return Ok(vec![]);
        };
        let mut sends = Vec::new();
        for (peer, track) in &mut self.gateway_health.tracks {
            if track
                .last
                .is_some_and(|last| now.saturating_duration_since(last) < INTERVAL)
            {
                continue;
            }
            if track.pending.take().is_some() {
                for id in track.bindings.keys() {
                    self.gateway_health.selector.observe(*id, false, now);
                }
            }
            track.last = Some(now);
            let Some(remote) = self
                .directory
                .active(*peer, wall)
                .map(|entry| entry.credential.wireguard_public_key)
            else {
                for id in track.bindings.keys() {
                    self.gateway_health.selector.observe(*id, false, now);
                }
                continue;
            };
            let (&binding, &version) = track
                .bindings
                .first_key_value()
                .ok_or(PeerError::InvalidConfig)?;
            let transaction = *Uuid::new_v4().as_bytes();
            let route = self.connectivity.route(&remote, now, 128);
            let ingress = route.map_or(WireguardIngress::Relay(*peer), |route| {
                route
                    .source
                    .map_or(WireguardIngress::Direct(route.endpoint), |local| {
                        WireguardIngress::DirectPath {
                            local,
                            remote: route.endpoint,
                        }
                    })
            });
            track.pending = Some(PendingProbe {
                transaction,
                local,
                remote,
                ingress,
            });
            sends.push(Send {
                local,
                remote,
                endpoint: route.map(|route| route.endpoint),
                source: route.and_then(|route| route.source),
                coordination: Coordination {
                    generation: version,
                    transaction,
                    message: Message::GatewayProbe(binding),
                },
            });
        }
        // Each provider receives one probe, regardless of how many resources it provides.
        self.expire_resource_flows(wall);
        self.send_coordination(sends, wall)
    }

    pub(super) fn receive_gateway_probe(
        &mut self,
        local: Key,
        remote: Key,
        message: &Coordination,
        ingress: WireguardIngress,
        wall: UnixTime,
        now: Instant,
    ) -> Result<Option<Vec<WireguardOutput>>, PeerError> {
        let (Message::GatewayProbe(id) | Message::GatewayAck(id, _)) = message.message else {
            return Ok(None);
        };
        let peer = self
            .directory
            .get(&remote, wall)
            .ok_or(PeerError::Revoked)?
            .peer_id;
        let Some(delivery) = &self.configuration else {
            return Ok(Some(vec![]));
        };
        if let Message::GatewayAck(_, ready) = message.message {
            let Some(track) = self.gateway_health.tracks.get_mut(&peer) else {
                return Ok(Some(vec![]));
            };
            if track.accept_ack(local, remote, message, ingress, now) {
                for id in track.bindings.keys() {
                    self.gateway_health.selector.observe(*id, ready, now);
                }
                self.expire_resource_flows(wall);
            }
            return Ok(Some(vec![]));
        }
        if !self.gateway_health.allow_response(now) {
            return Ok(Some(vec![]));
        }
        let ready = self.resource_platform_ready()
            && self.state_ready()
            && delivery.resources.bindings.iter().any(|binding| {
                binding.id == id
                    && binding.version == message.generation
                    && binding.peer_id == self.local
                    && binding.approved
                    && delivery.resources.advertisements.iter().any(|ad| {
                        ad.binding_id == id
                            && ad.binding_version == binding.version
                            && ad.peer_id == self.local
                            && ad.published
                            && ad.forwarding_ready
                            && ad.valid_until > wall.0
                    })
            });
        let (endpoint, source) = match ingress {
            WireguardIngress::Relay(_) => (None, None),
            WireguardIngress::Direct(remote) => (Some(remote), None),
            WireguardIngress::DirectPath { local, remote } => (Some(remote), Some(local)),
        };
        self.send_coordination(
            vec![Send {
                local,
                remote,
                endpoint,
                source,
                coordination: Coordination {
                    generation: message.generation,
                    transaction: message.transaction,
                    message: Message::GatewayAck(id, ready),
                },
            }],
            wall,
        )
        .map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wrong_path_key_binding_version_nonce_and_expired_or_replayed_ack_cannot_heal_a_gateway() {
        let now = Instant::now();
        let id = Uuid::new_v4();
        let ingress = WireguardIngress::Relay(PeerId::new());
        let ack = Coordination {
            generation: 3,
            transaction: [4; 16],
            message: Message::GatewayAck(id, true),
        };
        let mut track = Track {
            bindings: [(id, 3)].into(),
            last: Some(now),
            pending: Some(PendingProbe {
                transaction: [4; 16],
                local: [1; 32],
                remote: [2; 32],
                ingress,
            }),
        };
        assert!(!track.accept_ack([3; 32], [2; 32], &ack, ingress, now));
        assert!(!track.accept_ack([1; 32], [3; 32], &ack, ingress, now));
        assert!(!track.accept_ack(
            [1; 32],
            [2; 32],
            &ack,
            WireguardIngress::Direct("10.1.1.1:42".parse().unwrap()),
            now
        ));
        assert!(!track.accept_ack(
            [1; 32],
            [2; 32],
            &Coordination {
                generation: 2,
                ..ack.clone()
            },
            ingress,
            now
        ));
        assert!(!track.accept_ack(
            [1; 32],
            [2; 32],
            &Coordination {
                transaction: [5; 16],
                ..ack.clone()
            },
            ingress,
            now
        ));
        assert!(!track.accept_ack(
            [1; 32],
            [2; 32],
            &Coordination {
                message: Message::GatewayAck(Uuid::new_v4(), true),
                ..ack.clone()
            },
            ingress,
            now
        ));
        assert!(!track.accept_ack([1; 32], [2; 32], &ack, ingress, now + INTERVAL));
        assert!(track.accept_ack([1; 32], [2; 32], &ack, ingress, now));
        assert!(!track.accept_ack([1; 32], [2; 32], &ack, ingress, now));
        for message in [
            Message::GatewayProbe(id),
            Message::GatewayAck(id, false),
            Message::GatewayAck(id, true),
        ] {
            let message = Coordination {
                message,
                ..ack.clone()
            };
            assert_eq!(
                Coordination::decode(&message.encode().unwrap()).unwrap(),
                message
            );
        }
        let mut encoded = ack.encode().unwrap();
        *encoded.last_mut().unwrap() = 2;
        assert!(Coordination::decode(&encoded).is_err());
    }
}
