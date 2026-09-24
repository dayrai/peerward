use super::*;
use std::time::Duration;

impl WireguardRuntime {
    pub(super) fn output(
        &mut self,
        local: Key,
        events: Vec<Event>,
        reply_to: Option<WireguardIngress>,
        wall: UnixTime,
        now: Instant,
    ) -> Result<Vec<WireguardOutput>, PeerError> {
        let mut output = Vec::new();
        for event in events {
            match event {
                Event::Network { peer, packet } => {
                    let destination = match peer {
                        Some(key) => Some(
                            self.directory
                                .get(&key, wall)
                                .ok_or(PeerError::NoRoute)?
                                .peer_id,
                        ),
                        None => None,
                    };
                    let reply_to = reply_to.or_else(|| {
                        peer.and_then(|key| {
                            self.connectivity
                                .route(&key, now, packet.len())
                                .map(|route| {
                                    route.source.map_or(
                                        WireguardIngress::Direct(route.endpoint),
                                        |local| WireguardIngress::DirectPath {
                                            local,
                                            remote: route.endpoint,
                                        },
                                    )
                                })
                        })
                    });
                    output.push(WireguardOutput::Network {
                        local_key: local,
                        peer: destination,
                        packet,
                        reply_to,
                        path_probe: false,
                        authorization: self.authorization,
                        expires: now + Duration::from_secs(3),
                    });
                }
                Event::Plaintext { peer, packet } => {
                    let parsed = parse_packet(&packet).map_err(|_| PeerError::InvalidPacket)?;
                    let remote = self
                        .directory
                        .get(&peer, wall)
                        .ok_or(PeerError::Revoked)?
                        .peer_id;
                    let owns_source = self.directory.owns_source(&peer, parsed.source, wall);
                    let owns_destination =
                        self.directory.owns_source(&local, parsed.destination, wall);
                    let valid_ingress = if owns_source {
                        owns_destination
                            || self
                                .directory
                                .destination(parsed.destination, wall)
                                .is_none()
                    } else {
                        owns_destination
                            && self.resource_return_candidate(remote, parsed.destination, wall)
                    };
                    if !valid_ingress {
                        return Err(PeerError::InvalidPacket);
                    }
                    let ingress = reply_to.ok_or(PeerError::InvalidPacket)?;
                    let coordinate = self
                        .directory
                        .get(&local, wall)
                        .is_some_and(|key| key.active)
                        && self
                            .directory
                            .get(&peer, wall)
                            .is_some_and(|key| key.active);
                    if reserved(&parsed) {
                        if !coordinate || !owns_source || !owns_destination {
                            continue;
                        }
                        let message = crate::coordination::decode_ip(&packet)?;
                        if let Some(responses) =
                            self.receive_gateway_probe(local, peer, &message, ingress, wall, now)?
                        {
                            output.extend(responses);
                            continue;
                        }
                        let source = match ingress {
                            WireguardIngress::Direct(endpoint)
                            | WireguardIngress::DirectPath {
                                remote: endpoint, ..
                            } => Some(endpoint),
                            WireguardIngress::Relay(_) => None,
                        };
                        let responses = self.connectivity.receive_on(
                            local,
                            peer,
                            message,
                            source,
                            match ingress {
                                WireguardIngress::DirectPath { local, .. } => Some(local),
                                _ => None,
                            },
                            now,
                        )?;
                        output.extend(self.send_coordination(responses, wall)?);
                        continue;
                    }
                    let seconds = self.seconds(now);
                    let ReassemblyStatus::Complete(datagram) = self
                        .ingress_fragments
                        .push(&packet, seconds)
                        .map_err(|_| PeerError::InvalidPacket)?
                    else {
                        continue;
                    };
                    let parsed =
                        parse_packet(&datagram.packet).map_err(|_| PeerError::InvalidPacket)?;
                    if reserved(&parsed) {
                        return Err(PeerError::InvalidPacket);
                    }
                    self.inbound_allowed(&parsed, peer, local, wall, now)?;
                    if coordinate {
                        self.connectivity.touch(local, peer, now);
                    }
                    output.extend(datagram.original_fragments.into_iter().map(|packet| {
                        WireguardOutput::Tunnel {
                            peer: remote,
                            packet,
                            ingress,
                            authorization: self.authorization,
                            expires: now + Duration::from_secs(3),
                        }
                    }));
                }
            }
        }
        Ok(output)
    }
}
