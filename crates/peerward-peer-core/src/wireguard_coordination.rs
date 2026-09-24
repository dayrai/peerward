use super::{Event, PeerError, WireguardIngress, WireguardOutput, WireguardRuntime};
use crate::wireguard_connectivity::Send;
use peerward_types::UnixTime;
use std::net::SocketAddr;

impl WireguardRuntime {
    /// A network generation changes only path checks, never `WireGuard` key/session state.
    /// Empty candidates are valid and retain Relay connectivity.
    pub fn update_candidates(&mut self, candidates: Vec<SocketAddr>) -> Result<(), PeerError> {
        if self.closed {
            return Err(PeerError::Closed);
        }
        self.connectivity.update(candidates)
    }

    /// Installs actual platform socket endpoints separately from private advertised candidates.
    pub fn update_local_paths(
        &mut self,
        local: Vec<SocketAddr>,
        candidates: Vec<SocketAddr>,
    ) -> Result<(), PeerError> {
        if self.closed {
            return Err(PeerError::Closed);
        }
        self.connectivity.update_paths(local, candidates)
    }

    pub(super) fn send_coordination(
        &mut self,
        sends: Vec<Send>,
        wall: UnixTime,
    ) -> Result<Vec<WireguardOutput>, PeerError> {
        let mut output = Vec::new();
        for send in sends {
            let Some(local) = self.directory.get(&send.local, wall) else {
                continue;
            };
            let Some(remote) = self.directory.get(&send.remote, wall) else {
                continue;
            };
            let peer = remote.peer_id;
            let packet =
                crate::coordination::encode_ip(local.address, remote.address, &send.coordination)?;
            let Some(slot) = self
                .slots
                .iter_mut()
                .find(|slot| slot.engine.public_key() == send.local)
            else {
                continue;
            };
            let events = match slot
                .engine
                .send_ready(&send.remote, &packet)
                .map_err(super::wg_error)?
            {
                Some(event) => vec![event],
                None if send.endpoint.is_none() => slot
                    .engine
                    .initiate(&send.remote)
                    .map_err(super::wg_error)?,
                None => Vec::new(),
            };
            for event in events {
                if let Event::Network { packet, .. } = event {
                    output.push(WireguardOutput::Network {
                        local_key: send.local,
                        peer: Some(peer),
                        packet,
                        path_probe: send.endpoint.is_some(),
                        reply_to: Some(send.endpoint.map_or(
                            WireguardIngress::Relay(peer),
                            |remote| {
                                send.source
                                    .map_or(WireguardIngress::Direct(remote), |local| {
                                        WireguardIngress::DirectPath { local, remote }
                                    })
                            },
                        )),
                        authorization: self.authorization,
                        expires: std::time::Instant::now() + std::time::Duration::from_secs(3),
                    });
                }
            }
        }
        Ok(output)
    }
}
