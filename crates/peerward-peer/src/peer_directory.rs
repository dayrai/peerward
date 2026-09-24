#[derive(Clone)]
struct TrustedPeer {
    peer_id: PeerId,
    accepted_credentials: BTreeSet<CredentialSerial>,
    address: IpAddr,
    secondary_address: Option<IpAddr>,
    labels: BTreeMap<String, String>,
}

/// Policy-addressable peer name learned from a verified directory revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerDnsRecord {
    /// Verified owner of every address returned for this record.
    pub peer_id: PeerId,
    /// Canonical single-label peer name.
    pub name: String,
    /// Stable mesh address.
    pub address: IpAddr,
}

/// Verified Peer and Relay directory state used by the live client.
pub struct DirectPeerDirectory {
    mesh_id: MeshId,
    verifier: DirectoryPublicKey,
    chunks: ChunkAssembler,
    relay_chunks: ChunkAssembler,
    peers: BTreeMap<PeerId, TrustedPeer>,
    signed: Option<peerward_directory::SignedPeerDirectory>,
    revoked: BTreeSet<CredentialSerial>,
    revocation_revision: Option<u64>,
}

impl DirectPeerDirectory {
    /// Creates a bounded signed-directory receiver.
    pub fn new(mesh_id: MeshId, verifier: DirectoryPublicKey) -> Self {
        Self {
            mesh_id,
            verifier,
            chunks: ChunkAssembler::new(mesh_id, MAX_SIGNED_STATE_CHUNKS, MAX_SIGNED_STATE_BYTES),
            relay_chunks: ChunkAssembler::new(
                mesh_id,
                MAX_SIGNED_STATE_CHUNKS,
                MAX_SIGNED_STATE_BYTES,
            ),
            peers: BTreeMap::new(),
            signed: None,
            revoked: BTreeSet::new(),
            revocation_revision: None,
        }
    }

    /// Applies one independently bounded wire chunk and commits only a valid full revision.
    pub fn apply_chunk(
        &mut self,
        chunk: &peerward_wire::PeerDirectoryChunk,
    ) -> Result<bool, PacketPumpError> {
        let Some(signed) = self.prepare_chunk(chunk)? else {
            return Ok(false);
        };
        self.commit_directory(signed)?;
        Ok(true)
    }

    pub(crate) fn prepare_chunk(
        &mut self,
        chunk: &peerward_wire::PeerDirectoryChunk,
    ) -> Result<Option<peerward_directory::SignedPeerDirectory>, PacketPumpError> {
        let mesh_id = decode_mesh_id(&chunk.mesh_id)?;
        let completed = self
            .chunks
            .push_redundant(RevisionChunk {
                mesh_id,
                revision: chunk.revision,
                index: chunk.index,
                count: chunk.count,
                body: chunk.body.clone(),
            })
            .map_err(|error| invalid_control_error("signed directory", error))?;
        let Some(bytes) = completed else {
            return Ok(None);
        };
        let signed = decode_peer_directory(&bytes)
            .map_err(|error| invalid_control_error("signed directory", error))?;
        self.verifier
            .verify_peers(&signed, self.mesh_id, self.chunks.accepted_revision())
            .map_err(|error| invalid_control_error("signed directory", error))?;
        if signed.directory.revision != chunk.revision {
            return Err(PacketPumpError::InvalidControl);
        }
        Ok(Some(signed))
    }

    pub(crate) fn commit_directory(
        &mut self,
        signed: peerward_directory::SignedPeerDirectory,
    ) -> Result<(), PacketPumpError> {
        let peers = signed
            .directory
            .entries
            .iter()
            .filter(|entry| entry.entry.enabled)
            .map(|entry| {
                let peer = &entry.entry;
                let mut accepted_credentials: BTreeSet<_> = peer
                    .accepted_credentials
                    .iter()
                    .map(|credential| credential.serial)
                    .collect();
                accepted_credentials.insert(peer.credential_serial);
                accepted_credentials.retain(|serial| !self.revoked.contains(serial));
                (
                    peer.peer_id,
                    TrustedPeer {
                        peer_id: peer.peer_id,
                        accepted_credentials,
                        address: peer.address,
                        secondary_address: peer.secondary_address,
                        labels: peer.labels.clone(),
                    },
                )
            })
            .filter(|(_, peer)| !peer.accepted_credentials.is_empty())
            .collect();
        self.chunks
            .commit(signed.directory.revision)
            .map_err(|error| invalid_control_error("signed directory", error))?;
        self.signed = Some(signed);
        self.peers = peers;
        Ok(())
    }

    /// Authenticates and commits one complete Relay-directory revision.
    pub fn apply_relay_chunk(
        &mut self,
        chunk: &peerward_wire::RelayDirectoryChunk,
    ) -> Result<bool, PacketPumpError> {
        let Some(signed) = self.prepare_relay_chunk(chunk)? else {
            return Ok(false);
        };
        self.commit_relay_directory(signed.directory.revision)?;
        Ok(true)
    }

    pub(crate) fn prepare_relay_chunk(
        &mut self,
        chunk: &peerward_wire::RelayDirectoryChunk,
    ) -> Result<Option<peerward_directory::SignedRelayDirectory>, PacketPumpError> {
        let mesh_id = decode_mesh_id(&chunk.mesh_id)?;
        let completed = self
            .relay_chunks
            .push_redundant(RevisionChunk {
                mesh_id,
                revision: chunk.revision,
                index: chunk.index,
                count: chunk.count,
                body: chunk.body.clone(),
            })
            .map_err(|error| invalid_control_error("signed directory", error))?;
        let Some(bytes) = completed else {
            return Ok(None);
        };
        let signed = decode_relay_directory(&bytes)
            .map_err(|error| invalid_control_error("signed directory", error))?;
        self.verifier
            .verify_relays(&signed, self.mesh_id, self.relay_chunks.accepted_revision())
            .map_err(|error| invalid_control_error("signed directory", error))?;
        if signed.directory.revision != chunk.revision {
            return Err(PacketPumpError::InvalidControl);
        }
        Ok(Some(signed))
    }

    pub(crate) fn commit_relay_directory(&mut self, revision: u64) -> Result<(), PacketPumpError> {
        self.relay_chunks
            .commit(revision)
            .map_err(|error| invalid_control_error("signed directory", error))?;
        Ok(())
    }

    /// Revokes one exact credential without affecting a replacement.
    pub fn revoke(&mut self, serial: CredentialSerial) {
        self.revoked.insert(serial);
        for peer in self.peers.values_mut() {
            peer.accepted_credentials.remove(&serial);
        }
        self.peers
            .retain(|_, peer| !peer.accepted_credentials.is_empty());
    }

    /// Replaces the exact revocation set only after signature and revision verification.
    pub fn apply_revocations(
        &mut self,
        mesh_id: &[u8],
        body: &[u8],
    ) -> Result<Vec<CredentialSerial>, PacketPumpError> {
        if mesh_id != self.mesh_id.as_bytes() {
            return Err(PacketPumpError::InvalidControl);
        }
        let signed = decode_revocations(body)
            .map_err(|error| invalid_control_error("signed directory", error))?;
        self.verifier
            .verify_revocations(&signed, self.mesh_id, self.revocation_revision)
            .map_err(|error| invalid_control_error("signed directory", error))?;
        for serial in &signed.bundle.serials {
            self.revoke(*serial);
        }
        self.revocation_revision = Some(signed.bundle.revision);
        Ok(signed.bundle.serials)
    }

    /// Clones the last completely verified revision for signed-state consumers.
    pub fn signed_directory(&self) -> Option<peerward_directory::SignedPeerDirectory> {
        self.signed.clone()
    }

    /// Resolves a canonical peer label from the currently committed signed revision.
    pub fn dns_by_name(&self, name: &str) -> Option<PeerDnsRecord> {
        self.dns_by_name_family(name, None)
    }

    /// Resolves A/AAAA from the same authenticated owner, without substituting a provider.
    pub fn dns_by_name_family(&self, name: &str, ipv6: Option<bool>) -> Option<PeerDnsRecord> {
        self.peers.values().find_map(|peer| {
            let dns_name = peer.labels.get("name")?;
            if !dns_name.eq_ignore_ascii_case(name) {
                return None;
            }
            let address = std::iter::once(peer.address)
                .chain(peer.secondary_address)
                .find(|address| ipv6.is_none_or(|ipv6| address.is_ipv6() == ipv6))?;
            Some(PeerDnsRecord {
                peer_id: peer.peer_id,
                name: dns_name.clone(),
                address,
            })
        })
    }

    /// Resolves a reverse peer mapping from the currently committed signed revision.
    pub fn dns_by_address(&self, address: IpAddr) -> Option<PeerDnsRecord> {
        self.peers.values().find_map(|peer| {
            let dns_name = peer.labels.get("name")?;
            (peer.address == address || peer.secondary_address == Some(address)).then(|| {
                PeerDnsRecord {
                    peer_id: peer.peer_id,
                    name: dns_name.clone(),
                    address,
                }
            })
        })
    }

}

fn decode_mesh_id(raw: &[u8]) -> Result<MeshId, PacketPumpError> {
    let raw: [u8; 16] = raw
        .try_into()
        .map_err(|error| invalid_control_error("signed directory", error))?;
    MeshId::from_uuid(uuid::Uuid::from_bytes(raw))
        .map_err(|error| invalid_control_error("signed directory", error))
}

/// Evaluates whether an address-only peer DNS result is visible to a query source.
pub fn firewall_allows_peer_dns<P: PacketPolicy + ?Sized>(
    firewall: &P,
    source: IpAddr,
    destination: IpAddr,
) -> bool {
    let synthetic = peerward_dataplane::ParsedPacket {
        source,
        destination,
        protocol: if destination.is_ipv4() { 1 } else { 58 },
        source_port: None,
        destination_port: None,
        tcp_flags: None,
        icmp: Some((if destination.is_ipv4() { 8 } else { 128 }, 0)),
        fragment: None,
        packet_len: if destination.is_ipv4() { 28 } else { 48 },
        related_flow: None,
    };
    firewall.visible_packet(&synthetic) == Action::Allow
}

/// Evaluates service DNS visibility without creating connection-tracking state.
pub fn firewall_allows_service<P: PacketPolicy + ?Sized>(
    firewall: &P,
    source: IpAddr,
    service: &RemoteService,
    _monotonic_seconds: u64,
) -> bool {
    service.protocols.iter().any(|service_protocol| {
        let protocol = match service_protocol {
            ServiceProtocol::Tcp => 6,
            ServiceProtocol::Udp => 17,
        };
        let synthetic = peerward_dataplane::ParsedPacket {
            source,
            destination: service.virtual_address,
            protocol,
            source_port: Some(49_152),
            destination_port: Some(service.listen_port),
            tcp_flags: (protocol == 6).then_some(0x02),
            icmp: None,
            fragment: None,
            packet_len: if protocol == 6 { 40 } else { 28 },
            related_flow: None,
        };
        firewall.visible_packet(&synthetic) == Action::Allow
    })
}
