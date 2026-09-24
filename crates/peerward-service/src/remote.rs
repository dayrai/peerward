//! Signed remote-service reconciliation and ACL-gated transport bridging.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use async_trait::async_trait;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use peerward_dataplane::{Action, Firewall, ParsedPacket};
use peerward_types::{CredentialSerial, MeshId, PeerId, ServiceId};
use peerward_wire::{
    ControlEnvelope, ServiceSnapshot as WireServiceSnapshot,
    control_envelope::Message as ControlMessage,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::{
    net::{TcpStream, UdpSocket},
    sync::Mutex,
};

use crate::ServiceProtocol;

const SNAPSHOT_DOMAIN: &[u8] = b"peerward/service-directory/v2\0";

/// Signed remote service processing or transport failure.
#[derive(Debug, Error)]
pub enum RemoteServiceError {
    /// Signature, mesh scope, revision, or canonical ordering was invalid.
    #[error("remote service snapshot is invalid")]
    InvalidSnapshot,
    /// Requested service is absent, revoked, stale, or denied by policy.
    #[error("remote service is unavailable")]
    Unavailable,
    /// The selected transport did not match the publication protocol.
    #[error("remote service protocol mismatch")]
    Protocol,
    /// A local adapter or tunnel operation failed.
    #[error("remote service transport failed")]
    Io(#[from] std::io::Error),
}

/// One service advertised by an authenticated peer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteService {
    /// Stable service identity.
    pub id: ServiceId,
    /// Owning peer.
    pub owner: PeerId,
    /// Exact owner credential that published this entry.
    pub credential_serial: CredentialSerial,
    /// Mesh address used for policy and DNS visibility.
    pub virtual_address: IpAddr,
    /// Canonical nonempty published transport set.
    pub protocols: Vec<ServiceProtocol>,
    /// Mesh-visible port.
    pub listen_port: u16,
    /// Optional unique mesh label.
    pub alias: Option<String>,
}

/// Canonically ordered remote-service revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteServiceSnapshot {
    /// Mesh isolation boundary.
    pub mesh_id: MeshId,
    /// Strictly increasing revision.
    pub revision: u64,
    /// Entries sorted by service UUID bytes.
    pub services: Vec<RemoteService>,
}

/// Directory-authority signature over one snapshot transcript.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRemoteServiceSnapshot {
    /// Signed content.
    pub snapshot: RemoteServiceSnapshot,
    /// Exact Ed25519 signature bytes.
    pub signature: Vec<u8>,
}

/// Online directory signer used by the control distribution path.
pub struct ServiceSnapshotSigningKey(SigningKey);

impl ServiceSnapshotSigningKey {
    /// Imports a deterministic Ed25519 signing seed.
    pub fn from_bytes(seed: &[u8; 32]) -> Self {
        Self(SigningKey::from_bytes(seed))
    }

    /// Exports the verifier distributed in the rooted directory trust set.
    pub fn verifier(&self) -> ServiceSnapshotVerifier {
        ServiceSnapshotVerifier(self.0.verifying_key())
    }

    /// Sorts, validates, and signs one complete replacement snapshot.
    pub fn sign(
        &self,
        mut snapshot: RemoteServiceSnapshot,
    ) -> Result<SignedRemoteServiceSnapshot, RemoteServiceError> {
        snapshot.services.sort_by_key(|service| service.id);
        validate_snapshot(&snapshot)?;
        let signature = self
            .0
            .sign(&snapshot_transcript(&snapshot))
            .to_bytes()
            .to_vec();
        Ok(SignedRemoteServiceSnapshot {
            snapshot,
            signature,
        })
    }
}

/// Verifier for signed service snapshots.
#[derive(Debug, Clone, Copy)]
pub struct ServiceSnapshotVerifier(VerifyingKey);

impl ServiceSnapshotVerifier {
    /// Imports exactly one Ed25519 public key.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, RemoteServiceError> {
        VerifyingKey::from_bytes(bytes)
            .map(Self)
            .map_err(|_| RemoteServiceError::InvalidSnapshot)
    }

    /// Returns raw verifier bytes.
    #[must_use]
    pub fn to_bytes(self) -> [u8; 32] {
        self.0.to_bytes()
    }

    fn verify(&self, signed: &SignedRemoteServiceSnapshot) -> Result<(), RemoteServiceError> {
        validate_snapshot(&signed.snapshot)?;
        let signature: [u8; 64] = signed
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| RemoteServiceError::InvalidSnapshot)?;
        self.0
            .verify(
                &snapshot_transcript(&signed.snapshot),
                &Signature::from_bytes(&signature),
            )
            .map_err(|_| RemoteServiceError::InvalidSnapshot)
    }
}

/// Current verified remote services, replaced atomically by revision.
#[derive(Clone)]
pub struct RemoteServiceTable {
    mesh_id: MeshId,
    verifier: ServiceSnapshotVerifier,
    revision: Option<u64>,
    entries: BTreeMap<ServiceId, RemoteService>,
    aliases: BTreeMap<String, ServiceId>,
    revoked_credentials: BTreeSet<CredentialSerial>,
}

impl RemoteServiceTable {
    /// Creates an empty mesh-scoped table.
    pub fn new(mesh_id: MeshId, verifier: ServiceSnapshotVerifier) -> Self {
        Self {
            mesh_id,
            verifier,
            revision: None,
            entries: BTreeMap::new(),
            aliases: BTreeMap::new(),
            revoked_credentials: BTreeSet::new(),
        }
    }

    /// Verifies and atomically installs a newer complete snapshot, removing stale entries.
    pub fn reconcile(
        &mut self,
        signed: &SignedRemoteServiceSnapshot,
    ) -> Result<(), RemoteServiceError> {
        self.verifier.verify(signed)?;
        let snapshot = &signed.snapshot;
        if snapshot.mesh_id != self.mesh_id
            || self
                .revision
                .is_some_and(|revision| snapshot.revision <= revision)
            || snapshot.services.iter().any(|service| {
                self.revoked_credentials
                    .contains(&service.credential_serial)
            })
        {
            return Err(RemoteServiceError::InvalidSnapshot);
        }
        let entries = snapshot
            .services
            .iter()
            .cloned()
            .map(|service| (service.id, service))
            .collect();
        let aliases = snapshot
            .services
            .iter()
            .filter_map(|service| {
                service
                    .alias
                    .as_ref()
                    .map(|alias| (alias.to_ascii_lowercase(), service.id))
            })
            .collect();
        self.entries = entries;
        self.aliases = aliases;
        self.revision = Some(snapshot.revision);
        Ok(())
    }

    /// Removes every service issued under one exact revoked credential.
    pub fn revoke_credential(&mut self, serial: CredentialSerial) {
        self.revoked_credentials.insert(serial);
        self.entries
            .retain(|_, service| service.credential_serial != serial);
        self.rebuild_aliases();
    }

    /// Resolves an address record only when the current ACL permits the query source.
    pub fn resolve_visible<F>(&self, alias: &str, source: IpAddr, allows: F) -> Option<IpAddr>
    where
        F: FnOnce(IpAddr, &RemoteService) -> bool,
    {
        let id = self.aliases.get(&alias.to_ascii_lowercase())?;
        let service = self.entries.get(id)?;
        allows(source, service).then_some(service.virtual_address)
    }

    /// Resolves a reverse service mapping only when the current ACL permits the query source.
    pub fn resolve_ptr_visible<F>(
        &self,
        address: IpAddr,
        source: IpAddr,
        mut allows: F,
    ) -> Option<String>
    where
        F: FnMut(IpAddr, &RemoteService) -> bool,
    {
        self.entries.values().find_map(|service| {
            (service.virtual_address == address && allows(source, service))
                .then(|| service.alias.clone())
                .flatten()
        })
    }

    /// Looks up a service for forwarding only when protocol and ACL both match.
    pub fn permitted<F>(
        &self,
        id: ServiceId,
        protocol: ServiceProtocol,
        source: IpAddr,
        allows: F,
    ) -> Result<RemoteService, RemoteServiceError>
    where
        F: FnOnce(IpAddr, &RemoteService) -> bool,
    {
        let service = self
            .entries
            .get(&id)
            .ok_or(RemoteServiceError::Unavailable)?;
        if !service.protocols.contains(&protocol) {
            return Err(RemoteServiceError::Protocol);
        }
        if !allows(source, service) {
            return Err(RemoteServiceError::Unavailable);
        }
        Ok(service.clone())
    }

    fn rebuild_aliases(&mut self) {
        self.aliases = self
            .entries
            .values()
            .filter_map(|service| {
                service
                    .alias
                    .as_ref()
                    .map(|alias| (alias.to_ascii_lowercase(), service.id))
            })
            .collect();
    }
}

/// Encodes a signed snapshot into the authenticated Noise control family.
pub fn snapshot_control(
    signed: &SignedRemoteServiceSnapshot,
) -> Result<ControlEnvelope, RemoteServiceError> {
    let body = serde_json::to_vec(signed).map_err(|_| RemoteServiceError::InvalidSnapshot)?;
    Ok(ControlEnvelope {
        trace_context: None,
        message: Some(ControlMessage::Services(WireServiceSnapshot {
            mesh_id: signed.snapshot.mesh_id.as_bytes().to_vec(),
            revision: signed.snapshot.revision,
            index: 0,
            count: 1,
            body,
        })),
    })
}

/// Verifies and reconciles one service snapshot from an authenticated Noise envelope.
pub fn apply_snapshot_control(
    table: &mut RemoteServiceTable,
    envelope: &ControlEnvelope,
) -> Result<(), RemoteServiceError> {
    let Some(ControlMessage::Services(message)) = &envelope.message else {
        return Err(RemoteServiceError::InvalidSnapshot);
    };
    let signed: SignedRemoteServiceSnapshot =
        serde_json::from_slice(&message.body).map_err(|_| RemoteServiceError::InvalidSnapshot)?;
    if message.mesh_id != signed.snapshot.mesh_id.as_bytes()
        || message.revision != signed.snapshot.revision
        || message.index != 0
        || message.count != 1
    {
        return Err(RemoteServiceError::InvalidSnapshot);
    }
    table.reconcile(&signed)
}

/// Evaluates a service connection as a state-creating TCP SYN or UDP datagram.
pub fn firewall_allows_service(
    firewall: &Firewall,
    source: IpAddr,
    service: &RemoteService,
    requested_protocol: ServiceProtocol,
    _monotonic_seconds: u64,
) -> bool {
    if !service.protocols.contains(&requested_protocol) {
        return false;
    }
    let protocol = match requested_protocol {
        ServiceProtocol::Tcp => 6,
        ServiceProtocol::Udp => 17,
    };
    let synthetic = ParsedPacket {
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
    firewall.policy_decision(&synthetic).action == Action::Allow
}

/// Peer-transport abstraction used by TCP and UDP service forwarding.
#[async_trait]
pub trait RemoteServiceTransport: Send + Sync {
    /// Opens one ordered stream to the service owner.
    async fn connect_tcp(&self, service: &RemoteService) -> Result<TcpStream, RemoteServiceError>;
    /// Sends one datagram and awaits one associated response.
    async fn exchange_udp(
        &self,
        service: &RemoteService,
        request: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, RemoteServiceError>;
}

/// Bridges a local accepted stream into the authenticated peer transport.
pub async fn forward_remote_tcp<T: RemoteServiceTransport>(
    mut local: TcpStream,
    service: &RemoteService,
    transport: &T,
) -> Result<(), RemoteServiceError> {
    if !service.protocols.contains(&ServiceProtocol::Tcp) {
        return Err(RemoteServiceError::Protocol);
    }
    let mut remote = transport.connect_tcp(service).await?;
    tokio::io::copy_bidirectional(&mut local, &mut remote).await?;
    Ok(())
}

/// Loopback adapter used by the destination peer and localhost integration tests.
#[derive(Default)]
pub struct LoopbackServiceTransport {
    targets: Mutex<BTreeMap<ServiceId, SocketAddr>>,
}

impl LoopbackServiceTransport {
    /// Adds or replaces the destination selected after authenticated mesh routing.
    pub async fn register(
        &self,
        id: ServiceId,
        target: SocketAddr,
    ) -> Result<(), RemoteServiceError> {
        if !target.ip().is_loopback() || target.port() == 0 {
            return Err(RemoteServiceError::Unavailable);
        }
        self.targets.lock().await.insert(id, target);
        Ok(())
    }

    /// Removes a stale or revoked destination mapping.
    pub async fn remove(&self, id: ServiceId) {
        self.targets.lock().await.remove(&id);
    }

    async fn target(&self, id: ServiceId) -> Result<SocketAddr, RemoteServiceError> {
        self.targets
            .lock()
            .await
            .get(&id)
            .copied()
            .ok_or(RemoteServiceError::Unavailable)
    }
}

#[async_trait]
impl RemoteServiceTransport for LoopbackServiceTransport {
    async fn connect_tcp(&self, service: &RemoteService) -> Result<TcpStream, RemoteServiceError> {
        if !service.protocols.contains(&ServiceProtocol::Tcp) {
            return Err(RemoteServiceError::Protocol);
        }
        Ok(TcpStream::connect(self.target(service.id).await?).await?)
    }

    async fn exchange_udp(
        &self,
        service: &RemoteService,
        request: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, RemoteServiceError> {
        if !service.protocols.contains(&ServiceProtocol::Udp) {
            return Err(RemoteServiceError::Protocol);
        }
        let target = self.target(service.id).await?;
        let socket = UdpSocket::bind(crate::loopback_bind_address(target)).await?;
        socket.connect(target).await?;
        socket.send(request).await?;
        let mut response = vec![0_u8; 65_535];
        let length = tokio::time::timeout(timeout, socket.recv(&mut response))
            .await
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::TimedOut))??;
        response.truncate(length);
        Ok(response)
    }
}

fn validate_snapshot(snapshot: &RemoteServiceSnapshot) -> Result<(), RemoteServiceError> {
    let mut previous = None;
    let mut aliases = BTreeSet::new();
    for service in &snapshot.services {
        if service.listen_port == 0
            || !valid_remote_protocols(&service.protocols)
            || service
                .alias
                .as_deref()
                .is_some_and(|alias| !valid_alias(alias))
            || previous.is_some_and(|id| id >= service.id)
            || service
                .alias
                .as_ref()
                .is_some_and(|alias| !aliases.insert(alias.to_ascii_lowercase()))
        {
            return Err(RemoteServiceError::InvalidSnapshot);
        }
        previous = Some(service.id);
    }
    Ok(())
}

fn valid_alias(alias: &str) -> bool {
    !alias.is_empty()
        && alias.len() <= 63
        && !alias.starts_with('-')
        && !alias.ends_with('-')
        && alias
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn snapshot_transcript(snapshot: &RemoteServiceSnapshot) -> Vec<u8> {
    let mut transcript = Vec::new();
    transcript.extend_from_slice(SNAPSHOT_DOMAIN);
    transcript.extend_from_slice(snapshot.mesh_id.as_bytes());
    transcript.extend_from_slice(&snapshot.revision.to_be_bytes());
    transcript.extend_from_slice(
        &u32::try_from(snapshot.services.len())
            .expect("service count fits u32")
            .to_be_bytes(),
    );
    for service in &snapshot.services {
        transcript.extend_from_slice(service.id.as_bytes());
        transcript.extend_from_slice(service.owner.as_bytes());
        transcript.extend_from_slice(service.credential_serial.as_bytes());
        match service.virtual_address {
            IpAddr::V4(address) => {
                transcript.push(4);
                transcript.extend_from_slice(&address.octets());
            }
            IpAddr::V6(address) => {
                transcript.push(6);
                transcript.extend_from_slice(&address.octets());
            }
        }
        transcript.push(u8::try_from(service.protocols.len()).expect("protocol count fits u8"));
        for protocol in &service.protocols {
            transcript.push(match protocol {
                ServiceProtocol::Tcp => 1,
                ServiceProtocol::Udp => 2,
            });
        }
        transcript.extend_from_slice(&service.listen_port.to_be_bytes());
        if let Some(alias) = &service.alias {
            transcript.push(1);
            transcript.extend_from_slice(
                &u32::try_from(alias.len())
                    .expect("validated alias fits u32")
                    .to_be_bytes(),
            );
            transcript.extend_from_slice(alias.as_bytes());
        } else {
            transcript.push(0);
        }
    }
    transcript
}

fn valid_remote_protocols(protocols: &[ServiceProtocol]) -> bool {
    matches!(
        protocols,
        [ServiceProtocol::Tcp | ServiceProtocol::Udp]
            | [ServiceProtocol::Tcp, ServiceProtocol::Udp]
    )
}

#[cfg(test)]
#[path = "remote_tests.rs"]
mod tests;
