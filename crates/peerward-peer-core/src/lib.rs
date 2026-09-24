//! Platform-neutral Peer attachment, failover, revision, and rotation state.

use std::{
    collections::{BTreeSet, VecDeque},
    time::Duration,
};

use peerward_credentials::CredentialError;
use peerward_directory::{
    DirectoryError, DirectoryPublicKey, SignedPeerDirectory, SignedPolicyBundle,
    SignedRelayDirectory, SignedRevocationBundle,
};
use peerward_types::{AttachmentId, CredentialSerial, MeshId, RelayId};
use peerward_wire::WireError;
use thiserror::Error;

mod checkpoint;
pub use checkpoint::SnapshotKind;
mod coordination;
pub use coordination::filter_wireguard_candidates;
mod platform;
mod policy;
mod relay_pool;
mod runtime;
mod runtime_diagnostics;
mod schedule;
mod wireguard_connectivity;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod wireguard_socket;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use wireguard_socket::configure_wireguard_udp;
mod wireguard_directory;
mod wireguard_runtime;
pub use wireguard_directory::{WireguardDirectory, WireguardPeerAuthorization};
pub use wireguard_runtime::{WireguardIngress, WireguardOutput, WireguardRuntime};

pub use platform::{
    PlatformProtocolError, PlatformRequest, PlatformRequestBroker, PlatformRequestKind,
};
pub use policy::PolicyEngine;
pub use relay_pool::{
    RelayConnectCommit, RelayConnectRequest, RelayPoolError, RelayPoolOrchestrator, RelayRoute,
};
pub use runtime::{RuntimeEvent, RuntimeOrchestrator, RuntimePhase, RuntimeView};
pub use schedule::{RuntimeHealthFingerprint, RuntimeSchedule, RuntimeScheduler};

/// Platform-neutral session or transport failure.
#[derive(Debug, Error)]
pub enum PeerError {
    /// The old device data protocol is no longer supported.
    #[error("legacy peer profile is unsupported; update the client and join the Mesh again")]
    LegacyProfile,
    /// TOML could not be decoded into the strict schema.
    #[error("invalid peer TOML: {0}")]
    Toml(#[from] toml::de::Error),
    /// Configuration shape or value is invalid.
    #[error("invalid peer configuration")]
    InvalidConfig,
    /// A signed distribution object failed verification.
    #[error("signed update is invalid")]
    Directory(#[from] DirectoryError),
    /// A persisted signed-state checkpoint is unavailable or rejects rollback.
    #[error("signed-state checkpoint: {0}")]
    Checkpoint(&'static str),
    /// No usable Relay remains.
    #[error("no healthy relay attachment")]
    NoRelay,
    /// Root-verified permanent termination; persist before shutting down the Mesh.
    #[error("mesh has been permanently deleted")]
    MeshTerminated(Vec<u8>),
    /// Packet runtime failure with its original platform-adapter cause preserved.
    #[error("peer packet runtime failed")]
    PacketRuntime(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// A packet failed strict IP parsing.
    #[error("packet is invalid")]
    InvalidPacket,
    /// A valid IP packet is denied by the current signed application policy.
    #[error("packet denied by policy")]
    PolicyDenied,
    /// A bounded queue, candidate set, or pending-attempt table is full.
    #[error("packet queue is full")]
    QueueFull,
    /// No signed destination or usable path exists for the packet.
    #[error("packet destination has no route")]
    NoRoute,
    /// The state machine is shutting down.
    #[error("peer session is closed")]
    Closed,
    /// An exact credential serial is no longer usable.
    #[error("credential serial is revoked")]
    Revoked,
    /// Noise authentication or framing failed.
    #[error("peer relay transport failed")]
    Wire(#[from] WireError),
    /// A local or Relay credential is not rooted, current, or role-correct.
    #[error("peer credential validation failed")]
    Credential(#[from] CredentialError),
    /// A canonical identity policy could not be decoded.
    #[error("peer policy is invalid")]
    Policy(#[from] peerward_policy::PolicyError),
    /// Relay socket I/O failed.
    #[error("peer relay socket failed")]
    Io(#[from] std::io::Error),
}

/// Primary or warm-standby Relay role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachmentRole {
    /// Current forwarding attachment.
    Primary,
    /// Authenticated alternate maintained without forwarding.
    Standby,
}

/// Health and fencing state for one Relay connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelaySession {
    /// Relay identity.
    pub relay_id: RelayId,
    /// Fresh attachment identity.
    pub attachment_id: AttachmentId,
    /// Current role.
    pub role: AttachmentRole,
    /// Presence generation assigned by storage.
    pub fencing_generation: i64,
    /// Last measured round-trip in milliseconds.
    pub rtt_millis: Option<u64>,
    /// Consecutive missed replies.
    pub missed_keepalives: u8,
    /// Whether the authenticated transport is active.
    pub connected: bool,
}

/// Staged credential replacement state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationState {
    /// One serial is active.
    Active(CredentialSerial),
    /// Replacement is authenticated but not selected.
    Staged {
        /// Currently used serial.
        current: CredentialSerial,
        /// Candidate serial.
        replacement: CredentialSerial,
    },
}

/// Shared state machine driven by Linux, Android, or another platform adapter.
pub struct SessionManager {
    mesh_id: MeshId,
    verifier: DirectoryPublicKey,
    peer_revision: Option<u64>,
    relay_revision: Option<u64>,
    policy_revision: Option<u64>,
    revocation_revision: Option<u64>,
    primary: Option<RelaySession>,
    standby: Option<RelaySession>,
    packets: VecDeque<Vec<u8>>,
    packet_capacity: usize,
    unhealthy_after: u8,
    rotation: RotationState,
    revoked: BTreeSet<CredentialSerial>,
    closed: bool,
}

impl SessionManager {
    /// Starts disconnected with one active credential.
    pub fn new(
        mesh_id: MeshId,
        verifier: DirectoryPublicKey,
        credential: CredentialSerial,
        packet_capacity: usize,
        unhealthy_after: u8,
    ) -> Result<Self, PeerError> {
        if packet_capacity == 0 || unhealthy_after == 0 {
            return Err(PeerError::InvalidConfig);
        }
        Ok(Self {
            mesh_id,
            verifier,
            peer_revision: None,
            relay_revision: None,
            policy_revision: None,
            revocation_revision: None,
            primary: None,
            standby: None,
            packets: VecDeque::with_capacity(packet_capacity),
            packet_capacity,
            unhealthy_after,
            rotation: RotationState::Active(credential),
            revoked: BTreeSet::new(),
            closed: false,
        })
    }

    /// Installs an authenticated primary or warm standby.
    pub fn attach(&mut self, session: RelaySession) -> Result<(), PeerError> {
        if self.closed {
            return Err(PeerError::Closed);
        }
        match session.role {
            AttachmentRole::Primary => self.primary = Some(session),
            AttachmentRole::Standby => self.standby = Some(session),
        }
        Ok(())
    }

    /// Applies a strictly newer signed Peer directory.
    pub fn apply_peers(&mut self, update: &SignedPeerDirectory) -> Result<(), PeerError> {
        self.verifier
            .verify_peers(update, self.mesh_id, self.peer_revision)?;
        self.peer_revision = Some(update.directory.revision);
        Ok(())
    }

    /// Applies a strictly newer signed Relay directory.
    pub fn apply_relays(&mut self, update: &SignedRelayDirectory) -> Result<(), PeerError> {
        self.verifier
            .verify_relays(update, self.mesh_id, self.relay_revision)?;
        self.relay_revision = Some(update.directory.revision);
        Ok(())
    }

    /// Applies a strictly newer signed policy revision.
    pub fn apply_policy(&mut self, update: &SignedPolicyBundle) -> Result<(), PeerError> {
        self.verifier
            .verify_policy(update, self.mesh_id, self.policy_revision)?;
        self.policy_revision = Some(update.bundle.revision);
        Ok(())
    }

    /// Applies a complete, strictly newer signed exact-revocation set.
    pub fn apply_revocations(
        &mut self,
        update: &SignedRevocationBundle,
    ) -> Result<bool, PeerError> {
        self.verifier
            .verify_revocations(update, self.mesh_id, self.revocation_revision)?;
        self.revocation_revision = Some(update.bundle.revision);
        self.revoked = update.bundle.serials.iter().copied().collect();
        let active_revoked = self.revoked.contains(&self.active_serial());
        if active_revoked {
            self.primary = None;
            self.standby = None;
        }
        Ok(active_revoked)
    }

    /// Marks one missing reply and promotes a healthy standby when needed.
    pub fn miss_keepalive(&mut self, relay: RelayId) -> Result<bool, PeerError> {
        let Some(primary) = self.primary.as_mut() else {
            return Err(PeerError::NoRelay);
        };
        if primary.relay_id != relay {
            return Ok(false);
        }
        primary.missed_keepalives = primary.missed_keepalives.saturating_add(1);
        if primary.missed_keepalives < self.unhealthy_after {
            return Ok(false);
        }
        primary.connected = false;
        let Some(mut promoted) = self.standby.take().filter(|item| item.connected) else {
            return Err(PeerError::NoRelay);
        };
        promoted.role = AttachmentRole::Primary;
        let mut former = self.primary.replace(promoted).expect("primary exists");
        former.role = AttachmentRole::Standby;
        self.standby = Some(former);
        Ok(true)
    }

    /// Adds one complete IPv4 or IPv6 packet without blocking transport tasks.
    pub fn enqueue_packet(&mut self, packet: Vec<u8>) -> Result<(), PeerError> {
        if self.closed {
            return Err(PeerError::Closed);
        }
        if packet
            .first()
            .is_none_or(|first| !matches!(first >> 4, 4 | 6))
            || self.packets.len() == self.packet_capacity
        {
            return Err(PeerError::QueueFull);
        }
        self.packets.push_back(packet);
        Ok(())
    }

    /// Takes the next packet for the primary transport.
    pub fn dequeue_packet(&mut self) -> Result<Option<Vec<u8>>, PeerError> {
        if !self.primary.as_ref().is_some_and(|item| item.connected) {
            return Err(PeerError::NoRelay);
        }
        Ok(self.packets.pop_front())
    }

    /// Stages a distinct exact serial while retaining the current credential.
    pub fn stage_rotation(&mut self, replacement: CredentialSerial) -> Result<(), PeerError> {
        if self.revoked.contains(&replacement) || self.active_serial() == replacement {
            return Err(PeerError::Revoked);
        }
        self.rotation = RotationState::Staged {
            current: self.active_serial(),
            replacement,
        };
        Ok(())
    }

    /// Activates the staged replacement.
    pub fn activate_rotation(&mut self) -> Result<CredentialSerial, PeerError> {
        let RotationState::Staged { replacement, .. } = self.rotation else {
            return Err(PeerError::Revoked);
        };
        self.rotation = RotationState::Active(replacement);
        Ok(replacement)
    }

    /// Revokes exactly one serial and disconnects only when it is active.
    pub fn revoke(&mut self, serial: CredentialSerial) -> Result<(), PeerError> {
        self.revoked.insert(serial);
        if self.active_serial() == serial {
            self.primary = None;
            self.standby = None;
            return Err(PeerError::Revoked);
        }
        Ok(())
    }

    /// Active credential serial.
    pub const fn active_serial(&self) -> CredentialSerial {
        match self.rotation {
            RotationState::Active(serial)
            | RotationState::Staged {
                current: serial, ..
            } => serial,
        }
    }

    /// Deterministic bounded exponential retry with identity-derived jitter.
    pub fn reconnect_delay(attempt: u8, relay: RelayId) -> Duration {
        let entropy = relay
            .as_bytes()
            .iter()
            .fold(0_u64, |sum, byte| sum + u64::from(*byte));
        RuntimeOrchestrator::reconnect_delay(attempt, entropy)
    }

    /// Stops accepting packets and clears queued plaintext.
    pub fn graceful_shutdown(&mut self) {
        self.closed = true;
        self.packets.clear();
        self.primary = None;
        self.standby = None;
    }

    /// Current primary Relay.
    pub const fn primary(&self) -> Option<&RelaySession> {
        self.primary.as_ref()
    }
}
