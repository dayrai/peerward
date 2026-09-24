use peerward_carrier::BoxStream;
use peerward_carrier::RecordTransport as StreamTransport;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex as StdMutex, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use peerward_credentials::{
    CredentialError, DistributionCertificate, SignedAuthorityBundle, SubjectCredential, SubjectId,
    TrustSet,
};
use opentelemetry::{
    Context as OpenTelemetryContext,
    trace::{
        SpanContext as OpenTelemetrySpanContext, SpanId as OpenTelemetrySpanId,
        TraceContextExt as _, TraceFlags as OpenTelemetryTraceFlags,
        TraceId as OpenTelemetryTraceId, TraceState as OpenTelemetryTraceState,
    },
};
use peerward_directory::{
    DirectoryError, DirectoryPublicKey, RelayEntry, SignedPeerDirectory, SignedPolicyBundle,
    SignedRelayDirectory, SignedRelayTopologyV1, SignedRevocationBundle, decode_peer_directory,
    decode_policy, decode_relay_directory, decode_relay_topology, decode_revocations,
    encode_peer_directory, encode_policy, encode_relay_directory,
    encode_revocations, split_chunks,
};
use peerward_service::{RemoteServiceTable, ServiceSnapshotVerifier, SignedRemoteServiceSnapshot};
use peerward_store::{
    PeerCredentialAdmission, PresenceLease, PresenceRole, RelayCredentialAdmission,
    RelayNeighborHealth, SignedStateKind, Store, StoreError,
};
use peerward_types::{
    AttachmentId, CredentialSerial, MeshId, NetworkEndpoint, PeerId, RelayId, RotationId,
    ServiceId, ServiceProtocol, SubjectRole, UnixTime, validate_endpoint_list,
};
use peerward_wire::{
    AuthorityDirectoryChunk, ControlEnvelope, CredentialReplacement, CredentialRevocation,
    ForwardedPacket, HandshakePayload, Keepalive, PeerDirectoryChunk,
    PolicyBundle as WirePolicyBundle, PresenceUpdate, Record, RelayDirectoryChunk,
    ServiceMutationResult, ServiceSnapshot as WireServiceSnapshot,
    WireError, control_envelope::Message as ControlMessage, ik_responder,
    kk_handshake,
};
use prost::Message;
use serde::Deserialize;
use thiserror::Error;
use time::OffsetDateTime;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Mutex, RwLock as AsyncRwLock, Semaphore, mpsc, watch},
};
use tracing_opentelemetry::OpenTelemetrySpanExt as _;

fn remote_trace_parent(context: peerward_types::CorrelationContext) -> OpenTelemetryContext {
    OpenTelemetryContext::new().with_remote_span_context(OpenTelemetrySpanContext::new(
        OpenTelemetryTraceId::from_bytes(context.trace_id),
        OpenTelemetrySpanId::from_bytes(context.span_id),
        OpenTelemetryTraceFlags::new(context.flags),
        true,
        OpenTelemetryTraceState::default(),
    ))
}

/// Strict relay service configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayConfig {
    /// Outgoing backbone WSS trust and explicit CONNECT settings.
    #[serde(default)]
    pub relay_transport: peerward_carrier::ClientOptions,
    /// Must equal one.
    pub config_version: u32,
    /// Relay identity.
    pub relay_id: RelayId,
    /// Mesh served by this process.
    pub mesh_id: MeshId,
    /// Peer listener.
    #[serde(default = "default_peer_address")]
    pub peer_address: SocketAddr,
    /// Relay backbone listener.
    #[serde(default = "default_backbone_address")]
    pub backbone_address: SocketAddr,
    /// Optional local HTTP health and metrics listener.
    pub health_address: Option<SocketAddr>,
    /// `PostgreSQL` URL, with environment fallback when absent.
    pub database_url: Option<String>,
    /// X25519 private key file.
    pub private_key_file: PathBuf,
    /// Authority-signed relay credential file.
    pub credential_file: PathBuf,
    /// Offline root public key used to anchor peer credentials.
    pub root_public_key_file: PathBuf,
    /// Root-certified online authority document.
    pub authority_certificate_file: PathBuf,
    /// Authority-signed directory and service verifier binding.
    pub distribution_certificate_file: PathBuf,
    /// Per-destination packet bound.
    #[serde(default = "default_queue_capacity")]
    pub queue_capacity: usize,
    /// Presence lease duration.
    #[serde(default = "default_lease_seconds")]
    pub lease_seconds: u64,
    /// Keepalive cadence.
    #[serde(default = "default_keepalive_seconds")]
    pub keepalive_seconds: u64,
    /// Maximum concurrently established Peer sessions.
    #[serde(default = "default_max_peer_sessions")]
    pub max_peer_sessions: usize,
    /// Maximum Noise handshakes being processed at once.
    #[serde(default = "default_max_pending_handshakes")]
    pub max_pending_handshakes: usize,
    /// Maximum pending handshakes accepted from one source IP.
    #[serde(default = "default_max_pending_handshakes_per_ip")]
    pub max_pending_handshakes_per_ip: usize,
    /// Hard timeout for a Peer or backbone handshake.
    #[serde(default = "default_handshake_timeout_seconds")]
    pub handshake_timeout_seconds: u64,
}

impl RelayConfig {
    /// Parses versioned TOML, applies the database fallback, and resolves key paths.
    pub fn parse(
        contents: &str,
        config_path: &Path,
        environment_database_url: Option<String>,
    ) -> Result<Self, RelayError> {
        require_version_first(contents)?;
        let mut config: Self = toml::from_str(contents).map_err(|_| RelayError::InvalidConfig)?;
        if config.config_version != 1 {
            return Err(RelayError::InvalidConfig);
        }
        if config.database_url.is_none() {
            config.database_url = environment_database_url;
        }
        if config.database_url.as_deref().is_none_or(str::is_empty)
            || config.peer_address == config.backbone_address
            || config
                .health_address
                .is_some_and(|health| health == config.peer_address || health == config.backbone_address)
            || config.queue_capacity == 0
            || config.lease_seconds == 0
            || config.keepalive_seconds == 0
            || config.max_peer_sessions == 0
            || config.max_pending_handshakes == 0
            || config.max_pending_handshakes_per_ip == 0
            || config.handshake_timeout_seconds == 0
        {
            return Err(RelayError::InvalidConfig);
        }
        let base = config_path.parent().unwrap_or_else(|| Path::new("."));
        if config.private_key_file.is_relative() {
            config.private_key_file = base.join(&config.private_key_file);
        }
        if config.credential_file.is_relative() {
            config.credential_file = base.join(&config.credential_file);
        }
        if config.root_public_key_file.is_relative() {
            config.root_public_key_file = base.join(&config.root_public_key_file);
        }
        if config.authority_certificate_file.is_relative() {
            config.authority_certificate_file = base.join(&config.authority_certificate_file);
        }
        if config.distribution_certificate_file.is_relative() {
            config.distribution_certificate_file = base.join(&config.distribution_certificate_file);
        }
        Ok(config)
    }
}

fn default_peer_address() -> SocketAddr {
    "0.0.0.0:7777".parse().expect("fixed address")
}

fn default_backbone_address() -> SocketAddr {
    "0.0.0.0:7778".parse().expect("fixed address")
}

const fn default_queue_capacity() -> usize {
    512
}

const fn default_lease_seconds() -> u64 {
    30
}

const fn default_keepalive_seconds() -> u64 {
    10
}

const fn default_max_peer_sessions() -> usize {
    10_000
}

const fn default_max_pending_handshakes() -> usize {
    256
}

const fn default_max_pending_handshakes_per_ip() -> usize {
    16
}

const fn default_handshake_timeout_seconds() -> u64 {
    5
}

/// Relay authentication, routing, or storage failure.
#[derive(Debug, Error)]
pub enum RelayError {
    /// Configuration shape or value is invalid.
    #[error("invalid relay configuration")]
    InvalidConfig,
    /// Noise or record processing failed.
    #[error("relay transport protocol failed")]
    Wire(#[from] WireError),
    /// Socket I/O failed.
    #[error("relay socket operation failed")]
    Io(#[from] std::io::Error),
    /// Persistent fencing operation failed.
    #[error("relay presence operation failed")]
    Store(#[from] StoreError),
    /// Credential is invalid, wrong-role, or revoked.
    #[error("relay credential validation failed")]
    Credential(#[from] CredentialError),
    /// Signed distribution object failed authentication or ordering.
    #[error("relay signed update is invalid")]
    Directory(#[from] DirectoryError),
    /// No route is currently owned by this relay topology.
    #[error("relay route is unavailable")]
    NoRoute,
    /// A stale generation attempted to forward.
    #[error("stale presence generation")]
    StaleFence,
    /// A bounded packet queue reached capacity.
    #[error("relay packet queue is full")]
    QueueFull,
    /// A Relay backbone forwarding frame failed strict decoding.
    #[error("relay forwarding frame is malformed")]
    MalformedForwarded,
    /// A bounded handshake permit or deadline was exhausted.
    #[error("relay handshake capacity or deadline exhausted")]
    HandshakeLimited,
}

/// Deterministic ownership of a pairwise KK dial.
pub fn should_initiate(local: RelayId, remote: RelayId) -> bool {
    local.as_bytes() < remote.as_bytes()
}

/// Verifies subject credentials, role, Noise identity, and exact revocation.
pub struct CredentialGate {
    trust: RwLock<TrustSet>,
    revoked: RwLock<BTreeSet<CredentialSerial>>,
    peer_admissions: RwLock<Option<BTreeSet<(PeerId, CredentialSerial)>>>,
    relay_admissions: RwLock<Option<BTreeSet<(RelayId, CredentialSerial)>>>,
}

impl CredentialGate {
    /// Wraps one root-anchored mesh trust set.
    pub fn new(trust: TrustSet) -> Self {
        Self {
            trust: RwLock::new(trust),
            revoked: RwLock::new(BTreeSet::new()),
            peer_admissions: RwLock::new(None),
            relay_admissions: RwLock::new(None),
        }
    }

    /// Atomically replaces the transactionally consistent credential admission sets.
    pub fn install_admissions(
        &self,
        peers: &[PeerCredentialAdmission],
        relays: &[RelayCredentialAdmission],
    ) -> Result<(), RelayError> {
        let peer_set = peers
            .iter()
            .map(|entry| (entry.peer_id, entry.serial))
            .collect();
        let relay_set = relays
            .iter()
            .map(|entry| (entry.relay_id, entry.serial))
            .collect();
        *self
            .peer_admissions
            .write()
            .map_err(|_| RelayError::Credential(CredentialError::InvalidSignature))? =
            Some(peer_set);
        *self
            .relay_admissions
            .write()
            .map_err(|_| RelayError::Credential(CredentialError::InvalidSignature))? =
            Some(relay_set);
        Ok(())
    }

    /// Returns whether one exact Relay credential is admitted by the latest database snapshot.
    pub fn relay_admitted(
        &self,
        relay_id: RelayId,
        serial: CredentialSerial,
    ) -> Result<bool, RelayError> {
        self.relay_admissions
            .read()
            .map(|admissions| {
                admissions
                    .as_ref()
                    .is_none_or(|values| values.contains(&(relay_id, serial)))
            })
            .map_err(|_| RelayError::Credential(CredentialError::InvalidSignature))
    }

    /// Revokes one exact serial.
    pub fn revoke(&self, serial: CredentialSerial) {
        if let Ok(mut revoked) = self.revoked.write() {
            revoked.insert(serial);
        }
    }

    /// Returns whether an established session credential has since been revoked.
    pub fn is_revoked(&self, serial: CredentialSerial) -> Result<bool, RelayError> {
        self.revoked
            .read()
            .map(|revoked| revoked.contains(&serial))
            .map_err(|_| RelayError::Credential(CredentialError::InvalidSignature))
    }

    /// Atomically installs one newer Root-anchored Authority lifecycle bundle.
    pub fn install_authorities(
        &self,
        bundle: &SignedAuthorityBundle,
        now: UnixTime,
    ) -> Result<(), RelayError> {
        self.trust
            .write()
            .map_err(|_| RelayError::Credential(CredentialError::InvalidSignature))?
            .install_authority_bundle(bundle, now)?;
        Ok(())
    }

    /// Authenticates a peer credential against the static key established by Noise.
    pub fn peer(
        &self,
        credential: &SubjectCredential,
        remote_static: &[u8; 32],
        now: UnixTime,
    ) -> Result<PeerId, RelayError> {
        if credential.role != SubjectRole::Peer || &credential.public_noise_key != remote_static {
            return Err(RelayError::Credential(CredentialError::InvalidSignature));
        }
        if self.is_revoked(credential.serial)? {
            return Err(RelayError::Credential(CredentialError::Revoked));
        }
        self.trust
            .read()
            .map_err(|_| RelayError::Credential(CredentialError::InvalidSignature))?
            .verify_subject(credential, now)?;
        match credential.subject {
            SubjectId::Peer(peer) => {
                let admitted = self
                    .peer_admissions
                    .read()
                    .map_err(|_| RelayError::Credential(CredentialError::InvalidSignature))?
                    .as_ref()
                    .is_none_or(|values| values.contains(&(peer, credential.serial)));
                if admitted {
                    Ok(peer)
                } else {
                    Err(RelayError::Credential(CredentialError::Revoked))
                }
            }
            SubjectId::Relay(_) => Err(RelayError::Credential(CredentialError::InvalidSignature)),
        }
    }
}

/// Result of an authenticated peer-side IK handshake.
pub struct AcceptedPeer {
    /// Decoded typed application payload.
    pub hello: HandshakePayload,
    /// Authenticated remote X25519 identity.
    pub remote_static: [u8; 32],
    /// Ready encrypted record transport.
    pub transport: StreamTransport,
}

/// IK result after credential signature, role, identity, time, and revocation checks.
pub struct AuthenticatedPeer {
    /// Verified peer identity.
    pub peer_id: PeerId,
    /// Verified exact credential serial.
    pub credential_serial: CredentialSerial,
    /// Fresh attachment UUID supplied by the peer.
    pub attachment_id: AttachmentId,
    /// Whether this session is initially allowed to own the primary presence role.
    pub primary_attachment: bool,
    /// Exact feature intersection negotiated by the IK handshake.
    pub capabilities: u64,
    /// Encrypted record transport.
    pub transport: StreamTransport,
}

include!("link_handshake.rs");
