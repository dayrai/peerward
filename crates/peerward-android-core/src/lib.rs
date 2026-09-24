//! Android-facing `WireGuard` runtime and authenticated Relay Noise state.
//!
//! Kotlin requests Android system capabilities and protects/binds sockets.
//! Rust then owns detached TUN/Relay descriptors, blocking wire framing,
//! bounded runtime orchestration, cryptographic state and canonical records.
//! Descriptors cross JNI only after `VpnService.protect` has succeeded.

use peerward_carrier::RecordTransport as StreamTransport;
use std::sync::Arc;

use peerward_credentials::{
    CredentialError, DistributionCertificate, RotationActivationProof, RotationRequestProof,
    SignedAuthorityBundle, SubjectCredential, SubjectId, TrustSet, rotation_activation_transcript,
    rotation_request_transcript, verify_rotation_activation, verify_rotation_request,
};
use peerward_directory::{
    ChunkAssembler, DirectoryError, DirectoryPublicKey, RevisionChunk, decode_peer_directory,
    decode_policy, decode_relay_directory, decode_revocations,
};
use peerward_peer_core::{AttachmentRole, PeerError, PolicyEngine, RelaySession, SessionManager};
use peerward_service::{RemoteServiceError, RemoteServiceTable, ServiceSnapshotVerifier};
use peerward_types::{
    AttachmentId, MAX_SIGNED_STATE_BYTES, MAX_SIGNED_STATE_CHUNKS, MeshId, PeerId, RotationId,
    SubjectRole, UnixTime,
};
use peerward_wire::{
    ControlEnvelope, CredentialActivation, HandshakePayload, IK_SUITE, NOISE_PROLOGUE,
    OpaqueFrameKind, PROTOCOL_MAJOR, Record, WireError,
    control_envelope::Message as ControlMessage,
};
use prost::Message;
use rand::rngs::OsRng;
use snow::{
    Builder, HandshakeState,
    params::{CipherChoice, DHChoice, HashChoice, NoiseParams},
    resolvers::{CryptoResolver, DefaultResolver},
    types::{Cipher, Dh, Hash, Random},
};
use thiserror::Error;
use uuid::Uuid;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

mod tun_dns;
mod wireguard;
pub use peerward_p2p::{StunMapping, StunPoll, StunProbe, StunRuntime};
pub use tun_dns::{TunDnsDecision, TunDnsProxy, TunDnsTransport};
pub use wireguard::{
    MobileNetworkConfiguration, MobileNetworkObservation, MobileWireguard, MobileWireguardTicket,
    SharedMobileWireguard,
};

const MAX_HANDSHAKE: usize = 65_535;
const MAX_CONTROL: usize = 1_048_576;
const KEYSTORE_MARKER: [u8; 32] = [0xa5; 32];

/// Native protocol or validation failure, mapped to a stable JNI exception.
#[derive(Debug, Error)]
pub enum MobileError {
    /// Peerward wire state rejected an input.
    #[error("wire protocol rejected input")]
    Wire(#[from] WireError),
    /// Snow rejected a handshake operation.
    #[error("Noise handshake rejected input")]
    Noise(#[from] snow::Error),
    /// A rooted credential failed validation.
    #[error("credential validation failed")]
    Credential(#[from] CredentialError),
    /// Enrollment trust stage, with a fixed label and no received credential bytes.
    #[error("enrollment {0} credential validation failed")]
    EnrollmentCredential(&'static str, CredentialError),
    /// A signed directory or policy update failed validation.
    #[error("signed distribution update failed validation")]
    Directory(#[from] DirectoryError),
    /// A service snapshot failed validation.
    #[error("signed service update failed validation")]
    Service(#[from] RemoteServiceError),
    /// A NAT discovery or gateway mapping operation failed validation.
    #[error("authenticated direct path rejected input")]
    Direct(#[from] peerward_p2p::P2pError),
    /// Shared Peer attachment or signed-state machine rejected an event.
    #[error("peer session state rejected input")]
    Peer(#[from] PeerError),
    /// A data record is malformed, unrelated to this Peer, or denied by policy.
    #[error("packet denied by the authenticated mesh policy")]
    PolicyDenied,
    /// A JNI/provider DH callback failed closed.
    #[error("device key agreement failed")]
    KeyAgreement,
    /// An input exceeded its fixed resource bound or canonical shape.
    #[error("native input is malformed or exceeds its bound")]
    InvalidInput,
    /// The operation is invalid in the current handshake/session state.
    #[error("native session state is invalid")]
    InvalidState,
    /// Stable failure category only; excludes endpoint addresses and TLS material.
    #[error("Relay carrier I/O failed ({0:?})")]
    Carrier(std::io::ErrorKind),
}

/// Privacy-safe current Android runtime values accepted for encrypted Control reporting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MobileRuntimeHealth {
    pub sequence: u64,
    pub direct_path_count: u32,
    pub relay_packets: u64,
    pub direct_packets: u64,
    pub degraded_reasons: Vec<peerward_wire::RuntimeDegradedReasonV1>,
    pub signed_revision: u64,
}

/// Native signed-state readiness used by Android UI and lifecycle orchestration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MobileRuntimeStatus {
    pub signed_state_complete: bool,
    pub signed_revision: u64,
}

/// Non-exporting static X25519 provider. Android implements this with a
/// Keystore alias; tests use an in-memory provider through the same surface.
pub trait StaticDhProvider: Send + Sync {
    /// Raw 32-byte X25519 public key.
    fn public_key(&self) -> [u8; 32];
    /// Computes X25519 without exposing the private key.
    ///
    /// # Errors
    ///
    /// Returns [`MobileError::KeyAgreement`] when the backing provider refuses
    /// or cannot perform the operation.
    fn agree(&self, remote_public: &[u8; 32]) -> Result<[u8; 32], MobileError>;
}

/// In-memory provider used by deterministic native/relay interoperability tests.
#[cfg(test)]
struct RawStaticDh(StaticSecret);

#[cfg(test)]
impl RawStaticDh {
    /// Imports deterministic test-only static material.
    #[must_use]
    pub fn new(private: [u8; 32]) -> Self {
        Self(StaticSecret::from(private))
    }
}

#[cfg(test)]
impl StaticDhProvider for RawStaticDh {
    fn public_key(&self) -> [u8; 32] {
        PublicKey::from(&self.0).to_bytes()
    }

    fn agree(&self, remote_public: &[u8; 32]) -> Result<[u8; 32], MobileError> {
        Ok(self
            .0
            .diffie_hellman(&PublicKey::from(*remote_public))
            .to_bytes())
    }
}

struct AndroidResolver {
    default: DefaultResolver,
    provider: Arc<dyn StaticDhProvider>,
}

impl AndroidResolver {
    fn new(provider: Arc<dyn StaticDhProvider>) -> Self {
        Self {
            default: DefaultResolver,
            provider,
        }
    }
}

impl CryptoResolver for AndroidResolver {
    fn resolve_rng(&self) -> Option<Box<dyn Random>> {
        self.default.resolve_rng()
    }

    fn resolve_dh(&self, choice: &DHChoice) -> Option<Box<dyn Dh>> {
        if *choice == DHChoice::Curve25519 {
            Some(Box::new(ProviderDh::new(Arc::clone(&self.provider))))
        } else {
            self.default.resolve_dh(choice)
        }
    }

    fn resolve_hash(&self, choice: &HashChoice) -> Option<Box<dyn Hash>> {
        self.default.resolve_hash(choice)
    }

    fn resolve_cipher(&self, choice: &CipherChoice) -> Option<Box<dyn Cipher>> {
        self.default.resolve_cipher(choice)
    }
}

struct ProviderDh {
    provider: Arc<dyn StaticDhProvider>,
    private: Zeroizing<[u8; 32]>,
    public: [u8; 32],
    provider_backed: bool,
}

impl ProviderDh {
    fn new(provider: Arc<dyn StaticDhProvider>) -> Self {
        Self {
            public: provider.public_key(),
            provider,
            private: Zeroizing::new([0; 32]),
            provider_backed: false,
        }
    }
}

impl Dh for ProviderDh {
    fn name(&self) -> &'static str {
        "25519"
    }

    fn pub_len(&self) -> usize {
        32
    }

    fn priv_len(&self) -> usize {
        32
    }

    fn set(&mut self, private: &[u8]) {
        if private.len() != 32 {
            return;
        }
        self.private.copy_from_slice(private);
        self.provider_backed = private == KEYSTORE_MARKER;
        self.public = if self.provider_backed {
            self.provider.public_key()
        } else {
            PublicKey::from(&StaticSecret::from(*self.private)).to_bytes()
        };
    }

    fn generate(&mut self, rng: &mut dyn Random) -> Result<(), snow::Error> {
        rng.try_fill_bytes(self.private.as_mut())
            .map_err(|_| snow::Error::Rng)?;
        self.provider_backed = false;
        self.public = PublicKey::from(&StaticSecret::from(*self.private)).to_bytes();
        Ok(())
    }

    fn pubkey(&self) -> &[u8] {
        &self.public
    }

    fn privkey(&self) -> &[u8] {
        self.private.as_ref()
    }

    fn dh(&self, public: &[u8], output: &mut [u8]) -> Result<(), snow::Error> {
        let remote: [u8; 32] = public
            .get(..32)
            .ok_or(snow::Error::Dh)?
            .try_into()
            .map_err(|_| snow::Error::Dh)?;
        let shared = Zeroizing::new(if self.provider_backed {
            self.provider.agree(&remote).map_err(|_| snow::Error::Dh)?
        } else {
            StaticSecret::from(*self.private)
                .diffie_hellman(&PublicKey::from(remote))
                .to_bytes()
        });
        if output.len() < shared.len() {
            return Err(snow::Error::Dh);
        }
        output[..32].copy_from_slice(shared.as_ref());
        Ok(())
    }
}

/// Rooted trust and signed-update verification material installed at enrollment.
pub struct MobileTrust {
    mesh_id: MeshId,
    credentials: TrustSet,
    distribution: DirectoryPublicKey,
    services: ServiceSnapshotVerifier,
    audit_recipient: [u8; 32],
    binding: DistributionCertificate,
}

impl MobileTrust {
    /// Creates a complete trust set after proving that both online update keys
    /// were bound by a currently valid, rooted authority.
    ///
    /// # Errors
    ///
    /// Returns an error when the binding is outside the mesh trust chain or
    /// names different directory/service keys than the supplied verifiers.
    pub fn new(
        mesh_id: MeshId,
        credentials: TrustSet,
        distribution: DirectoryPublicKey,
        services: ServiceSnapshotVerifier,
        audit_recipient: [u8; 32],
        binding: &DistributionCertificate,
        now: UnixTime,
    ) -> Result<Self, MobileError> {
        credentials.verify_distribution(binding, now)?;
        if binding.mesh_id != mesh_id
            || binding.directory_public_key != distribution.to_bytes()
            || binding.service_public_key != services.to_bytes()
            || binding.audit_public_key != audit_recipient
        {
            return Err(MobileError::InvalidInput);
        }
        Ok(Self {
            mesh_id,
            credentials,
            distribution,
            services,
            audit_recipient,
            binding: *binding,
        })
    }

    /// Returns the Authority-bound Control HPKE recipient for native audit reporting.
    #[must_use]
    pub const fn audit_recipient(&self) -> [u8; 32] {
        self.audit_recipient
    }
}

/// Validated control-plane update accepted by the native state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcceptedUpdate {
    /// Verified irreversible Mesh termination; persist before closing platform resources.
    Terminated(Vec<u8>),
    /// A complete newer Root-anchored Authority lifecycle was committed.
    Authorities(AuthorityTrustUpdate),
    /// A complete newer peer directory was committed.
    PeerDirectory(u64),
    /// A complete newer signed policy was committed.
    Policy(u64),
    /// A complete newer signed Relay directory was committed.
    RelayDirectory(u64),
    /// A complete newer signed service snapshot was committed.
    Services,
    /// A complete exact-revocation revision was committed.
    Revocations(u64),
    /// An Authority-signed locally requested replacement credential was accepted.
    CredentialReplacement(CredentialReplacementUpdate),
    /// The signed directory now publishes the activated replacement, so local
    /// key/profile commit may occur and force a new authenticated connection.
    CredentialActivated(Vec<u8>),
    /// A verified administrator command permits the existing local renewal transaction.
    CredentialRenewalRequested,
    /// Another authenticated control record needs Kotlin/session-manager handling.
    Control,
}

enum State {
    Handshake(Box<HandshakeState>),
    Transport(StreamTransport),
    #[cfg(target_os = "android")]
    CarrierAdmission,
    Closed,
}

/// Protocol state used by both JNI exports and the localhost relay interop test.
pub struct NativeSession {
    expected_relay: Option<peerward_types::RelayId>,
    state: State,
    trust: MobileTrust,
    local_peer: PeerId,
    current_credential: SubjectCredential,
    pending_rotation: Option<PendingMobileRotation>,
    console_renewal: Option<peerward_management::SignedCredentialRenewal>,
    remote_noise_key: [u8; 32],
    attachment_id: AttachmentId,
    primary_attachment: bool,
    chunks: DistributionAssemblers,
    session: SessionManager,
    policy: Arc<PolicyEngine>,
    wireguard: Option<SharedMobileWireguard>,
    services: RemoteServiceTable,
    audit_counts: std::collections::BTreeMap<(i32, i32), u32>,
    pending_audit: Option<PendingMobileAudit>,
    pending_health: Option<PendingMobileHealth>,
    pending_management: Option<peerward_management::PeerCommand>,
    evidence_acknowledged: Option<(peerward_types::CredentialSerial, u64)>,
    management_acknowledged: Vec<(
        peerward_types::CredentialSerial,
        peerward_management::PeerOperation,
    )>,
}

include!("session_handshake.rs");

include!("session_data.rs");
include!("control_types.rs");
include!("control_state.rs");
include!("audit.rs");
include!("management.rs");
include!("dns.rs");
#[cfg(any(test, target_os = "android"))]
include!("enrollment.rs");
#[cfg(any(test, target_os = "android"))]
include!("profile.rs");
#[cfg(any(test, target_os = "android"))]
include!("profile_recovery.rs");
#[cfg(any(test, target_os = "android"))]
include!("wireguard_profile.rs");
include!("rotation.rs");

#[cfg(target_os = "android")]
#[allow(unsafe_code)]
mod android_jni;

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

#[cfg(test)]
#[path = "rotation_tests.rs"]
mod rotation_tests;
#[cfg(test)]
mod wireguard_tests;
