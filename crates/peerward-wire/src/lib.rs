//! Peerward Wire 5 Relay Noise links and opaque `WireGuard` / HPKE envelopes.

use prost::Message;
use snow::{Builder, HandshakeState, TransportState, params::NoiseParams};
use thiserror::Error;

/// Handshake capability bit identifying the attachment selected as the Peer primary.
///
/// A warm-standby attachment clears this bit. The Relay promotes it only when the Peer first
/// sends data after primary-path failure, which atomically advances the database fence.
pub const PRIMARY_ATTACHMENT_CAPABILITY: u64 = 1 << 63;
/// Carries validated W3C-compatible request and trace identifiers in control envelopes.
pub const TRACE_CONTEXT_V1_CAPABILITY: u64 = 1 << 0;
/// Allows mapped and bounded predicted direct candidates.
pub const EXTENDED_CANDIDATES_V1_CAPABILITY: u64 = 1 << 1;
/// Allows signed sparse Relay topology and bounded multi-hop routing.
pub const SPARSE_BACKBONE_V1_CAPABILITY: u64 = 1 << 2;
/// Signed administrator requests for device-local credential renewal.
pub const CREDENTIAL_RENEWAL_V1_CAPABILITY: u64 = 1 << 3;
/// All non-role capabilities implemented by this binary.
pub const SUPPORTED_CAPABILITIES: u64 = TRACE_CONTEXT_V1_CAPABILITY
    | EXTENDED_CANDIDATES_V1_CAPABILITY
    | SPARSE_BACKBONE_V1_CAPABILITY
    | CREDENTIAL_RENEWAL_V1_CAPABILITY;

include!("transport.rs");
mod relay_preface;
pub use relay_preface::{RELAY_PREFACE_LEN, RelayPreface};
mod recovery;
pub use recovery::{ROOT_RECOVERY_LEN, open_root_recovery, seal_root_recovery};
include!("records.rs");
include!("control.rs");
include!("session.rs");
mod audit;
pub use audit::*;
#[cfg(test)]
#[path = "tests.rs"]
mod tests;
