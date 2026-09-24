//! STUN, gateway mapping, and bounded candidate discovery for `WireGuard`.

mod candidates;
mod error;
mod mapping;
mod stun;
mod stun_resolver;
mod stun_runtime;
mod stun_server;

pub use candidates::*;
pub use error::*;
pub use mapping::*;
pub use stun::*;
pub use stun_resolver::{resolve_stun_servers, resolve_with as resolve_stun_servers_with};
pub use stun_runtime::{StunMapping, StunPoll, StunProbe, StunRuntime};
pub use stun_server::{serve_stun, stun_binding_response};

/// Current egress carrier class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataPath {
    /// Authenticated `WireGuard` over direct UDP.
    Direct,
    /// Authenticated Relay carrying opaque `WireGuard`.
    Relay,
}

#[cfg(test)]
mod tests;
