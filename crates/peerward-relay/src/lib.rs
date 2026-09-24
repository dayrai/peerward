//! Peerward authenticated relay, policy router, presence, and backbone runtime.

include!("relay/protocol.rs");
include!("relay/clock.rs");
include!("relay/presence_cache.rs");
include!("relay/routing.rs");
include!("relay/runtime.rs");
include!("relay/traffic.rs");
include!("relay/traffic_queues.rs");
include!("relay/traffic_tests.rs");
#[path = "relay/host.rs"]
mod host;
pub use host::{RelayHostConfig, serve_host};
include!("relay/tests.rs");
