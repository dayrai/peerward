//! Platform-neutral relay attachment, update ordering, and packet queue state.

mod dns;
mod packet;
mod packet_underlay;

pub use dns::*;
pub use packet::*;

use peerward_carrier::BoxStream;
use peerward_carrier::RecordTransport as StreamTransport;
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use peerward_credentials::{
    SubjectCredential, SubjectId, TrustSet, private_files::read_bounded_regular_file,
};
use peerward_dataplane::{Action as PacketAction, Firewall, Rule as PacketRule};
use peerward_platform::{
    DnsBackend, LinuxNetworkConfig, LinuxUnderlayNetwork, NftAllow, UnderlayNetwork,
};
use peerward_types::{
    AttachmentId, MeshId, NetworkEndpoint, PeerId, RelayId, RuleId, UnixTime,
    validate_endpoint_list,
};
use peerward_wire::{
    ControlEnvelope, HandshakePayload, Keepalive, Record, WireError,
    control_envelope::Message as ControlMessage, ik_initiator,
};
use prost::Message;
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub use peerward_peer_core::{
    AttachmentRole, PeerError, RelaySession, RotationState, SessionManager,
};

include!("config.rs");
include!("clock.rs");
include!("transport.rs");
include!("relay_endpoints.rs");
#[cfg(test)]
#[path = "tests.rs"]
mod tests;
