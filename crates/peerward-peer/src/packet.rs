//! Concurrent packet pumping between an attached TUN file and authenticated paths.

use peerward_carrier::BoxStream;
use peerward_carrier::RecordTransport as StreamTransport;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    io,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, RwLock as StdRwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use ed25519_dalek::SigningKey as IdentitySigningKey;
use opentelemetry::{
    Context as OpenTelemetryContext,
    trace::{
        SpanContext as OpenTelemetrySpanContext, SpanId as OpenTelemetrySpanId,
        TraceContextExt as _, TraceFlags as OpenTelemetryTraceFlags,
        TraceId as OpenTelemetryTraceId, TraceState as OpenTelemetryTraceState,
    },
};
use peerward_credentials::{
    DynamicTrust, RotationActivationProof, RotationRequestProof, SignedAuthorityBundle,
    SubjectCredential, SubjectId, TrustSet, sign_rotation_activation, sign_rotation_request,
};
use peerward_dataplane::{Action, Firewall, FragmentReassembler, ReassemblyStatus, parse_packet};
use peerward_directory::{
    ChunkAssembler, DirectoryPublicKey, PeerEntry, RevisionChunk, SignedPolicyBundle,
    decode_peer_directory, decode_policy, decode_relay_directory, decode_revocations,
};
use peerward_p2p::{CandidateKind, DataPath, DirectCandidate};
use peerward_peer_core::{RuntimeHealthFingerprint, RuntimeScheduler};
use peerward_platform::{TunnelDevice, UnderlayNetwork};
use peerward_policy::PeerDescriptor;
use peerward_service::{
    RemoteService, RemoteServiceTable, ServiceChange, ServiceProtocol, ServiceSnapshotVerifier,
    SignedRemoteServiceSnapshot,
};
use peerward_types::{
    CredentialSerial, MAX_SIGNED_STATE_BYTES, MAX_SIGNED_STATE_CHUNKS, MeshId, PeerId, RotationId,
    ServiceId, UnixTime,
};
use peerward_wire::{
    ControlEnvelope, CredentialActivation, HandshakePayload, OpaqueFrameKind, PROTOCOL_MAJOR,
    Record, RelayEnvelopeV2, control_envelope::Message as ControlMessage,
};
use prost::Message;
use rand::rngs::OsRng;
use serde::Serialize;
use thiserror::Error;
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf},
    net::UdpSocket,
    sync::{Mutex, mpsc, oneshot, watch},
};
use tracing_opentelemetry::OpenTelemetrySpanExt as _;
use uuid::Uuid;

use crate::{PeerConfig, PeerError, monotonic_seconds};

fn remote_trace_parent(context: peerward_types::CorrelationContext) -> OpenTelemetryContext {
    OpenTelemetryContext::new().with_remote_span_context(OpenTelemetrySpanContext::new(
        OpenTelemetryTraceId::from_bytes(context.trace_id),
        OpenTelemetrySpanId::from_bytes(context.span_id),
        OpenTelemetryTraceFlags::new(context.flags),
        true,
        OpenTelemetryTraceState::default(),
    ))
}

include!("packet_io.rs");
include!("policy_runtime.rs");
include!("peer_directory.rs");
include!("credential_rotation.rs");
include!("credential_recovery.rs");
include!("service_control.rs");
include!("relay_pool.rs");
include!("gateway_mapping_runtime.rs");
include!("wireguard_path.rs");
include!("wireguard_worker.rs");
include!("wireguard_pump.rs");
include!("packet_runtime.rs");
include!("audit_reporter.rs");
include!("candidate_discovery.rs");
include!("udp_demux.rs");
include!("gateway_demux.rs");
include!("udp_paths.rs");
include!("path_discovery.rs");
include!("direct_control.rs");
include!("management_control.rs");
include!("resource_platform.rs");
include!("target_health.rs");
include!("device_evidence.rs");
include!("client_exit.rs");
include!("client_management.rs");
include!("dns_platform.rs");
#[cfg(test)]
#[path = "packet_tests.rs"]
mod tests;

#[cfg(test)]
use tokio::net::TcpStream;

#[cfg(test)]
#[path = "gateway_mapping_tests.rs"]
mod gateway_mapping_tests;
