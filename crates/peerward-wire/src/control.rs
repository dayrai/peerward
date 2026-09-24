/// Top-level control envelope with a distinct type for every Wire 5 family member.
#[derive(Clone, PartialEq, Message)]
pub struct ControlEnvelope {
    /// Exactly one typed control message.
    #[prost(
        oneof = "control_envelope::Message",
        tags = "1, 2, 3, 4, 5, 6, 7, 8, 9, 14, 15, 16, 17, 18, 19, 20, 21, 22, 24, 26, 27, 28, 29, 30"
    )]
    pub message: Option<control_envelope::Message>,
    /// Optional strict request/trace correlation, negotiated by capability.
    #[prost(message, optional, tag = "25")]
    pub trace_context: Option<TraceContextV1>,
}

impl ControlEnvelope {
    /// Strictly validates an optional transported context.
    pub fn correlation_context(
        &self,
    ) -> Result<Option<peerward_types::CorrelationContext>, peerward_types::CorrelationError> {
        self.trace_context
            .as_ref()
            .map(TraceContextV1::try_into_context)
            .transpose()
    }

    /// Advances an existing trace to a new producer/consumer span ID.
    pub fn advance_trace(&mut self) -> Result<(), peerward_types::CorrelationError> {
        if let Some(context) = self.correlation_context()? {
            self.trace_context = Some(TraceContextV1::from_context(context.child()));
        }
        Ok(())
    }
}

/// OTel-independent binary representation of W3C request correlation.
#[derive(Clone, PartialEq, Message)]
pub struct TraceContextV1 {
    /// `UUIDv4` operational request identity.
    #[prost(bytes = "vec", tag = "1")]
    pub request_id: Vec<u8>,
    /// Nonzero 16-byte W3C trace identity.
    #[prost(bytes = "vec", tag = "2")]
    pub trace_id: Vec<u8>,
    /// Nonzero 8-byte W3C span identity.
    #[prost(bytes = "vec", tag = "3")]
    pub span_id: Vec<u8>,
    /// W3C trace flags.
    #[prost(uint32, tag = "4")]
    pub flags: u32,
}

impl TraceContextV1 {
    /// Encodes a validated transport-neutral context.
    pub fn from_context(context: peerward_types::CorrelationContext) -> Self {
        Self {
            request_id: context.request_id.as_bytes().to_vec(),
            trace_id: context.trace_id.to_vec(),
            span_id: context.span_id.to_vec(),
            flags: u32::from(context.flags),
        }
    }

    /// Strictly validates lengths, UUID version, and nonzero W3C identifiers.
    pub fn try_into_context(
        &self,
    ) -> Result<peerward_types::CorrelationContext, peerward_types::CorrelationError> {
        let request_id = uuid::Uuid::from_slice(&self.request_id)
            .map_err(|_| peerward_types::CorrelationError::InvalidIdentifier)?;
        let trace_id = self
            .trace_id
            .as_slice()
            .try_into()
            .map_err(|_| peerward_types::CorrelationError::InvalidIdentifier)?;
        let span_id = self
            .span_id
            .as_slice()
            .try_into()
            .map_err(|_| peerward_types::CorrelationError::InvalidIdentifier)?;
        let flags = u8::try_from(self.flags)
            .map_err(|_| peerward_types::CorrelationError::InvalidIdentifier)?;
        peerward_types::CorrelationContext::from_parts(request_id, trace_id, span_id, flags)
    }
}

/// Prost message variants for [`ControlEnvelope`].
pub mod control_envelope {
    use prost::Oneof;

    use super::*;

    /// Typed Wire 5 control message.
    #[derive(Clone, PartialEq, Oneof)]
    pub enum Message {
        #[prost(message, tag = "30")]
        CredentialRenewal(CredentialRenewal),
        /// Device-signed management observation or application receipt.
        #[prost(message, tag = "28")]
        PeerManagement(PeerManagement),
        /// Persistence result, scoped to the original signed request.
        #[prost(message, tag = "29")]
        PeerManagementResult(PeerManagementResult),
        /// Signed configuration and independently sequenced lease chunk.
        #[prost(message, tag = "27")]
        Configuration(PeerDirectoryChunk),
        /// Initial stream greeting.
        #[prost(message, tag = "1")]
        Hello(Hello),
        /// Greeting response.
        #[prost(message, tag = "2")]
        Welcome(Welcome),
        /// Liveness request or response.
        #[prost(message, tag = "3")]
        Keepalive(Keepalive),
        /// Graceful close notice.
        #[prost(message, tag = "4")]
        Close(GracefulClose),
        /// Peer directory chunk.
        #[prost(message, tag = "5")]
        PeerDirectory(PeerDirectoryChunk),
        /// Signed policy bundle.
        #[prost(message, tag = "6")]
        Policy(PolicyBundle),
        /// Relay directory chunk.
        #[prost(message, tag = "7")]
        RelayDirectory(RelayDirectoryChunk),
        /// Presence update.
        #[prost(message, tag = "8")]
        Presence(PresenceUpdate),
        /// Authenticated backbone forwarding envelope; Peer ingress rejects it.
        #[prost(message, tag = "9")]
        Forwarded(ForwardedPacket),
        /// Published service snapshot.
        #[prost(message, tag = "14")]
        Services(ServiceSnapshot),
        /// Credential rotation request.
        #[prost(message, tag = "15")]
        RotationRequest(Box<CredentialRotationRequest>),
        /// Credential replacement.
        #[prost(message, tag = "16")]
        Replacement(CredentialReplacement),
        /// Credential activation.
        #[prost(message, tag = "17")]
        Activation(CredentialActivation),
        /// Credential revocation.
        #[prost(message, tag = "18")]
        Revocation(CredentialRevocation),
        /// Authenticated local service publication.
        #[prost(message, tag = "19")]
        ServicePublish(ServicePublish),
        /// Authenticated local service withdrawal.
        #[prost(message, tag = "20")]
        ServiceRemove(ServiceRemove),
        /// Relay persistence result for a local service mutation.
        #[prost(message, tag = "21")]
        ServiceResult(ServiceMutationResult),
        /// Root-anchored Authority lifecycle bundle chunk.
        #[prost(message, tag = "22")]
        AuthorityDirectory(AuthorityDirectoryChunk),
        /// End-to-end opaque Peer frame routed without packet inspection.
        #[prost(message, tag = "24")]
        Opaque(RelayEnvelopeV2),
        /// Independently signed Relay topology chunk.
        #[prost(message, tag = "26")]
        RelayTopology(RelayTopologyChunk),
    }
}

macro_rules! mesh_blob_message {
    ($name:ident) => {
        #[derive(Clone, PartialEq, Message)]
        pub struct $name {
            /// Raw mesh UUID bytes.
            #[prost(bytes = "vec", tag = "1")]
            pub mesh_id: Vec<u8>,
            /// Type-specific encoded data.
            #[prost(bytes = "vec", tag = "2")]
            pub body: Vec<u8>,
        }
    };
}

mesh_blob_message!(Hello);
mesh_blob_message!(Welcome);
mesh_blob_message!(GracefulClose);
mesh_blob_message!(PresenceUpdate);
mesh_blob_message!(ForwardedPacket);

macro_rules! signed_state_chunk_message {
    ($name:ident) => {
        #[derive(Clone, PartialEq, Message)]
        pub struct $name {
            /// Raw mesh UUID bytes.
            #[prost(bytes = "vec", tag = "1")]
            pub mesh_id: Vec<u8>,
            /// Monotonic signed-state revision.
            #[prost(uint64, tag = "2")]
            pub revision: u64,
            /// Zero-based chunk index.
            #[prost(uint32, tag = "3")]
            pub index: u32,
            /// Total chunk count.
            #[prost(uint32, tag = "4")]
            pub count: u32,
            /// Independently bounded chunk bytes.
            #[prost(bytes = "vec", tag = "5")]
            pub body: Vec<u8>,
        }
    };
}

signed_state_chunk_message!(PolicyBundle);
signed_state_chunk_message!(ServiceSnapshot);
signed_state_chunk_message!(CredentialRevocation);
signed_state_chunk_message!(RelayTopologyChunk);

/// Current-identity-authenticated request to stage a replacement Peer identity.
#[derive(Clone, PartialEq, Message)]
pub struct CredentialRotationRequest {
    /// Raw mesh UUID bytes.
    #[prost(bytes = "vec", tag = "1")]
    pub mesh_id: Vec<u8>,
    /// Fresh rotation UUID used for idempotency.
    #[prost(bytes = "vec", tag = "2")]
    pub request_id: Vec<u8>,
    /// New Ed25519 identity verifier generated locally by the Peer.
    #[prost(bytes = "vec", tag = "3")]
    pub identity_public_key: Vec<u8>,
    /// New X25519 session key generated locally by the Peer.
    #[prost(bytes = "vec", tag = "4")]
    pub session_public_key: Vec<u8>,
    /// Credential serial authenticating this request.
    #[prost(bytes = "vec", tag = "5")]
    pub current_serial: Vec<u8>,
    /// Ed25519 signature by the current certified identity over every request field.
    #[prost(bytes = "vec", tag = "6")]
    pub signature: Vec<u8>,
    /// Independent new `WireGuard` data key bound by the request signature.
    #[prost(bytes = "vec", tag = "7")]
    pub wireguard_public_key: Vec<u8>,
}

/// Authority-signed staged credential returned to the requesting Peer.
#[derive(Clone, PartialEq, Message)]
pub struct CredentialReplacement {
    /// Raw mesh UUID bytes.
    #[prost(bytes = "vec", tag = "1")]
    pub mesh_id: Vec<u8>,
    /// Rotation UUID matching the local pending private key.
    #[prost(bytes = "vec", tag = "2")]
    pub request_id: Vec<u8>,
    /// Canonically encoded [`peerward_credentials::SubjectCredential`].
    #[prost(bytes = "vec", tag = "3")]
    pub credential: Vec<u8>,
    /// Server-generated one-time challenge to be signed by the new identity.
    #[prost(bytes = "vec", tag = "4")]
    pub activation_challenge: Vec<u8>,
}

/// New-identity-authenticated request to activate an issued staged credential.
#[derive(Clone, PartialEq, Message)]
pub struct CredentialActivation {
    /// Raw mesh UUID bytes.
    #[prost(bytes = "vec", tag = "1")]
    pub mesh_id: Vec<u8>,
    /// Rotation UUID matching the staged credential.
    #[prost(bytes = "vec", tag = "2")]
    pub request_id: Vec<u8>,
    /// Newly issued credential serial.
    #[prost(bytes = "vec", tag = "3")]
    pub issued_serial: Vec<u8>,
    /// Ed25519 signature by the new identity over the one-time challenge transcript.
    #[prost(bytes = "vec", tag = "4")]
    pub signature: Vec<u8>,
}

/// Peer-authenticated request to atomically publish one local service.
#[derive(Clone, PartialEq, Message)]
pub struct ServicePublish {
    /// Raw mesh UUID bytes.
    #[prost(bytes = "vec", tag = "1")]
    pub mesh_id: Vec<u8>,
    /// Stable service UUID generated by the Peer.
    #[prost(bytes = "vec", tag = "2")]
    pub service_id: Vec<u8>,
    /// Canonical transport tags: one for TCP, two for UDP.
    #[prost(uint32, repeated, tag = "3")]
    pub protocols: Vec<u32>,
    /// Mesh-visible destination port.
    #[prost(uint32, tag = "4")]
    pub listen_port: u32,
    /// Optional mesh DNS label, empty when absent.
    #[prost(string, tag = "5")]
    pub alias: String,
}

/// Peer-authenticated request to withdraw one owned service.
#[derive(Clone, PartialEq, Message)]
pub struct ServiceRemove {
    /// Raw mesh UUID bytes.
    #[prost(bytes = "vec", tag = "1")]
    pub mesh_id: Vec<u8>,
    /// Exact service UUID.
    #[prost(bytes = "vec", tag = "2")]
    pub service_id: Vec<u8>,
}

/// Durable Control mutation result returned on the authenticated Relay stream.
#[derive(Clone, PartialEq, Message)]
pub struct ServiceMutationResult {
    /// Raw mesh UUID bytes.
    #[prost(bytes = "vec", tag = "1")]
    pub mesh_id: Vec<u8>,
    /// Exact service UUID.
    #[prost(bytes = "vec", tag = "2")]
    pub service_id: Vec<u8>,
    /// True only after the database transaction commits.
    #[prost(bool, tag = "3")]
    pub committed: bool,
    /// Stable failure code without database details.
    #[prost(string, tag = "4")]
    pub error: String,
}

/// Keepalive timestamp used only for round-trip measurement.
#[derive(Clone, Copy, PartialEq, Message)]
pub struct Keepalive {
    /// Sender monotonic timestamp to echo.
    #[prost(uint64, tag = "1")]
    pub monotonic_timestamp: u64,
}

/// Independently bounded chunk of a peer directory revision.
#[derive(Clone, PartialEq, Message)]
pub struct PeerDirectoryChunk {
    /// Raw mesh UUID bytes.
    #[prost(bytes = "vec", tag = "1")]
    pub mesh_id: Vec<u8>,
    /// Monotonic directory revision.
    #[prost(uint64, tag = "2")]
    pub revision: u64,
    /// Zero-based chunk index.
    #[prost(uint32, tag = "3")]
    pub index: u32,
    /// Total chunk count.
    #[prost(uint32, tag = "4")]
    pub count: u32,
    /// Chunk bytes.
    #[prost(bytes = "vec", tag = "5")]
    pub body: Vec<u8>,
}

/// Independently bounded chunk of a relay directory revision.
#[derive(Clone, PartialEq, Message)]
pub struct RelayDirectoryChunk {
    /// Raw mesh UUID bytes.
    #[prost(bytes = "vec", tag = "1")]
    pub mesh_id: Vec<u8>,
    /// Monotonic directory revision.
    #[prost(uint64, tag = "2")]
    pub revision: u64,
    /// Zero-based chunk index.
    #[prost(uint32, tag = "3")]
    pub index: u32,
    /// Total chunk count.
    #[prost(uint32, tag = "4")]
    pub count: u32,
    /// Chunk bytes.
    #[prost(bytes = "vec", tag = "5")]
    pub body: Vec<u8>,
}

/// Independently bounded chunk of a signed Authority lifecycle bundle.
#[derive(Clone, PartialEq, Message)]
pub struct AuthorityDirectoryChunk {
    /// Raw mesh UUID bytes.
    #[prost(bytes = "vec", tag = "1")]
    pub mesh_id: Vec<u8>,
    /// Monotonic Authority lifecycle revision.
    #[prost(uint64, tag = "2")]
    pub revision: u64,
    /// Zero-based chunk index.
    #[prost(uint32, tag = "3")]
    pub index: u32,
    /// Total chunk count.
    #[prost(uint32, tag = "4")]
    pub count: u32,
    /// Chunk bytes.
    #[prost(bytes = "vec", tag = "5")]
    pub body: Vec<u8>,
}

/// Bounded typed JSON containing a device signature; the Relay authenticates scope too.
#[derive(Clone, PartialEq, Message)]
pub struct PeerManagement {
    #[prost(bytes = "vec", tag = "1")]
    pub body: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
pub struct PeerManagementResult {
    #[prost(bytes = "vec", tag = "1")]
    pub request_id: Vec<u8>,
    #[prost(bool, tag = "2")]
    pub committed: bool,
    #[prost(string, tag = "3")]
    pub error: String,
}

/// Signed, bounded renewal request; gated by `CREDENTIAL_RENEWAL_V1_CAPABILITY`.
#[derive(Clone, PartialEq, Message)]
pub struct CredentialRenewal {
    #[prost(bytes = "vec", tag = "1")]
    pub body: Vec<u8>,
}
