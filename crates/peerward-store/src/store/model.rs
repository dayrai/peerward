impl Store {
    /// Opens a transactional `PostgreSQL` notification listener.
    pub async fn dispatcher(&self, database_url: &str) -> Result<OutboxDispatcher, StoreError> {
        OutboxDispatcher::connect(database_url).await
    }
}

/// Approximate immutable audit-log storage statistics reported by `PostgreSQL`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditStorageStats {
    /// Database statistics reset marker; table-specific resets may only be visible as a counter regression.
    pub stats_reset: Option<OffsetDateTime>,
    /// Planner-maintained live-row estimate; avoids a full table scan on every metrics scrape.
    pub estimated_rows: u64,
    /// Heap, indexes, and TOAST bytes consumed by the audit table.
    pub total_bytes: u64,
    /// `PostgreSQL` inserted tuple estimate, subject to statistics resets.
    pub inserted_rows: u64,
}

/// Mesh creation input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewMesh {
    /// Mutable display name.
    pub name: String,
    /// Primary IPv4 or IPv6 CIDR; the opposite family is allocated separately.
    pub address_cidr: IpNet,
    /// Reserved gateway within the CIDR.
    pub gateway: IpAddr,
    /// Lower-case split-DNS suffix.
    pub dns_suffix: String,
    /// Mesh packet MTU distributed to all platform profiles.
    #[serde(default = "default_mesh_mtu")]
    pub mtu: u16,
    /// Explicitly reserved addresses.
    #[serde(default)]
    pub reserved: Vec<IpAddr>,
    /// Default policy decision.
    pub default_policy: DefaultPolicy,
    /// Released-address quarantine.
    pub quarantine_seconds: u64,
    /// Credential overlap bound.
    pub rotation_overlap_seconds: u64,
}

impl NewMesh {
    fn validate(&self) -> Result<(), StoreError> {
        if self.name.trim().is_empty()
            || self.name.len() > 128
            || self.reserved.len() > MAX_RESERVED_ADDRESSES
            || !self.address_cidr.contains(&self.gateway)
            || self
                .reserved
                .iter()
                .any(|address| !self.address_cidr.contains(address))
            || !normalize_dns_suffix(&self.dns_suffix).is_ok_and(|suffix| suffix == self.dns_suffix)
            || !(1280..=9000).contains(&self.mtu)
            || self.rotation_overlap_seconds > 7 * 24 * 60 * 60
        {
            return Err(StoreError::Invalid("mesh"));
        }
        Ok(())
    }
}

const fn default_mesh_mtu() -> u16 {
    1280
}

/// Mesh default action.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DefaultPolicy {
    /// Permit unmatched initiations.
    Allow,
    /// Deny unmatched initiations.
    Deny,
}

impl DefaultPolicy {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }
}

/// Mesh API representation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MeshRecord {
    /// Immutable human-readable identifier, absent for legacy networks.
    pub network_identifier: Option<String>,
    pub lease_seconds: u32,
    pub lifecycle: String,
    pub lifecycle_revision: i64,
    pub lifecycle_job: Option<Uuid>,
    /// Monotonic resource version used for optimistic concurrency.
    pub version: u64,
    /// Stable mesh ID.
    pub id: MeshId,
    /// Mutable display name.
    pub name: String,
    /// Mesh IPv4 CIDR.
    pub address_cidr: IpNet,
    /// Independently allocated opposite-family pool.
    pub secondary_cidr: IpNet,
    /// Reserved secondary gateway.
    pub secondary_gateway: IpAddr,
    /// Mesh gateway.
    pub gateway: IpAddr,
    /// Split-DNS suffix.
    pub dns_suffix: String,
    /// Mesh packet MTU.
    pub mtu: u16,
    /// Unmatched action.
    pub default_policy: DefaultPolicy,
    /// Current policy revision.
    pub policy_revision: u64,
    /// Current Root-anchored Authority lifecycle revision.
    pub authority_revision: u64,
    /// Current peer directory revision.
    pub directory_revision: u64,
    /// Current relay directory revision.
    pub relay_revision: u64,
    /// Current signed service snapshot revision.
    pub service_revision: u64,
    /// Current exact-revocation bundle revision.
    pub revocation_revision: u64,
}

/// One cursor page.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Page<T> {
    /// Returned items.
    pub items: Vec<T>,
    /// Cursor for the next page.
    pub next_cursor: Option<PageCursor>,
}

/// Stable keyset cursor used by store-backed resource listings.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct PageCursor {
    /// Resource creation time at `PostgreSQL` microsecond precision.
    pub timestamp: OffsetDateTime,
    /// UUID tie-breaker for equal timestamps.
    pub id: Uuid,
}

/// Audit and event data committed beside one external mutation.
pub struct MutationRecord {
    /// Optional mesh isolation scope.
    pub mesh_id: Option<MeshId>,
    /// Sanitized actor identifier.
    pub actor: String,
    /// Stable audit action.
    pub action: String,
    /// Stable event type.
    pub event_type: String,
    /// Resource family.
    pub resource_type: String,
    /// Optional resource ID.
    pub resource_id: Option<Uuid>,
    /// `success`, `denied`, or `failure`.
    pub result: String,
    /// Sanitized metadata without secrets or raw credentials.
    pub metadata: Value,
    /// Optional validated HTTP/control correlation context.
    pub correlation: Option<peerward_types::CorrelationContext>,
}

/// Public ticket fields; plaintext token is deliberately absent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TicketRecord {
    /// Monotonic resource version used for optimistic concurrency.
    pub version: u64,
    /// Ticket resource ID.
    pub id: TicketId,
    /// Owning mesh.
    pub mesh_id: MeshId,
    /// Claim deadline.
    pub expires_at: OffsetDateTime,
    /// Whether a claim committed.
    pub consumed: bool,
}

/// Atomic join claim input.
#[derive(Debug, Clone)]
pub struct JoinClaim {
    /// Plaintext presented once and never persisted.
    pub token: Vec<u8>,
    /// Requested peer name.
    pub name: String,
    /// Sanitized labels.
    pub labels: Value,
    /// Client-generated idempotency `UUIDv4`.
    pub claim_id: Uuid,
    /// SHA-256 of the canonical ticket-bound claim transcript.
    pub request_digest: [u8; 32],
    /// Issuing authority.
    pub authority_id: Uuid,
    /// Credential serial.
    pub serial: CredentialSerial,
    /// Ed25519 identity verifier.
    pub identity_public_key: Vec<u8>,
    /// X25519 session public key.
    pub public_key: Vec<u8>,
    /// Independent `WireGuard` data key.
    pub wireguard_public_key: Vec<u8>,
    /// Credential validity.
    pub not_before: OffsetDateTime,
    /// Credential validity.
    pub not_after: OffsetDateTime,
    /// Credential signature.
    pub signature: Vec<u8>,
}

/// Untrusted public enrollment fields accepted from a ticket holder.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicJoinClaim {
    /// Plaintext ticket presented once and never persisted.
    #[serde(skip)]
    pub token: Vec<u8>,
    /// Client-generated idempotency `UUIDv4`.
    pub claim_id: Uuid,
    /// SHA-256 of the canonical ticket-bound request.
    pub request_digest: [u8; 32],
    /// Server-normalized peer DNS label.
    pub name: String,
    /// Sanitized device metadata labels.
    pub labels: Value,
    /// On-device Ed25519 identity verifier.
    pub identity_public_key: Vec<u8>,
    /// On-device X25519 session public key.
    pub public_noise_key: Vec<u8>,
    /// Independent `WireGuard` data key.
    pub wireguard_public_key: Vec<u8>,
}

/// Trusted credential material produced inside the locked claim transaction.
#[derive(Debug, Clone)]
pub struct IssuedPeerCredential {
    /// Active or overlap authority relation.
    pub authority_id: Uuid,
    /// Expected authority verifier, when issuance is performed online.
    pub authority_public_key: Option<Vec<u8>>,
    /// Exact credential serial.
    pub serial: CredentialSerial,
    /// Credential validity start.
    pub not_before: OffsetDateTime,
    /// Credential validity end.
    pub not_after: OffsetDateTime,
    /// Authority signature over the fixed subject transcript.
    pub signature: Vec<u8>,
}

/// Credential and exact canonical response committed by one Join transaction.
#[derive(Debug, Clone)]
pub struct IssuedPeerEnrollment {
    /// Authority-issued credential fields stored with the Peer.
    pub credential: IssuedPeerCredential,
    /// Complete canonical JSON response; returned byte-for-byte on every retry.
    pub response_document: Vec<u8>,
}

include!("rotation_model.rs");

/// Result of a committed join.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimedPeer {
    /// Created peer.
    pub peer_id: PeerId,
    /// Ticket mesh.
    pub mesh_id: MeshId,
    /// Stable allocated address.
    pub address: IpAddr,
    /// Created credential resource.
    pub credential_id: Uuid,
    /// Canonical response committed atomically with the Peer and credential.
    pub response_document: Vec<u8>,
    /// True when an identical committed claim was recovered after response loss.
    pub replayed: bool,
}

/// Authority staging input.
#[derive(Debug, Clone)]
pub struct NewAuthority {
    /// Owning mesh.
    pub mesh_id: MeshId,
    /// Exact serial.
    pub serial: CredentialSerial,
    /// Ed25519 public key.
    pub public_key: Vec<u8>,
    /// Validity start.
    pub not_before: OffsetDateTime,
    /// Validity end.
    pub not_after: OffsetDateTime,
    /// Replaced authority ID.
    pub replaces: Option<Uuid>,
    /// End of overlap.
    pub overlap_deadline: Option<OffsetDateTime>,
    /// Root-signed certificate bytes.
    pub certificate: Vec<u8>,
}

/// Credential lifecycle transition.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Lifecycle {
    /// Prepared but not advertised.
    Staged,
    /// Old and replacement both accepted.
    Overlap,
    /// Current credential.
    Active,
    /// Exact serial denied.
    Revoked,
}

impl Lifecycle {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Staged => "staged",
            Self::Overlap => "overlap",
            Self::Active => "active",
            Self::Revoked => "revoked",
        }
    }
}

/// Presence role.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "lowercase")]
pub enum PresenceRole {
    /// Routable primary.
    Primary,
    /// Warm standby.
    Standby,
}

impl PresenceRole {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::Standby => "standby",
        }
    }
}

impl std::fmt::Display for PresenceRole {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Fenced relay presence request.
#[derive(Debug, Clone)]
pub struct PresenceLease {
    /// Mesh.
    pub mesh_id: MeshId,
    /// Attached peer.
    pub peer_id: PeerId,
    /// Owning relay.
    pub relay_id: RelayId,
    /// Fresh attachment.
    pub attachment_id: AttachmentId,
    /// Primary or standby role.
    pub role: PresenceRole,
    /// Lease deadline.
    pub lease_deadline: OffsetDateTime,
}

/// Current non-expired primary owner used for cross-relay fencing.
#[derive(Debug, Clone, Copy)]
pub struct PresenceOwner {
    /// Relay that owns the primary attachment.
    pub relay_id: RelayId,
    /// Monotonic generation that must accompany forwarded packets.
    pub generation: i64,
}

/// One live fenced presence row captured in a Relay admission snapshot.
#[derive(Debug, Clone)]
pub struct PresenceSnapshot {
    /// Attached Peer.
    pub peer_id: PeerId,
    /// Owning Relay.
    pub relay_id: RelayId,
    /// Exact attachment incarnation.
    pub attachment_id: AttachmentId,
    /// Primary or warm-standby role.
    pub role: PresenceRole,
    /// Monotonic fencing generation.
    pub generation: i64,
    /// Database lease deadline.
    pub lease_deadline: OffsetDateTime,
}

/// One live Relay process lease captured in an admission snapshot.
#[derive(Debug, Clone)]
pub struct RelayRuntimeSnapshot {
    /// Relay identity.
    pub relay_id: RelayId,
    /// Process incarnation.
    pub instance_id: Uuid,
    /// Monotonic runtime fencing generation.
    pub generation: i64,
    /// Database lease deadline.
    pub lease_deadline: OffsetDateTime,
    /// Named Wire capabilities declared by this fenced runtime.
    pub wire_capabilities: u64,
    /// Bounded health summaries for authenticated backbone neighbors.
    pub neighbor_health: Vec<RelayNeighborHealth>,
}

/// Aggregate, identity-safe link quality reported by one Relay for a neighbor.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RelayNeighborHealth {
    /// Adjacent Relay identity. This is persisted for routing, never used as a metric label.
    pub relay_id: RelayId,
    /// Exponentially weighted authenticated keepalive RTT.
    pub rtt_millis: u32,
    /// Loss over the latest bounded probe window, in 1/10,000 units.
    pub loss_permyriad: u16,
    /// Number of observations in the loss window, from one through 32.
    pub samples: u8,
}

/// One currently acceptable Peer credential and its bound subject.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCredentialAdmission {
    /// Credential subject.
    pub peer_id: PeerId,
    /// Exact serial accepted by the signed directory.
    pub serial: CredentialSerial,
}

/// One currently acceptable Relay credential and its bound subject.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayCredentialAdmission {
    /// Credential subject.
    pub relay_id: RelayId,
    /// Exact serial accepted by the signed directory.
    pub serial: CredentialSerial,
}

/// One transactionally consistent Relay bootstrap view and durable event high-water mark.
#[derive(Debug, Clone)]
pub struct RelayAdmissionSnapshot {
    /// Latest immutable revision for every published state family.
    pub signed_states: Vec<SignedStateRevision>,
    /// Peer credentials accepted at the snapshot instant.
    pub peer_credentials: Vec<PeerCredentialAdmission>,
    /// Relay credentials accepted at the snapshot instant.
    pub relay_credentials: Vec<RelayCredentialAdmission>,
    /// Current non-expired presence leases.
    pub presence: Vec<PresenceSnapshot>,
    /// Current non-expired Relay runtime leases.
    pub runtimes: Vec<RelayRuntimeSnapshot>,
    /// Highest committed outbox sequence visible in the same snapshot.
    pub event_high_water: i64,
}

/// Sanitized committed event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboxEvent {
    /// Database ordering sequence.
    #[serde(skip)]
    pub sequence: i64,
    /// Public UUID cursor.
    pub cursor: EventId,
    /// Optional mesh scope.
    pub mesh_id: Option<MeshId>,
    /// Stable event type.
    pub event_type: String,
    /// Resource family.
    pub resource_type: String,
    /// Optional resource ID.
    pub resource_id: Option<Uuid>,
    /// Sanitized JSON body.
    pub payload: Value,
    /// Commit timestamp.
    pub committed_at: OffsetDateTime,
    /// Independent operational request identity, when the producer supplied one.
    pub request_id: Option<Uuid>,
    /// Canonical W3C parent context, when the producer supplied one.
    pub traceparent: Option<String>,
}

/// Resolved start point for a replay or a fresh high-water handshake.
#[derive(Debug, Clone, Copy)]
pub struct EventReplayStart {
    /// Internal sequence after which events must be emitted.
    pub after_sequence: i64,
    /// Public cursor at the resolved sequence, absent before the first event.
    pub cursor: Option<EventId>,
}

/// Bounded event catch-up result with retention-gap detection.
#[derive(Debug)]
pub struct EventBatch {
    /// Events committed after the requested sequence.
    pub events: Vec<OutboxEvent>,
    /// Latest globally committed event sequence.
    pub high_water_sequence: i64,
    /// True when the requested sequence predates the retained window.
    pub retention_gap: bool,
}

/// Bounded retention policy applied by one elected Control instance.
#[derive(Debug, Clone, Copy)]
pub struct MaintenancePolicy {
    /// Rows deleted from each table in one pass.
    pub batch_size: u32,
    /// Maximum replay age for durable events.
    pub event_retention_seconds: u64,
    /// Maximum retained durable event rows.
    pub event_max_rows: u64,
    /// Number of signed and policy revisions retained per family.
    pub signed_state_versions: u32,
    /// Grace period for expired or terminal operational state.
    pub terminal_retention_seconds: u64,
}

/// Result of one bounded maintenance pass.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MaintenanceReport {
    /// False when another Control instance held the maintenance election lock.
    pub elected: bool,
    /// Total rows deleted across operational tables.
    pub deleted_rows: u64,
    /// Tables whose deletion batch filled completely and may still have eligible backlog.
    pub backlog_tables: u32,
}

/// OIDC flow inputs retained for one short-lived authorization exchange.
pub struct NewOidcFlow {
    /// State secret.
    pub state: String,
    /// Nonce secret.
    pub nonce: String,
    /// PKCE verifier.
    pub pkce_verifier: String,
    /// Exact callback URI.
    pub redirect_uri: String,
    /// Validated console route to restore after authentication.
    pub return_to: String,
    /// Require a fresh identity-provider authentication.
    pub reauthenticate: bool,
    /// One-use deadline.
    pub expires_at: OffsetDateTime,
}

/// Secrets released exactly once after a matching OIDC state is consumed.
pub struct ConsumedOidcFlow {
    /// Server time when the reauthentication flow began.
    pub created_at: OffsetDateTime,
    /// Expected ID-token nonce.
    pub nonce: String,
    /// PKCE verifier required at the token endpoint.
    pub pkce_verifier: String,
    /// Callback URI bound when the flow was created.
    pub redirect_uri: String,
    /// Validated console route to restore after authentication.
    pub return_to: String,
    /// Require a fresh identity-provider authentication.
    pub reauthenticate: bool,
}

include!("auth_model.rs");

/// `PostgreSQL` LISTEN/NOTIFY receiver. Payloads are cursors; consumers replay rows.
pub struct OutboxDispatcher {
    listener: PgListener,
}

impl OutboxDispatcher {
    async fn connect(database_url: &str) -> Result<Self, StoreError> {
        let mut listener = PgListener::connect(database_url).await?;
        listener.listen(EVENT_CHANNEL).await?;
        Ok(Self { listener })
    }

    /// Waits for the next committed event cursor notification.
    pub async fn next_cursor(&mut self) -> Result<EventId, StoreError> {
        let notification = self.listener.recv().await?;
        notification
            .payload()
            .parse()
            .map_err(|_| StoreError::Invalid("event cursor"))
    }
}
