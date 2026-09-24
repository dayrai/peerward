/// Authenticated console role. Authorization is defined only by [`Capability`].
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Read status summaries and audit records only.
    Auditor,
    /// Read resources.
    Viewer,
    /// Mutate ordinary resources.
    Operator,
    /// Manage trust and bootstrap.
    Admin,
}

impl Role {
    /// Lowercase storage/API representation.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auditor => "auditor",
            Self::Viewer => "viewer",
            Self::Operator => "operator",
            Self::Admin => "admin",
        }
    }

    /// Stable explicit capability matrix for this role.
    pub const fn capabilities(self) -> &'static [Capability] {
        match self {
            Self::Auditor => &[Capability::StatusAuditRead],
            Self::Viewer => &[Capability::StatusAuditRead, Capability::ResourceRead],
            Self::Operator => &[
                Capability::StatusAuditRead,
                Capability::ResourceRead,
                Capability::ResourceWrite,
            ],
            Self::Admin => &[
                Capability::StatusAuditRead,
                Capability::ResourceRead,
                Capability::ResourceWrite,
                Capability::TrustManage,
            ],
        }
    }

    /// Whether this role grants one capability.
    pub fn allows(self, capability: Capability) -> bool {
        self.capabilities().contains(&capability)
    }
}

impl FromStr for Role {
    type Err = StoreError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "auditor" => Ok(Self::Auditor),
            "viewer" => Ok(Self::Viewer),
            "operator" => Ok(Self::Operator),
            "admin" => Ok(Self::Admin),
            _ => Err(StoreError::Invalid("role")),
        }
    }
}

/// Stable API capabilities; roles are never compared or sorted.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    /// Status summaries and immutable audit records.
    StatusAuditRead,
    /// Mesh, Peer, Relay, Service, Policy, and lifecycle reads.
    ResourceRead,
    /// Ordinary resource and policy mutations.
    ResourceWrite,
    /// Authority, Mesh creation, and trust mutations.
    TrustManage,
}

impl Capability {
    /// Stable session/API spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StatusAuditRead => "status_audit_read",
            Self::ResourceRead => "resource_read",
            Self::ResourceWrite => "resource_write",
            Self::TrustManage => "trust_manage",
        }
    }
}

/// New browser session material.
pub struct NewSession {
    /// Plain session token; only its digest persists.
    pub token: String,
    /// Separate CSRF token; only its digest persists.
    pub csrf_token: String,
    /// OIDC subject.
    pub subject: String,
    /// Effective role.
    pub role: Role,
    /// Session deadline.
    pub expires_at: OffsetDateTime,
}

/// Authenticated browser session.
pub struct SessionRecord {
    /// Session resource ID.
    pub id: Uuid,
    /// OIDC subject.
    pub subject: String,
    /// Effective role.
    pub role: Role,
    /// Expected CSRF digest.
    pub csrf_digest: [u8; 32],
    /// Expiry.
    pub expires_at: OffsetDateTime,
}

/// One opaque Relay-forwarded audit batch leased to a Control collector.
#[derive(Debug, Clone)]
pub struct EncryptedAuditRecord {
    /// Inbox row identity.
    pub id: Uuid,
    /// Authenticated mesh supplied by the Relay process.
    pub mesh_id: MeshId,
    /// Authenticated link identity supplied by the Relay process.
    pub source_peer: PeerId,
    /// Uninterpreted HPKE envelope.
    pub envelope: Vec<u8>,
    /// Number of collector attempts including the current lease.
    pub attempts: u32,
}

/// Decrypted, payload-free event ready for the immutable audit log.
#[derive(Debug, Clone, Copy)]
pub struct PeerAuditEventRecord {
    /// Stable event direction label.
    pub direction: &'static str,
    /// Stable rejection/anomaly reason label.
    pub reason: &'static str,
    /// Aggregated number of equivalent events.
    pub count: u32,
}

/// Decrypted current-only runtime health ready for a 90-second TTL upsert.
#[derive(Debug, Clone)]
pub struct PeerRuntimeHealthRecord {
    pub sequence: u64,
    pub observed_at: OffsetDateTime,
    pub direct_path_count: u32,
    pub relay_packets: u64,
    pub direct_packets: u64,
    pub degraded_reasons: Vec<String>,
    pub signed_revision: u64,
}
