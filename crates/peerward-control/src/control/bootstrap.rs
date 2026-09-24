use std::{
    collections::{BTreeMap, HashMap, HashSet},
    convert::Infallible,
    net::SocketAddr,
    sync::{Arc, atomic::{AtomicU64, Ordering}},
    time::Duration,
};

use async_stream::stream;
use axum::{
    Extension, Json, Router,
    extract::{DefaultBodyLimit, FromRequest, Path, Query, Request, State, rejection::JsonRejection},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response, Sse, sse::{Event, KeepAlive}},
    routing::{delete, get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use openidconnect::{
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope,
    core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata},
    reqwest as oidc_reqwest,
};
use opentelemetry::{
    Context as OpenTelemetryContext,
    trace::{
        SpanContext as OpenTelemetrySpanContext, SpanId as OpenTelemetrySpanId,
        TraceContextExt as _, TraceFlags as OpenTelemetryTraceFlags,
        TraceId as OpenTelemetryTraceId, TraceState as OpenTelemetryTraceState,
    },
};
use peerward_api::{
    AdministrativeState, ApiErrorBody, AuthorityResource, AuthorityStageRequest,
    BulkCommitResponse, BulkPreviewItem, BulkPreviewResponse, BulkRequest, BulkResourceFamily,
    AuditResource, CredentialResource, CredentialRotationRequest, ErrorEnvelope, JoinClaimRequest,
    JoinRelayTarget, JoinResponse, JoinTicketCreateRequest, JoinTicketCreateResponse,
    JoinTicketResource, MeshCreateRequest, MeshDeleteRequest, MeshPatchRequest, MeshResource, Page as ApiPage,
    PageCursor as ApiPageCursor, PeerCreateRequest, PeerPatchRequest, PeerResource, PolicyPutRequest, PolicyRuleRequest,
    PolicySimulationRequest, PolicySimulationResponse, PolicyValidationResponse,
    RelayCreateRequest, RelayPatchRequest, RelayResource, RuntimeHealthSummary,
    ServiceCreateRequest, ServiceResource, TopologyEdgeItem, TopologyNodeItem, TopologyPeerNode,
    TopologyPresenceEdge, TopologyRegionSummary, TopologyRelayNode, TopologyResource,
    TopologySummary, decode_page_cursor, encode_page_cursor,
};
use peerward_credentials::{
    AuthorityCertificate, AuthoritySigningKey, DistributionCertificate, RootPublicKey,
    JoinClaimProof, SubjectId, UnsignedSubject, join_claim_transcript,
    verify_join_claim,
};
use peerward_directory::{
    DirectorySigningKey, PeerEntry, RelayEntry, RelayTopologyNodeV1, RelayTopologyV1,
    decode_relay_topology, encode_peer_directory, encode_policy, encode_relay_directory,
    encode_relay_topology, encode_revocations,
};
use peerward_policy::{
    Action as PolicyAction, PeerDescriptor, Policy, PortRange, Rule as CanonicalRule, Selector,
    encode_policy_document,
};
use peerward_service::{
    RemoteService, RemoteServiceSnapshot, ServiceProtocol, ServiceSnapshotSigningKey,
};
use peerward_store::{
    DefaultPolicy, IssuedPeerCredential, IssuedPeerEnrollment, Lifecycle, MeshRecord,
    MutationRecord, NewAuthority, NewMesh, NewOidcFlow, NewSession, OutboxEvent,
    PageCursor as StorePageCursor, PeerAuditEventRecord, PeerRuntimeHealthRecord,
    Capability, PublicJoinClaim, RelayNeighborHealth, Role, Store, StoreError, SignedStateKind,
    normalize_dns_suffix, secret_digest,
};
use peerward_types::{
    CorrelationContext, CredentialSerial, EventId, IpProtocol, MeshId, NetworkEndpoint, PeerId,
    RelayId, RuleId, ServiceId, TicketId, UnixTime, validate_endpoint_list,
};
use peerward_wire::{
    AuditBatchV1, AuditDirectionV1, AuditReasonV1, RuntimeDegradedReasonV1, SealedAuditBatchV1,
    SPARSE_BACKBONE_V1_CAPABILITY, audit_recipient_public, open_audit_batch,
};
use prost::Message;
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::Row;
use subtle::ConstantTimeEq;
use time::{Duration as TimeDuration, OffsetDateTime};
use time::format_description::well_known::Rfc3339;
use tracing::Instrument as _;
use tracing_opentelemetry::OpenTelemetrySpanExt as _;
use tokio::{
    net::TcpListener,
    sync::{Semaphore, watch},
};
use url::Url;
use uuid::Uuid;

tokio::task_local! {
    static REQUEST_ID: Uuid;
    static CORRELATION_CONTEXT: CorrelationContext;
}

/// Strict control-service TOML document.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlConfig {
    /// Must be exactly one.
    pub config_version: u32,
    /// HTTP listener, defaulting to loopback port 8080.
    #[serde(default = "default_http_address")]
    pub http_address: SocketAddr,
    /// Device-reachable HTTPS origin for enrollment; never inferred from request headers.
    pub public_url: Option<Url>,
    /// Private listener for liveness, readiness, and metrics.
    #[serde(default = "default_management_address")]
    pub management_address: SocketAddr,
    /// `PostgreSQL` URL, overridden only when absent by `PEERWARD_DATABASE_URL`.
    pub database_url: Option<String>,
    /// Maximum database connections.
    #[serde(default = "default_connections")]
    pub max_connections: u32,
    /// Optional OIDC provider. Absence enables explicit development bearer auth.
    pub oidc: Option<OidcConfig>,
    /// Directory containing `<mesh UUID>/<authority relation UUID>.key` online signing seeds.
    pub authority_key_directory: Option<std::path::PathBuf>,
    /// Online mesh issuers used only by public one-time ticket claims.
    #[serde(default)]
    pub join_issuers: Vec<JoinIssuerConfig>,
    /// Cluster-elected cleanup for bounded operational state.
    #[serde(default)]
    pub maintenance: MaintenanceConfig,
}

/// Bounded cleanup settings for one Control deployment.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MaintenanceConfig {
    /// Delay between elected cleanup passes.
    pub interval_seconds: u64,
    /// Maximum rows removed from each table per pass.
    pub batch_size: u32,
    /// Durable event replay age.
    pub event_retention_seconds: u64,
    /// Durable event row ceiling.
    pub event_max_rows: u64,
    /// Signed and policy revisions retained per family.
    pub signed_state_versions: u32,
    /// Grace period for expired operational rows.
    pub terminal_retention_seconds: u64,
}

impl Default for MaintenanceConfig {
    fn default() -> Self {
        Self {
            interval_seconds: 60,
            batch_size: 1_000,
            event_retention_seconds: 86_400,
            event_max_rows: 100_000,
            signed_state_versions: 2,
            terminal_retention_seconds: 86_400,
        }
    }
}

/// Rooted online enrollment material for one mesh.
#[derive(Debug, Clone, serde::Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoinIssuerConfig {
    /// Mesh served by this issuer.
    pub mesh_id: MeshId,
    /// Active authority relation identifier in `PostgreSQL`.
    pub authority_id: Uuid,
    /// Deprecated development-only inline seed; new configurations use `authority_key_directory`.
    pub authority_private_key: Option<String>,
    /// Offline root verifier as 64 hexadecimal characters.
    pub root_public_key: String,
    /// Exact root-signed authority certificate encoded as unpadded base64url.
    pub authority_certificate: String,
    /// Distribution Ed25519 seed as 64 hexadecimal characters.
    pub directory_private_key: String,
    /// Service-snapshot Ed25519 seed as 64 hexadecimal characters.
    pub service_private_key: String,
    /// X25519 private key used only to open encrypted Peer security-audit batches.
    pub audit_private_key: String,
    /// Issued subject lifetime in seconds.
    #[serde(default = "default_join_validity")]
    pub credential_validity_seconds: u64,
    /// Optional RFC 5389 servers used by joined Peers for protected direct-path discovery.
    #[serde(default)]
    pub stun_servers: Vec<peerward_types::StunEndpoint>,
}

fn load_join_issuers(
    configured: &[JoinIssuerConfig],
    key_directory: Option<&std::path::Path>,
) -> Result<HashMap<MeshId, Vec<Arc<JoinIssuer>>>, ApiError> {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let now = u64::try_from(now)
        .map(UnixTime)
        .map_err(|_| ApiError::invalid("invalid_clock", "system clock predates Unix time"))?;
    let mut issuers: HashMap<MeshId, Vec<Arc<JoinIssuer>>> = HashMap::new();
    for config in configured {
        if config.credential_validity_seconds < 300
            || config.credential_validity_seconds > 31_536_000
            || config.authority_id.get_version_num() != 4
            || peerward_types::validate_stun_servers(&config.stun_servers).is_err()
        {
            return Err(ApiError::invalid(
                "invalid_join_issuer",
                "join issuer validity or authority ID is invalid",
            ));
        }
        let authority_seed = load_authority_seed(config, key_directory)?;
        let authority = AuthoritySigningKey::from_bytes(&authority_seed);
        let root_bytes = decode_config_key(&config.root_public_key)?;
        let root = RootPublicKey::from_bytes(&root_bytes)
            .map_err(|_| ApiError::invalid("invalid_join_root", "join root key is invalid"))?;
        let certificate_bytes = URL_SAFE_NO_PAD
            .decode(&config.authority_certificate)
            .map_err(|_| {
                ApiError::invalid(
                    "invalid_join_certificate",
                    "authority certificate is not base64url",
                )
            })?;
        let certificate = AuthorityCertificate::decode(&certificate_bytes).map_err(|_| {
            ApiError::invalid(
                "invalid_join_certificate",
                "authority certificate is malformed",
            )
        })?;
        root.verify_authority(&certificate, config.mesh_id, now)
            .map_err(|_| {
                ApiError::invalid(
                    "invalid_join_certificate",
                    "authority certificate is not currently root anchored",
                )
            })?;
        if certificate.public_key != authority.public_key() {
            return Err(ApiError::invalid(
                "join_authority_key_mismatch",
                "authority certificate does not cover the online key",
            ));
        }
        let directory =
            DirectorySigningKey::from_bytes(&decode_config_key(&config.directory_private_key)?);
        let services =
            ServiceSnapshotSigningKey::from_bytes(&decode_config_key(&config.service_private_key)?);
        let audit_private_key = decode_config_key(&config.audit_private_key)?;
        if audit_recipient_public(&audit_private_key) == [0; 32] {
            return Err(ApiError::invalid(
                "invalid_audit_key",
                "audit recipient private key is invalid",
            ));
        }
        let distribution_certificate = authority.certify_distribution(
            config.mesh_id,
            directory.public_key().to_bytes(),
            services.verifier().to_bytes(),
            audit_recipient_public(&audit_private_key),
        );
        let issuer = Arc::new(JoinIssuer {
            authority_id: config.authority_id,
            authority,
            root_public_key: root_bytes,
            authority_certificate: certificate,
            directory,
            services,
            audit_private_key,
            distribution_certificate,
            validity_seconds: config.credential_validity_seconds,
            stun_servers: config.stun_servers.clone(),
        });
        let mesh_issuers = issuers.entry(config.mesh_id).or_default();
        if mesh_issuers
            .iter()
            .any(|configured| configured.authority_id == config.authority_id)
        {
            return Err(ApiError::invalid(
                "duplicate_join_issuer",
                "an Authority relation may only be configured once",
            ));
        }
        if mesh_issuers
            .first()
            .is_some_and(|configured| configured.root_public_key != root_bytes)
        {
            return Err(ApiError::invalid(
                "join_root_mismatch",
                "all configured Authorities for a mesh must share one Root",
            ));
        }
        if mesh_issuers.first().is_some_and(|configured| {
            audit_recipient_public(&configured.audit_private_key)
                != audit_recipient_public(&audit_private_key)
        }) {
            return Err(ApiError::invalid(
                "join_audit_key_mismatch",
                "all configured Authorities for a mesh must share one audit recipient key",
            ));
        }
        mesh_issuers.push(issuer);
    }
    Ok(issuers)
}

fn load_authority_seed(
    config: &JoinIssuerConfig,
    key_directory: Option<&std::path::Path>,
) -> Result<[u8; 32], ApiError> {
    if let Some(directory) = key_directory {
        let path = directory
            .join(config.mesh_id.to_string())
            .join(format!("{}.key", config.authority_id));
        reject_symlink_components(&path)?;
        let metadata = std::fs::symlink_metadata(&path).map_err(|_| {
            ApiError::invalid(
                "authority_key_unavailable",
                "configured Authority private key file is unavailable",
            )
        })?;
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            return Err(ApiError::invalid(
                "authority_key_invalid",
                "Authority private key must be a regular file",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(ApiError::invalid(
                    "authority_key_permissions",
                    "Authority private key must not be group or world accessible",
                ));
            }
        }
        let seed = peerward_credentials::private_files::read_private(&path, 1024).map_err(|_| {
            ApiError::invalid(
                "authority_key_unavailable",
                "configured Authority private key file cannot be read",
            )
        })?;
        let seed = std::str::from_utf8(&seed).map_err(|_| {
            ApiError::invalid(
                "authority_key_invalid",
                "configured Authority private key is not UTF-8",
            )
        })?;
        return decode_config_key(seed.trim());
    }
    config
        .authority_private_key
        .as_deref()
        .ok_or_else(|| {
            ApiError::invalid(
                "authority_key_directory_required",
                "authority_key_directory is required for configured Mesh issuers",
            )
        })
        .and_then(decode_config_key)
}

fn decode_config_key(value: &str) -> Result<[u8; 32], ApiError> {
    hex::decode(value)
        .map_err(|_| ApiError::invalid("invalid_join_key", "join key is not hexadecimal"))?
        .try_into()
        .map_err(|_| ApiError::invalid("invalid_join_key", "join key must contain 32 bytes"))
}

/// Verifies every configured signer against its database lifecycle and active selection.
pub async fn check_authority_configuration(
    config: &ControlConfig,
    store: &Store,
) -> Result<(), ApiError> {
    let issuers = load_startup_join_issuers(config)?;
    validate_authority_configuration(store, &issuers).await
}

async fn validate_authority_configuration(
    store: &Store,
    issuers: &HashMap<MeshId, Vec<Arc<JoinIssuer>>>,
) -> Result<(), ApiError> {
    for (mesh_id, candidates) in issuers {
        for issuer in candidates {
            let row = sqlx::query(
                "SELECT serial,public_key,certificate,lifecycle,not_before,not_after
                 FROM mesh_authorities WHERE mesh_id=$1 AND id=$2",
            )
            .bind(mesh_id.into_uuid())
            .bind(issuer.authority_id)
            .fetch_optional(store.pool())
            .await?
            .ok_or_else(|| {
                ApiError::invalid(
                    "authority_database_mismatch",
                    "configured Authority relation is absent from the database",
                )
            })?;
            let serial: Uuid = row.try_get("serial")?;
            let public_key: Vec<u8> = row.try_get("public_key")?;
            let certificate: Vec<u8> = row.try_get("certificate")?;
            let lifecycle: String = row.try_get("lifecycle")?;
            let not_before: OffsetDateTime = row.try_get("not_before")?;
            let not_after: OffsetDateTime = row.try_get("not_after")?;
            let configured = &issuer.authority_certificate;
            if serial.as_bytes() != configured.serial.as_bytes()
                || public_key.as_slice() != configured.public_key
                || certificate != configured.encode()
                || !matches!(lifecycle.as_str(), "staged" | "active" | "overlap")
                || not_before.unix_timestamp()
                    != i64::try_from(configured.not_before.0).unwrap_or(i64::MIN)
                || not_after.unix_timestamp()
                    != i64::try_from(configured.not_after.0).unwrap_or(i64::MIN)
            {
                return Err(ApiError::invalid(
                    "authority_database_mismatch",
                    "Authority key, certificate, and database lifecycle do not agree",
                ));
            }
        }
        let active: Uuid = sqlx::query_scalar(
            "SELECT id FROM mesh_authorities WHERE mesh_id=$1 AND lifecycle='active'
             AND not_before<=clock_timestamp() AND not_after>clock_timestamp()",
        )
        .bind(mesh_id.into_uuid())
        .fetch_optional(store.pool())
        .await?
        .ok_or_else(|| {
            ApiError::invalid(
                "active_authority_unavailable",
                "configured Mesh has no currently active Authority",
            )
        })?;
        if !candidates.iter().any(|issuer| issuer.authority_id == active) {
            return Err(ApiError::invalid(
                "active_authority_key_unavailable",
                "database active Authority has no matching configured private key",
            ));
        }
    }
    Ok(())
}

impl ControlConfig {
    /// Parses a complete TOML document and applies the database environment fallback.
    pub fn parse(
        contents: &str,
        environment_database_url: Option<String>,
    ) -> Result<Self, ApiError> {
        let first = contents
            .lines()
            .find(|line| !line.trim().is_empty() && !line.trim_start().starts_with('#'))
            .and_then(|line| line.split_once('='))
            .map(|(key, value)| (key.trim(), value.trim()));
        if !matches!(first, Some(("config_version", "1" | "2"))) {
            return Err(ApiError::invalid(
                "config_version_first",
                "configuration must begin with config_version = 1 or 2",
            ));
        }
        let mut config: Self = toml::from_str(contents).map_err(|_| {
            ApiError::invalid("invalid_control_config", "invalid control configuration")
        })?;
        if !matches!(config.config_version, 1 | 2) {
            return Err(ApiError::invalid(
                "unsupported_config_version",
                "config_version must be 1 or 2",
            ));
        }
        if config.database_url.is_none() {
            config.database_url = environment_database_url;
        }
        if config.database_url.as_deref().is_none_or(str::is_empty) {
            return Err(ApiError::invalid(
                "missing_database_url",
                "database_url or PEERWARD_DATABASE_URL is required",
            ));
        }
        if !(2..=256).contains(&config.max_connections) {
            return Err(ApiError::invalid(
                "invalid_database_pool",
                "max_connections must be between 2 and 256",
            ));
        }
        if config.public_url.as_ref().is_some_and(|url| {
            !secure_oidc_url(url) || url.path() != "/" || url.query().is_some()
        }) {
            return Err(ApiError::invalid(
                "invalid_public_url",
                "public_url must be an HTTPS origin without credentials, path, query or fragment (loopback HTTP is allowed for development)",
            ));
        }
        if let Some(oidc) = &config.oidc
            && (!oidc
                .scopes
                .split_whitespace()
                .any(|scope| scope == "openid")
                || !secure_oidc_url(&oidc.issuer_url)
                || !secure_oidc_url(&oidc.redirect_uri)
                || oidc.admin_groups.is_empty())
            {
                return Err(ApiError::invalid(
                    "invalid_oidc_config",
                    "OIDC requires secure URLs, the openid scope, and an admin mapping",
                ));
            }
        if !(10..=3_600).contains(&config.maintenance.interval_seconds)
            || !(100..=10_000).contains(&config.maintenance.batch_size)
            || !(3_600..=604_800).contains(&config.maintenance.event_retention_seconds)
            || !(10_000..=1_000_000).contains(&config.maintenance.event_max_rows)
            || !(1..=10).contains(&config.maintenance.signed_state_versions)
            || !(3_600..=604_800).contains(&config.maintenance.terminal_retention_seconds)
        {
            return Err(ApiError::invalid(
                "invalid_maintenance_config",
                "maintenance configuration is outside its bounds",
            ));
        }
        Ok(config)
    }
}

/// OIDC Authorization Code + PKCE configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcConfig {
    /// Provider issuer used for `OpenID` discovery.
    pub issuer_url: Url,
    /// Client identifier.
    pub client_id: String,
    /// Optional confidential-client secret.
    pub client_secret: Option<String>,
    /// Exact callback URL.
    pub redirect_uri: Url,
    /// Space-separated scopes; `openid` is required.
    #[serde(default = "default_scopes")]
    pub scopes: String,
    /// ID-token claim containing group names.
    #[serde(default = "default_groups_claim")]
    pub groups_claim: String,
    /// Groups mapped to operator.
    #[serde(default)]
    pub operator_groups: Vec<String>,
    /// Groups mapped to auditor when no higher-priority group matches.
    #[serde(default)]
    pub auditor_groups: Vec<String>,
    /// Groups mapped to admin; at least one is required.
    pub admin_groups: Vec<String>,
}

fn default_scopes() -> String {
    "openid profile email".into()
}

fn default_groups_claim() -> String {
    "groups".into()
}

fn secure_oidc_url(url: &Url) -> bool {
    url.host().is_some() && url.username().is_empty() && url.password().is_none()
        && url.fragment().is_none()
        && (url.scheme() == "https" || (url.scheme() == "http" && match url.host() {
            Some(url::Host::Domain("localhost")) => true,
            Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
            _ => false,
        }))
}

/// Authentication configuration passed to the router.
#[derive(Clone)]
pub struct AuthConfig {
    /// OIDC provider; when set, development bearer authentication is disabled.
    pub oidc: Option<OidcConfig>,
    /// Explicit development bearer token sourced from the bootstrap environment variable.
    pub development_bearer_token: Option<String>,
    /// One-time bootstrap token.
    pub bootstrap_token: Option<String>,
}

include!("state.rs");

struct JoinIssuer {
    authority_id: Uuid,
    authority: AuthoritySigningKey,
    root_public_key: [u8; 32],
    authority_certificate: AuthorityCertificate,
    directory: DirectorySigningKey,
    services: ServiceSnapshotSigningKey,
    audit_private_key: [u8; 32],
    distribution_certificate: DistributionCertificate,
    validity_seconds: u64,
    stun_servers: Vec<peerward_types::StunEndpoint>,
}

include!("router_factories.rs");
