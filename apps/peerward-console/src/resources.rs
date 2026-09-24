/// Mesh-scoped REST family used by generic table workflows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceFamily {
    /// Root-anchored mesh Authorities.
    Authorities,
    /// Enrolled peers.
    Peers,
    /// Public relays.
    Relays,
    /// One-time tickets.
    JoinTickets,
    /// Published services.
    Services,
}

impl ResourceFamily {
    fn segment(self) -> &'static str {
        match self {
            Self::Authorities => "authorities",
            Self::Peers => "peers",
            Self::Relays => "relays",
            Self::JoinTickets => "join-tickets",
            Self::Services => "services",
        }
    }

    fn collection_path(self, mesh: &str) -> String {
        format!("/api/v1/meshes/{mesh}/{}", self.segment())
    }

    fn member_path(self, mesh: &str, id: &str) -> String {
        format!("{}/{id}", self.collection_path(mesh))
    }
}

fn summary_page<T>(page: Page<T>) -> Page<ResourceSummary>
where
    T: Into<ResourceSummary>,
{
    Page {
        items: page.items.into_iter().map(Into::into).collect(),
        next_cursor: page.next_cursor,
    }
}

/// Subject families that own independently rotated Noise credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialSubject {
    /// Enrolled Peer identity.
    Peer,
    /// Relay identity.
    Relay,
}

impl CredentialSubject {
    fn member_path(self, mesh: &str, id: &str) -> String {
        let family = match self {
            Self::Peer => ResourceFamily::Peers,
            Self::Relay => ResourceFamily::Relays,
        };
        family.member_path(mesh, id)
    }
}

/// Parsed Server-Sent Event.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SseEvent {
    /// Replay cursor.
    pub id: Option<String>,
    /// Event family.
    pub event: Option<String>,
    /// Joined data lines.
    pub data: String,
}

/// Incremental SSE decoder preserving partial network chunks.
const MAX_SSE_EVENT_BYTES: usize = peerward_api::MAX_SSE_EVENT_BYTES;
const MAX_REPLAY_IDS: usize = 1024;

/// Bounded SSE transport decoding failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum SseParseError {
    /// An event block was not strict UTF-8.
    #[error("SSE event is not valid UTF-8")]
    InvalidUtf8,
    /// One event exceeded the allocation ceiling.
    #[error("SSE event exceeds 256 KiB")]
    TooLarge,
}

#[derive(Debug, Default)]
pub struct SseParser {
    pending: Vec<u8>,
    saw_cr: bool,
}

impl SseParser {
    /// Pushes arbitrary transport bytes and returns strictly decoded complete events.
    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<SseEvent>, SseParseError> {
        let mut events = Vec::new();
        for &byte in chunk {
            if self.saw_cr {
                self.saw_cr = false;
                if byte == b'\n' {
                    continue;
                }
            }
            if byte == b'\r' {
                self.push_normalized(b'\n', &mut events)?;
                self.saw_cr = true;
            } else {
                self.push_normalized(byte, &mut events)?;
            }
        }
        Ok(events)
    }

    fn push_normalized(
        &mut self,
        byte: u8,
        events: &mut Vec<SseEvent>,
    ) -> Result<(), SseParseError> {
        if self.pending.len() >= MAX_SSE_EVENT_BYTES {
            return Err(SseParseError::TooLarge);
        }
        self.pending.push(byte);
        if self.pending.ends_with(b"\n\n") {
            let boundary = self.pending.len() - 2;
            let block = std::str::from_utf8(&self.pending[..boundary])
                .map_err(|_| SseParseError::InvalidUtf8)?;
            if let Some(event) = parse_sse_block(block) {
                events.push(event);
            }
            self.pending.clear();
        }
        Ok(())
    }
}

fn parse_sse_block(block: &str) -> Option<SseEvent> {
    let mut parsed = SseEvent::default();
    let mut data = Vec::new();
    for line in block.lines() {
        if line.starts_with(':') || line.is_empty() {
            continue;
        }
        let (field, value) = line.split_once(':').map_or((line, ""), |(key, value)| {
            (key, value.strip_prefix(' ').unwrap_or(value))
        });
        match field {
            "id" if !value.contains('\0') => parsed.id = Some(value.to_owned()),
            "event" => parsed.event = Some(value.to_owned()),
            "data" => data.push(value),
            _ => {}
        }
    }
    parsed.data = data.join("\n");
    (parsed.id.is_some() || parsed.event.is_some() || !parsed.data.is_empty()).then_some(parsed)
}

/// Cursor and bounded retry schedule for SSE replay.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EventReplay {
    cursor: Option<String>,
    failures: u8,
    recent: VecDeque<String>,
    seen: HashSet<String>,
}

impl EventReplay {
    /// Records a delivered cursor and resets reconnect backoff.
    pub fn delivered(&mut self, event: &SseEvent) -> bool {
        if let Some(id) = &event.id {
            if !self.seen.insert(id.clone()) {
                return false;
            }
            self.cursor = Some(id.clone());
            self.recent.push_back(id.clone());
            if self.recent.len() > MAX_REPLAY_IDS
                && let Some(expired) = self.recent.pop_front()
            {
                self.seen.remove(&expired);
            }
        }
        self.failures = 0;
        true
    }

    /// Returns the exact `Last-Event-ID` value for the next request.
    pub fn cursor(&self) -> Option<&str> {
        self.cursor.as_deref()
    }

    /// Clears an expired cursor and its deduplication window before a fresh handshake.
    pub fn reset(&mut self) {
        self.cursor = None;
        self.failures = 0;
        self.recent.clear();
        self.seen.clear();
    }

    /// Returns bounded exponential reconnect milliseconds.
    pub fn failed(&mut self) -> u64 {
        self.failures = self.failures.saturating_add(1).min(6);
        250_u64.saturating_mul(1_u64 << u32::from(self.failures - 1))
    }
}

#[cfg(any(test, target_arch = "wasm32"))]
fn event_affects_route(event: &SseEvent, route: ConsoleRoute, selected_mesh: &str) -> bool {
    if event.event.as_deref() == Some("peerward.ready") {
        return true;
    }
    let Ok(document) = serde_json::from_str::<Value>(&event.data) else {
        return false;
    };
    if !matches!(route,ConsoleRoute::Meshes|ConsoleRoute::Networks)
        && !selected_mesh.is_empty()
        && document
            .get("mesh_id")
            .and_then(Value::as_str)
            .is_some_and(|mesh_id| mesh_id != selected_mesh)
    {
        return false;
    }
    let resource = document
        .get("resource_type")
        .and_then(Value::as_str)
        .unwrap_or_default();
    match route {
        ConsoleRoute::Overview
        | ConsoleRoute::Audit
        | ConsoleRoute::Operations
        | ConsoleRoute::Webhooks => true,
        ConsoleRoute::Meshes | ConsoleRoute::Networks => resource == "mesh",
        ConsoleRoute::Authorities => matches!(resource, "authority" | "signed_state"),
        ConsoleRoute::Peers => {
            matches!(
                resource,
                "peer" | "peer_credential" | "credential_renewal" | "signed_state"
            )
        }
        ConsoleRoute::Relays => {
            matches!(resource, "relay" | "relay_credential" | "signed_state")
        }
        ConsoleRoute::JoinTickets => matches!(resource, "join_ticket" | "installation"),
        ConsoleRoute::Policy => matches!(
            resource,
            "policy" | "resource_policy" | "sharing" | "collection" | "peer" | "signed_state"
        ),
        ConsoleRoute::Services => matches!(
            resource,
            "service" | "sharing" | "network_resource" | "gateway_binding" | "signed_state"
        ),
    }
}

/// Console route families.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ConsoleRoute {
    /// Health and counts.
    #[default]
    Overview,
    /// Mesh lifecycle.
    Meshes,
    /// Portfolio across independent networks.
    Networks,
    /// Root-anchored Authority lifecycle.
    Authorities,
    /// Peer lifecycle and rotation.
    Peers,
    /// Relay lifecycle and rotation.
    Relays,
    /// Ticket lifecycle.
    JoinTickets,
    /// Ordered policy editor.
    Policy,
    /// Service publications.
    Services,
    /// Metadata-only audit stream.
    Audit,
    /// Task-oriented network and installation maintenance.
    Operations,
    /// Mesh integration settings.
    Webhooks,
}

impl ConsoleRoute {
    /// Parses a browser path without accepting ambiguous partial matches.
    pub fn from_path(path: &str) -> Self {
        match path.trim_matches('/') {
            "meshes" => Self::Meshes,
            "networks" => Self::Networks,
            "authorities" => Self::Authorities,
            "peers" => Self::Peers,
            "relays" => Self::Relays,
            "join-tickets" => Self::JoinTickets,
            "policy" => Self::Policy,
            "services" => Self::Services,
            "audit" => Self::Audit,
            "operations" => Self::Operations,
            "webhooks" => Self::Webhooks,
            _ => Self::Overview,
        }
    }

    pub fn path(self) -> &'static str {
        match self {
            Self::Overview => "/",
            Self::Meshes => "/meshes",
            Self::Networks => "/networks",
            Self::Authorities => "/authorities",
            Self::Peers => "/peers",
            Self::Relays => "/relays",
            Self::JoinTickets => "/join-tickets",
            Self::Policy => "/policy",
            Self::Services => "/services",
            Self::Audit => "/audit",
            Self::Operations => "/operations",
            Self::Webhooks => "/webhooks",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Meshes => "Meshes",
            Self::Networks => "All networks",
            Self::Authorities => "Signing authorities",
            Self::Peers => "Devices",
            Self::Relays => "Relays",
            Self::JoinTickets => "Join tickets",
            Self::Policy => "Policy",
            Self::Services => "Services",
            Self::Audit => "Audit",
            Self::Operations => "Issues and maintenance",
            Self::Webhooks => "Webhooks and integrations",
        }
    }
}

/// Server-provided console state suitable for SSR and hydration.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsoleSnapshot {
    /// Mesh choices available to the current principal.
    #[serde(default)]
    pub meshes: Vec<ResourceSummary>,
    /// Active typed mesh identifier used to build exact REST actions.
    pub mesh_id: String,
    /// Active mesh name.
    pub mesh_name: String,
    /// Current role.
    pub role: String,
    /// Stable server-provided capabilities used for route and action visibility.
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// CSRF value supplied by the authenticated session for browser mutations.
    #[serde(default)]
    pub csrf_token: Option<String>,
    /// Control health.
    pub healthy: bool,
    /// Resources for the selected route.
    pub resources: Vec<ResourceSummary>,
    /// Searchable related resources used by typed selectors, never by authorization.
    #[serde(default)]
    pub lookups: Vec<ResourceSummary>,
    /// Optional stable error envelope.
    pub error: Option<ApiErrorBody>,
    /// Opaque next page cursor.
    pub next_cursor: Option<String>,
    /// Optional Relay-scoped Peer drill-down retained across page loads and SSE refreshes.
    #[serde(default)]
    pub relay_filter: Option<String>,
}

#[cfg(test)]
impl ConsoleSnapshot {
    /// Deterministic non-secret state for rendering and client regression tests.
    fn sample() -> Self {
        Self {
            meshes: vec![ResourceSummary {
                id: "00000000-0000-4000-8000-000000000000".into(),
                name: "Example mesh".into(),
                details: BTreeMap::new(),
            }],
            mesh_id: "00000000-0000-4000-8000-000000000000".into(),
            mesh_name: "Example mesh".into(),
            role: "viewer".into(),
            capabilities: vec!["status_audit_read".into(), "resource_read".into()],
            csrf_token: None,
            healthy: true,
            resources: vec![ResourceSummary {
                id: "00000000-0000-4000-8000-000000000001".into(),
                name: "Example".into(),
                details: BTreeMap::new(),
            }],
            lookups: Vec::new(),
            error: None,
            next_cursor: None,
            relay_filter: None,
        }
    }
}

impl ConsoleSnapshot {
    /// Whether the authenticated session grants one stable capability.
    pub fn has_capability(&self, capability: &str) -> bool {
        self.capabilities.iter().any(|item| item == capability)
    }
}
