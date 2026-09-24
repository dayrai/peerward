/// Long-running Peer task represented in local health.
#[derive(Debug, Clone, Copy)]
pub enum PeerTask {
    /// TUN packet pump.
    Packet,
    /// Signed control-state and P2P task.
    Control,
    /// Split-DNS task.
    Dns,
}

/// One signed state family required before the Peer is healthy.
#[derive(Debug, Clone, Copy)]
pub enum SignedStateFamily {
    /// Root-anchored online Authority lifecycle.
    Authorities,
    /// Peer directory.
    Peers,
    /// Relay directory.
    Relays,
    /// ACL policy.
    Policy,
    /// Published services.
    Services,
    /// Exact credential revocations.
    Revocations,
}

/// Bounded privacy-safe runtime degradation category used for Control health reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerDegradedReason {
    RelayUnavailable,
    SignedStateIncomplete,
    DirectPathUnavailable,
    DnsDegraded,
    UnderlayUnavailable,
    PacketPumpUnavailable,
}

impl From<PeerDegradedReason> for peerward_types::DiagnosticCode {
    fn from(reason: PeerDegradedReason) -> Self {
        match reason {
            PeerDegradedReason::RelayUnavailable => Self::RelayUnavailable,
            PeerDegradedReason::SignedStateIncomplete => Self::SignedStateIncomplete,
            PeerDegradedReason::DirectPathUnavailable => Self::DirectPathUnavailable,
            PeerDegradedReason::DnsDegraded => Self::DnsDegraded,
            PeerDegradedReason::UnderlayUnavailable => Self::UnderlayUnavailable,
            PeerDegradedReason::PacketPumpUnavailable => Self::PacketPumpUnavailable,
        }
    }
}

/// Stable fallback facts; presentation text must not influence health decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerFallbackReason {
    RuntimeStarting,
    AllRelaysUnavailable,
    DirectPathUnavailable,
}

/// Current report values containing no identities, addresses, endpoints, or DNS data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerRuntimeReport {
    pub generation: u64,
    pub direct_path_count: u32,
    pub relay_packets: u64,
    pub direct_packets: u64,
    pub degraded_reasons: Vec<PeerDegradedReason>,
    pub signed_revision: u64,
}

#[derive(Debug, Clone, Serialize)]
struct RelayAttachmentStatus {
    relay_id: String,
    role: &'static str,
    healthy: bool,
    carrier: Option<&'static str>,
}

#[derive(Debug, Clone, Default, Serialize)]
struct SignedRevisions {
    authorities: Option<u64>,
    peers: Option<u64>,
    relays: Option<u64>,
    policy: Option<u64>,
    services: Option<u64>,
    revocations: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize)]
struct TaskLiveness {
    packet: bool,
    control: bool,
    dns: bool,
}

impl TaskLiveness {
    const fn all_alive(&self) -> bool {
        self.packet && self.control && self.dns
    }

    fn set(&mut self, task: PeerTask, alive: bool) {
        match task {
            PeerTask::Packet => self.packet = alive,
            PeerTask::Control => self.control = alive,
            PeerTask::Dns => self.dns = alive,
        }
    }
}

impl SignedRevisions {
    fn complete(&self) -> bool {
        self.authorities.is_some()
            && self.peers.is_some()
            && self.relays.is_some()
            && self.policy.is_some()
            && self.services.is_some()
            && self.revocations.is_some()
    }

    fn set(&mut self, family: SignedStateFamily, revision: u64) {
        match family {
            SignedStateFamily::Authorities => self.authorities = Some(revision),
            SignedStateFamily::Peers => self.peers = Some(revision),
            SignedStateFamily::Relays => self.relays = Some(revision),
            SignedStateFamily::Policy => self.policy = Some(revision),
            SignedStateFamily::Services => self.services = Some(revision),
            SignedStateFamily::Revocations => self.revocations = Some(revision),
        }
    }

    fn minimum(&self) -> u64 {
        [
            self.authorities,
            self.peers,
            self.relays,
            self.policy,
            self.services,
            self.revocations,
        ]
        .into_iter()
        .flatten()
        .min()
        .unwrap_or_default()
    }
}

#[derive(Debug, Clone, Serialize)]
struct RuntimeState {
    mesh_id: String,
    peer_id: String,
    tun_up: bool,
    dns_host_ready: Option<bool>,
    tasks: TaskLiveness,
    relay_attachments: Vec<RelayAttachmentStatus>,
    signed_revisions: SignedRevisions,
    signed_state_updated_at: Option<u64>,
    direct_peers: Vec<String>,
    fallback_reason: Option<PeerFallbackReason>,
}

impl Default for RuntimeState {
    fn default() -> Self {
        Self {
            mesh_id: String::new(),
            peer_id: String::new(),
            tun_up: false,
            dns_host_ready: None,
            tasks: TaskLiveness::default(),
            relay_attachments: Vec::new(),
            signed_revisions: SignedRevisions::default(),
            signed_state_updated_at: None,
            direct_peers: Vec::new(),
            fallback_reason: Some(PeerFallbackReason::RuntimeStarting),
        }
    }
}
