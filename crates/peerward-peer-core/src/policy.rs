use std::{
    collections::BTreeMap,
    net::IpAddr,
    sync::{
        Mutex, RwLock,
        atomic::{AtomicBool, Ordering},
    },
};

use peerward_dataplane::{Action, ParsedPacket};
use peerward_directory::{DirectoryPublicKey, SignedPeerDirectory, SignedPolicyBundle};
use peerward_policy::{
    Action as IdentityAction, Evaluator, FlowKey as PolicyFlowKey, Packet as PolicyPacket,
    PeerDescriptor, Policy, decode_policy_document,
};
use peerward_types::{IpProtocol, MeshId, PeerId, RuleId, TransportProtocol};

use crate::PeerError;

struct PolicyState {
    directory_revision: Option<u64>,
    policy_revision: Option<u64>,
    peers: BTreeMap<IpAddr, PeerDescriptor>,
    policy: Option<Policy>,
    evaluator: Option<Mutex<Evaluator>>,
}

/// Shared signed identity policy and bounded connection-tracking engine.
pub struct PolicyEngine {
    ready: AtomicBool,
    mesh_id: MeshId,
    local_peer: PeerId,
    verifier: DirectoryPublicKey,
    state_limit: usize,
    expiry_budget: usize,
    state: RwLock<PolicyState>,
    log_last: Mutex<BTreeMap<RuleId, u64>>,
}

impl PolicyEngine {
    /// Creates a deny-until-verified engine for one local Peer.
    pub fn new(
        mesh_id: MeshId,
        local_peer: PeerId,
        verifier: DirectoryPublicKey,
        state_limit: usize,
        shards: usize,
    ) -> Result<Self, PeerError> {
        if state_limit == 0 || shards == 0 {
            return Err(PeerError::InvalidConfig);
        }
        Ok(Self {
            ready: AtomicBool::new(true),
            mesh_id,
            local_peer,
            verifier,
            state_limit,
            expiry_budget: (state_limit / shards).max(1),
            state: RwLock::new(PolicyState {
                directory_revision: None,
                policy_revision: None,
                peers: BTreeMap::new(),
                policy: None,
                evaluator: None,
            }),
            log_last: Mutex::new(BTreeMap::new()),
        })
    }

    pub(crate) fn set_ready(&self, ready: bool) {
        self.ready.store(ready, Ordering::Release);
    }

    pub(crate) fn clear_connections(&self) -> Result<(), PeerError> {
        let mut state = self.state.write().map_err(|_| PeerError::Closed)?;
        state.evaluator = state.policy.as_ref().map(|policy| {
            Mutex::new(Evaluator::new(
                self.mesh_id,
                policy.clone(),
                self.state_limit,
                self.expiry_budget,
                10,
            ))
        });
        Ok(())
    }

    pub(crate) fn descriptor(&self, address: IpAddr) -> Option<PeerDescriptor> {
        self.state.read().ok()?.peers.get(&address).cloned()
    }

    pub(crate) fn verify_policy(&self, signed: &SignedPolicyBundle) -> Result<(), PeerError> {
        let state = self.state.read().map_err(|_| PeerError::Closed)?;
        self.verifier
            .verify_policy(signed, self.mesh_id, state.policy_revision)?;
        decode_policy_document(signed.bundle.revision, &signed.bundle.policy)?;
        Ok(())
    }

    /// Authenticates and atomically installs a strictly newer Peer directory.
    pub fn install_directory(&self, signed: &SignedPeerDirectory) -> Result<u64, PeerError> {
        let mut state = self.state.write().map_err(|_| PeerError::Closed)?;
        self.verifier
            .verify_peers(signed, self.mesh_id, state.directory_revision)?;
        let peers = signed
            .directory
            .entries
            .iter()
            .filter(|entry| entry.entry.enabled)
            .flat_map(|entry| {
                entry.entry.addresses().map(|address| PeerDescriptor {
                    id: entry.entry.peer_id,
                    address,
                    labels: entry.entry.labels.clone(),
                })
            })
            .collect();
        Self::replace_peers(
            &mut state,
            self.local_peer,
            self.mesh_id,
            self.state_limit,
            self.expiry_budget,
            peers,
        )?;
        state.directory_revision = Some(signed.directory.revision);
        self.clear_logs();
        Ok(signed.directory.revision)
    }

    /// Installs descriptors already authenticated by an outer directory assembler.
    pub fn install_verified_peers(&self, peers: Vec<PeerDescriptor>) -> Result<(), PeerError> {
        let mut state = self.state.write().map_err(|_| PeerError::Closed)?;
        Self::replace_peers(
            &mut state,
            self.local_peer,
            self.mesh_id,
            self.state_limit,
            self.expiry_budget,
            peers,
        )?;
        self.clear_logs();
        Ok(())
    }

    /// Authenticates, decodes, and atomically installs a newer policy revision.
    pub fn install_policy(&self, signed: &SignedPolicyBundle) -> Result<u64, PeerError> {
        let mut state = self.state.write().map_err(|_| PeerError::Closed)?;
        self.verifier
            .verify_policy(signed, self.mesh_id, state.policy_revision)?;
        let policy = decode_policy_document(signed.bundle.revision, &signed.bundle.policy)?;
        state.evaluator = Some(Mutex::new(Evaluator::new(
            self.mesh_id,
            policy.clone(),
            self.state_limit,
            self.expiry_budget,
            10,
        )));
        state.policy_revision = Some(policy.revision);
        state.policy = Some(policy);
        self.clear_logs();
        Ok(signed.bundle.revision)
    }

    /// Stateful source/destination enforcement for a real packet.
    pub fn evaluate(&self, packet: &ParsedPacket, now: u64) -> Action {
        if !self.ready.load(Ordering::Acquire) {
            return Action::Deny;
        }
        self.state.read().map_or(Action::Deny, |state| {
            Self::decide(
                &state,
                self.mesh_id,
                self.local_peer,
                packet,
                Some(now),
                Some(&self.log_last),
                true,
            )
        })
    }

    /// Blocking inbound initiation must retain responses to locally initiated flows.
    pub fn evaluate_inbound(
        &self,
        packet: &ParsedPacket,
        now: u64,
        allow_initiation: bool,
    ) -> Action {
        if !self.ready.load(Ordering::Acquire) {
            return Action::Deny;
        }
        self.state.read().map_or(Action::Deny, |state| {
            Self::decide(
                &state,
                self.mesh_id,
                self.local_peer,
                packet,
                Some(now),
                Some(&self.log_last),
                allow_initiation,
            )
        })
    }

    /// Stateless visibility decision used for DNS and service metadata.
    pub fn visible(&self, packet: &ParsedPacket) -> Action {
        if !self.ready.load(Ordering::Acquire) {
            return Action::Deny;
        }
        self.state.read().map_or(Action::Deny, |state| {
            Self::decide(
                &state,
                self.mesh_id,
                self.local_peer,
                packet,
                None,
                None,
                true,
            )
        })
    }

    /// Resolves one signed peer label only when the querying peer may see it.
    pub fn resolve_peer_name(&self, label: &str, source: IpAddr) -> Option<IpAddr> {
        self.resolve_peer_name_family(label, source, None)
    }

    /// DNS record family is independent of the querying socket's family.
    pub fn resolve_peer_name_family(
        &self,
        label: &str,
        source: IpAddr,
        ipv6: Option<bool>,
    ) -> Option<IpAddr> {
        if !self.ready.load(Ordering::Acquire) {
            return None;
        }
        let state = self.state.read().ok()?;
        state.peers.values().find_map(|peer| {
            let name = peer.labels.get("name")?;
            (name.eq_ignore_ascii_case(label)
                && ipv6.is_none_or(|ipv6| peer.address.is_ipv6() == ipv6)
                && Self::allows_peer_visibility(
                    &state,
                    self.mesh_id,
                    self.local_peer,
                    source,
                    peer.address,
                ))
            .then_some(peer.address)
        })
    }

    /// Resolves one signed reverse peer label under the same ACL visibility rule.
    pub fn resolve_peer_address(&self, address: IpAddr, source: IpAddr) -> Option<String> {
        if !self.ready.load(Ordering::Acquire) {
            return None;
        }
        let state = self.state.read().ok()?;
        let peer = state.peers.get(&address)?;
        (Self::allows_peer_visibility(&state, self.mesh_id, self.local_peer, source, address))
            .then(|| peer.labels.get("name").cloned())
            .flatten()
    }

    /// Statelessly checks visibility of a signed service record.
    pub fn allows_service(
        &self,
        source: IpAddr,
        destination: IpAddr,
        protocol: TransportProtocol,
        port: u16,
    ) -> bool {
        if !self.ready.load(Ordering::Acquire) {
            return false;
        }
        let Ok(state) = self.state.read() else {
            return false;
        };
        let protocol = match protocol {
            TransportProtocol::Tcp => 6,
            TransportProtocol::Udp => 17,
            TransportProtocol::Icmp => return false,
        };
        let packet = ParsedPacket {
            source,
            destination,
            protocol,
            source_port: Some(49_152),
            destination_port: Some(port),
            tcp_flags: (protocol == 6).then_some(0x02),
            icmp: None,
            fragment: None,
            packet_len: if destination.is_ipv4() { 40 } else { 60 },
            related_flow: None,
        };
        Self::decide(
            &state,
            self.mesh_id,
            self.local_peer,
            &packet,
            None,
            None,
            true,
        ) == Action::Allow
    }

    fn replace_peers(
        state: &mut PolicyState,
        local_peer: PeerId,
        mesh_id: MeshId,
        state_limit: usize,
        expiry_budget: usize,
        peers: Vec<PeerDescriptor>,
    ) -> Result<(), PeerError> {
        if !peers.iter().any(|peer| peer.id == local_peer) {
            return Err(PeerError::InvalidConfig);
        }
        let mut by_address = BTreeMap::new();
        for peer in peers {
            if by_address.insert(peer.address, peer).is_some() {
                return Err(PeerError::InvalidConfig);
            }
        }
        state.peers = by_address;
        state.evaluator = state.policy.clone().map(|policy| {
            Mutex::new(Evaluator::new(
                mesh_id,
                policy,
                state_limit,
                expiry_budget,
                10,
            ))
        });
        Ok(())
    }

    fn allows_peer_visibility(
        state: &PolicyState,
        mesh_id: MeshId,
        local_peer: PeerId,
        source: IpAddr,
        destination: IpAddr,
    ) -> bool {
        let Some(source_peer) = state.peers.get(&source) else {
            return false;
        };
        let Some(destination_peer) = state.peers.get(&destination) else {
            return false;
        };
        // A Peer must be able to discover its own assigned address even in a
        // default-deny Mesh. This reveals no other identity and does not bypass
        // data-plane policy; all non-self DNS visibility still follows policy.
        if source_peer.id == local_peer && destination_peer.id == local_peer {
            return true;
        }
        let packet = ParsedPacket {
            source,
            destination,
            protocol: if destination.is_ipv4() { 1 } else { 58 },
            source_port: None,
            destination_port: None,
            tcp_flags: None,
            icmp: Some((if destination.is_ipv4() { 8 } else { 128 }, 0)),
            fragment: None,
            packet_len: if destination.is_ipv4() { 28 } else { 48 },
            related_flow: None,
        };
        Self::decide(state, mesh_id, local_peer, &packet, None, None, true) == Action::Allow
    }

    fn decide(
        state: &PolicyState,
        mesh_id: MeshId,
        local_peer: PeerId,
        packet: &ParsedPacket,
        now: Option<u64>,
        log_last: Option<&Mutex<BTreeMap<RuleId, u64>>>,
        allow_initiation: bool,
    ) -> Action {
        let Some(source) = state.peers.get(&packet.source) else {
            return Action::Deny;
        };
        let Some(destination) = state.peers.get(&packet.destination) else {
            return Action::Deny;
        };
        if source.id != local_peer && destination.id != local_peer {
            return Action::Deny;
        }
        let protocol = IpProtocol::new(packet.protocol);
        let Some(policy) = state.policy.as_ref() else {
            return Action::Deny;
        };
        let direct_decision = || {
            let decision =
                policy.decide_initiation(source, destination, protocol, packet.destination_port);
            if decision.log
                && let (Some(rule_id), Some(now), Some(log_last)) =
                    (decision.rule_id, now, log_last)
                && bounded_log_due(log_last, rule_id, now)
            {
                tracing::info!(
                    rule_id = %rule_id,
                    source = %packet.source,
                    destination = %packet.destination,
                    protocol = packet.protocol,
                    "policy rule matched"
                );
            }
            (
                match decision.action {
                    IdentityAction::Allow => Action::Allow,
                    IdentityAction::Deny => Action::Deny,
                },
                decision.rule_id,
            )
        };
        let Some(now) = now else {
            return direct_decision().0;
        };
        let Some(evaluator) = state.evaluator.as_ref() else {
            return Action::Deny;
        };
        let Ok(mut evaluator) = evaluator.lock() else {
            return Action::Deny;
        };
        let flow = PolicyFlowKey {
            source: packet.source,
            destination: packet.destination,
            protocol,
            source_port: packet.source_port,
            destination_port: packet.destination_port,
        };
        let related_flow = packet.related_flow.as_ref().map(|flow| PolicyFlowKey {
            source: flow.source,
            destination: flow.destination,
            protocol: IpProtocol::new(flow.protocol),
            source_port: flow.source_port,
            destination_port: flow.destination_port,
        });
        let initiating = match packet.protocol {
            6 => packet
                .tcp_flags
                .is_some_and(|flags| flags & 0x02 != 0 && flags & 0x10 == 0),
            1 => packet.icmp.is_some_and(|(kind, _)| kind == 8),
            58 => packet.icmp.is_some_and(|(kind, _)| kind == 128),
            _ => packet.fragment.is_none_or(|fragment| fragment.offset == 0),
        };
        let evaluation = evaluator.evaluate(
            &PolicyPacket {
                mesh_id,
                source,
                destination,
                flow,
                initiating: initiating && allow_initiation,
                related_flow,
                fragment_of: None,
            },
            now,
        );
        if evaluation.rule_id.is_some() {
            let _ = direct_decision();
        }
        match evaluation.action {
            IdentityAction::Allow => Action::Allow,
            IdentityAction::Deny => Action::Deny,
        }
    }

    fn clear_logs(&self) {
        if let Ok(mut logs) = self.log_last.lock() {
            logs.clear();
        }
    }
}

fn bounded_log_due(log_last: &Mutex<BTreeMap<RuleId, u64>>, rule_id: RuleId, now: u64) -> bool {
    const LOG_INTERVAL_SECONDS: u64 = 10;
    const MAX_LOG_KEYS: usize = 4_096;
    let Ok(mut logs) = log_last.lock() else {
        return false;
    };
    if logs
        .get(&rule_id)
        .is_some_and(|last| now.saturating_sub(*last) < LOG_INTERVAL_SECONDS)
    {
        return false;
    }
    if logs.len() >= MAX_LOG_KEYS
        && !logs.contains_key(&rule_id)
        && let Some(oldest) = logs
            .iter()
            .min_by_key(|(_, time)| **time)
            .map(|(id, _)| *id)
    {
        logs.remove(&oldest);
    }
    logs.insert(rule_id, now);
    true
}
