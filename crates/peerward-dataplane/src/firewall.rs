/// ACL action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Permit this direction.
    Allow,
    /// Drop this packet.
    Deny,
}

/// One ordered initiation rule.
#[derive(Debug, Clone)]
pub struct Rule {
    /// Stable identity for audit decisions.
    pub id: RuleId,
    /// Lower values match first.
    pub priority: u32,
    /// Result when all predicates match.
    pub action: Action,
    /// Source prefix; absent matches any address family.
    pub source: Option<IpNet>,
    /// Destination prefix; absent matches any address family.
    pub destination: Option<IpNet>,
    /// Exact IP protocol; absent matches any supported protocol.
    pub protocol: Option<u8>,
    /// TCP/UDP destination ranges; empty matches any port.
    pub destination_ports: Vec<RangeInclusive<u16>>,
}

impl Rule {
    fn matches(&self, packet: &ParsedPacket) -> bool {
        self.source
            .as_ref()
            .is_none_or(|network| network.contains(&packet.source))
            && self
                .destination
                .as_ref()
                .is_none_or(|network| network.contains(&packet.destination))
            && self.protocol.is_none_or(|value| value == packet.protocol)
            && (self.destination_ports.is_empty()
                || packet.destination_port.is_some_and(|port| {
                    self.destination_ports
                        .iter()
                        .any(|range| range.contains(&port))
                }))
    }
}

/// Directional transport identity.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FlowKey {
    /// Source address.
    pub source: IpAddr,
    /// Destination address.
    pub destination: IpAddr,
    /// Final IP protocol.
    pub protocol: u8,
    /// Transport source or echo identifier.
    pub source_port: Option<u16>,
    /// Transport destination or echo identifier.
    pub destination_port: Option<u16>,
}

impl FlowKey {
    /// Extracts a flow from an unfragmented or first-fragment packet.
    pub fn from_packet(packet: &ParsedPacket) -> Option<Self> {
        let transport_header_is_present =
            packet.fragment.is_none_or(|fragment| fragment.offset == 0);
        transport_header_is_present.then(|| {
            Self::from_endpoints(
                (packet.source, packet.source_port),
                (packet.destination, packet.destination_port),
                packet.protocol,
            )
        })
    }

    /// Reverses both network and transport endpoints.
    #[must_use]
    pub fn reverse(&self) -> Self {
        let mut opposite = self.clone();
        std::mem::swap(&mut opposite.source, &mut opposite.destination);
        std::mem::swap(&mut opposite.source_port, &mut opposite.destination_port);
        opposite
    }

    fn from_endpoints(
        origin: (IpAddr, Option<u16>),
        target: (IpAddr, Option<u16>),
        protocol: u8,
    ) -> Self {
        let (source, source_port) = origin;
        let (destination, destination_port) = target;
        Self {
            source,
            destination,
            protocol,
            source_port,
            destination_port,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TcpPhase {
    SynSent,
    SynReceived,
    Established,
    Closing,
}

#[derive(Debug, Clone, Copy)]
struct FlowState {
    expires_at: u64,
    phase: Option<TcpPhase>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct FragmentKey {
    source: IpAddr,
    destination: IpAddr,
    protocol: u8,
    identification: u32,
}

#[derive(Debug, Clone, Copy)]
struct FragmentState {
    expires_at: u64,
    action: Action,
    rule_id: Option<RuleId>,
}

#[derive(Default)]
struct Shard {
    flows: HashMap<FlowKey, FlowState>,
    flow_expirations: BTreeSet<(u64, FlowKey)>,
    fragments: HashMap<FragmentKey, FragmentState>,
    fragment_expirations: BTreeSet<(u64, FragmentKey)>,
}

impl Shard {
    fn remove_flow(&mut self, key: &FlowKey) {
        if let Some(state) = self.flows.remove(key) {
            self.flow_expirations.remove(&(state.expires_at, key.clone()));
        }
    }

    fn store_flow(&mut self, key: FlowKey, state: FlowState) {
        if let Some(previous) = self.flows.insert(key.clone(), state) {
            if previous.expires_at == state.expires_at {
                return;
            }
            self.flow_expirations.remove(&(previous.expires_at, key.clone()));
        }
        self.flow_expirations.insert((state.expires_at, key));
    }

    fn remove_fragment(&mut self, key: &FragmentKey) {
        if let Some(state) = self.fragments.remove(key) {
            self.fragment_expirations.remove(&(state.expires_at, key.clone()));
        }
    }
}

/// Authorization outcome without packet contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decision {
    /// Permit or deny.
    pub action: Action,
    /// Matching initiation rule, if any.
    pub rule_id: Option<RuleId>,
    /// Whether existing state authorized the packet.
    pub stateful: bool,
}

/// Thread-safe sharded stateful firewall with fixed per-shard limits.
pub struct Firewall {
    rules: Vec<Rule>,
    default: Action,
    revision: u64,
    shards: Vec<Mutex<Shard>>,
    per_shard_limit: usize,
    flow_timeout: u64,
    tcp_timeout: u64,
    fragment_timeout: u64,
    expiry_budget: usize,
}

impl Firewall {
    /// Builds a bounded firewall and orders rules by ascending priority.
    pub fn new(
        revision: u64,
        default: Action,
        mut rules: Vec<Rule>,
        state_limit: usize,
        shard_count: usize,
    ) -> Self {
        rules.sort_by_key(|rule| rule.priority);
        let count = shard_count.max(1);
        let per_shard_limit = state_limit.max(1).div_ceil(count);
        Self {
            rules,
            default,
            revision,
            shards: (0..count).map(|_| Mutex::new(Shard::default())).collect(),
            per_shard_limit,
            flow_timeout: 60,
            tcp_timeout: 600,
            fragment_timeout: 15,
            expiry_budget: 64,
        }
    }

    /// Replaces policy and invalidates all flow and fragment state.
    pub fn replace(&mut self, revision: u64, default: Action, mut rules: Vec<Rule>) -> bool {
        if revision <= self.revision {
            return false;
        }
        rules.sort_by_key(|rule| rule.priority);
        self.revision = revision;
        self.default = default;
        self.rules = rules;
        self.invalidate_state();
        true
    }

    /// Invalidates every flow and fragment after a non-policy authorization input changes.
    pub fn invalidate_state(&self) {
        for shard in &self.shards {
            let mut state = shard.lock().expect("firewall shard poisoned");
            state.flows.clear();
            state.flow_expirations.clear();
            state.fragments.clear();
            state.fragment_expirations.clear();
        }
    }

    /// Removes one connection without invalidating healthy unrelated flows.
    pub fn forget_flow(&self, key: &FlowKey) {
        let reverse = key.reverse();
        for shard in &self.shards {
            let mut state = shard.lock().expect("firewall shard poisoned");
            state.remove_flow(key);
            state.remove_flow(&reverse);
            let fragments_to_remove: Vec<_> = state.fragments.keys().filter(|fragment| {
                (fragment.protocol == key.protocol || fragment.source.is_ipv6())
                    && ((fragment.source == key.source && fragment.destination == key.destination)
                        || (fragment.source == key.destination && fragment.destination == key.source))
            }).cloned().collect();
            for fragment in fragments_to_remove {
                state.remove_fragment(&fragment);
            }
        }
    }

    /// Returns the bounded number of flow entries across all shards.
    pub fn state_len(&self) -> usize {
        self.shards
            .iter()
            .map(|shard| shard.lock().expect("firewall shard poisoned").flows.len())
            .sum()
    }

    /// Evaluates ordered policy without reading or creating flow state.
    ///
    /// This is used for visibility decisions such as DNS answers; actual packets must use
    /// [`Self::evaluate`] so TCP/UDP/ICMP state remains authoritative.
    pub fn policy_decision(&self, packet: &ParsedPacket) -> Decision {
        let (action, rule_id) = self
            .rules
            .iter()
            .find(|rule| rule.matches(packet))
            .map_or((self.default, None), |rule| (rule.action, Some(rule.id)));
        Decision {
            action,
            rule_id,
            stateful: false,
        }
    }

    /// Evaluates one parsed packet using caller-supplied monotonic seconds.
    pub fn evaluate(&self, packet: &ParsedPacket, now: u64) -> Decision {
        self.evaluate_with_policy(packet, now, |packet| {
            let decision = self.policy_decision(packet);
            (decision.action, decision.rule_id)
        })
    }

    /// Evaluates strict state using an identity-aware initiation policy supplied by the caller.
    ///
    /// The callback is consulted only for a structurally valid new initiation. Existing return,
    /// related-ICMP, and fragment state remains owned and bounded by this firewall.
    pub fn evaluate_with_policy<F>(&self, packet: &ParsedPacket, now: u64, policy: F) -> Decision
    where
        F: FnOnce(&ParsedPacket) -> (Action, Option<RuleId>),
    {
        if let Some(fragment) = packet.fragment
            && fragment.offset != 0
        {
            return self.evaluate_later_fragment(packet, fragment, now);
        }
        if let Some(related) = &packet.related_flow
            && (self.has_state(related, now) || self.has_state(&related.reverse(), now))
        {
            return Decision {
                action: Action::Allow,
                rule_id: None,
                stateful: true,
            };
        }
        let Some(flow) = FlowKey::from_packet(packet) else {
            return denied();
        };
        if let Some(decision) = self.evaluate_existing(packet, &flow, now) {
            return decision;
        }
        if !valid_initiation(packet) {
            return denied();
        }
        let (action, rule_id) = policy(packet);
        if action == Action::Allow {
            if matches!(packet.protocol, TCP | UDP | ICMP_V4 | ICMP_V6) {
                self.insert_flow(&flow, packet, now);
            }
            if let Some(fragment) = packet.fragment.filter(|item| item.more) {
                self.insert_fragment(packet, fragment, action, rule_id, now);
            }
        }
        Decision {
            action,
            rule_id,
            stateful: false,
        }
    }

    fn evaluate_existing(
        &self,
        packet: &ParsedPacket,
        flow: &FlowKey,
        now: u64,
    ) -> Option<Decision> {
        for (key, initiator_direction) in [(flow, true), (&flow.reverse(), false)] {
            let index = self.shard_index(key);
            let mut shard = self.shards[index].lock().expect("firewall shard poisoned");
            expire(&mut shard, now, self.expiry_budget);
            let Some(mut state) = shard.flows.get(key).copied() else {
                continue;
            };
            // Reclamation is bounded, but authorization expiry is exact even
            // when this entry was not reached by the current cleanup sweep.
            if state.expires_at <= now {
                shard.remove_flow(key);
                continue;
            }
            if packet.protocol == TCP
                && !advance_tcp(&mut state, packet.tcp_flags.unwrap_or(0), initiator_direction)
            {
                return Some(denied());
            }
            let remove = packet.protocol == TCP && packet.tcp_flags.unwrap_or(0) & TCP_RST != 0;
            if remove {
                shard.remove_flow(key);
            } else {
                let timeout = if state.phase == Some(TcpPhase::Closing) {
                    self.flow_timeout
                } else {
                    timeout(packet.protocol, self.flow_timeout, self.tcp_timeout)
                };
                state.expires_at = now.saturating_add(timeout);
                shard.store_flow(key.clone(), state);
            }
            return Some(Decision {
                action: Action::Allow,
                rule_id: None,
                stateful: true,
            });
        }
        None
    }

    fn insert_flow(&self, flow: &FlowKey, packet: &ParsedPacket, now: u64) {
        let index = self.shard_index(flow);
        let mut shard = self.shards[index].lock().expect("firewall shard poisoned");
        expire(&mut shard, now, self.expiry_budget);
        evict_flow_if_full(&mut shard, self.per_shard_limit);
        shard.store_flow(
            flow.clone(),
            FlowState {
                expires_at: now.saturating_add(timeout(packet.protocol, self.flow_timeout, self.tcp_timeout)),
                phase: (packet.protocol == TCP).then_some(TcpPhase::SynSent),
            },
        );
    }

    fn insert_fragment(
        &self,
        packet: &ParsedPacket,
        fragment: Fragment,
        action: Action,
        rule_id: Option<RuleId>,
        now: u64,
    ) {
        let key = fragment_key(packet, fragment);
        let index = self.shard_index(&key);
        let mut shard = self.shards[index].lock().expect("firewall shard poisoned");
        shard.remove_fragment(&key);
        if shard.fragments.len() >= self.per_shard_limit
            && let Some((_, expiring)) = shard.fragment_expirations.first().cloned()
        {
            shard.remove_fragment(&expiring);
        }
        let expires_at = now.saturating_add(self.fragment_timeout);
        shard.fragment_expirations.insert((expires_at, key.clone()));
        shard.fragments.insert(
            key,
            FragmentState {
                expires_at,
                action,
                rule_id,
            },
        );
    }

    fn evaluate_later_fragment(
        &self,
        packet: &ParsedPacket,
        fragment: Fragment,
        now: u64,
    ) -> Decision {
        let key = fragment_key(packet, fragment);
        let index = self.shard_index(&key);
        let mut shard = self.shards[index].lock().expect("firewall shard poisoned");
        let Some(state) = shard.fragments.get(&key).copied() else {
            return denied();
        };
        if state.expires_at <= now {
            shard.remove_fragment(&key);
            return denied();
        }
        Decision {
            action: state.action,
            rule_id: state.rule_id,
            stateful: true,
        }
    }

    fn has_state(&self, key: &FlowKey, now: u64) -> bool {
        let index = self.shard_index(key);
        let shard = self.shards[index].lock().expect("firewall shard poisoned");
        shard
            .flows
            .get(key)
            .is_some_and(|state| state.expires_at > now)
    }

    fn shard_index<T: Hash>(&self, value: &T) -> usize {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        value.hash(&mut hasher);
        usize::try_from(hasher.finish()).unwrap_or(0) % self.shards.len()
    }
}

fn evict_flow_if_full(shard: &mut Shard, limit: usize) {
    if shard.flows.len() < limit {
        return;
    }
    if let Some((_, oldest)) = shard.flow_expirations.first().cloned()
    {
        shard.remove_flow(&oldest);
    }
}

fn valid_initiation(packet: &ParsedPacket) -> bool {
    match packet.protocol {
        TCP => packet
            .tcp_flags
            .is_some_and(|flags| flags & TCP_SYN != 0 && flags & TCP_ACK == 0),
        ICMP_V4 => packet.icmp.is_some_and(|(kind, _)| kind == 8),
        ICMP_V6 => packet.icmp.is_some_and(|(kind, _)| kind == 128),
        _ => true,
    }
}

fn advance_tcp(state: &mut FlowState, flags: u8, initiator: bool) -> bool {
    if flags & TCP_RST != 0 {
        state.phase = Some(TcpPhase::Closing);
        return true;
    }
    state.phase = match (
        state.phase,
        initiator,
        flags & (TCP_SYN | TCP_ACK | TCP_FIN),
    ) {
        // Lost SYN/SYN-ACK packets must be retransmittable without resetting
        // the authorization state or advancing the handshake in the wrong direction.
        (Some(TcpPhase::SynSent | TcpPhase::SynReceived), true, TCP_SYN) => state.phase,
        (Some(TcpPhase::SynReceived), false, value) if value == TCP_SYN | TCP_ACK => state.phase,
        (Some(TcpPhase::SynSent), false, value)
            if value & (TCP_SYN | TCP_ACK) == TCP_SYN | TCP_ACK =>
        {
            Some(TcpPhase::SynReceived)
        }
        (Some(TcpPhase::SynReceived), true, value) if value & TCP_ACK != 0 => {
            Some(TcpPhase::Established)
        }
        (Some(TcpPhase::Established), _, value) if value & TCP_FIN != 0 => Some(TcpPhase::Closing),
        (Some(TcpPhase::Established | TcpPhase::Closing), _, _) => state.phase,
        _ => return false,
    };
    true
}

fn timeout(protocol: u8, flow: u64, tcp: u64) -> u64 {
    if protocol == TCP { tcp } else { flow }
}

fn fragment_key(packet: &ParsedPacket, fragment: Fragment) -> FragmentKey {
    FragmentKey {
        source: packet.source,
        destination: packet.destination,
        protocol: if packet.source.is_ipv6() {
            0
        } else {
            packet.protocol
        },
        identification: fragment.identification,
    }
}

fn expire(shard: &mut Shard, now: u64, budget: usize) {
    for _ in 0..budget {
        let Some((expires_at, key)) = shard.flow_expirations.first().cloned() else { break };
        if expires_at > now { break; }
        shard.remove_flow(&key);
    }
    for _ in 0..budget {
        let Some((expires_at, key)) = shard.fragment_expirations.first().cloned() else { break };
        if expires_at > now { break; }
        shard.remove_fragment(&key);
    }
}

const fn denied() -> Decision {
    Decision {
        action: Action::Deny,
        rule_id: None,
        stateful: false,
    }
}
