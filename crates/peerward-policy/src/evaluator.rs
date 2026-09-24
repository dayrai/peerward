/// Directional flow identity used for return traffic and related errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FlowKey {
    /// Source address.
    pub source: IpAddr,
    /// Destination address.
    pub destination: IpAddr,
    /// Layer-4 protocol.
    pub protocol: IpProtocol,
    /// TCP/UDP source port, or ICMP echo identifier.
    pub source_port: Option<u16>,
    /// TCP/UDP destination port, or ICMP echo identifier.
    pub destination_port: Option<u16>,
}

impl FlowKey {
    /// Reverses the directional tuple.
    #[must_use]
    pub const fn reverse(mut self) -> Self {
        let previous_source = self.source;
        self.source = self.destination;
        self.destination = previous_source;

        let previous_source_port = self.source_port;
        self.source_port = self.destination_port;
        self.destination_port = previous_source_port;
        self
    }
}

/// Packet metadata required for an enforcement decision.
#[derive(Debug)]
pub struct Packet<'a> {
    /// Mesh carried by the authenticated session.
    pub mesh_id: MeshId,
    /// Authenticated source attributes.
    pub source: &'a PeerDescriptor,
    /// Resolved destination attributes.
    pub destination: &'a PeerDescriptor,
    /// Directional tuple.
    pub flow: FlowKey,
    /// Whether this packet may initiate state.
    pub initiating: bool,
    /// Original initiating flow for an ICMP error.
    pub related_flow: Option<FlowKey>,
    /// First-fragment flow tuple for a later IP fragment.
    pub fragment_of: Option<FlowKey>,
}

/// Observable enforcement result without packet contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decision {
    /// Effective action.
    pub action: Action,
    /// Matching rule, or none for default/state decisions.
    pub rule_id: Option<RuleId>,
    /// Whether a rate-limited denial audit should be emitted.
    pub emit_denial_audit: bool,
    /// Policy revision that produced the result.
    pub revision: u64,
}

#[derive(Debug, Clone, Copy)]
struct StateEntry {
    expires_at: u64,
    touched_at: u64,
}

/// Stateful evaluator with fixed memory and bounded expiry work.
pub struct Evaluator {
    mesh_id: MeshId,
    policy: Policy,
    states: HashMap<FlowKey, StateEntry>,
    state_expirations: BTreeSet<(u64, FlowKey)>,
    state_recency: BTreeSet<(u64, FlowKey)>,
    denial_audits: HashMap<FlowKey, u64>,
    denial_expirations: BTreeSet<(u64, FlowKey)>,
    max_states: usize,
    expiry_budget: usize,
    denial_interval: u64,
}

impl Evaluator {
    /// Creates an evaluator for exactly one mesh. Flow state and audit throttle
    /// state are each limited to `max_states`. A full throttle table suppresses
    /// new audit identities until expiry; packet denial remains unconditional.
    /// A zero denial interval emits without retaining throttle state.
    pub fn new(
        mesh_id: MeshId,
        policy: Policy,
        max_states: usize,
        expiry_budget: usize,
        denial_interval: u64,
    ) -> Self {
        Self {
            mesh_id,
            policy,
            states: HashMap::new(),
            state_expirations: BTreeSet::new(),
            state_recency: BTreeSet::new(),
            denial_audits: HashMap::new(),
            denial_expirations: BTreeSet::new(),
            max_states,
            expiry_budget,
            denial_interval,
        }
    }

    /// Atomically replaces policy state and invalidates all flow state.
    pub fn replace_policy(&mut self, policy: Policy) -> Result<(), PolicyError> {
        if policy.revision <= self.policy.revision {
            return Err(PolicyError::RevisionRollback);
        }
        self.policy = policy;
        self.states.clear();
        self.state_expirations.clear();
        self.state_recency.clear();
        self.denial_audits.clear();
        self.denial_expirations.clear();
        Ok(())
    }

    /// Evaluates one packet at monotonic time `now`.
    pub fn evaluate(&mut self, packet: &Packet<'_>, now: u64) -> Decision {
        self.expire_some(now);
        if packet.mesh_id != self.mesh_id {
            return self.denial(packet.flow, None, now);
        }

        let has_state = if let Some(first_fragment) = packet.fragment_of {
            self.state_valid(&first_fragment, now, false)
                || self.state_valid(&first_fragment.reverse(), now, false)
        } else {
            self.state_valid(&packet.flow, now, packet.related_flow.is_none())
                || self.state_valid(&packet.flow.reverse(), now, packet.related_flow.is_none())
                || packet
                    .related_flow
                    .is_some_and(|flow| self.state_valid(&flow, now, false))
        };
        if has_state {
            return Decision {
                action: Action::Allow,
                rule_id: None,
                emit_denial_audit: false,
                revision: self.policy.revision,
            };
        }

        if packet.fragment_of.is_some() || packet.related_flow.is_some() || !packet.initiating {
            return self.denial(packet.flow, None, now);
        }

        let decision = self.policy.decide(packet);
        if decision.action == Action::Allow {
            self.insert_state(packet.flow, now);
            Decision {
                action: decision.action,
                rule_id: decision.rule_id,
                emit_denial_audit: false,
                revision: self.policy.revision,
            }
        } else {
            self.denial(packet.flow, decision.rule_id, now)
        }
    }

    /// Number of live or not-yet-scanned state entries.
    pub fn state_len(&self) -> usize {
        self.states.len()
    }

    fn state_valid(&mut self, key: &FlowKey, now: u64, refresh: bool) -> bool {
        let Some(entry) = self.states.get_mut(key) else {
            return false;
        };
        if entry.expires_at <= now {
            self.remove_state(key);
            return false;
        }
        if refresh && now > entry.touched_at {
            self.state_expirations.remove(&(entry.expires_at, *key));
            self.state_recency.remove(&(entry.touched_at, *key));
            entry.touched_at = now;
            entry.expires_at = entry.touched_at.saturating_add(flow_lifetime(key.protocol));
            self.state_expirations.insert((entry.expires_at, *key));
            self.state_recency.insert((entry.touched_at, *key));
        }
        true
    }

    fn insert_state(&mut self, flow: FlowKey, now: u64) {
        if self.max_states == 0 {
            return;
        }
        if self.states.len() >= self.max_states
            && let Some(&(_, oldest)) = self.state_recency.first()
            {
                self.remove_state(&oldest);
            }
        let lifetime = flow_lifetime(flow.protocol);
        self.states.insert(
            flow,
            StateEntry {
                expires_at: now.saturating_add(lifetime),
                touched_at: now,
            },
        );
        self.state_expirations.insert((now.saturating_add(lifetime), flow));
        self.state_recency.insert((now, flow));
    }

    fn expire_some(&mut self, now: u64) {
        // Inspect only the earliest expiry and at most the reclamation budget.
        // Filtering a HashMap and then taking N bounds removals, not scan work.
        for _ in 0..self.expiry_budget {
            let Some(&(expires_at, key)) = self.state_expirations.first() else { break };
            if expires_at > now {
                break;
            }
            self.remove_state(&key);
        }
    }

    fn remove_state(&mut self, key: &FlowKey) {
        if let Some(entry) = self.states.remove(key) {
            self.state_expirations.remove(&(entry.expires_at, *key));
            self.state_recency.remove(&(entry.touched_at, *key));
        }
    }

    fn denial(&mut self, flow: FlowKey, rule_id: Option<RuleId>, now: u64) -> Decision {
        let emit = self.admit_denial_audit(flow, now);
        Decision {
            action: Action::Deny,
            rule_id,
            emit_denial_audit: emit,
            revision: self.policy.revision,
        }
    }

    fn admit_denial_audit(&mut self, flow: FlowKey, now: u64) -> bool {
        if self.denial_interval == 0 {
            return true;
        }
        // Reclaim by timestamp without scanning every denied flow per packet.
        // Even an evaluator with disabled flow reclamation must recover audit capacity.
        for _ in 0..self.expiry_budget.max(1) {
            let Some(&(last, key)) = self.denial_expirations.first() else { break };
            if now.saturating_sub(last) < self.denial_interval {
                break;
            }
            self.denial_expirations.pop_first();
            self.denial_audits.remove(&key);
        }
        if let Some(&last) = self.denial_audits.get(&flow) {
            if now.saturating_sub(last) < self.denial_interval {
                return false;
            }
            self.denial_expirations.remove(&(last, flow));
        } else if self.denial_audits.len() >= self.max_states {
            // Do not evict live throttle entries: rotating flow tuples must not
            // bypass the audit rate limit for a previously denied connection.
            return false;
        }
        self.denial_audits.insert(flow, now);
        self.denial_expirations.insert((now, flow));
        true
    }
}

// These are idle lifetimes, not maximum durations for an authorized connection.
fn flow_lifetime(protocol: IpProtocol) -> u64 {
    if protocol == IpProtocol::TCP {
        300
    } else if protocol == IpProtocol::UDP {
        60
    } else {
        30
    }
}
