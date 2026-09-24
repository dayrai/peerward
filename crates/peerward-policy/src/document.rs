const POLICY_DOCUMENT_DOMAIN: &[u8] = b"peerward/policy-document/v2\0";

/// Policy construction or revision failure.
#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum PolicyError {
    /// A rule contains an inverted or zero port range.
    #[error("invalid destination port range")]
    InvalidPortRange,
    /// Policy revisions may only increase.
    #[error("policy revision rollback")]
    RevisionRollback,
    /// Canonical binary policy bytes were malformed or ambiguous.
    #[error("invalid canonical policy encoding")]
    InvalidEncoding,
}

/// Allow or deny action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Permit initiation and create return state where appropriate.
    Allow,
    /// Refuse the packet.
    Deny,
}

/// Peer attributes used by selectors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerDescriptor {
    /// Stable peer identifier.
    pub id: PeerId,
    /// Peer IPv4 or IPv6 address.
    pub address: IpAddr,
    /// Exact label key/value pairs.
    pub labels: BTreeMap<String, String>,
}

/// Conjunctive source or destination selector.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Selector {
    /// Exact Peer alternatives; empty removes this dimension.
    pub peer_ids: BTreeSet<PeerId>,
    /// Every label pair must match.
    pub labels: BTreeMap<String, String>,
    /// Network alternatives; empty removes this dimension.
    pub cidrs: Vec<IpNet>,
}

impl Selector {
    /// Matches every Peer.
    pub const fn any() -> Self {
        Self {
            peer_ids: BTreeSet::new(),
            labels: BTreeMap::new(),
            cidrs: Vec::new(),
        }
    }

    /// Matches one exact Peer.
    pub fn peer(peer: PeerId) -> Self {
        Self {
            peer_ids: BTreeSet::from([peer]),
            ..Self::default()
        }
    }

    /// Matches every supplied label pair.
    pub fn labels(labels: BTreeMap<String, String>) -> Self {
        Self {
            labels,
            ..Self::default()
        }
    }

    /// Matches one network.
    pub fn cidr(network: IpNet) -> Self {
        Self {
            cidrs: vec![network],
            ..Self::default()
        }
    }

    /// Builds a selector and canonicalizes CIDR alternatives.
    pub fn new(
        peer_ids: impl IntoIterator<Item = PeerId>,
        labels: BTreeMap<String, String>,
        mut cidrs: Vec<IpNet>,
    ) -> Self {
        cidrs.sort_unstable();
        cidrs.dedup();
        Self {
            peer_ids: peer_ids.into_iter().collect(),
            labels,
            cidrs,
        }
    }

    fn matches(&self, peer: &PeerDescriptor) -> bool {
        (self.peer_ids.is_empty() || self.peer_ids.contains(&peer.id))
            && self
                .labels
                .iter()
                .all(|(key, value)| peer.labels.get(key) == Some(value))
            && (self.cidrs.is_empty()
                || self
                    .cidrs
                    .iter()
                    .any(|network| network.contains(&peer.address)))
    }
}

/// Inclusive destination port interval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortRange(RangeInclusive<u16>);

impl PortRange {
    /// Validates a non-zero inclusive interval.
    pub fn new(first: u16, last: u16) -> Result<Self, PolicyError> {
        if first == 0 || first > last {
            return Err(PolicyError::InvalidPortRange);
        }
        Ok(Self(first..=last))
    }

    fn contains(&self, port: u16) -> bool {
        self.0.contains(&port)
    }

    /// Returns the first included port.
    pub const fn first(&self) -> u16 {
        *self.0.start()
    }

    /// Returns the last included port.
    pub const fn last(&self) -> u16 {
        *self.0.end()
    }
}

/// One ordered initiation rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    /// Stable rule identity.
    pub id: RuleId,
    /// Lower priorities evaluate first.
    pub priority: u32,
    /// Whether the rule participates in evaluation.
    pub enabled: bool,
    /// Whether a matched decision requests bounded structured logging.
    pub log: bool,
    /// Result when every predicate matches.
    pub action: Action,
    /// Initiator selector.
    pub source: Selector,
    /// Destination selector.
    pub destination: Selector,
    /// Required IP protocol.
    pub protocol: PolicyProtocol,
    /// TCP/UDP destination ports; empty matches every port.
    pub destination_ports: Vec<PortRange>,
}

/// Detailed result of ordered rule evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyDecision {
    /// Effective action.
    pub action: Action,
    /// Matching enabled rule, if any.
    pub rule_id: Option<RuleId>,
    /// Whether the matching rule requests a bounded log.
    pub log: bool,
}

/// One immutable policy revision.
#[derive(Debug, Clone)]
pub struct Policy {
    /// Monotonic revision.
    pub revision: u64,
    /// Action when no rule matches.
    pub default: Action,
    rules: Vec<Rule>,
}

impl Policy {
    /// Creates a policy and applies its deterministic ordering.
    pub fn new(revision: u64, default: Action, mut rules: Vec<Rule>) -> Self {
        for rule in &mut rules {
            rule.source.cidrs.sort_unstable();
            rule.source.cidrs.dedup();
            rule.destination.cidrs.sort_unstable();
            rule.destination.cidrs.dedup();
            rule.destination_ports
                .sort_by_key(|ports| (ports.first(), ports.last()));
            rule.destination_ports.dedup();
        }
        rules.sort_by_key(|rule| (rule.priority, action_order(rule.action), rule.id));
        Self {
            revision,
            default,
            rules,
        }
    }

    fn decide(&self, packet: &Packet<'_>) -> PolicyDecision {
        self.decide_initiation(
            packet.source,
            packet.destination,
            packet.flow.protocol,
            packet.flow.destination_port,
        )
    }

    /// Evaluates ordered identity selectors for one new initiation.
    pub fn decide_initiation(
        &self,
        source: &PeerDescriptor,
        destination: &PeerDescriptor,
        protocol: IpProtocol,
        destination_port: Option<u16>,
    ) -> PolicyDecision {
        for rule in &self.rules {
            if !rule.enabled
                || !rule.protocol.matches(protocol)
                || !rule.source.matches(source)
                || !rule.destination.matches(destination)
            {
                continue;
            }
            let port_match = match rule.protocol {
                PolicyProtocol::Tcp | PolicyProtocol::Udp => {
                    rule.destination_ports.is_empty()
                        || destination_port.is_some_and(|port| {
                            rule.destination_ports
                                .iter()
                                .any(|range| range.contains(port))
                        })
                }
                PolicyProtocol::Any | PolicyProtocol::Icmp => true,
            };
            if port_match {
                return PolicyDecision {
                    action: rule.action,
                    rule_id: Some(rule.id),
                    log: rule.log,
                };
            }
        }
        PolicyDecision {
            action: self.default,
            rule_id: None,
            log: false,
        }
    }
}

/// Encodes a policy as one canonical, versioned binary document.
pub fn encode_policy_document(policy: &Policy) -> Result<Vec<u8>, PolicyError> {
    if policy.rules.len() > MAX_POLICY_RULES {
        return Err(PolicyError::InvalidEncoding);
    }
    let mut bytes = Vec::from(POLICY_DOCUMENT_DOMAIN);
    bytes.push(action_tag(policy.default));
    put_u32(&mut bytes, policy.rules.len())?;
    let mut ids = BTreeSet::new();
    for rule in &policy.rules {
        if !ids.insert(rule.id)
            || matches!(rule.protocol, PolicyProtocol::Any | PolicyProtocol::Icmp)
                && !rule.destination_ports.is_empty()
        {
            return Err(PolicyError::InvalidEncoding);
        }
        bytes.extend_from_slice(rule.id.as_bytes());
        bytes.extend_from_slice(&rule.priority.to_be_bytes());
        bytes.push(u8::from(rule.enabled));
        bytes.push(u8::from(rule.log));
        bytes.push(action_tag(rule.action));
        encode_selector(&mut bytes, &rule.source)?;
        encode_selector(&mut bytes, &rule.destination)?;
        if rule.destination_ports.len() > MAX_PORT_SPANS {
            return Err(PolicyError::InvalidEncoding);
        }
        bytes.push(protocol_tag(rule.protocol));
        put_u32(&mut bytes, rule.destination_ports.len())?;
        for ports in &rule.destination_ports {
            bytes.extend_from_slice(&ports.first().to_be_bytes());
            bytes.extend_from_slice(&ports.last().to_be_bytes());
        }
    }
    Ok(bytes)
}

/// Decodes a canonical policy document and binds it to its outer revision.
pub fn decode_policy_document(revision: u64, bytes: &[u8]) -> Result<Policy, PolicyError> {
    let body = bytes
        .strip_prefix(POLICY_DOCUMENT_DOMAIN)
        .ok_or(PolicyError::InvalidEncoding)?;
    let mut decoder = Decoder::new(body);
    let default = decode_action(decoder.byte()?)?;
    let count = decoder.count()?;
    if count > MAX_POLICY_RULES {
        return Err(PolicyError::InvalidEncoding);
    }
    let mut rules = Vec::with_capacity(count);
    for _ in 0..count {
        let id = RuleId::from_uuid(uuid::Uuid::from_bytes(decoder.array()?))
            .map_err(|_| PolicyError::InvalidEncoding)?;
        let priority = decoder.u32()?;
        let enabled = decoder.boolean()?;
        let log = decoder.boolean()?;
        let action = decode_action(decoder.byte()?)?;
        let source = decode_selector(&mut decoder)?;
        let destination = decode_selector(&mut decoder)?;
        let protocol = decode_protocol(decoder.byte()?)?;
        let range_count = decoder.count()?;
        if range_count > MAX_PORT_SPANS {
            return Err(PolicyError::InvalidEncoding);
        }
        let mut destination_ports = Vec::with_capacity(range_count);
        for _ in 0..range_count {
            destination_ports.push(PortRange::new(decoder.u16()?, decoder.u16()?)?);
        }
        rules.push(Rule {
            id,
            priority,
            enabled,
            log,
            action,
            source,
            destination,
            protocol,
            destination_ports,
        });
    }
    if !decoder.finished() {
        return Err(PolicyError::InvalidEncoding);
    }
    let policy = Policy::new(revision, default, rules);
    if encode_policy_document(&policy)? != bytes {
        return Err(PolicyError::InvalidEncoding);
    }
    Ok(policy)
}

fn encode_selector(bytes: &mut Vec<u8>, selector: &Selector) -> Result<(), PolicyError> {
    if selector.peer_ids.len() > MAX_SELECTOR_PEERS
        || selector.labels.len() > MAX_LABELS
        || selector.cidrs.len() > MAX_SELECTOR_CIDRS
        || selector
            .labels
            .iter()
            .any(|(key, value)| key.is_empty() || key.len() > 64 || value.is_empty() || value.len() > 256)
    {
        return Err(PolicyError::InvalidEncoding);
    }
    put_u32(bytes, selector.peer_ids.len())?;
    for peer in &selector.peer_ids {
        bytes.extend_from_slice(peer.as_bytes());
    }
    put_u32(bytes, selector.labels.len())?;
    for (key, value) in &selector.labels {
        if key.is_empty() {
            return Err(PolicyError::InvalidEncoding);
        }
        put_text(bytes, key)?;
        put_text(bytes, value)?;
    }
    put_u32(bytes, selector.cidrs.len())?;
    for network in &selector.cidrs {
        match network {
            IpNet::V4(network) => {
                bytes.push(4);
                bytes.extend_from_slice(&network.network().octets());
                bytes.push(network.prefix_len());
            }
            IpNet::V6(network) => {
                bytes.push(6);
                bytes.extend_from_slice(&network.network().octets());
                bytes.push(network.prefix_len());
            }
        }
    }
    Ok(())
}

fn decode_selector(decoder: &mut Decoder<'_>) -> Result<Selector, PolicyError> {
    let peer_count = decoder.count()?;
    if peer_count > MAX_SELECTOR_PEERS {
        return Err(PolicyError::InvalidEncoding);
    }
    let mut peer_ids = BTreeSet::new();
    for _ in 0..peer_count {
        let peer = PeerId::from_uuid(uuid::Uuid::from_bytes(decoder.array()?))
            .map_err(|_| PolicyError::InvalidEncoding)?;
        if !peer_ids.insert(peer) {
            return Err(PolicyError::InvalidEncoding);
        }
    }
    let label_count = decoder.count()?;
    if label_count > MAX_LABELS {
        return Err(PolicyError::InvalidEncoding);
    }
    let mut labels = BTreeMap::new();
    for _ in 0..label_count {
        let key = decoder.text()?;
        let value = decoder.text()?;
        if key.is_empty()
            || key.len() > 64
            || value.is_empty()
            || value.len() > 256
            || labels.insert(key, value).is_some()
        {
            return Err(PolicyError::InvalidEncoding);
        }
    }
    let cidr_count = decoder.count()?;
    if cidr_count > MAX_SELECTOR_CIDRS {
        return Err(PolicyError::InvalidEncoding);
    }
    let mut cidrs = Vec::with_capacity(cidr_count);
    for _ in 0..cidr_count {
        let network = match decoder.byte()? {
            4 => Ipv4Net::new(Ipv4Addr::from(decoder.array::<4>()?), decoder.byte()?)
                .map(IpNet::V4),
            6 => Ipv6Net::new(Ipv6Addr::from(decoder.array::<16>()?), decoder.byte()?)
                .map(IpNet::V6),
            _ => return Err(PolicyError::InvalidEncoding),
        }
        .map_err(|_| PolicyError::InvalidEncoding)?;
        cidrs.push(network);
    }
    Ok(Selector::new(peer_ids, labels, cidrs))
}

const fn action_order(action: Action) -> u8 {
    match action {
        Action::Deny => 0,
        Action::Allow => 1,
    }
}

const fn action_tag(action: Action) -> u8 {
    match action {
        Action::Allow => 1,
        Action::Deny => 2,
    }
}

fn decode_action(tag: u8) -> Result<Action, PolicyError> {
    match tag {
        1 => Ok(Action::Allow),
        2 => Ok(Action::Deny),
        _ => Err(PolicyError::InvalidEncoding),
    }
}

const fn protocol_tag(protocol: PolicyProtocol) -> u8 {
    match protocol {
        PolicyProtocol::Any => 0,
        PolicyProtocol::Tcp => 6,
        PolicyProtocol::Udp => 17,
        PolicyProtocol::Icmp => 1,
    }
}

fn decode_protocol(tag: u8) -> Result<PolicyProtocol, PolicyError> {
    match tag {
        0 => Ok(PolicyProtocol::Any),
        6 => Ok(PolicyProtocol::Tcp),
        17 => Ok(PolicyProtocol::Udp),
        1 => Ok(PolicyProtocol::Icmp),
        _ => Err(PolicyError::InvalidEncoding),
    }
}

fn put_u32(bytes: &mut Vec<u8>, value: usize) -> Result<(), PolicyError> {
    bytes.extend_from_slice(
        &u32::try_from(value)
            .map_err(|_| PolicyError::InvalidEncoding)?
            .to_be_bytes(),
    );
    Ok(())
}

fn put_text(bytes: &mut Vec<u8>, value: &str) -> Result<(), PolicyError> {
    put_u32(bytes, value.len())?;
    bytes.extend_from_slice(value.as_bytes());
    Ok(())
}

struct Decoder<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> Decoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], PolicyError> {
        self.take(N)?
            .try_into()
            .map_err(|_| PolicyError::InvalidEncoding)
    }

    fn byte(&mut self) -> Result<u8, PolicyError> {
        Ok(self.array::<1>()?[0])
    }

    fn boolean(&mut self) -> Result<bool, PolicyError> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(PolicyError::InvalidEncoding),
        }
    }

    fn u16(&mut self) -> Result<u16, PolicyError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, PolicyError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn count(&mut self) -> Result<usize, PolicyError> {
        let count = usize::try_from(self.u32()?).map_err(|_| PolicyError::InvalidEncoding)?;
        (count <= self.bytes.len().saturating_sub(self.cursor))
            .then_some(count)
            .ok_or(PolicyError::InvalidEncoding)
    }

    fn text(&mut self) -> Result<String, PolicyError> {
        let length = self.count()?;
        let value =
            std::str::from_utf8(self.take(length)?).map_err(|_| PolicyError::InvalidEncoding)?;
        Ok(value.to_owned())
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], PolicyError> {
        let end = self
            .cursor
            .checked_add(length)
            .filter(|end| *end <= self.bytes.len())
            .ok_or(PolicyError::InvalidEncoding)?;
        let value = &self.bytes[self.cursor..end];
        self.cursor = end;
        Ok(value)
    }

    const fn finished(&self) -> bool {
        self.cursor == self.bytes.len()
    }
}
