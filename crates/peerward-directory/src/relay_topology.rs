/// Relay graph selection mode covered by `RelayTopologyV1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayTopologyMode {
    /// Compatibility graph used below the sparse threshold or during rolling upgrades.
    FullMesh,
    /// Bounded regional graph enabled only when every live Relay advertises support.
    Sparse,
}

/// One live Relay participating in a signed topology revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayTopologyNodeV1 {
    /// Relay identity.
    pub relay_id: RelayId,
    /// Lowercase scheduling region.
    pub region: String,
    /// Relative routing preference in `1..=1000`.
    pub routing_weight: u16,
    /// Named Wire capabilities reported by the current fenced runtime.
    pub capabilities: u64,
}

/// An undirected, canonically ordered Relay backbone edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RelayTopologyEdgeV1 {
    /// Lexicographically smaller Relay ID.
    pub left: RelayId,
    /// Lexicographically larger Relay ID.
    pub right: RelayId,
    /// Control-aggregated link RTT EWMA. Unknown links use the conservative maximum.
    #[serde(default = "default_backbone_rtt_millis")]
    pub rtt_millis: u32,
    /// Control-aggregated loss in ten-thousandths. Unknown links are treated as fully lossy.
    #[serde(default = "default_backbone_loss_permyriad")]
    pub loss_permyriad: u16,
}

impl RelayTopologyEdgeV1 {
    fn new(first: RelayId, second: RelayId) -> Option<Self> {
        (first != second).then(|| {
            let (left, right) = if first < second {
                (first, second)
            } else {
                (second, first)
            };
            Self {
                left,
                right,
                rtt_millis: default_backbone_rtt_millis(),
                loss_permyriad: default_backbone_loss_permyriad(),
            }
        })
    }

    /// Returns the opposite endpoint when `relay` is incident to this edge.
    pub fn other(self, relay: RelayId) -> Option<RelayId> {
        if relay == self.left {
            Some(self.right)
        } else if relay == self.right {
            Some(self.left)
        } else {
            None
        }
    }

    fn routing_cost(self) -> u64 {
        u64::from(self.rtt_millis)
            .saturating_add(u64::from(self.loss_permyriad).saturating_mul(10))
    }
}

const fn default_backbone_rtt_millis() -> u32 {
    120_000
}

const fn default_backbone_loss_permyriad() -> u16 {
    10_000
}

/// Independently signed Relay graph. This deliberately does not extend `RelayEntry`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayTopologyV1 {
    /// Owning mesh.
    pub mesh_id: MeshId,
    /// Monotonic topology-only revision.
    pub revision: u64,
    /// Compatibility or sparse construction mode.
    pub mode: RelayTopologyMode,
    /// Nodes sorted by raw Relay UUID.
    pub nodes: Vec<RelayTopologyNodeV1>,
    /// Undirected edges sorted by `(left, right)`.
    pub edges: Vec<RelayTopologyEdgeV1>,
}

impl RelayTopologyV1 {
    /// Builds the deterministic regional graph, falling back to Full Mesh when required.
    pub fn build(
        mesh_id: MeshId,
        revision: u64,
        mut nodes: Vec<RelayTopologyNodeV1>,
        sparse_threshold: usize,
        sparse_capability: u64,
    ) -> Result<Self, DirectoryError> {
        nodes.sort_by_key(|node| node.relay_id);
        ensure_unique(nodes.iter().map(|node| node.relay_id))?;
        let sparse = nodes.len() >= sparse_threshold
            && nodes
                .iter()
                .all(|node| node.capabilities & sparse_capability != 0);
        let mut edges = BTreeSet::new();
        if sparse {
            let mut regions = BTreeMap::<&str, Vec<&RelayTopologyNodeV1>>::new();
            for node in &nodes {
                regions.entry(&node.region).or_default().push(node);
            }
            let mut gateways = Vec::with_capacity(regions.len());
            for (region, members) in &regions {
                add_forward_ring(&mut edges, members, 1);
                add_forward_ring(&mut edges, members, 2);
                let mut selected = members.clone();
                selected.sort_by_key(|node| {
                    (std::cmp::Reverse(node.routing_weight), node.relay_id)
                });
                selected.truncate(2);
                // The two required forward rings alone have a diameter above four for a
                // 32-Relay region. Two deterministic gateway spokes retain O(N) edges while
                // making every intra-region path fit the signed hop bound.
                for member in members {
                    for gateway in &selected {
                        if let Some(edge) =
                            RelayTopologyEdgeV1::new(member.relay_id, gateway.relay_id)
                        {
                            edges.insert(edge);
                        }
                    }
                }
                gateways.push((*region, selected));
            }
            if gateways.len() > 1 {
                for index in 0..gateways.len() {
                    let next = (index + 1) % gateways.len();
                    for lane in 0..2 {
                        let left = gateways[index].1.get(lane).or_else(|| gateways[index].1.first());
                        let right = gateways[next].1.get(lane).or_else(|| gateways[next].1.first());
                        if let (Some(left), Some(right)) = (left, right)
                            && let Some(edge) = RelayTopologyEdgeV1::new(left.relay_id, right.relay_id) {
                                edges.insert(edge);
                            }
                    }
                }
                let mut global_gateways = gateways
                    .iter()
                    .flat_map(|(_, members)| members.iter().copied())
                    .collect::<Vec<_>>();
                global_gateways.sort_by_key(|node| {
                    (std::cmp::Reverse(node.routing_weight), node.relay_id)
                });
                global_gateways.truncate(2);
                // Adjacent-region rings remain the normal topology. These deterministic
                // redundant shortcuts cap the worst-case inter-region diameter at four.
                for (_, regional_gateways) in &gateways {
                    for regional in regional_gateways {
                        for global in &global_gateways {
                            if let Some(edge) =
                                RelayTopologyEdgeV1::new(regional.relay_id, global.relay_id)
                            {
                                edges.insert(edge);
                            }
                        }
                    }
                }
            }
        } else {
            for (index, left) in nodes.iter().enumerate() {
                for right in &nodes[index + 1..] {
                    if let Some(edge) = RelayTopologyEdgeV1::new(left.relay_id, right.relay_id) {
                        edges.insert(edge);
                    }
                }
            }
        }
        let topology = Self {
            mesh_id,
            revision,
            mode: if sparse {
                RelayTopologyMode::Sparse
            } else {
                RelayTopologyMode::FullMesh
            },
            nodes,
            edges: edges.into_iter().collect(),
        };
        topology.validate()?;
        Ok(topology)
    }

    /// Returns deterministic primary and backup next hops whose paths fit the four-hop bound.
    pub fn next_hops(&self, source: RelayId, destination: RelayId) -> Vec<RelayId> {
        let Some((_, primary)) = shortest_next_hop(self, source, destination, None) else {
            return Vec::new();
        };
        let mut hops = vec![primary];
        if let Some((_, backup)) = shortest_next_hop(self, source, destination, Some(primary)) {
            hops.push(backup);
        }
        hops
    }

    /// Applies one bounded, Control-aggregated health sample per undirected edge.
    pub fn apply_link_health(
        &mut self,
        health: &BTreeMap<(RelayId, RelayId), (u32, u16)>,
    ) -> Result<(), DirectoryError> {
        if health.values().any(|(rtt_millis, loss_permyriad)| {
            *rtt_millis > default_backbone_rtt_millis()
                || *loss_permyriad > default_backbone_loss_permyriad()
        }) {
            return Err(DirectoryError::NonCanonical);
        }
        for edge in &mut self.edges {
            if let Some((rtt_millis, loss_permyriad)) = health.get(&(edge.left, edge.right)) {
                edge.rtt_millis = *rtt_millis;
                edge.loss_permyriad = *loss_permyriad;
            }
        }
        self.validate()
    }

    fn validate(&self) -> Result<(), DirectoryError> {
        if self.nodes.len() > 4_096 || self.edges.len() > 65_536 {
            return Err(DirectoryError::NonCanonical);
        }
        ensure_sorted_unique(self.nodes.iter().map(|node| node.relay_id))?;
        let node_ids = self
            .nodes
            .iter()
            .map(|node| node.relay_id)
            .collect::<BTreeSet<_>>();
        if self.nodes.iter().any(|node| {
            node.region.is_empty()
                || node.region.len() > 32
                || !(1..=1000).contains(&node.routing_weight)
                || !node.region.as_bytes().iter().all(|byte| {
                    byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-'
                })
        }) {
            return Err(DirectoryError::NonCanonical);
        }
        ensure_sorted_unique(self.edges.iter().copied())?;
        ensure_unique(self.edges.iter().map(|edge| (edge.left, edge.right)))?;
        if self.edges.iter().any(|edge| {
            edge.left >= edge.right
                || !node_ids.contains(&edge.left)
                || !node_ids.contains(&edge.right)
                || edge.rtt_millis > default_backbone_rtt_millis()
                || edge.loss_permyriad > default_backbone_loss_permyriad()
        }) {
            return Err(DirectoryError::NonCanonical);
        }
        Ok(())
    }
}

/// Signed representation of `RelayTopologyV1`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedRelayTopologyV1 {
    /// Covered topology.
    pub topology: RelayTopologyV1,
    /// Ed25519 signature over its dedicated v1 transcript.
    #[serde(with = "signature_bytes")]
    pub signature: [u8; 64],
}

fn add_forward_ring(
    edges: &mut BTreeSet<RelayTopologyEdgeV1>,
    nodes: &[&RelayTopologyNodeV1],
    distance: usize,
) {
    if nodes.len() < 2 {
        return;
    }
    for (index, node) in nodes.iter().enumerate() {
        let other = nodes[(index + distance) % nodes.len()];
        if let Some(edge) = RelayTopologyEdgeV1::new(node.relay_id, other.relay_id) {
            edges.insert(edge);
        }
    }
}

fn shortest_next_hop(
    topology: &RelayTopologyV1,
    source: RelayId,
    destination: RelayId,
    excluded_first_hop: Option<RelayId>,
) -> Option<(u64, RelayId)> {
    if source == destination {
        return None;
    }
    let mut adjacency = BTreeMap::<RelayId, Vec<(RelayId, u64)>>::new();
    for edge in &topology.edges {
        let cost = edge.routing_cost();
        adjacency.entry(edge.left).or_default().push((edge.right, cost));
        adjacency.entry(edge.right).or_default().push((edge.left, cost));
    }
    let mut best = BTreeMap::<(RelayId, u8), u64>::new();
    let mut pending = BinaryHeap::new();
    for &(neighbor, cost) in adjacency.get(&source)? {
        if excluded_first_hop == Some(neighbor) {
            continue;
        }
        best.insert((neighbor, 1), cost);
        pending.push(Reverse((cost, 1_u8, neighbor, neighbor)));
    }
    while let Some(Reverse((cost, hops, node, first_hop))) = pending.pop() {
        if cost > best.get(&(node, hops)).copied().unwrap_or(u64::MAX) {
            continue;
        }
        if node == destination {
            return Some((cost, first_hop));
        }
        if hops == 4 {
            continue;
        }
        for &(neighbor, edge_cost) in adjacency.get(&node).into_iter().flatten() {
            if neighbor == source {
                continue;
            }
            let next_hops = hops + 1;
            let next_cost = cost.saturating_add(edge_cost);
            let key = (neighbor, next_hops);
            if best.get(&key).is_some_and(|known| *known <= next_cost) {
                continue;
            }
            best.insert(key, next_cost);
            pending.push(Reverse((next_cost, next_hops, neighbor, first_hop)));
        }
    }
    None
}
