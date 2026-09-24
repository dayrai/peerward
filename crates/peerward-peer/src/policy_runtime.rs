/// Packet-policy interface shared by static bootstrap and signed live policy state.
pub trait PacketPolicy: Send + Sync {
    /// Stateful packet decision used by the TUN data path.
    fn evaluate_packet(&self, packet: &peerward_dataplane::ParsedPacket, now: u64) -> Action;
    /// Stateless initiation decision used to hide DNS and service metadata.
    fn visible_packet(&self, packet: &peerward_dataplane::ParsedPacket) -> Action;
}

impl PacketPolicy for Firewall {
    fn evaluate_packet(&self, packet: &peerward_dataplane::ParsedPacket, now: u64) -> Action {
        self.evaluate(packet, now).action
    }

    fn visible_packet(&self, packet: &peerward_dataplane::ParsedPacket) -> Action {
        self.policy_decision(packet).action
    }
}

/// Linux adapter around the platform-neutral signed ACL engine shared with Android.
pub struct LivePeerPolicy {
    pub(crate) mesh_id: MeshId,
    pub(crate) termination_path: Option<std::path::PathBuf>,
    engine: Arc<peerward_peer_core::PolicyEngine>,
}

impl LivePeerPolicy {
    /// Creates a deny-until-verified policy state.
    pub fn new(
        mesh_id: MeshId,
        local_peer: PeerId,
        verifier: DirectoryPublicKey,
        state_limit: usize,
        shards: usize,
    ) -> Self {
        Self {
            mesh_id,
            termination_path: None,
            engine: Arc::new(peerward_peer_core::PolicyEngine::new(
                mesh_id,
                local_peer,
                verifier,
                state_limit,
                shards,
            )
            .expect("validated non-zero Peer policy bounds")),
        }
    }

    /// Atomically replaces a directory already authenticated by the chunk assembler.
    pub fn install_directory(&self, peers: Vec<PeerDescriptor>) -> Result<(), PacketPumpError> {
        self.engine
            .install_verified_peers(peers)
            .map_err(|error| {
                tracing::error!(?error, "Peer policy directory installation failed");
                PacketPumpError::InvalidControl
            })
    }

    /// Authenticates and installs a monotonically newer signed policy.
    pub fn install_policy(&self, signed: SignedPolicyBundle) -> Result<u64, PacketPumpError> {
        self.engine
            .install_policy(&signed)
            .map_err(|error| {
                tracing::error!(revision = signed.bundle.revision, ?error, "Peer signed policy installation failed");
                PacketPumpError::InvalidControl
            })
    }
}

impl PacketPolicy for LivePeerPolicy {
    fn evaluate_packet(&self, packet: &peerward_dataplane::ParsedPacket, now: u64) -> Action {
        self.engine.evaluate(packet, now)
    }

    fn visible_packet(&self, packet: &peerward_dataplane::ParsedPacket) -> Action {
        self.engine.visible(packet)
    }
}
