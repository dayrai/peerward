#[derive(Default)]
struct RelayDistributions {
    configuration: Option<peerward_management::ConfigurationDelivery>,
    authorities: Option<SignedAuthorityBundle>,
    peers: Option<SignedPeerDirectory>,
    relays: Option<SignedRelayDirectory>,
    topology: Option<SignedRelayTopologyV1>,
    previous_topology: Option<(tokio::time::Instant, SignedRelayTopologyV1)>,
    publication_context: Option<peerward_types::CorrelationContext>,
    policy: Option<SignedPolicyBundle>,
    services: Option<SignedRemoteServiceSnapshot>,
    revocations: Option<SignedRevocationBundle>,
}

impl RelayDistributions {
    fn complete(&self) -> bool {
        self.configuration.is_some()
            && self.authorities.is_some()
            && self.peers.is_some()
            && self.relays.is_some()
            && self.policy.is_some()
            && self.services.is_some()
            && self.revocations.is_some()
    }
}
