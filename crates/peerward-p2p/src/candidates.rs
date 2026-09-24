use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// Source of one direct UDP candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateKind {
    /// Explicit endpoint configured by the operator.
    Static,
    /// Address observed on the protected local socket.
    Host,
    /// Server-reflexive mapping authenticated by a STUN transaction.
    ServerReflexive,
    /// Explicit mapping granted by PCP, NAT-PMP, or `UPnP` IGD.
    Mapped,
    /// Experimental bounded prediction for endpoint-dependent NAT.
    Predicted,
}

/// One bounded, canonically ordered direct UDP candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectCandidate {
    /// Nonzero UDP endpoint.
    pub endpoint: SocketAddr,
    /// Candidate origin.
    pub kind: CandidateKind,
    /// Larger values are probed first.
    pub priority: u32,
}
