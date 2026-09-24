//! Ordered, mesh-scoped policy with bounded return-flow state.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ops::RangeInclusive,
};

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use peerward_types::{
    IpProtocol, MAX_LABELS, MAX_POLICY_RULES, MAX_PORT_SPANS, MAX_SELECTOR_CIDRS,
    MAX_SELECTOR_PEERS, MeshId, PeerId, PolicyProtocol, RuleId,
};
use thiserror::Error;

include!("document.rs");
include!("evaluator.rs");
#[cfg(test)]
#[path = "tests.rs"]
mod tests;
