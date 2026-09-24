//! Strict IP parsing and bounded, sharded, stateful packet authorization.
//!
//! Fragment policy is deliberately conservative: a permitted first fragment creates a
//! short-lived association, while later fragments require that exact association. Orphans,
//! malformed extension chains, and fragments arriving after policy replacement are denied.

use std::{
    collections::HashMap,
    hash::{Hash, Hasher},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ops::RangeInclusive,
    sync::Mutex,
};

use ipnet::IpNet;
use peerward_types::RuleId;
use thiserror::Error;

include!("parse.rs");
include!("reassembly.rs");
include!("firewall.rs");
#[cfg(test)]
#[path = "tests.rs"]
mod tests;
