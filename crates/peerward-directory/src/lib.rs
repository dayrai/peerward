//! Canonical, Ed25519-signed mesh directories and bounded revision assembly.

use std::{
    cmp::Reverse,
    collections::{BTreeMap, BTreeSet, BinaryHeap},
    net::IpAddr,
};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use peerward_types::{
    CredentialSerial, MeshId, NetworkEndpoint, PeerId, RelayId, UnixTime, validate_endpoint_list,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

include!("signing.rs");
include!("chunks.rs");
include!("codec.rs");
include!("transcripts.rs");
#[cfg(test)]
#[path = "tests.rs"]
mod tests;

include!("credential_renewal_signing.rs");
