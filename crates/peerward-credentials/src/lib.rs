//! Fixed-transcript credentials anchored by an offline Ed25519 root.

use std::collections::BTreeSet;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use peerward_types::{CredentialSerial, MeshId, PeerId, RelayId, SubjectRole, UnixTime};
use rand::{CryptoRng, RngCore, rngs::OsRng};
use thiserror::Error;
use uuid::Uuid;
pub mod private_files;

include!("authority.rs");
include!("terminal.rs");
include!("bundle.rs");
include!("dynamic.rs");
include!("identity_claim.rs");
include!("rotation_proof.rs");
include!("subject.rs");
include!("transcripts.rs");
#[cfg(test)]
#[path = "tests.rs"]
mod tests;
