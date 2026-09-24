//! Parser and local operations for the unified `peerward` binary.

use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process::Command as ProcessCommand,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::{Args, Parser, Subcommand, ValueEnum};
use ed25519_dalek::SigningKey as IdentitySigningKey;
use futures_util::StreamExt as _;
use peerward_control::{AuthConfig, ControlConfig};
use peerward_credentials::{
    AuthorityCertificate, AuthoritySigningKey, DistributionCertificate, JoinClaimProof,
    RootPublicKey, RootSigningKey, SubjectCredential, SubjectId, TrustSet, UnsignedAuthority,
    UnsignedSubject, private_files::read_bounded_regular_file as read_bounded_regular_file_io,
    sign_join_claim,
};
use peerward_directory::DirectorySigningKey;
use peerward_peer::PeerConfig;
use peerward_platform::{LinuxCommandBackend, StateCoordinator};
use peerward_relay::RelayConfig;
use peerward_service::{
    Request as ServiceRequest, ServiceProtocol as PublishedProtocol, ServiceSnapshotSigningKey,
};
use peerward_store::{
    DefaultPolicy, InitialAuthority, InitialInstallation, InitialRelay, NewMesh, Store,
    secret_digest,
};
use peerward_types::{
    CredentialSerial, MeshId, NetworkEndpoint, RelayId, UnixTime, validate_endpoint_list,
};
use peerward_updater::{
    ArtifactKind, Channel as UpdateChannel, UpdateDirection, UpdateTransaction, accept_manifest,
    install_verified, rollback, sign_manifest, verify_manifest,
};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use snow::Builder;
use url::Url;
use uuid::Uuid;
use x25519_dalek::{PublicKey as NoisePublicKey, StaticSecret};
use zeroize::Zeroizing;

/// Successful process exit.
pub const EXIT_SUCCESS: u8 = 0;
/// Invalid input or configuration.
pub const EXIT_INVALID: u8 = 2;
/// Required service or implementation is unavailable.
pub const EXIT_UNAVAILABLE: u8 = 3;
/// Authentication or authorization failed.
pub const EXIT_AUTH: u8 = 4;
/// Unclassified failure.
pub const EXIT_FAILURE: u8 = 1;

include!("command_tree.rs");
include!("client_preferences.rs");
include!("saved_profiles.rs");
mod peer_install;
include!("dispatch.rs");
include!("identity.rs");
include!("join_profile.rs");
include!("join_input.rs");
include!("config.rs");
include!("doctor.rs");
include!("runtime.rs");
include!("service_commands.rs");
include!("update_commands.rs");
include!("update_preflight.rs");
include!("update_recovery.rs");
include!("update_peer_health.rs");
include!("update_register.rs");
include!("update_preview.rs");
#[cfg(test)]
mod doctor_tests;
#[cfg(test)]
mod saved_profiles_tests;
#[cfg(test)]
#[path = "tests.rs"]
mod tests;
