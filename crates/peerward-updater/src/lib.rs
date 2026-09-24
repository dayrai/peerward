//! Signed release selection and rollback-safe binary replacement.
//!
//! Release manifests are signed as their exact UTF-8 bytes. Parsing happens
//! only after Ed25519 verification, and every selected artifact is checked
//! against both its declared byte length and SHA-256 digest before installation.

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

const MANIFEST_DOMAIN: &[u8] = b"peerward/release-manifest/v1\0";
const MAX_MANIFEST_BYTES: usize = 4 * 1024 * 1024;
const MAX_ARTIFACT_BYTES: usize = 256 * 1024 * 1024;

/// Stable updater error classes.
#[derive(Debug, Error)]
pub enum UpdateError {
    /// Manifest or artifact shape is invalid.
    #[error("release data is malformed")]
    Malformed,
    /// Signature verification failed.
    #[error("release manifest signature is invalid")]
    Signature,
    /// No artifact matches the requested target.
    #[error("release has no matching artifact")]
    NoArtifact,
    /// Artifact bytes do not match the signed declaration.
    #[error("release artifact digest or length is invalid")]
    Digest,
    /// Manifest is expired or its publication window is invalid.
    #[error("release manifest is expired")]
    Expired,
    /// Sequence or rollback floor would permit a downgrade.
    #[error("release manifest is older than accepted update state")]
    Rollback,
    /// Running schema or Wire protocol is outside the declared compatibility range.
    #[error("release is incompatible with this installation")]
    Incompatible,
    /// A previous role transaction must be reconciled first.
    #[error("an update requires recovery; run update status and update recover")]
    RecoveryRequired,
    /// Atomic filesystem operation failed.
    #[error("release installation failed: {0}")]
    Io(#[from] std::io::Error),
}

/// Release stability channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Channel {
    /// Production releases.
    Stable,
    /// Explicitly opted-in pre-release ring used for staged rollout.
    Canary,
    /// Preview releases.
    Beta,
    /// Continuously produced development releases.
    Nightly,
}

/// Artifact packaging shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    /// Directly installable unified executable.
    Binary,
    /// Compressed release archive.
    Archive,
    /// Native operating-system package.
    Package,
    /// Android application package.
    Android,
}

/// One signed release document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseManifest {
    /// Must be exactly one.
    pub schema_version: u32,
    /// Monotonic release sequence within the signing-key epoch.
    pub sequence: u64,
    /// Semantic release version.
    pub version: String,
    /// Release channel.
    pub channel: Channel,
    /// Unix publication timestamp.
    pub published_at: u64,
    /// Unix expiry timestamp after which the manifest must be rejected.
    pub expires_at: u64,
    /// Supported persistent schema versions.
    pub schema_compatibility: CompatibilityRange,
    /// Supported Wire major versions.
    pub wire_compatibility: CompatibilityRange,
    /// Lowest version to which an automatic rollback is allowed.
    pub rollback_floor: String,
    /// Complete artifact inventory.
    pub artifacts: Vec<ReleaseArtifact>,
}

/// Inclusive compatibility interval signed into a release manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompatibilityRange {
    pub min: u32,
    pub max: u32,
}

impl CompatibilityRange {
    pub const fn contains(self, value: u32) -> bool {
        self.min <= value && value <= self.max
    }

    const fn valid(self) -> bool {
        self.min > 0 && self.min <= self.max
    }
}

/// One content-addressed release artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseArtifact {
    /// Operating-system identifier such as `linux`.
    pub platform: String,
    /// Architecture identifier such as `x86_64` or `aarch64`.
    pub architecture: String,
    /// Packaging shape.
    pub kind: ArtifactKind,
    /// Download filename.
    pub name: String,
    /// HTTPS download URL.
    pub url: String,
    /// Lowercase SHA-256 hexadecimal digest.
    pub sha256: String,
    /// Exact artifact length.
    pub size: u64,
}

impl ReleaseManifest {
    /// Selects exactly one artifact for the requested channel and target.
    pub fn select(
        &self,
        channel: Channel,
        platform: &str,
        architecture: &str,
        kind: ArtifactKind,
    ) -> Result<&ReleaseArtifact, UpdateError> {
        if self.channel != channel {
            return Err(UpdateError::NoArtifact);
        }
        let mut matches = self.artifacts.iter().filter(|artifact| {
            artifact.platform == platform
                && artifact.architecture == architecture
                && artifact.kind == kind
        });
        let selected = matches.next().ok_or(UpdateError::NoArtifact)?;
        if matches.next().is_some() {
            return Err(UpdateError::Malformed);
        }
        Ok(selected)
    }

    fn validate(&self) -> Result<(), UpdateError> {
        if self.schema_version != 1
            || self.sequence == 0
            || canonical_version(&self.version).is_none()
            || canonical_version(&self.rollback_floor).is_none()
            || parsed_version(&self.version)?
                .cmp_precedence(&parsed_version(&self.rollback_floor)?)
                .is_lt()
            || self.published_at >= self.expires_at
            || !self.schema_compatibility.valid()
            || !self.wire_compatibility.valid()
            || self.artifacts.is_empty()
            || self.artifacts.iter().any(|artifact| {
                artifact.platform.is_empty()
                    || artifact.platform.len() > 32
                    || artifact.architecture.is_empty()
                    || artifact.architecture.len() > 32
                    || artifact.name.is_empty()
                    || artifact.name.len() > 160
                    || artifact.name.contains(['/', '\\'])
                    || !artifact.url.starts_with("https://")
                    || artifact.sha256.len() != 64
                    || hex::decode(&artifact.sha256).is_err()
                    || artifact.size == 0
                    || artifact.size > MAX_ARTIFACT_BYTES as u64
            })
        {
            return Err(UpdateError::Malformed);
        }
        Ok(())
    }

    /// Applies temporal, monotonic-sequence, and compatibility release gates.
    pub fn validate_candidate(
        &self,
        now: u64,
        highest_sequence: u64,
        current_version: &str,
        schema_version: u32,
        wire_major: u32,
    ) -> Result<(), UpdateError> {
        self.validate()?;
        if now < self.published_at || now >= self.expires_at {
            return Err(UpdateError::Expired);
        }
        let current = parsed_version(current_version)?;
        let candidate = parsed_version(&self.version)?;
        let rollback_floor = parsed_version(&self.rollback_floor)?;
        if self.sequence < highest_sequence
            || current.cmp_precedence(&rollback_floor).is_lt()
            || candidate.cmp_precedence(&current).is_lt()
        {
            return Err(UpdateError::Rollback);
        }
        if !self.schema_compatibility.contains(schema_version)
            || !self.wire_compatibility.contains(wire_major)
        {
            return Err(UpdateError::Incompatible);
        }
        Ok(())
    }
}

include!("accepted_state.rs");

/// Verifies exact manifest bytes before parsing their strict schema.
pub fn verify_manifest(
    bytes: &[u8],
    signature: &[u8; 64],
    public_key: &[u8; 32],
) -> Result<ReleaseManifest, UpdateError> {
    if bytes.is_empty() || bytes.len() > MAX_MANIFEST_BYTES {
        return Err(UpdateError::Malformed);
    }
    let verifier = VerifyingKey::from_bytes(public_key).map_err(|_| UpdateError::Signature)?;
    verifier
        .verify(
            &manifest_transcript(bytes),
            &Signature::from_bytes(signature),
        )
        .map_err(|_| UpdateError::Signature)?;
    let manifest: ReleaseManifest =
        serde_json::from_slice(bytes).map_err(|_| UpdateError::Malformed)?;
    if serde_json::to_vec(&manifest).map_err(|_| UpdateError::Malformed)? != bytes {
        return Err(UpdateError::Malformed);
    }
    manifest.validate()?;
    Ok(manifest)
}

/// Signs exact manifest bytes with the domain-separated updater transcript.
#[must_use]
pub fn sign_manifest(bytes: &[u8], private_key: &[u8; 32]) -> [u8; 64] {
    SigningKey::from_bytes(private_key)
        .sign(&manifest_transcript(bytes))
        .to_bytes()
}

/// Checks an artifact against the signed length and SHA-256 declaration.
pub fn verify_artifact(bytes: &[u8], artifact: &ReleaseArtifact) -> Result<(), UpdateError> {
    let expected_size = usize::try_from(artifact.size).map_err(|_| UpdateError::Digest)?;
    if expected_size == 0 || expected_size > MAX_ARTIFACT_BYTES {
        return Err(UpdateError::Digest);
    }
    let expected: [u8; 32] = hex::decode(&artifact.sha256)
        .map_err(|_| UpdateError::Digest)?
        .try_into()
        .map_err(|_| UpdateError::Digest)?;
    let actual: [u8; 32] = Sha256::digest(bytes).into();
    if bytes.len() == expected_size && actual == expected {
        Ok(())
    } else {
        Err(UpdateError::Digest)
    }
}

fn verify_artifact_file(path: &Path, artifact: &ReleaseArtifact) -> Result<(), UpdateError> {
    let expected_size = usize::try_from(artifact.size).map_err(|_| UpdateError::Digest)?;
    if expected_size == 0 || expected_size > MAX_ARTIFACT_BYTES {
        return Err(UpdateError::Digest);
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW);
    }
    let mut file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() != artifact.size {
        return Err(UpdateError::Digest);
    }
    let expected: [u8; 32] = hex::decode(&artifact.sha256)
        .map_err(|_| UpdateError::Digest)?
        .try_into()
        .map_err(|_| UpdateError::Digest)?;
    let mut actual = Sha256::new();
    let mut total = 0_usize;
    let mut buffer = [0_u8; 16_384];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total.checked_add(read).ok_or(UpdateError::Digest)?;
        if total > expected_size {
            return Err(UpdateError::Digest);
        }
        actual.update(&buffer[..read]);
    }
    if total == expected_size && <[u8; 32]>::from(actual.finalize()) == expected {
        Ok(())
    } else {
        Err(UpdateError::Digest)
    }
}

/// Installs verified bytes next to the destination and retains one rollback copy.
///
/// This function never invokes a package manager, `sudo`, or another privilege
/// boundary. The caller must already have write access to the destination.
pub fn install_verified(
    bytes: &[u8],
    artifact: &ReleaseArtifact,
    destination: &Path,
) -> Result<PathBuf, UpdateError> {
    verify_artifact(bytes, artifact)?;
    let parent = destination.parent().ok_or(UpdateError::Malformed)?;
    let metadata = fs::metadata(destination)?;
    if !metadata.is_file() {
        return Err(UpdateError::Malformed);
    }
    let temporary = unique_sibling(destination, "incoming")?;
    let rollback = sibling(destination, "rollback")?;
    let retired = sibling(destination, "rollback.previous")?;
    let result = (|| {
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        let mut file = options.open(&temporary)?;
        file.set_permissions(metadata.permissions())?;
        file.write_all(bytes)?;
        file.sync_all()?;
        if retired.exists() {
            fs::remove_file(&retired)?;
        }
        if rollback.exists() {
            fs::rename(&rollback, &retired)?;
        }
        fs::rename(destination, &rollback)?;
        if let Err(error) = fs::rename(&temporary, destination) {
            let _ = fs::rename(&rollback, destination);
            return Err(error.into());
        }
        sync_directory(parent)?;
        Ok(rollback)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

/// Restores the retained rollback copy atomically.
pub fn rollback(destination: &Path) -> Result<(), UpdateError> {
    let parent = destination.parent().ok_or(UpdateError::Malformed)?;
    let saved = sibling(destination, "rollback")?;
    if !saved.is_file() || !destination.is_file() {
        return Err(UpdateError::Malformed);
    }
    let failed = unique_sibling(destination, "failed")?;
    fs::rename(destination, &failed)?;
    if let Err(error) = fs::rename(&saved, destination) {
        let _ = fs::rename(&failed, destination);
        return Err(error.into());
    }
    sync_directory(parent)?;
    fs::remove_file(failed)?;
    Ok(())
}

include!("versioned.rs");
#[cfg(unix)]
mod transaction;
#[cfg(unix)]
pub use transaction::{
    TransactionOptions, UpdateDirection, UpdateStage, UpdateTransaction, installed_role_version,
};

#[cfg(unix)]
fn replace_symlink(directory: &Path, name: &str, target: &Path) -> Result<(), UpdateError> {
    use std::os::unix::fs::symlink;

    let temporary = directory.join(format!(".{name}.incoming.{}", std::process::id()));
    if temporary.exists() {
        fs::remove_file(&temporary)?;
    }
    symlink(target, &temporary)?;
    let destination = directory.join(name);
    if let Err(error) = fs::rename(&temporary, &destination) {
        let _ = fs::remove_file(&temporary);
        return Err(error.into());
    }
    Ok(())
}

fn valid_role(role: &str) -> bool {
    !role.is_empty()
        && role.len() <= 32
        && role
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn canonical_version(version: &str) -> Option<Version> {
    let parsed = Version::parse(version).ok()?;
    (parsed.to_string() == version).then_some(parsed)
}

fn parsed_version(version: &str) -> Result<Version, UpdateError> {
    canonical_version(version).ok_or(UpdateError::Malformed)
}

fn manifest_transcript(bytes: &[u8]) -> Vec<u8> {
    let mut transcript = Vec::with_capacity(MANIFEST_DOMAIN.len() + 8 + bytes.len());
    transcript.extend_from_slice(MANIFEST_DOMAIN);
    transcript.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    transcript.extend_from_slice(bytes);
    transcript
}

fn sibling(path: &Path, suffix: &str) -> Result<PathBuf, UpdateError> {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or(UpdateError::Malformed)?;
    Ok(path.with_file_name(format!(".{name}.{suffix}")))
}

fn unique_sibling(path: &Path, label: &str) -> Result<PathBuf, UpdateError> {
    for sequence in 0..32_u8 {
        let candidate = sibling(
            path,
            &format!("{label}.{}.{}", std::process::id(), sequence),
        )?;
        if !candidate.exists() {
            return Ok(candidate);
        }
    }
    Err(UpdateError::Io(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "cannot allocate update temporary path",
    )))
}

fn sync_directory(path: &Path) -> Result<(), UpdateError> {
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
#[path = "updater_tests.rs"]
mod tests;
#[cfg(all(test, unix))]
mod transaction_tests;
