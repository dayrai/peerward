use crate::{ManagementError, content_digest};
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use peerward_types::MeshId;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

const MANIFEST_DOMAIN: &[u8] = b"peerward/configuration-manifest/v1\0";
const LEASE_DOMAIN: &[u8] = b"peerward/authorization-lease/v1\0";
pub const MAX_CLOCK_TOLERANCE_SECONDS: u64 = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigurationPart {
    Authorities,
    Peers,
    Policy,
    Resources,
    Dns,
    Revocations,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentReference {
    pub version: u64,
    pub digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigurationManifest {
    pub mesh_id: MeshId,
    pub version: u64,
    pub parts: BTreeMap<ConfigurationPart, ComponentReference>,
}

impl ConfigurationManifest {
    pub fn validate(&self) -> Result<(), ManagementError> {
        if self.version == 0
            || self.parts.len() != 6
            || self.parts.iter().any(|(kind, part)| {
                part.version == 0
                    && matches!(kind, ConfigurationPart::Resources | ConfigurationPart::Dns)
            })
        {
            return Err(ManagementError::Invalid("manifest"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationLease {
    pub mesh_id: MeshId,
    pub configuration_digest: [u8; 32],
    pub sequence: u64,
    pub issued_at: u64,
    pub valid_until: u64,
}

impl AuthorizationLease {
    pub fn validate(&self) -> Result<(), ManagementError> {
        if self.sequence == 0
            || self.valid_until <= self.issued_at
            || ![300, 900, 3600].contains(&(self.valid_until - self.issued_at))
        {
            return Err(ManagementError::Invalid("lease"));
        }
        Ok(())
    }
    pub fn renew_at(&self) -> u64 {
        self.issued_at + (self.valid_until - self.issued_at) / 3
    }
}

/// Signatures are encoded as a bounded array of 64 bytes in typed JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedManifest {
    pub manifest: ConfigurationManifest,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedLease {
    pub lease: AuthorizationLease,
    pub signature: Vec<u8>,
}

fn transcript(domain: &[u8], value: &impl Serialize) -> Result<Vec<u8>, ManagementError> {
    let mut bytes = domain.to_vec();
    bytes.extend(serde_json::to_vec(value).map_err(|_| ManagementError::Invalid("encoding"))?);
    Ok(bytes)
}

impl SignedManifest {
    pub fn sign(
        manifest: ConfigurationManifest,
        key: &SigningKey,
    ) -> Result<Self, ManagementError> {
        manifest.validate()?;
        let signature = key
            .sign(&transcript(MANIFEST_DOMAIN, &manifest)?)
            .to_bytes()
            .to_vec();
        Ok(Self {
            manifest,
            signature,
        })
    }
    pub fn verify(&self, key: &VerifyingKey, mesh: MeshId) -> Result<(), ManagementError> {
        self.manifest.validate()?;
        if self.manifest.mesh_id != mesh {
            return Err(ManagementError::Signature);
        }
        key.verify_strict(
            &transcript(MANIFEST_DOMAIN, &self.manifest)?,
            &Signature::from_slice(&self.signature).map_err(|_| ManagementError::Signature)?,
        )
        .map_err(|_| ManagementError::Signature)
    }
}

impl SignedLease {
    pub fn sign(lease: AuthorizationLease, key: &SigningKey) -> Result<Self, ManagementError> {
        lease.validate()?;
        let signature = key
            .sign(&transcript(LEASE_DOMAIN, &lease)?)
            .to_bytes()
            .to_vec();
        Ok(Self { lease, signature })
    }
    pub fn verify(&self, key: &VerifyingKey, mesh: MeshId) -> Result<(), ManagementError> {
        self.lease.validate()?;
        if self.lease.mesh_id != mesh {
            return Err(ManagementError::Signature);
        }
        key.verify_strict(
            &transcript(LEASE_DOMAIN, &self.lease)?,
            &Signature::from_slice(&self.signature).map_err(|_| ManagementError::Signature)?,
        )
        .map_err(|_| ManagementError::Signature)
    }
}

/// Persist this before activation; a restart deliberately loses the live lease.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationFloor {
    pub configuration_version: u64,
    pub configuration_digest: [u8; 32],
    pub lease_sequence: u64,
    pub lease_digest: [u8; 32],
    pub time_floor: u64,
}

/// Validates all dependencies before activation. Caller must durably save `floor`.
pub struct LeaseClock {
    floor: AuthorizationFloor,
    active: Option<(u64, Instant)>,
    pending: Option<(u64, Instant)>,
}

impl LeaseClock {
    pub const fn new(floor: AuthorizationFloor) -> Self {
        Self {
            floor,
            active: None,
            pending: None,
        }
    }
    pub const fn floor(&self) -> &AuthorizationFloor {
        &self.floor
    }

    pub fn install(
        &mut self,
        manifest: &SignedManifest,
        lease: &SignedLease,
        key: &VerifyingKey,
        mesh: MeshId,
        available: &BTreeMap<ConfigurationPart, ComponentReference>,
        wall: u64,
        monotonic: Instant,
    ) -> Result<bool, ManagementError> {
        manifest.verify(key, mesh)?;
        lease.verify(key, mesh)?;
        let digest = content_digest(&manifest.manifest)?;
        let lease_digest = content_digest(&lease.lease)?;
        let current = &self.floor;
        if digest != lease.lease.configuration_digest {
            return Err(ManagementError::Signature);
        }
        if manifest.manifest.version < current.configuration_version
            || (manifest.manifest.version == current.configuration_version
                && digest != current.configuration_digest)
            || lease.lease.sequence < current.lease_sequence
            || (lease.lease.sequence == current.lease_sequence
                && lease_digest != current.lease_digest)
        {
            return Err(ManagementError::Rollback);
        }
        if wall.saturating_add(MAX_CLOCK_TOLERANCE_SECONDS) < current.time_floor
            || lease.lease.issued_at > wall.saturating_add(MAX_CLOCK_TOLERANCE_SECONDS)
            || wall.max(current.time_floor) >= lease.lease.valid_until
        {
            return Err(ManagementError::Expired);
        }
        if available.iter().any(|(part, known)| {
            manifest.manifest.parts.get(part).is_some_and(|required| {
                known.version > required.version
                    || (known.version == required.version && known.digest != required.digest)
            })
        }) {
            return Err(ManagementError::Rollback);
        }
        if lease.lease.sequence > current.lease_sequence {
            let floor = wall.max(current.time_floor).max(lease.lease.issued_at);
            let deadline = monotonic
                .checked_add(Duration::from_secs(lease.lease.valid_until - floor))
                .ok_or(ManagementError::Expired)?;
            // Authenticated observations survive a crash even while dependencies are missing.
            // The pending deadline is deliberately memory-only: replay after restart cannot activate it.
            self.floor = AuthorizationFloor {
                configuration_version: manifest.manifest.version,
                configuration_digest: digest,
                lease_sequence: lease.lease.sequence,
                lease_digest,
                time_floor: floor,
            };
            self.pending = Some((lease.lease.valid_until, deadline));
            self.active = None;
        }
        if &manifest.manifest.parts != available {
            return Err(ManagementError::Incomplete);
        }
        let Some((until, deadline)) = self.pending.take() else {
            return Ok(false);
        };
        if wall.max(self.floor.time_floor) >= until || monotonic >= deadline {
            return Err(ManagementError::Expired);
        }
        self.active = Some((until, deadline));
        Ok(true)
    }

    pub fn valid(&mut self, wall: u64, monotonic: Instant) -> bool {
        if wall.saturating_add(MAX_CLOCK_TOLERANCE_SECONDS) < self.floor.time_floor {
            self.active = None;
            self.pending = None;
        }
        self.floor.time_floor = self.floor.time_floor.max(wall);
        if self
            .active
            .is_some_and(|(until, deadline)| wall >= until || monotonic >= deadline)
        {
            self.active = None;
        }
        self.active.is_some()
    }
    pub fn invalidate(&mut self) {
        self.active = None;
    }

    /// Suspend can omit elapsed time from Instant; a staged lease must not survive it either.
    pub fn suspend(&mut self) {
        self.active = None;
        self.pending = None;
    }
}
