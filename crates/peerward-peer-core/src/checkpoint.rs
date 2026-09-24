//! Private, crash-consistent floors. No private keys, addresses or plaintext are stored here.
use crate::PeerError;
use peerward_credentials::private_files::{
    private_dir, read_private, reject_symlinks, write_private_atomic,
};
use peerward_types::{CredentialSerial, MeshId, PeerId, UnixTime};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

const MAX_BYTES: u64 = 48 * 1024 * 1024;
const MAX_SUBJECTS: usize = 1_000_000;
const MAX_AUTHORITIES: usize = 65_536;
const GENERATION_LEASE: u64 = 1 << 32;

/// Independent signed revision domains. Callers must verify the complete object before commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SnapshotKind {
    Authorities,
    Peers,
    Policy,
    Revocations,
    Services,
    Relays,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stamp {
    revision: u64,
    digest: [u8; 32],
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    version: u8,
    root: [u8; 32],
    mesh: MeshId,
    peer: PeerId,
    stamps: BTreeMap<SnapshotKind, Stamp>,
    subjects: BTreeSet<CredentialSerial>,
    authorities: BTreeSet<CredentialSerial>,
    time_floor: UnixTime,
    generation_ceiling: u64,
    authorization: peerward_management::AuthorizationFloor,
}

pub(crate) struct Checkpoint {
    path: PathBuf,
    // Lock a stable inode, never the atomically replaced state file.
    _lock: File,
    state: State,
    applied: BTreeSet<SnapshotKind>,
}

impl Checkpoint {
    pub fn open(
        path: &Path,
        root: [u8; 32],
        mesh: MeshId,
        peer: PeerId,
        now: UnixTime,
        generation: u64,
    ) -> Result<(Self, u64, u64), PeerError> {
        private_dir(path)?;
        let lock_path = path.join("owner.lock");
        reject_symlinks(&lock_path)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut lock = options.open(&lock_path)?;
        let initialized = read_private(&lock_path, 1)?;
        if !initialized.is_empty() && initialized != b"1" {
            return Err(PeerError::Checkpoint("corrupt ownership marker"));
        }
        lock_owner(&lock)?;
        let file = path.join("state.json");
        let mut state = match read_private(&file, MAX_BYTES) {
            Ok(bytes) => serde_json::from_slice::<State>(&bytes).map_err(|_| {
                PeerError::Checkpoint("corrupt state; refusing to reset trust history")
            })?,
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound && initialized.is_empty() =>
            {
                State {
                    version: 2,
                    root,
                    mesh,
                    peer,
                    stamps: BTreeMap::new(),
                    subjects: BTreeSet::new(),
                    authorities: BTreeSet::new(),
                    time_floor: now,
                    generation_ceiling: 0,
                    authorization: peerward_management::AuthorizationFloor::default(),
                }
            }
            Err(error) => return Err(error.into()),
        };
        if state.version != 2 || state.root != root || state.mesh != mesh || state.peer != peer {
            return Err(PeerError::Checkpoint("state identity/version mismatch"));
        }
        let start = generation.max(state.generation_ceiling);
        let ceiling = start
            .checked_add(GENERATION_LEASE)
            .ok_or(PeerError::Checkpoint("path generation exhausted"))?;
        state.generation_ceiling = ceiling;
        state.time_floor = state.time_floor.max(now);
        // Commit the marker only after a complete state exists. A missing committed state must
        // never silently reset floors; an interrupted first initialization can still be retried.
        let bytes = serde_json::to_vec(&state).map_err(|_| PeerError::InvalidConfig)?;
        if state.subjects.len() > MAX_SUBJECTS
            || state.authorities.len() > MAX_AUTHORITIES
            || bytes.len() as u64 > MAX_BYTES
        {
            return Err(PeerError::Checkpoint("state capacity exhausted"));
        }
        write_private_atomic(&file, &bytes)?;
        if initialized.is_empty() {
            lock.write_all(b"1")?;
            lock.sync_all()?;
        }
        let checkpoint = Self {
            path: file,
            _lock: lock,
            state,
            applied: BTreeSet::new(),
        };
        Ok((checkpoint, start, ceiling))
    }

    /// Identical persisted state may be installed once again after restart; conflicts never may.
    pub fn check(
        &self,
        kind: SnapshotKind,
        revision: u64,
        bytes: &[u8],
    ) -> Result<bool, PeerError> {
        let stamp = stamp(revision, bytes);
        if let Some(previous) = self.state.stamps.get(&kind) {
            if revision < previous.revision || (revision == previous.revision && &stamp != previous)
            {
                return Err(PeerError::Checkpoint(
                    "older revision or conflicting signed contents",
                ));
            }
            if &stamp == previous && self.applied.contains(&kind) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub fn commit(
        &mut self,
        kind: SnapshotKind,
        revision: u64,
        bytes: &[u8],
        now: UnixTime,
        revoked: &[CredentialSerial],
    ) -> Result<(), PeerError> {
        self.check(kind, revision, bytes)?;
        let mut next = self.state.clone();
        next.stamps.insert(kind, stamp(revision, bytes));
        match kind {
            SnapshotKind::Revocations => next.subjects.extend(revoked.iter().copied()),
            SnapshotKind::Authorities => next.authorities.extend(revoked.iter().copied()),
            _ if !revoked.is_empty() => return Err(PeerError::InvalidConfig),
            _ => {}
        }
        next.time_floor = next.time_floor.max(now);
        self.write(&next)?;
        self.state = next;
        self.applied.insert(kind);
        Ok(())
    }

    fn write(&self, state: &State) -> Result<(), PeerError> {
        if state.subjects.len() > MAX_SUBJECTS || state.authorities.len() > MAX_AUTHORITIES {
            return Err(PeerError::Checkpoint(
                "revocation history capacity exhausted",
            ));
        }
        let bytes = serde_json::to_vec(state).map_err(|_| PeerError::InvalidConfig)?;
        if bytes.len() as u64 > MAX_BYTES {
            return Err(PeerError::Checkpoint("state too large"));
        }
        write_private_atomic(&self.path, &bytes)?;
        Ok(())
    }

    pub fn advance_expiry_floor(&mut self, now: UnixTime) -> Result<(), PeerError> {
        if now <= self.state.time_floor {
            return Ok(());
        }
        let mut next = self.state.clone();
        next.time_floor = now;
        self.write(&next)?;
        self.state = next;
        Ok(())
    }

    pub fn ready(&self, include_policy: bool) -> bool {
        use SnapshotKind::{Authorities, Peers, Policy, Revocations};
        [Peers, Revocations]
            .iter()
            .all(|kind| self.applied.contains(kind))
            && (!include_policy || self.applied.contains(&Policy))
            && [Authorities, Policy]
                .iter()
                .filter(|kind| include_policy || **kind != Policy)
                .all(|kind| !self.state.stamps.contains_key(kind) || self.applied.contains(kind))
    }
    pub fn time_floor(&self) -> UnixTime {
        self.state.time_floor
    }
    pub fn authorization_floor(&self) -> &peerward_management::AuthorizationFloor {
        &self.state.authorization
    }
    pub fn commit_authorization(
        &mut self,
        floor: &peerward_management::AuthorizationFloor,
    ) -> Result<(), PeerError> {
        let mut next = self.state.clone();
        if floor.configuration_version < next.authorization.configuration_version
            || floor.lease_sequence < next.authorization.lease_sequence
        {
            return Err(PeerError::Checkpoint("authorization rollback"));
        }
        next.authorization = floor.clone();
        next.time_floor = next.time_floor.max(UnixTime(floor.time_floor));
        self.write(&next)?;
        self.state = next;
        Ok(())
    }
    pub fn revoked_subjects(&self) -> &BTreeSet<CredentialSerial> {
        &self.state.subjects
    }
    pub fn revoked_authorities(&self) -> &BTreeSet<CredentialSerial> {
        &self.state.authorities
    }
}

fn stamp(revision: u64, bytes: &[u8]) -> Stamp {
    Stamp {
        revision,
        digest: Sha256::digest(bytes).into(),
    }
}

// Rust 1.95 std::fs::File::try_lock returns Unsupported on Android. Use the same
// safe flock wrapper for both production platforms so host tests cover its semantics.
fn lock_owner(file: &File) -> Result<(), PeerError> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let result = rustix::fs::flock(file, rustix::fs::FlockOperation::NonBlockingLockExclusive);
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let result = file.try_lock();
    result.map_err(|_| PeerError::Checkpoint("state already owned or cannot be locked"))
}
