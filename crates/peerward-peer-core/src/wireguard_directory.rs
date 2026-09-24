//! Root-authenticated credential generations for Linux and Android adapters.
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use peerward_credentials::{
    DistributionCertificate, SignedAuthorityBundle, SubjectCredential, TrustSet,
};
use peerward_directory::{DirectoryPublicKey, SignedPeerDirectory, SignedRevocationBundle};
use peerward_types::{CredentialSerial, MeshId, PeerId, UnixTime};
use peerward_wireguard::{Engine, Key};

use crate::PeerError;

/// An exact, verified credential generation and its signed address ownership.
#[derive(Clone, Debug)]
pub struct WireguardPeerAuthorization {
    pub peer_id: PeerId,
    pub address: IpAddr,
    pub secondary_address: Option<IpAddr>,
    pub credential: SubjectCredential,
    /// The earliest credential, Authority or previous-generation deadline.
    pub valid_until: UnixTime,
    pub active: bool,
}

impl WireguardPeerAuthorization {
    pub fn owns(&self, address: IpAddr) -> bool {
        self.address == address || self.secondary_address == Some(address)
    }

    pub fn valid_at(&self, now: UnixTime) -> bool {
        self.credential.not_before <= now && now < self.valid_until
    }
}

/// A bounded Mesh-wide authorization table. Candidate updates never enter it.
/// Directory signatures cannot replace the independent Root/Authority check.
#[derive(Clone)]
pub struct WireguardDirectory {
    mesh_id: MeshId,
    trust: TrustSet,
    verifier: DirectoryPublicKey,
    revision: Option<u64>,
    revocation_revision: Option<u64>,
    revoked: BTreeSet<CredentialSerial>,
    keys: BTreeMap<Key, WireguardPeerAuthorization>,
    time_floor: UnixTime,
    active: BTreeMap<PeerId, Key>,
    addresses: BTreeMap<IpAddr, PeerId>,
    peers: BTreeMap<PeerId, Vec<Key>>,
}

impl WireguardDirectory {
    pub(crate) fn restore_checkpoint(&mut self, state: &crate::checkpoint::Checkpoint) {
        self.time_floor = self.time_floor.max(state.time_floor());
        for serial in state.revoked_subjects() {
            self.revoked.insert(*serial);
            self.trust.revoke_subject(*serial);
        }
        for serial in state.revoked_authorities() {
            self.trust.revoke_authority(*serial);
        }
    }

    pub(crate) fn has_revocations(&self) -> bool {
        self.revocation_revision.is_some()
    }

    /// Authenticates the directory verifier through the supplied Root trust set.
    pub fn new(
        mesh_id: MeshId,
        trust: TrustSet,
        distribution: &DistributionCertificate,
        now: UnixTime,
    ) -> Result<Self, PeerError> {
        if distribution.mesh_id != mesh_id {
            return Err(PeerError::InvalidConfig);
        }
        trust.verify_distribution(distribution, now)?;
        Ok(Self {
            mesh_id,
            trust,
            verifier: DirectoryPublicKey::from_bytes(&distribution.directory_public_key)?,
            revision: None,
            revocation_revision: None,
            revoked: BTreeSet::new(),
            keys: BTreeMap::new(),
            time_floor: now,
            active: BTreeMap::new(),
            addresses: BTreeMap::new(),
            peers: BTreeMap::new(),
        })
    }

    /// Verifies all installable generations before atomically replacing the table.
    /// Returns keys removed by deletion, disable, replacement or a shortened lifetime.
    pub fn install(
        &mut self,
        signed: &SignedPeerDirectory,
        now: UnixTime,
    ) -> Result<Vec<Key>, PeerError> {
        self.verifier
            .verify_peers(signed, self.mesh_id, self.revision)?;
        if signed.directory.entries.len() > 10_000 {
            return Err(PeerError::InvalidConfig);
        }
        let now = now.max(self.time_floor);
        let mut keys = BTreeMap::new();
        let mut active = BTreeMap::new();
        let mut addresses = BTreeMap::new();
        let mut peers: BTreeMap<PeerId, Vec<Key>> = BTreeMap::new();
        for entry in signed
            .directory
            .entries
            .iter()
            .map(|signed| &signed.entry)
            .filter(|entry| entry.enabled)
        {
            for binding in &entry.accepted_credentials {
                if self.revoked.contains(&binding.serial) {
                    continue;
                }
                // Do not commit a partial snapshot that silently loses a future active key.
                // The same signed revision must remain retryable when its validity begins.
                if binding.not_before > now {
                    return Err(peerward_credentials::CredentialError::OutsideValidity.into());
                }
                if !binding.valid_at(now) {
                    continue;
                }
                let credential = binding.subject(entry.mesh_id, entry.peer_id);
                let authority_until = self.trust.subject_valid_until(&credential, now)?;
                if self
                    .keys
                    .get(&credential.wireguard_public_key)
                    .is_some_and(|previous| {
                        previous.peer_id != entry.peer_id || previous.credential != credential
                    })
                {
                    return Err(PeerError::InvalidConfig);
                }
                let valid_until = binding
                    .overlap_until
                    .unwrap_or(credential.not_after)
                    .min(authority_until);
                // Reject non-contributory Curve25519 points before touching any engine.
                let public = x25519_dalek::PublicKey::from(binding.wireguard_public_key);
                if !x25519_dalek::StaticSecret::from([0x42; 32])
                    .diffie_hellman(&public)
                    .was_contributory()
                {
                    return Err(PeerError::InvalidConfig);
                }
                let is_active = binding.serial == entry.credential_serial;
                if is_active {
                    active.insert(entry.peer_id, binding.wireguard_public_key);
                }
                for address in entry.addresses() {
                    addresses.insert(address, entry.peer_id);
                }
                peers
                    .entry(entry.peer_id)
                    .or_default()
                    .push(binding.wireguard_public_key);
                keys.insert(
                    binding.wireguard_public_key,
                    WireguardPeerAuthorization {
                        peer_id: entry.peer_id,
                        address: entry.address,
                        secondary_address: entry.secondary_address,
                        credential,
                        valid_until,
                        active: is_active,
                    },
                );
            }
        }
        let removed = self
            .keys
            .keys()
            .filter(|key| !keys.contains_key(*key))
            .copied()
            .collect();
        self.time_floor = now;
        self.keys = keys;
        self.active = active;
        self.addresses = addresses;
        self.peers = peers;
        self.revision = Some(signed.directory.revision);
        Ok(removed)
    }

    /// Exact revocations are sticky even when a later snapshot omits a serial.
    pub fn revoke(
        &mut self,
        signed: &SignedRevocationBundle,
        now: UnixTime,
    ) -> Result<Vec<Key>, PeerError> {
        self.verifier
            .verify_revocations(signed, self.mesh_id, self.revocation_revision)?;
        for serial in &signed.bundle.serials {
            self.revoked.insert(*serial);
            self.trust.revoke_subject(*serial);
        }
        self.revocation_revision = Some(signed.bundle.revision);
        Ok(self.expire(now))
    }

    /// Installs a Root-verified Authority revision and immediately rechecks every key.
    pub fn authorities(
        &mut self,
        bundle: &SignedAuthorityBundle,
        now: UnixTime,
    ) -> Result<Vec<Key>, PeerError> {
        let now = now.max(self.time_floor);
        self.trust
            .install_authority_bundle_after_resume(bundle, now)?;
        for value in self.keys.values_mut() {
            value.valid_until = self
                .trust
                .subject_valid_until(&value.credential, now)
                .map_or(now, |until| value.valid_until.min(until));
        }
        Ok(self.expire(now))
    }

    /// Removes expired or revoked generations; callers remove returned engine keys.
    /// Admission always checks time, even before the next scheduled cleanup.
    pub fn expire(&mut self, now: UnixTime) -> Vec<Key> {
        self.time_floor = now.max(self.time_floor);
        let now = self.time_floor;
        let mut removed = Vec::new();
        self.keys.retain(|key, value| {
            let keep = value.valid_at(now) && !self.revoked.contains(&value.credential.serial);
            if !keep {
                removed.push(*key);
            }
            keep
        });
        self.active.retain(|_, key| self.keys.contains_key(key));
        self.peers.retain(|_, keys| {
            keys.retain(|key| self.keys.contains_key(key));
            !keys.is_empty()
        });
        self.addresses
            .retain(|_, peer| self.peers.contains_key(peer));
        removed
    }

    pub fn get(&self, key: &Key, now: UnixTime) -> Option<&WireguardPeerAuthorization> {
        self.keys
            .get(key)
            .filter(|value| value.valid_at(now.max(self.time_floor)))
    }

    pub fn active(&self, peer: PeerId, now: UnixTime) -> Option<&WireguardPeerAuthorization> {
        self.active.get(&peer).and_then(|key| self.get(key, now))
    }

    /// Uses the signed IP assignment without scanning every Peer for each packet.
    pub fn destination(
        &self,
        address: IpAddr,
        now: UnixTime,
    ) -> Option<&WireguardPeerAuthorization> {
        self.addresses
            .get(&address)
            .and_then(|peer| self.active(*peer, now))
    }

    /// At most two live generations for an authenticated Relay source identity.
    pub fn keys_for_peer(&self, peer: PeerId, now: UnixTime) -> impl Iterator<Item = &Key> {
        self.peers
            .get(&peer)
            .into_iter()
            .flatten()
            .filter(move |key| self.get(key, now).is_some())
    }

    /// Validates a locally staged key before it becomes directory-authorized.
    pub fn verify_credential(
        &self,
        credential: &SubjectCredential,
        now: UnixTime,
    ) -> Result<(), PeerError> {
        self.trust
            .verify_subject(credential, now.max(self.time_floor))?;
        Ok(())
    }

    pub const fn revision(&self) -> Option<u64> {
        self.revision
    }

    /// Installs only authorized remote keys and preserves unchanged sessions.
    /// Invalid local credentials cause complete engine teardown, including queues.
    pub fn reconcile_engine(
        &self,
        engine: &mut Engine,
        local: PeerId,
        now: UnixTime,
    ) -> Result<(), PeerError> {
        let now = now.max(self.time_floor);
        let local_valid = self
            .get(&engine.public_key(), now)
            .is_some_and(|value| value.peer_id == local);
        if !local_valid {
            engine.close();
            return Err(PeerError::Revoked);
        }
        if self
            .keys
            .values()
            .filter(|value| value.peer_id != local && value.valid_at(now))
            .count()
            > engine.peer_capacity()
        {
            return Err(PeerError::InvalidConfig);
        }
        let installed = engine.peer_keys();
        for key in installed {
            if self
                .get(&key, now)
                .is_none_or(|value| value.peer_id == local)
            {
                engine.remove(&key);
            }
        }
        for (key, value) in &self.keys {
            if value.peer_id != local && value.valid_at(now) {
                engine
                    .install(*key)
                    .map_err(|error| PeerError::PacketRuntime(Box::new(error)))?;
            }
        }
        Ok(())
    }

    /// Address attribution runs before application ACL evaluation.
    pub fn owns_source(&self, key: &Key, source: IpAddr, now: UnixTime) -> bool {
        self.get(key, now).is_some_and(|value| value.owns(source))
    }
}

#[cfg(test)]
#[path = "wireguard_directory_tests.rs"]
mod tests;
