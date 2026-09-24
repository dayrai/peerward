use super::*;
use crate::{SnapshotKind, checkpoint::Checkpoint};
use peerward_types::CredentialSerial;

impl WireguardRuntime {
    /// Attach a private checkpoint before exposing this owner to TUN or carriers.
    /// The directory is stable across credential rotation and exclusively locked until close.
    pub fn enable_checkpoint(
        &mut self,
        path: &std::path::Path,
        now: UnixTime,
    ) -> Result<(), PeerError> {
        if self.closed || self.checkpoint.is_some() || self.updates_started {
            return Err(PeerError::InvalidConfig);
        }
        self.policy.set_ready(false);
        let opened = Checkpoint::open(
            path,
            self.root,
            self.mesh,
            self.local,
            now,
            self.connectivity.generation(),
        );
        let (checkpoint, start, ceiling) = match opened {
            Ok(value) => value,
            Err(error) => {
                self.close();
                return Err(error);
            }
        };
        self.directory.restore_checkpoint(&checkpoint);
        self.configuration_clock =
            peerward_management::LeaseClock::new(checkpoint.authorization_floor().clone());
        self.connectivity.reserve_generation(start, ceiling);
        self.management_sequence = start;
        self.management_ceiling = ceiling;
        self.checkpoint = Some(checkpoint);
        self.last_validation = None;
        self.prune(now);
        Ok(())
    }

    pub(super) fn state_ready(&self) -> bool {
        !self.closed
            && self.configuration_active
            && self
                .checkpoint
                .as_ref()
                .is_none_or(|state| state.ready(true))
    }

    pub(super) fn recovery_ready(&self) -> bool {
        !self.closed
            && self
                .checkpoint
                .as_ref()
                .is_none_or(|state| state.ready(false))
    }

    /// Sticky subject revocations also constrain service metadata maintained by platform adapters.
    pub fn revoked_credentials(&self) -> Vec<CredentialSerial> {
        self.checkpoint.as_ref().map_or_else(Vec::new, |state| {
            state.revoked_subjects().iter().copied().collect()
        })
    }

    /// Restores sticky revocations into an independent carrier trust verifier before authentication.
    pub fn restore_carrier_trust(&self, trust: &mut TrustSet) -> Result<(), PeerError> {
        if trust.root_public_key().to_bytes() != self.root || trust.mesh_id() != self.mesh {
            return Err(PeerError::InvalidConfig);
        }
        if let Some(state) = &self.checkpoint {
            for serial in state.revoked_subjects() {
                trust.revoke_subject(*serial);
            }
            for serial in state.revoked_authorities() {
                trust.revoke_authority(*serial);
            }
        }
        Ok(())
    }

    fn needs_update(
        &self,
        kind: SnapshotKind,
        revision: u64,
        bytes: &[u8],
    ) -> Result<bool, PeerError> {
        if self.closed {
            return Err(PeerError::Closed);
        }
        self.checkpoint
            .as_ref()
            .map_or(Ok(true), |state| state.check(kind, revision, bytes))
    }

    /// For external service/Relay tables only: verify signatures, identity and full contents first,
    /// then persist here, then atomically publish the already-validated replacement table.
    pub fn checkpoint_verified_snapshot(
        &mut self,
        kind: SnapshotKind,
        revision: u64,
        canonical: &[u8],
        now: UnixTime,
    ) -> Result<(), PeerError> {
        if !matches!(kind, SnapshotKind::Services | SnapshotKind::Relays) {
            return Err(PeerError::InvalidConfig);
        }
        self.needs_update(kind, revision, canonical)?;
        self.persist(kind, revision, canonical, now, &[])
    }

    fn persist(
        &mut self,
        kind: SnapshotKind,
        revision: u64,
        bytes: &[u8],
        now: UnixTime,
        revoked: &[CredentialSerial],
    ) -> Result<(), PeerError> {
        self.updates_started = true;
        if let Some(state) = &mut self.checkpoint
            && let Err(error) = state.commit(kind, revision, bytes, now, revoked)
        {
            // No previous policy, queued output, session or DNS view may outlive failed fsync.
            self.close();
            return Err(error);
        }
        self.record_configuration_part(kind, revision, bytes);
        Ok(())
    }

    fn publish_directory(
        &mut self,
        candidate: WireguardDirectory,
        now: UnixTime,
    ) -> Result<(), PeerError> {
        self.directory = candidate;
        self.clear_pending();
        if let Err(error) = self.reconcile(now) {
            self.close();
            return Err(error);
        }
        self.policy.set_ready(self.active_local(now).is_ok());
        Ok(())
    }

    pub fn install_directory(
        &mut self,
        signed: &SignedPeerDirectory,
        now: UnixTime,
    ) -> Result<(), PeerError> {
        let bytes = peerward_directory::encode_peer_directory(signed)?;
        if !self.needs_update(SnapshotKind::Peers, signed.directory.revision, &bytes)? {
            return Ok(());
        }
        let mut candidate = self.directory.clone();
        candidate.install(signed, now)?;
        self.persist(
            SnapshotKind::Peers,
            signed.directory.revision,
            &bytes,
            now,
            &[],
        )?;
        self.publish_directory(candidate, now)?;
        if !signed
            .directory
            .entries
            .iter()
            .any(|entry| entry.entry.peer_id == self.local && entry.entry.enabled)
        {
            self.close();
            return Err(PeerError::Revoked);
        }
        if let Err(error) = self.policy.install_directory(signed) {
            self.close();
            return Err(error);
        }
        self.reconcile_configuration(now)?;
        Ok(())
    }

    pub fn install_policy(&mut self, signed: &SignedPolicyBundle) -> Result<u64, PeerError> {
        let bytes = peerward_directory::encode_policy(signed)?;
        let revision = signed.bundle.revision;
        if !self.needs_update(SnapshotKind::Policy, revision, &bytes)? {
            return Ok(revision);
        }
        self.policy.verify_policy(signed)?;
        self.persist(
            SnapshotKind::Policy,
            revision,
            &bytes,
            self.last_validation.unwrap_or(UnixTime(0)),
            &[],
        )?;
        if let Err(error) = self.policy.install_policy(signed) {
            self.close();
            return Err(error);
        }
        self.clear_pending();
        self.policy.set_ready(
            self.active_local(self.last_validation.unwrap_or(UnixTime(0)))
                .is_ok(),
        );
        self.reconcile_configuration(self.last_validation.unwrap_or(UnixTime(0)))?;
        Ok(revision)
    }

    pub fn revoke(
        &mut self,
        signed: &SignedRevocationBundle,
        now: UnixTime,
    ) -> Result<(), PeerError> {
        let bytes = peerward_directory::encode_revocations(signed)?;
        if !self.needs_update(SnapshotKind::Revocations, signed.bundle.revision, &bytes)? {
            return Ok(());
        }
        let mut candidate = self.directory.clone();
        candidate.revoke(signed, now)?;
        self.persist(
            SnapshotKind::Revocations,
            signed.bundle.revision,
            &bytes,
            now,
            &signed.bundle.serials,
        )?;
        self.publish_directory(candidate, now)?;
        self.reconcile_configuration(now)
    }

    pub fn authorities(
        &mut self,
        signed: &SignedAuthorityBundle,
        now: UnixTime,
    ) -> Result<(), PeerError> {
        let bytes = signed.encode()?;
        if !self.needs_update(SnapshotKind::Authorities, signed.bundle.revision, &bytes)? {
            return Ok(());
        }
        let mut candidate = self.directory.clone();
        candidate.authorities(signed, now)?;
        self.persist(
            SnapshotKind::Authorities,
            signed.bundle.revision,
            &bytes,
            now,
            &signed.bundle.revoked,
        )?;
        if let Some(checkpoint) = &self.checkpoint {
            candidate.restore_checkpoint(checkpoint);
        }
        self.publish_directory(candidate, now)?;
        self.reconcile_configuration(now)
    }
}
