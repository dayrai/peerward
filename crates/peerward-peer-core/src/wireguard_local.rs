use std::time::Instant;

use super::{SubjectCredential, UnixTime, WireguardRuntime};

impl WireguardRuntime {
    /// Current local admission, credential and signed lease, including expiry/suspend.
    pub fn data_ready(&mut self, now: UnixTime) -> bool {
        self.prune(now);
        self.active_local(now).is_ok()
    }

    /// Returns a locally held credential only after both signed directory and revocation state
    /// confirm it is the active generation. Used to finish an interrupted local rotation.
    pub fn confirmed_local_credential(&mut self, now: UnixTime) -> Option<SubjectCredential> {
        self.prune(now);
        if !self.recovery_ready() || !self.directory.has_revocations() {
            return None;
        }
        let active = self.directory.active(self.local, now)?;
        self.slots.iter().find_map(|slot| {
            (slot.credential == active.credential).then(|| slot.credential.clone())
        })
    }

    /// Invalidates transport state whose monotonic lifetime omitted system suspend.
    /// Root state, static credentials and the platform TUN remain installed.
    pub fn resume_after_suspend(&mut self) {
        self.configuration_active = false;
        self.configuration_clock.suspend();
        self.policy.set_ready(false);
        self.clear_pending();
        for slot in &mut self.slots {
            slot.engine.reset_sessions();
        }
        if self.connectivity.resume().is_err() {
            self.close();
        }
    }

    /// A carrier can attach only for a valid local credential whose data secret this owner holds.
    pub fn accepts_carrier(&self, credential: &SubjectCredential, now: UnixTime) -> bool {
        !self.closed
            && self.directory.verify_credential(credential, now).is_ok()
            && self.slots.iter().any(|slot| slot.credential == *credential)
    }
    pub(super) fn prune(&mut self, now: UnixTime) {
        self.prune_device_admission(now);
        if self.suspend_clock.resumed() {
            self.resume_after_suspend();
        }
        if self.configuration_active && !self.configuration_clock.valid(now.0, Instant::now()) {
            self.configuration_active = false;
            self.clear_pending();
            self.policy.set_ready(false);
            if let Some(checkpoint) = &mut self.checkpoint
                && checkpoint
                    .commit_authorization(self.configuration_clock.floor())
                    .is_err()
            {
                self.close();
            }
        }
        self.expire_resource_flows(now);
        if self.last_validation.is_some_and(|previous| now <= previous) {
            return;
        }
        self.last_validation = Some(now);
        let removed = self.directory.expire(now);
        let before = self.slots.len();
        self.slots.retain(|slot| {
            self.directory
                .verify_credential(&slot.credential, now)
                .is_ok()
                && (!slot.published || self.directory.get(&slot.engine.public_key(), now).is_some())
        });
        for slot in &mut self.slots {
            for key in &removed {
                slot.engine.remove(key);
            }
        }
        self.connectivity.retain(|local, remote| {
            self.directory.get(local, now).is_some_and(|key| key.active)
                && self
                    .directory
                    .get(remote, now)
                    .is_some_and(|key| key.active)
        });
        if !removed.is_empty() || before != self.slots.len() {
            self.clear_pending();
            if let Some(checkpoint) = &mut self.checkpoint
                && checkpoint.advance_expiry_floor(now).is_err()
            {
                self.close();
            }
        }
        self.policy.set_ready(self.active_local(now).is_ok());
    }
}
