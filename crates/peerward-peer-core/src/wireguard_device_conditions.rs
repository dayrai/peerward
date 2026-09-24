use super::*;

impl WireguardRuntime {
    #[cfg(test)]
    pub(crate) fn elapse_admission_for_test(&mut self, seconds: u64) {
        self.admission_anchor.1 -= std::time::Duration::from_secs(seconds);
    }
    /// A data-plane admission restriction. The authenticated Relay control channel
    /// remains available for fresh evidence, configuration and credential recovery.
    pub fn device_admitted(&self, peer: PeerId, wall: UnixTime) -> bool {
        self.configuration_active
            && self.configuration.as_ref().is_some_and(|delivery| {
                delivery
                    .resources
                    .admission
                    .permits(peer, self.admission_now(wall))
            })
    }

    pub(super) fn prune_device_admission(&mut self, wall: UnixTime) {
        let now = self.admission_now(wall);
        if now
            > self
                .admission_anchor
                .0
                .saturating_add(self.admission_anchor.1.elapsed().as_secs())
        {
            self.admission_anchor = (now, Instant::now());
        }
        self.admission_floor = now;
        let allowed = self
            .configuration
            .as_ref()
            .filter(|delivery| delivery.resources.admission.enabled)
            .map(|delivery| {
                delivery
                    .resources
                    .admission
                    .peers
                    .iter()
                    .filter_map(|(peer, decision)| {
                        decision.permits(self.admission_floor).then_some(*peer)
                    })
                    .collect()
            });
        if self.admission_permitted != allowed {
            self.admission_permitted = allowed;
            self.clear_pending();
            if let Some(checkpoint) = &mut self.checkpoint
                && checkpoint
                    .advance_expiry_floor(UnixTime(self.admission_floor))
                    .is_err()
            {
                self.close();
            }
        }
    }

    fn admission_now(&self, wall: UnixTime) -> u64 {
        wall.0
            .max(self.admission_floor)
            .max(
                self.admission_anchor
                    .0
                    .saturating_add(self.admission_anchor.1.elapsed().as_secs()),
            )
            .max(self.checkpoint.as_ref().map_or(0, |c| c.time_floor().0))
    }
}
