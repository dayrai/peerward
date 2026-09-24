use super::*;
use crate::SnapshotKind;
use peerward_management::{ComponentReference, ConfigurationDelivery, ConfigurationPart};
use sha2::{Digest as _, Sha256};

impl WireguardRuntime {
    /// DNS traffic to a managed destination must use the TUN even while its path is unavailable.
    pub fn dns_requires_tunnel(
        &mut self,
        address: std::net::IpAddr,
        wall: UnixTime,
    ) -> Result<bool, PeerError> {
        self.prune(wall);
        if !self.configuration_active {
            return Err(PeerError::PolicyDenied);
        }
        Ok(self.preferences.exit_resource.is_some()
            || self.directory.destination(address, wall).is_some()
            || self.configuration.as_ref().is_some_and(|delivery| {
                delivery.resources.withdrawals.iter().any(|withdrawal| {
                    matches!(
                        withdrawal.target,
                        peerward_management::ResourceTarget::Subnet { .. }
                    ) && withdrawal.target.contains(address)
                }) || delivery.resources.resources.iter().any(|resource| {
                    match resource.definition.target {
                        peerward_management::ResourceTarget::Subnet { prefix, .. } => {
                            prefix.contains(&address)
                        }
                        peerward_management::ResourceTarget::Internet { .. } => {
                            self.preferences.exit_resource == Some(resource.id)
                        }
                    }
                })
            }))
    }
    /// Resolves scoped DNS only under a live authorization, for the actual local device.
    /// A conflicting profile or expired lease is an error, never public DNS fallback.
    pub fn effective_dns(
        &mut self,
        source: std::net::IpAddr,
        wall: UnixTime,
    ) -> Result<(u64, Arc<peerward_management::EffectiveDns>), PeerError> {
        if !self.local_source_authorized(source, wall) || !self.preferences.accept_dns {
            return Err(PeerError::PolicyDenied);
        }
        let peer = self
            .policy
            .descriptor(source)
            .ok_or(PeerError::PolicyDenied)?;
        if peer.id != self.local {
            return Err(PeerError::PolicyDenied);
        }
        let delivery = self.configuration.as_ref().ok_or(PeerError::PolicyDenied)?;
        let version = delivery.manifest.manifest.version;
        if let Some((cached_version, address, dns)) = &self.dns_cache
            && *cached_version == version
            && *address == source
        {
            return Ok((version, Arc::clone(dns)));
        }
        let dns = peerward_management::EffectiveDns::for_peer(
            &delivery.dns,
            self.local,
            source,
            &peer.labels,
        )
        .map_err(|_| PeerError::InvalidConfig)?;
        let dns = Arc::new(dns);
        self.dns_cache = Some((version, source, Arc::clone(&dns)));
        Ok((version, dns))
    }

    pub fn dns_system_fallback_allowed(&mut self, wall: UnixTime) -> bool {
        self.prune(wall);
        self.configuration_active && self.preferences.exit_resource.is_none()
    }

    pub const fn local_peer(&self) -> PeerId {
        self.local
    }

    /// Reserves an operation number from the durable startup range before a signature is created.
    pub fn next_management_sequence(&mut self) -> Result<u64, PeerError> {
        let next = self
            .management_sequence
            .checked_add(1)
            .filter(|next| *next < self.management_ceiling && i64::try_from(*next).is_ok())
            .ok_or(PeerError::InvalidConfig)?;
        self.management_sequence = next;
        Ok(next)
    }
    /// Verified component stamps for diagnostics and application receipts.
    pub fn configuration_dependencies(&self) -> BTreeMap<ConfigurationPart, ComponentReference> {
        self.configuration_parts.clone()
    }
    pub fn authorization_floor(&self) -> &peerward_management::AuthorizationFloor {
        self.configuration_clock.floor()
    }
    pub(super) fn record_configuration_part(
        &mut self,
        kind: SnapshotKind,
        version: u64,
        bytes: &[u8],
    ) {
        let part = match kind {
            SnapshotKind::Authorities => ConfigurationPart::Authorities,
            SnapshotKind::Peers => ConfigurationPart::Peers,
            SnapshotKind::Policy => ConfigurationPart::Policy,
            SnapshotKind::Revocations => ConfigurationPart::Revocations,
            _ => return,
        };
        let reference = ComponentReference {
            version,
            digest: Sha256::digest(bytes).into(),
        };
        if self.configuration_parts.get(&part) != Some(&reference) {
            self.configuration_parts.insert(part, reference);
            self.configuration_active = false;
            self.configuration_clock.invalidate();
            self.policy.set_ready(false);
            self.clear_pending();
        }
    }

    /// Installs only after signature, dependency, monotonic lease and durable-floor checks.
    pub fn install_configuration(
        &mut self,
        delivery: ConfigurationDelivery,
        wall: UnixTime,
        now: Instant,
    ) -> Result<bool, PeerError> {
        if self.closed {
            return Err(PeerError::Closed);
        }
        delivery
            .validate_payload()
            .map_err(|_| PeerError::InvalidConfig)?;
        let mut parts = self.configuration_parts.clone();
        for part in [ConfigurationPart::Resources, ConfigurationPart::Dns] {
            parts.insert(
                part,
                delivery
                    .manifest
                    .manifest
                    .parts
                    .get(&part)
                    .ok_or(PeerError::InvalidConfig)?
                    .clone(),
            );
        }
        let key = ed25519_dalek::VerifyingKey::from_bytes(&self.configuration_key)
            .map_err(|_| PeerError::InvalidConfig)?;
        if self
            .pending_configuration
            .as_ref()
            .is_some_and(|pending| pending.lease.lease.sequence > delivery.lease.lease.sequence)
        {
            return Err(PeerError::InvalidConfig);
        }
        let changed = match self.configuration_clock.install(
            &delivery.manifest,
            &delivery.lease,
            &key,
            self.mesh,
            &parts,
            wall.0,
            now,
        ) {
            Ok(changed) => changed,
            Err(peerward_management::ManagementError::Incomplete) => {
                // Multiple Relay streams can interleave revisions. Keep the authenticated set
                // pending and stop traffic until all independently verified dependencies arrive.
                if let Some(checkpoint) = &mut self.checkpoint
                    && let Err(error) =
                        checkpoint.commit_authorization(self.configuration_clock.floor())
                {
                    self.close();
                    return Err(error);
                }
                self.pending_configuration = Some(delivery);
                self.configuration_active = false;
                self.configuration_clock.invalidate();
                self.clear_pending();
                self.policy.set_ready(false);
                return Ok(false);
            }
            Err(_) => return Err(PeerError::InvalidConfig),
        };
        if !changed {
            return Ok(false);
        }
        if let Some(checkpoint) = &mut self.checkpoint
            && let Err(error) = checkpoint.commit_authorization(self.configuration_clock.floor())
        {
            self.close();
            return Err(error);
        }
        if self.configuration.as_ref().is_none_or(|previous| {
            !previous.resources.same_grants(&delivery.resources)
                || previous.dns != delivery.dns
                || previous.lease.lease.valid_until - previous.lease.lease.issued_at
                    != delivery.lease.lease.valid_until - delivery.lease.lease.issued_at
        }) {
            self.clear_pending();
        }
        if self.resource_platform != resources::PlatformState::Unmanaged
            && self
                .configuration
                .as_ref()
                .is_none_or(|previous| !previous.resources.same_grants(&delivery.resources))
        {
            self.resource_platform = resources::PlatformState::Pending;
        }
        self.configuration = Some(delivery);
        self.pending_configuration = None;
        self.configuration_active = true;
        self.last_validation = None;
        self.prune(wall);
        self.policy.set_ready(self.active_local(wall).is_ok());
        Ok(true)
    }

    pub(super) fn reconcile_configuration(&mut self, wall: UnixTime) -> Result<(), PeerError> {
        if let Some(delivery) = self.pending_configuration.take() {
            self.install_configuration(delivery, wall, Instant::now())?;
        }
        Ok(())
    }

    /// Returns only a live, verified intent. Missing state never grants platform forwarding.
    pub fn resource_network_configuration(
        &mut self,
        wall: UnixTime,
    ) -> Option<(
        peerward_management::ResourceConfiguration,
        peerward_management::ClientPreferences,
    )> {
        self.prune(wall);
        if !self.configuration_active {
            return None;
        }
        Some((
            self.configuration.as_ref()?.resources.clone(),
            self.preferences.clone(),
        ))
    }

    /// Only acknowledges the shared core. Platform adapters must separately acknowledge
    /// installed routes, DNS and firewall state after their own transaction succeeds.
    pub fn core_application_receipt(
        &mut self,
        wall: UnixTime,
    ) -> Option<peerward_management::PeerOperation> {
        self.prune(wall);
        if !self.configuration_active {
            return None;
        }
        let delivery = self.configuration.as_ref()?;
        Some(peerward_management::PeerOperation::Applied {
            category: peerward_management::ApplicationCategory::Core,
            configuration_version: delivery.manifest.manifest.version,
            configuration_digest: delivery.lease.lease.configuration_digest,
            lease_sequence: delivery.lease.lease.sequence,
            result: peerward_management::ApplicationResult::Applied,
            reason: None,
        })
    }

    /// Report a live application, or request fresh authorization after restart/suspend.
    /// Replayed leases never regain their lost monotonic lifetime.
    pub fn core_management_receipt(
        &mut self,
        wall: UnixTime,
    ) -> Option<peerward_management::PeerOperation> {
        if let Some(applied) = self.core_application_receipt(wall) {
            return Some(applied);
        }
        let floor = self.configuration_clock.floor();
        if self.closed || floor.lease_sequence == 0 {
            return None;
        }
        Some(peerward_management::PeerOperation::Applied {
            category: peerward_management::ApplicationCategory::Core,
            configuration_version: floor.configuration_version,
            configuration_digest: floor.configuration_digest,
            lease_sequence: floor.lease_sequence,
            result: peerward_management::ApplicationResult::Rejected,
            reason: Some(peerward_management::FRESH_AUTHORIZATION_REQUIRED.into()),
        })
    }

    /// Read-only local status; absent acknowledgement must not be displayed as applied.
    pub fn configuration_status(&self) -> Option<(u64, u64, bool)> {
        self.configuration.as_ref().map(|delivery| {
            (
                delivery.manifest.manifest.version,
                delivery.lease.lease.sequence,
                self.configuration_active,
            )
        })
    }
}
