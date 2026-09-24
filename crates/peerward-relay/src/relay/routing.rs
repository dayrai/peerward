/// Presence-fenced opaque/control router. It never parses or stores IP packets.
pub struct OpaqueRouter {
    mesh_id: MeshId,
    relay_id: RelayId,
    verifier: DirectoryPublicKey,
    directory_revision: Option<u64>,
    relay_revision: Option<u64>,
    policy_revision: Option<u64>,
    attachments: BTreeMap<PeerId, Attachment>,
    directory_credentials: BTreeMap<PeerId, BTreeSet<CredentialSerial>>,
    revoked: BTreeSet<CredentialSerial>,
    control_queues: BTreeMap<PeerId, VecDeque<ControlEnvelope>>,
    known_fences: BTreeMap<PeerId, i64>,
    queue_capacity: usize,
}

impl OpaqueRouter {
    fn queued_usage(&self) -> (u64, u64) {
        self.control_queues.values().flatten().fold((0_u64, 0_u64), |(count, bytes), envelope| {
            (count.saturating_add(1), bytes.saturating_add(u64::try_from(envelope.encoded_len()).unwrap_or(u64::MAX)))
        })
    }
    /// Creates an empty mesh-isolated opaque forwarding table.
    pub fn new(
        mesh_id: MeshId,
        relay_id: RelayId,
        verifier: DirectoryPublicKey,
        queue_capacity: usize,
    ) -> Result<Self, RelayError> {
        if queue_capacity == 0 {
            return Err(RelayError::InvalidConfig);
        }
        Ok(Self {
            mesh_id,
            relay_id,
            verifier,
            directory_revision: None,
            relay_revision: None,
            policy_revision: None,
            attachments: BTreeMap::new(),
            directory_credentials: BTreeMap::new(),
            revoked: BTreeSet::new(),
            control_queues: BTreeMap::new(),
            known_fences: BTreeMap::new(),
            queue_capacity,
        })
    }

    /// Acquires storage-backed presence and installs the returned fence.
    pub async fn acquire(
        &mut self,
        store: &Store,
        lease: PresenceLease,
        credential_serial: CredentialSerial,
    ) -> Result<Attachment, RelayError> {
        if lease.mesh_id != self.mesh_id || lease.relay_id != self.relay_id {
            return Err(RelayError::NoRoute);
        }
        let generation = store.acquire_presence(&lease).await?;
        self.install_acquired(lease, credential_serial, generation)
    }

    /// Installs presence only after persistence completes.
    pub fn install_acquired(
        &mut self,
        lease: PresenceLease,
        credential_serial: CredentialSerial,
        generation: i64,
    ) -> Result<Attachment, RelayError> {
        if lease.mesh_id != self.mesh_id || lease.relay_id != self.relay_id {
            return Err(RelayError::NoRoute);
        }
        let attachment = Attachment {
            peer_id: lease.peer_id,
            attachment_id: lease.attachment_id,
            role: lease.role,
            generation,
            credential_serial,
        };
        if lease.role == PresenceRole::Primary {
            self.install_attachment(attachment);
        }
        Ok(attachment)
    }

    /// Renews only the exact generation that was acquired.
    pub async fn renew(
        &self,
        store: &Store,
        lease: &PresenceLease,
        generation: i64,
    ) -> Result<(), RelayError> {
        Self::persist_renewal(store, lease, generation).await
    }

    /// Persists a renewal without holding the router guard.
    pub async fn persist_renewal(
        store: &Store,
        lease: &PresenceLease,
        generation: i64,
    ) -> Result<(), RelayError> {
        store
            .renew_presence(lease, generation)
            .await
            .map_err(|error| match error {
                StoreError::Conflict | StoreError::SignedStateConflict { .. } => {
                    RelayError::StaleFence
                }
                other => RelayError::Store(other),
            })
    }

    /// Verifies a directory and retains only identity/credential admission data.
    pub fn install_directory(&mut self, update: &SignedPeerDirectory) -> Result<(), RelayError> {
        self.verifier
            .verify_peers(update, self.mesh_id, self.directory_revision)?;
        self.directory_credentials = update
            .directory
            .entries
            .iter()
            .filter(|entry| entry.entry.enabled)
            .map(|signed| {
                let entry = &signed.entry;
                let mut accepted: BTreeSet<_> = entry
                    .accepted_credentials
                    .iter()
                    .map(|credential| credential.serial)
                    .collect();
                accepted.insert(entry.credential_serial);
                (entry.peer_id, accepted)
            })
            .collect();
        self.directory_revision = Some(update.directory.revision);
        self.control_queues
            .retain(|peer, _| self.directory_credentials.contains_key(peer));
        Ok(())
    }

    /// Verifies and advances the Relay directory revision.
    pub fn install_relays(&mut self, update: &SignedRelayDirectory) -> Result<(), RelayError> {
        self.verifier
            .verify_relays(update, self.mesh_id, self.relay_revision)?;
        self.relay_revision = Some(update.directory.revision);
        Ok(())
    }

    /// Verifies policy distribution without decoding IP rules on the Relay.
    pub fn install_policy(&mut self, update: &SignedPolicyBundle) -> Result<(), RelayError> {
        self.verifier
            .verify_policy(update, self.mesh_id, self.policy_revision)?;
        self.policy_revision = Some(update.bundle.revision);
        Ok(())
    }

    /// Installs an already fenced primary attachment.
    pub fn install_attachment(&mut self, attachment: Attachment) {
        if attachment.role == PresenceRole::Primary
            && self
                .known_fences
                .get(&attachment.peer_id)
                .is_none_or(|current| attachment.generation >= *current)
        {
            self.known_fences
                .insert(attachment.peer_id, attachment.generation);
            self.attachments.insert(attachment.peer_id, attachment);
        }
    }

    /// Removes only the exact session generation.
    pub fn detach(&mut self, peer: PeerId, generation: i64) {
        if self
            .attachments
            .get(&peer)
            .is_some_and(|attachment| attachment.generation == generation)
        {
            self.attachments.remove(&peer);
            self.control_queues.remove(&peer);
        }
    }

    /// Learns a committed presence fence.
    pub fn observe_fence(&mut self, peer: PeerId, generation: i64) -> Result<(), RelayError> {
        if self
            .known_fences
            .get(&peer)
            .is_some_and(|current| generation < *current)
        {
            return Err(RelayError::StaleFence);
        }
        self.known_fences.insert(peer, generation);
        Ok(())
    }

    /// Revokes one credential and removes affected attachments and queues.
    pub fn revoke(&mut self, serial: CredentialSerial) {
        self.revoked.insert(serial);
        self.attachments
            .retain(|_, attachment| attachment.credential_serial != serial);
        self.control_queues.retain(|peer, _| {
            self.directory_credentials
                .get(peer)
                .is_none_or(|credentials| !credentials.contains(&serial))
        });
    }

    /// Queues one authenticated, bounded opaque/control message locally.
    pub fn route_control(&mut self, routed: RoutedControl) -> Result<(), RelayError> {
        self.validate_control_source(routed.source, routed.generation)?;
        self.validate_local_destination(routed.destination)?;
        self.enqueue(routed.destination, routed.envelope)
    }

    /// Routes from an exact live authenticated session, including a standby data link.
    pub fn route_authenticated_control(&mut self, routed: RoutedControl) -> Result<(), RelayError> {
        if !self.directory_credentials.contains_key(&routed.source) {
            return Err(RelayError::StaleFence);
        }
        self.validate_local_destination(routed.destination)?;
        self.enqueue(routed.destination, routed.envelope)
    }

    /// Queues cross-Relay opaque/control after source ownership is checked.
    pub fn accept_cross_relay_control(&mut self, routed: RoutedControl) -> Result<(), RelayError> {
        if !self.directory_credentials.contains_key(&routed.source) {
            return Err(RelayError::NoRoute);
        }
        self.validate_local_destination(routed.destination)?;
        self.enqueue(routed.destination, routed.envelope)
    }

    /// Receives one queued opaque/control message for a local primary.
    pub fn receive_control(
        &mut self,
        peer: PeerId,
        generation: i64,
    ) -> Result<Option<ControlEnvelope>, RelayError> {
        self.validate_control_source(peer, generation)?;
        Ok(self
            .control_queues
            .get_mut(&peer)
            .and_then(VecDeque::pop_front))
    }

    fn enqueue(
        &mut self,
        destination: PeerId,
        envelope: ControlEnvelope,
    ) -> Result<(), RelayError> {
        let queue = self.control_queues.entry(destination).or_default();
        if queue.len() >= self.queue_capacity {
            return Err(RelayError::QueueFull);
        }
        queue.push_back(envelope);
        Ok(())
    }

    fn validate_control_source(&self, source: PeerId, generation: i64) -> Result<(), RelayError> {
        let attachment = self
            .attachments
            .get(&source)
            .ok_or(RelayError::StaleFence)?;
        if attachment.generation != generation
            || self.known_fences.get(&source) != Some(&generation)
            || self.revoked.contains(&attachment.credential_serial)
            || self
                .directory_credentials
                .get(&source)
                .is_none_or(|credentials| !credentials.contains(&attachment.credential_serial))
        {
            return Err(RelayError::StaleFence);
        }
        Ok(())
    }

    fn validate_local_destination(&self, peer: PeerId) -> Result<(), RelayError> {
        let attachment = self.attachments.get(&peer).ok_or(RelayError::NoRoute)?;
        if attachment.role != PresenceRole::Primary
            || self.known_fences.get(&peer) != Some(&attachment.generation)
            || self.revoked.contains(&attachment.credential_serial)
            || self
                .directory_credentials
                .get(&peer)
                .is_none_or(|credentials| !credentials.contains(&attachment.credential_serial))
        {
            return Err(RelayError::NoRoute);
        }
        Ok(())
    }
}
