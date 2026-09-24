struct DistributionAssemblers {
    configuration: ChunkAssembler,
    authorities: ChunkAssembler,
    peers: ChunkAssembler,
    relays: ChunkAssembler,
    policy: ChunkAssembler,
    services: ChunkAssembler,
    revocations: ChunkAssembler,
}

impl DistributionAssemblers {
    fn new(mesh: MeshId) -> Self {
        let bounded = || ChunkAssembler::new(mesh, MAX_SIGNED_STATE_CHUNKS, MAX_SIGNED_STATE_BYTES);
        Self {
            configuration: bounded(),
            authorities: bounded(),
            peers: bounded(),
            relays: bounded(),
            policy: bounded(),
            services: bounded(),
            revocations: bounded(),
        }
    }
}

impl NativeSession {
    /// Reports the soft link-key boundary while the old link remains usable.
    ///
    /// # Errors
    ///
    /// Returns an error unless the authenticated transport is active.
    pub fn link_replacement_due(&self, monotonic_seconds: u64) -> Result<bool, MobileError> {
        let State::Transport(transport) = &self.state else {
            return Err(MobileError::InvalidState);
        };
        Ok(transport.rekey_due(monotonic_seconds))
    }

    /// Authenticates the Relay's post-presence readiness confirmation.
    ///
    /// # Errors
    ///
    /// Returns an error for an inactive transport or invalid readiness record.
    pub fn confirm_link_ready(
        &mut self,
        frame: &[u8],
        monotonic_seconds: u64,
    ) -> Result<(), MobileError> {
        let (record, _) = self.decrypt(frame, monotonic_seconds)?;
        match record {
            Record::Control(ControlEnvelope {
                trace_context: _,
                message: Some(ControlMessage::Welcome(peerward_wire::Welcome { mesh_id, body })),
            }) if mesh_id == self.trust.mesh_id.as_bytes() && body == b"link_ready" => Ok(()),
            _ => Err(MobileError::InvalidInput),
        }
    }

    fn apply_control(&mut self, envelope: &ControlEnvelope) -> Result<AcceptedUpdate, MobileError> {
        envelope
            .correlation_context()
            .map_err(|_| MobileError::InvalidInput)?;
        match envelope.message.as_ref() {
            Some(ControlMessage::CredentialRenewal(message)) => {
                if message.body.len() > 2048 {
                    return Err(MobileError::InvalidInput);
                }
                let signed: peerward_management::SignedCredentialRenewal =
                    serde_json::from_slice(&message.body).map_err(|_| MobileError::InvalidInput)?;
                let now = wall_clock_seconds();
                self.trust
                    .credentials
                    .verify_distribution(&self.trust.binding, UnixTime(now))?;
                signed
                    .verify(
                        &self.trust.binding.directory_public_key,
                        self.trust.mesh_id,
                        self.local_peer,
                        self.current_credential.serial,
                        now,
                    )
                    .map_err(|_| MobileError::InvalidInput)?;
                self.console_renewal = Some(signed);
                Ok(AcceptedUpdate::CredentialRenewalRequested)
            }
            Some(ControlMessage::PeerManagementResult(result)) => {
                self.management_result(result);
                Ok(AcceptedUpdate::Control)
            }
            Some(ControlMessage::Close(close)) if close.body.starts_with(b"PWM1") => {
                if close.mesh_id != self.trust.mesh_id.as_bytes() {
                    return Err(MobileError::InvalidInput);
                }
                let terminal = peerward_credentials::MeshTermination::decode(&close.body)?;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|_| MobileError::InvalidState)?
                    .as_secs();
                self.trust
                    .credentials
                    .verify_termination(&terminal, 0, UnixTime(now))?;
                if let Some(owner) = &self.wireguard {
                    owner.lock().map_err(|_| MobileError::InvalidState)?.close();
                }
                Ok(AcceptedUpdate::Terminated(close.body.clone()))
            }
            Some(ControlMessage::AuthorityDirectory(chunk)) => self.apply_authority_chunk(
                &chunk.mesh_id,
                chunk.revision,
                chunk.index,
                chunk.count,
                &chunk.body,
            ),
            Some(ControlMessage::Configuration(chunk)) => {
                self.validate_mesh(&chunk.mesh_id)?;
                let complete = self.chunks.configuration.push(RevisionChunk {
                    mesh_id: self.trust.mesh_id,
                    revision: chunk.revision,
                    index: chunk.index,
                    count: chunk.count,
                    body: chunk.body.clone(),
                })?;
                let Some(bytes) = complete else {
                    return Ok(AcceptedUpdate::Control);
                };
                let delivery: peerward_management::ConfigurationDelivery =
                    serde_json::from_slice(&bytes).map_err(|_| MobileError::InvalidInput)?;
                if delivery.lease.lease.sequence != chunk.revision || self.wireguard.is_none() {
                    return Err(MobileError::InvalidState);
                }
                self.shared_update(7, chunk.revision, &bytes, |core| {
                    core.install_configuration(
                        delivery,
                        UnixTime(wall_clock_seconds()),
                        std::time::Instant::now(),
                    )
                    .map(|_| ())
                })?;
                self.chunks.configuration.commit(chunk.revision)?;
                Ok(AcceptedUpdate::Control)
            }
            Some(ControlMessage::PeerDirectory(chunk)) => self.apply_peer_chunk(
                &chunk.mesh_id,
                chunk.revision,
                chunk.index,
                chunk.count,
                &chunk.body,
            ),
            Some(ControlMessage::Policy(policy)) => self.apply_policy_update(
                &policy.mesh_id,
                policy.revision,
                policy.index,
                policy.count,
                &policy.body,
            ),
            Some(ControlMessage::RelayDirectory(chunk)) => self.apply_relay_chunk(
                &chunk.mesh_id,
                chunk.revision,
                chunk.index,
                chunk.count,
                &chunk.body,
            ),
            Some(ControlMessage::Services(snapshot)) => self.apply_service_chunk(
                &snapshot.mesh_id,
                snapshot.revision,
                snapshot.index,
                snapshot.count,
                &snapshot.body,
            ),
            Some(ControlMessage::Revocation(revocation)) => self.apply_revocation_update(
                &revocation.mesh_id,
                revocation.revision,
                revocation.index,
                revocation.count,
                &revocation.body,
            ),
            Some(ControlMessage::Replacement(replacement)) => {
                self.accept_credential_replacement(replacement)
            }
            Some(_) => Ok(AcceptedUpdate::Control),
            None => Err(MobileError::InvalidInput),
        }
    }

    fn apply_authority_chunk(
        &mut self,
        mesh_id: &[u8],
        revision: u64,
        index: u32,
        count: u32,
        body: &[u8],
    ) -> Result<AcceptedUpdate, MobileError> {
        self.validate_mesh(mesh_id)?;
        let complete = self.chunks.authorities.push(RevisionChunk {
            mesh_id: self.trust.mesh_id,
            revision,
            index,
            count,
            body: body.to_vec(),
        })?;
        let Some(bytes) = complete else {
            return Ok(AcceptedUpdate::Control);
        };
        let signed = SignedAuthorityBundle::decode(&bytes)?;
        if signed.bundle.revision != revision {
            return Err(MobileError::InvalidInput);
        }
        let now = UnixTime(wall_clock_seconds());
        self.shared_update(1, revision, &bytes, |core| core.authorities(&signed, now))?;
        self.trust
            .credentials
            .install_authority_bundle_after_resume(&signed, now)?;
        self.chunks.authorities.commit(revision)?;
        if self
            .trust
            .credentials
            .verify_subject(&self.current_credential, now)
            .is_err()
        {
            self.state = State::Closed;
            return Err(MobileError::Peer(PeerError::Revoked));
        }
        let certificates = std::iter::once(&signed.bundle.active)
            .chain(signed.bundle.overlap.iter())
            .map(peerward_credentials::AuthorityCertificate::encode)
            .collect();
        Ok(AcceptedUpdate::Authorities(AuthorityTrustUpdate {
            revision,
            certificates,
        }))
    }

    fn apply_peer_chunk(
        &mut self,
        mesh_id: &[u8],
        revision: u64,
        index: u32,
        count: u32,
        body: &[u8],
    ) -> Result<AcceptedUpdate, MobileError> {
        self.validate_mesh(mesh_id)?;
        let complete = self.chunks.peers.push(RevisionChunk {
            mesh_id: self.trust.mesh_id,
            revision,
            index,
            count,
            body: body.to_vec(),
        })?;
        let Some(bytes) = complete else {
            return Ok(AcceptedUpdate::Control);
        };
        let signed = decode_peer_directory(&bytes)?;
        if signed.directory.revision != revision {
            return Err(MobileError::InvalidInput);
        }
        if self.wireguard.is_some() {
            self.shared_update(2, revision, &bytes, |core| {
                core.install_directory(&signed, UnixTime(wall_clock_seconds()))
            })?;
        } else {
            self.policy.install_directory(&signed)?;
        }
        self.session.apply_peers(&signed)?;
        self.chunks.peers.commit(revision)?;
        if let Some(credential) = self.activated_credential_in_directory(&signed) {
            Ok(AcceptedUpdate::CredentialActivated(credential))
        } else {
            Ok(AcceptedUpdate::PeerDirectory(revision))
        }
    }

    fn apply_policy_update(
        &mut self,
        mesh_id: &[u8],
        revision: u64,
        index: u32,
        count: u32,
        body: &[u8],
    ) -> Result<AcceptedUpdate, MobileError> {
        self.validate_mesh(mesh_id)?;
        let complete = self.chunks.policy.push(RevisionChunk {
            mesh_id: self.trust.mesh_id,
            revision,
            index,
            count,
            body: body.to_vec(),
        })?;
        let Some(bytes) = complete else {
            return Ok(AcceptedUpdate::Control);
        };
        let signed = decode_policy(&bytes)?;
        if signed.bundle.revision != revision {
            return Err(MobileError::InvalidInput);
        }
        if self.wireguard.is_some() {
            self.shared_update(3, revision, &bytes, |core| {
                core.install_policy(&signed).map(|_| ())
            })?;
        } else {
            self.policy.install_policy(&signed)?;
        }
        self.session.apply_policy(&signed)?;
        self.chunks.policy.commit(revision)?;
        Ok(AcceptedUpdate::Policy(revision))
    }

    fn apply_relay_chunk(
        &mut self,
        mesh_id: &[u8],
        revision: u64,
        index: u32,
        count: u32,
        body: &[u8],
    ) -> Result<AcceptedUpdate, MobileError> {
        self.validate_mesh(mesh_id)?;
        let complete = self.chunks.relays.push(RevisionChunk {
            mesh_id: self.trust.mesh_id,
            revision,
            index,
            count,
            body: body.to_vec(),
        })?;
        let Some(bytes) = complete else {
            return Ok(AcceptedUpdate::Control);
        };
        let signed = decode_relay_directory(&bytes)?;
        if signed.directory.revision != revision {
            return Err(MobileError::InvalidInput);
        }
        self.session.apply_relays(&signed)?;
        let canonical = peerward_directory::encode_relay_directory(&signed)?;
        self.shared_update(6, revision, &canonical, |core| {
            core.checkpoint_verified_snapshot(
                peerward_peer_core::SnapshotKind::Relays,
                revision,
                &canonical,
                UnixTime(wall_clock_seconds()),
            )
        })?;
        self.chunks.relays.commit(revision)?;
        Ok(AcceptedUpdate::RelayDirectory(revision))
    }

    fn apply_service_chunk(
        &mut self,
        mesh_id: &[u8],
        revision: u64,
        index: u32,
        count: u32,
        body: &[u8],
    ) -> Result<AcceptedUpdate, MobileError> {
        self.validate_mesh(mesh_id)?;
        let complete = self.chunks.services.push(RevisionChunk {
            mesh_id: self.trust.mesh_id,
            revision,
            index,
            count,
            body: body.to_vec(),
        })?;
        let Some(bytes) = complete else {
            return Ok(AcceptedUpdate::Control);
        };
        let signed: peerward_service::SignedRemoteServiceSnapshot =
            serde_json::from_slice(&bytes).map_err(|_| MobileError::InvalidInput)?;
        if signed.snapshot.mesh_id != self.trust.mesh_id || signed.snapshot.revision != revision {
            return Err(MobileError::InvalidInput);
        }
        if let Some(owner) = &self.wireguard {
            owner
                .lock()
                .map_err(|_| MobileError::InvalidState)?
                .accept_update(5, revision, &bytes, |owner| {
                    let mut candidate = owner.services.clone();
                    for serial in owner.core.revoked_credentials() {
                        candidate.revoke_credential(serial);
                    }
                    candidate.reconcile(&signed)?;
                    let canonical =
                        serde_json::to_vec(&signed).map_err(|_| MobileError::InvalidInput)?;
                    owner.core.checkpoint_verified_snapshot(
                        peerward_peer_core::SnapshotKind::Services,
                        revision,
                        &canonical,
                        UnixTime(wall_clock_seconds()),
                    )?;
                    owner.services = candidate;
                    Ok(())
                })?;
        } else {
            self.services.reconcile(&signed)?;
        }
        self.chunks.services.commit(revision)?;
        Ok(AcceptedUpdate::Services)
    }

    fn apply_revocation_update(
        &mut self,
        mesh_id: &[u8],
        revision: u64,
        index: u32,
        count: u32,
        body: &[u8],
    ) -> Result<AcceptedUpdate, MobileError> {
        self.validate_mesh(mesh_id)?;
        let complete = self.chunks.revocations.push(RevisionChunk {
            mesh_id: self.trust.mesh_id,
            revision,
            index,
            count,
            body: body.to_vec(),
        })?;
        let Some(bytes) = complete else {
            return Ok(AcceptedUpdate::Control);
        };
        let signed = decode_revocations(&bytes)?;
        if signed.bundle.revision != revision {
            return Err(MobileError::InvalidInput);
        }
        if let Some(owner) = &self.wireguard {
            owner
                .lock()
                .map_err(|_| MobileError::InvalidState)?
                .accept_update(4, revision, &bytes, |owner| {
                    owner.core.revoke(&signed, UnixTime(wall_clock_seconds()))?;
                    for serial in &signed.bundle.serials {
                        owner.services.revoke_credential(*serial);
                    }
                    Ok(())
                })?;
        }
        let active_revoked = self.session.apply_revocations(&signed)?;
        for serial in &signed.bundle.serials {
            self.trust.credentials.revoke_subject(*serial);
            self.services.revoke_credential(*serial);
        }
        if active_revoked {
            self.state = State::Closed;
            return Err(MobileError::Peer(PeerError::Revoked));
        }
        self.chunks.revocations.commit(revision)?;
        Ok(AcceptedUpdate::Revocations(revision))
    }

    fn validate_mesh(&self, mesh: &[u8]) -> Result<(), MobileError> {
        if mesh == self.trust.mesh_id.as_bytes() {
            Ok(())
        } else {
            Err(MobileError::InvalidInput)
        }
    }
}

fn wall_clock_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}
