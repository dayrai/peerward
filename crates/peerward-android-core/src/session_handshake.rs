impl NativeSession {
    /// Creates an IK initiator whose static DH calls the provider rather than
    /// importing private bytes.
    ///
    /// # Errors
    ///
    /// Fails closed when local trust, credentials, Noise keys, or the initial
    /// handshake payload are invalid.
    pub fn initiate(
        provider: Arc<dyn StaticDhProvider>,
        remote_noise_key: [u8; 32],
        local_credential: &SubjectCredential,
        attachment_id: [u8; 16],
        capabilities: u64,
        now: UnixTime,
        trust: MobileTrust,
    ) -> Result<(Self, Vec<u8>), MobileError> {
        Self::initiate_routed(
            provider,
            remote_noise_key,
            local_credential,
            attachment_id,
            capabilities,
            now,
            trust,
            None,
        )
    }

    /// Production shared-port handshake. The optional form exists for low-level crypto fixtures.
    pub fn initiate_routed(
        provider: Arc<dyn StaticDhProvider>,
        remote_noise_key: [u8; 32],
        local_credential: &SubjectCredential,
        attachment_id: [u8; 16],
        capabilities: u64,
        now: UnixTime,
        trust: MobileTrust,
        target: Option<peerward_types::RelayId>,
    ) -> Result<(Self, Vec<u8>), MobileError> {
        trust.credentials.verify_subject(local_credential, now)?;
        if local_credential.role != SubjectRole::Peer
            || local_credential.public_noise_key != provider.public_key()
            || local_credential.mesh_id != trust.mesh_id
        {
            return Err(MobileError::InvalidInput);
        }
        let SubjectId::Peer(local_peer) = local_credential.subject else {
            return Err(MobileError::InvalidInput);
        };
        let parameters: NoiseParams = IK_SUITE.parse()?;
        let resolver = AndroidResolver::new(Arc::clone(&provider));
        let preface = target.map(|target| peerward_wire::RelayPreface {
            mesh_id: trust.mesh_id,
            target,
            source: None,
        });
        let prologue = preface.map_or_else(
            || NOISE_PROLOGUE.to_vec(),
            peerward_wire::RelayPreface::prologue,
        );
        let mut handshake = Builder::with_resolver(parameters, Box::new(resolver))
            .prologue(&prologue)?
            .local_private_key(&KEYSTORE_MARKER)?
            .remote_public_key(&remote_noise_key)?
            .build_initiator()?;
        let hello = HandshakePayload {
            major: PROTOCOL_MAJOR,
            minor: 0,
            capabilities,
            credential: local_credential.encode(),
            attachment_id: attachment_id.to_vec(),
        };
        let mut first = vec![0; MAX_HANDSHAKE];
        let length = handshake.write_message(&hello.encode_to_vec(), &mut first)?;
        first.truncate(length);
        if let Some(preface) = preface {
            let mut prefaced = preface.encode().to_vec();
            prefaced.extend_from_slice(&first);
            first = prefaced;
        }
        let mesh = trust.mesh_id;
        let attachment_uuid =
            Uuid::from_slice(&attachment_id).map_err(|_| MobileError::InvalidInput)?;
        let attachment_id =
            AttachmentId::from_uuid(attachment_uuid).map_err(|_| MobileError::InvalidInput)?;
        let session =
            SessionManager::new(mesh, trust.distribution, local_credential.serial, 512, 3)?;
        let policy = PolicyEngine::new(mesh, local_peer, trust.distribution, 65_536, 16)?;
        let service_table = RemoteServiceTable::new(mesh, trust.services);
        Ok((
            Self {
                expected_relay: target,
                state: State::Handshake(Box::new(handshake)),
                trust,
                local_peer,
                current_credential: local_credential.clone(),
                pending_rotation: None,
                console_renewal: None,
                remote_noise_key,
                attachment_id,
                primary_attachment: capabilities & peerward_wire::PRIMARY_ATTACHMENT_CAPABILITY
                    != 0,
                chunks: DistributionAssemblers::new(mesh),
                session,
                policy: Arc::new(policy),
                wireguard: None,
                services: service_table,
                audit_counts: std::collections::BTreeMap::new(),
                pending_audit: None,
                pending_health: None,
                pending_management: None,
                evidence_acknowledged: None,
                management_acknowledged: Vec::new(),
            },
            first,
        ))
    }

    /// Authenticates the relay welcome credential before enabling records.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid state, malformed handshake, untrusted
    /// relay credential, wrong role/mesh/key, or incompatible wire version.
    pub fn finish_handshake(
        &mut self,
        response: &[u8],
        now: UnixTime,
        monotonic_seconds: u64,
    ) -> Result<u64, MobileError> {
        if response.is_empty() || response.len() > MAX_HANDSHAKE {
            return Err(MobileError::InvalidInput);
        }
        if response.starts_with(b"PWM1") {
            let terminal = peerward_credentials::MeshTermination::decode(response)?;
            self.trust
                .credentials
                .verify_termination(&terminal, 0, now)?;
            if let Some(owner) = &self.wireguard {
                owner.lock().map_err(|_| MobileError::InvalidState)?.close();
            }
            self.state = State::Closed;
            return Ok(0);
        }
        let State::Handshake(handshake) = std::mem::replace(&mut self.state, State::Closed) else {
            return Err(MobileError::InvalidState);
        };
        let mut handshake = *handshake;
        let mut plaintext = vec![0; MAX_HANDSHAKE];
        let length = handshake.read_message(response, &mut plaintext)?;
        plaintext.truncate(length);
        let welcome =
            HandshakePayload::decode(plaintext.as_slice()).map_err(WireError::MalformedControl)?;
        let negotiated = welcome.negotiate(
            peerward_wire::SUPPORTED_CAPABILITIES | peerward_wire::PRIMARY_ATTACHMENT_CAPABILITY,
        )?;
        let relay = SubjectCredential::decode(&welcome.credential)?;
        self.trust.credentials.verify_subject(&relay, now)?;
        if self
            .expected_relay
            .is_some_and(|target| relay.subject != SubjectId::Relay(target))
        {
            return Err(MobileError::InvalidInput);
        }
        let SubjectId::Relay(relay_id) = relay.subject else {
            return Err(MobileError::InvalidInput);
        };
        if relay.role != SubjectRole::Relay
            || relay.public_noise_key != self.remote_noise_key
            || relay.mesh_id != self.trust.mesh_id
        {
            return Err(MobileError::InvalidInput);
        }
        self.state = State::Transport(StreamTransport::from_handshake(
            handshake,
            monotonic_seconds,
        )?);
        self.session.attach(RelaySession {
            relay_id,
            attachment_id: self.attachment_id,
            role: if self.primary_attachment {
                AttachmentRole::Primary
            } else {
                AttachmentRole::Standby
            },
            fencing_generation: 0,
            rtt_millis: None,
            missed_keepalives: 0,
            connected: true,
        })?;
        Ok(negotiated)
    }

    /// Irreversibly closes this native handle.
    pub fn close(&mut self) {
        self.session.graceful_shutdown();
        if let Some(owner) = &self.wireguard
            && let Ok(mut owner) = owner.lock()
        {
            for (key, count) in std::mem::take(&mut self.audit_counts) {
                let total = owner.audit_counts.entry(key).or_default();
                *total = total.saturating_add(count);
            }
        }
        self.audit_counts.clear();
        self.pending_audit = None;
        self.pending_health = None;
        self.pending_management = None;
        self.state = State::Closed;
    }

    /// Returns the Relay currently selected by the shared failover state.
    #[must_use]
    pub fn primary_relay(&self) -> Option<peerward_types::RelayId> {
        self.session.primary().map(|relay| relay.relay_id)
    }

    /// Returns only state proven by the live Rust runtime, never profile-derived readiness.
    #[must_use]
    pub fn runtime_status(&self) -> MobileRuntimeStatus {
        let revisions = [
            self.trust.credentials.authority_revision(),
            self.chunks.peers.accepted_revision(),
            self.chunks.relays.accepted_revision(),
            self.chunks.policy.accepted_revision(),
            self.chunks.services.accepted_revision(),
            self.chunks.revocations.accepted_revision(),
        ];
        let data_ready = self.wireguard.as_ref().is_some_and(|owner| {
            owner
                .lock()
                .is_ok_and(|mut owner| owner.core.data_ready(UnixTime(wall_clock_seconds())))
        });
        let signed_state_complete = matches!(self.state, State::Transport(_))
            && revisions.iter().all(Option::is_some)
            && data_ready;
        let signed_revision = if signed_state_complete {
            revisions.into_iter().flatten().min().unwrap_or(0)
        } else {
            0
        };
        MobileRuntimeStatus {
            signed_state_complete,
            signed_revision,
        }
    }
}
