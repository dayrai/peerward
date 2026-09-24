/// Selects staged files without changing the committed identity. Call journal recovery first.
pub fn staged_peer_identity_config(config: &PeerConfig) -> Result<Option<PeerConfig>, PeerError> {
    let marker = adjacent_path(&config.private_key_file, "rotation");
    if !marker.exists() {
        return Ok(None);
    }
    let bytes = peerward_credentials::private_files::read_private(&marker, 128)?;
    let state = std::str::from_utf8(&bytes).map_err(|_| PeerError::InvalidConfig)?;
    if state.starts_with("requested:") {
        return Ok(None);
    }
    state
        .strip_prefix("staged:")
        .ok_or(PeerError::InvalidConfig)?
        .parse::<RotationId>()
        .map_err(|_| PeerError::InvalidConfig)?;
    let mut candidate = config.clone();
    candidate.credential_file = adjacent_path(&config.credential_file, "next");
    candidate.identity_private_key_file = adjacent_path(&config.identity_private_key_file, "next");
    candidate.private_key_file = adjacent_path(&config.private_key_file, "next");
    candidate.wireguard_private_key_file =
        adjacent_path(&config.wireguard_private_key_file, "next");
    Ok(Some(candidate))
}

/// Tries the staged identity on an authenticated Relay before the expired old identity is loaded.
/// Nothing is committed until current signed directory AND revocation state authorize it.
/// A staged-but-not-activated identity falls back to the normal old-identity activation flow.
pub async fn recover_activated_peer_identity(
    config: &PeerConfig,
    trust: Arc<TrustSet>,
) -> Result<bool, PeerError> {
    let Some(candidate) = staged_peer_identity_config(config)? else {
        return Ok(false);
    };
    let credential_bytes =
        peerward_credentials::private_files::read_private(&candidate.credential_file, 225)?;
    let credential = SubjectCredential::decode(&credential_bytes)?;
    let private = zeroize::Zeroizing::new(
        read_identity_private_key(&candidate.private_key_file).map_err(packet_error_to_peer)?,
    );
    let data_private = zeroize::Zeroizing::new(
        read_identity_private_key(&candidate.wireguard_private_key_file)
            .map_err(packet_error_to_peer)?,
    );
    let distribution = peerward_credentials::DistributionCertificate::decode(
        &peerward_credentials::private_files::read_bounded_regular_file(
            config
                .distribution_certificate_file
                .as_ref()
                .ok_or(PeerError::InvalidConfig)?,
            65_536,
        )?,
    )?;
    let now = UnixTime(wall_clock_seconds());
    let terminal_path = config.private_key_file.with_extension("mesh-terminated");
    if terminal_path.exists() {
        let body = peerward_credentials::private_files::read_private(&terminal_path, 228)?;
        let terminal = peerward_credentials::MeshTermination::decode(&body)?;
        trust.verify_termination(&terminal, 0, now)?;
        return Err(PeerError::MeshTerminated(body));
    }
    trust.verify_subject(&credential, now)?;
    if credential.mesh_id != config.mesh_id
        || credential.subject != SubjectId::Peer(config.peer_id)
        || credential.public_noise_key
            != x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(*private)).to_bytes()
    {
        return Err(PeerError::InvalidConfig);
    }
            let mut runtime = peerward_peer_core::WireguardRuntime::new(
                config.mesh_id,
                config.peer_id,
                (*trust).clone(),
                &distribution,
                credential.clone(),
                x25519_dalek::StaticSecret::from(*data_private),
                1280,
                1024,
                1,
                UnixTime(wall_clock_seconds()),
            )?;
            runtime.enable_checkpoint(&config.private_key_file.with_extension("wireguard-state"), UnixTime(wall_clock_seconds()))?;
    let mut carrier_trust = (*trust).clone();
    runtime.restore_carrier_trust(&mut carrier_trust)?;
    let trust = Arc::new(carrier_trust);
    let attempt = async {
        for target in &config.relays {
            let remote = hex::decode(&target.public_key)
                .map_err(|_| PeerError::InvalidConfig)?
                .try_into()
                .map_err(|_| PeerError::InvalidConfig)?;
            let connected = crate::RelayEndpointPool::default().with_options(config.relay_transport.clone())
                .connect_trusted(
                    &target.endpoints,
                    &private,
                    &remote,
                    target.relay_id,
                    config.mesh_id,
                    &trust,
                    UnixTime(wall_clock_seconds()),
                    HandshakePayload {
                        major: peerward_wire::PROTOCOL_MAJOR,
                        minor: 0,
                        capabilities: peerward_wire::SUPPORTED_CAPABILITIES
                            | peerward_wire::PRIMARY_ATTACHMENT_CAPABILITY,
                        credential: credential_bytes.clone(),
                        attachment_id: peerward_types::AttachmentId::new().as_bytes().to_vec(),
                    },
                )
                .await;
            let (mut socket, mut transport, _) = match connected {
                Ok(value) => value,
                Err(PeerError::MeshTerminated(body)) => {
                    return Err(PeerError::MeshTerminated(body));
                }
                Err(_) => continue,
            };
            let mut recovery = RecoveryDistributions::new(config.mesh_id, Arc::clone(&trust));
            loop {
                let record = crate::read_noise_record(&mut socket, &mut transport).await?;
                if let Record::Control(envelope) = record {
                    recovery.apply(&envelope, &mut runtime, UnixTime(wall_clock_seconds()))?;
                } else {
                    return Err(PeerError::InvalidConfig);
                }
                if runtime
                    .confirmed_local_credential(UnixTime(wall_clock_seconds()))
                    .as_ref()
                    == Some(&credential)
                {
                    verify_staged_commit(&candidate, &credential)?;
                    commit_staged_peer_identity(
                        &config.identity_private_key_file,
                        &config.private_key_file,
                        &config.wireguard_private_key_file,
                        &config.credential_file,
                    )
                    .map_err(packet_error_to_peer)?;
                    return Ok(true);
                }
            }
        }
        Ok(false)
    };
    match tokio::time::timeout(Duration::from_secs(3), attempt).await {
        Ok(Err(PeerError::MeshTerminated(body))) => {
            peerward_credentials::private_files::write_private_atomic(
                &config.private_key_file.with_extension("mesh-terminated"),
                &body,
            )?;
            Err(PeerError::MeshTerminated(body))
        }
        Ok(value) => value,
        Err(_) => Ok(false),
    }
}

fn verify_staged_commit(
    candidate: &PeerConfig,
    credential: &SubjectCredential,
) -> Result<(), PeerError> {
    if peerward_credentials::private_files::read_private(&candidate.credential_file, 225)?
        != credential.encode()
    {
        return Err(PeerError::InvalidConfig);
    }
    let identity = zeroize::Zeroizing::new(
        read_identity_private_key(&candidate.identity_private_key_file)
            .map_err(packet_error_to_peer)?,
    );
    let noise = zeroize::Zeroizing::new(
        read_identity_private_key(&candidate.private_key_file).map_err(packet_error_to_peer)?,
    );
    let data = zeroize::Zeroizing::new(
        read_identity_private_key(&candidate.wireguard_private_key_file)
            .map_err(packet_error_to_peer)?,
    );
    if IdentitySigningKey::from_bytes(&identity)
        .verifying_key()
        .to_bytes()
        != credential.identity_public_key
        || x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(*noise)).to_bytes()
            != credential.public_noise_key
        || x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(*data)).to_bytes()
            != credential.wireguard_public_key
    {
        return Err(PeerError::InvalidConfig);
    }
    Ok(())
}

struct RecoveryDistributions {
    mesh: MeshId,
    trust: Arc<TrustSet>,
    chunks: [ChunkAssembler; 3],
}

impl RecoveryDistributions {
    fn new(mesh: MeshId, trust: Arc<TrustSet>) -> Self {
        Self {
            mesh,
            trust,
            chunks: std::array::from_fn(|_| {
                ChunkAssembler::new(mesh, MAX_SIGNED_STATE_CHUNKS, MAX_SIGNED_STATE_BYTES)
            }),
        }
    }

    fn apply(
        &mut self,
        envelope: &ControlEnvelope,
        runtime: &mut peerward_peer_core::WireguardRuntime,
        now: UnixTime,
    ) -> Result<(), PeerError> {
        let (kind, mesh, revision, index, count, body) = match envelope.message.as_ref() {
            Some(ControlMessage::AuthorityDirectory(c)) => {
                (0, &c.mesh_id, c.revision, c.index, c.count, &c.body)
            }
            Some(ControlMessage::PeerDirectory(c)) => {
                (1, &c.mesh_id, c.revision, c.index, c.count, &c.body)
            }
            Some(ControlMessage::Revocation(c)) => {
                (2, &c.mesh_id, c.revision, c.index, c.count, &c.body)
            }
            Some(ControlMessage::Close(close)) => {
                if close.mesh_id != self.mesh.as_bytes() {
                    return Err(PeerError::InvalidConfig);
                }
                let terminal = peerward_credentials::MeshTermination::decode(&close.body)?;
                self.trust.verify_termination(&terminal, 0, now)?;
                runtime.close();
                return Err(PeerError::MeshTerminated(close.body.clone()));
            }
            _ => return Ok(()),
        };
        if mesh != self.mesh.as_bytes() {
            return Err(PeerError::InvalidConfig);
        }
        let Some(bytes) = self.chunks[kind].push(RevisionChunk {
            mesh_id: self.mesh,
            revision,
            index,
            count,
            body: body.clone(),
        })?
        else {
            return Ok(());
        };
        match kind {
            0 => {
                let signed = SignedAuthorityBundle::decode(&bytes)?;
                if signed.bundle.revision != revision {
                    return Err(PeerError::InvalidConfig);
                }
                runtime.authorities(&signed, now)?;
            }
            1 => {
                let signed = decode_peer_directory(&bytes)?;
                if signed.directory.revision != revision {
                    return Err(PeerError::InvalidConfig);
                }
                runtime.install_directory(&signed, now)?;
            }
            _ => {
                let signed = decode_revocations(&bytes)?;
                if signed.bundle.revision != revision {
                    return Err(PeerError::InvalidConfig);
                }
                runtime.revoke(&signed, now)?;
            }
        }
        self.chunks[kind].commit(revision)?;
        Ok(())
    }
}
