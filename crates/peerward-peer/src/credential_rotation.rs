use std::path::{Path, PathBuf};

use peerward_wire::{CredentialReplacement, CredentialRotationRequest};

struct PendingCredentialRotation {
    id: RotationId,
    sent: bool,
    identity_private_key: [u8; 32],
    identity_public_key: [u8; 32],
    session_private_key: [u8; 32],
    wireguard_private_key: [u8; 32],
    session_public_key: [u8; 32],
    wireguard_public_key: [u8; 32],
}

struct PendingCredentialCommit {
    identity_private_key: [u8; 32],
    session_private_key: [u8; 32],
    wireguard_private_key: [u8; 32],
    credential: Vec<u8>,
    decoded: SubjectCredential,
}

impl Drop for PendingCredentialRotation {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.identity_private_key.zeroize();
        self.session_private_key.zeroize();
        self.wireguard_private_key.zeroize();
    }
}

impl Drop for PendingCredentialCommit {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.identity_private_key.zeroize();
        self.session_private_key.zeroize();
        self.wireguard_private_key.zeroize();
    }
}

struct CredentialRotator {
    mesh_id: MeshId,
    peer_id: PeerId,
    current: SubjectCredential,
    renewal_distribution: Option<peerward_credentials::DistributionCertificate>,
    current_identity_private_key: [u8; 32],
    trust: DynamicTrust,
    identity_private_key_file: PathBuf,
    private_key_file: PathBuf,
    wireguard_private_key_file: PathBuf,
    credential_file: PathBuf,
    identity: watch::Sender<RelayIdentity>,
    pending: Option<PendingCredentialRotation>,
    pending_commit: Option<PendingCredentialCommit>,
    published: Option<PeerEntry>,
    wireguard: Option<Arc<Mutex<peerward_peer_core::WireguardRuntime>>>,
}

impl CredentialRotator {
    fn new(
        config: &PeerConfig,
        credential: &[u8],
        trust: DynamicTrust,
        identity: watch::Sender<RelayIdentity>,
    ) -> Result<Self, PacketPumpError> {
        let current =
            SubjectCredential::decode(credential).map_err(|_| PacketPumpError::InvalidControl)?;
        if current.mesh_id != config.mesh_id || current.subject != SubjectId::Peer(config.peer_id) {
            return Err(PacketPumpError::InvalidControl);
        }
        let current_identity_private_key =
            read_identity_private_key(&config.identity_private_key_file)?;
        if IdentitySigningKey::from_bytes(&current_identity_private_key)
            .verifying_key()
            .to_bytes()
            != current.identity_public_key
        {
            return Err(PacketPumpError::InvalidControl);
        }
        let mut rotator = Self {
            mesh_id: config.mesh_id,
            peer_id: config.peer_id,
            current,
            renewal_distribution: config
                .distribution_certificate_file
                .as_ref()
                .and_then(|p| {
                    peerward_credentials::private_files::read_bounded_regular_file(p, 65_536).ok()
                })
                .and_then(|b| peerward_credentials::DistributionCertificate::decode(&b).ok()),
            current_identity_private_key,
            trust,
            identity_private_key_file: config.identity_private_key_file.clone(),
            private_key_file: config.private_key_file.clone(),
            wireguard_private_key_file: config.wireguard_private_key_file.clone(),
            credential_file: config.credential_file.clone(),
            identity,
            pending: None,
            pending_commit: None,
            published: None,
            wireguard: None,
        };
        rotator.restore_pending()?;
        Ok(rotator)
    }

    fn restore_pending(&mut self) -> Result<(), PacketPumpError> {
        let marker = adjacent_path(&self.private_key_file, "rotation");
        if !marker.exists() {
            return Ok(());
        }
        let state = peerward_credentials::private_files::read_private(&marker, 128)?;
        let state = std::str::from_utf8(&state).map_err(|_| PacketPumpError::InvalidControl)?;
        let id = state
            .strip_prefix("staged:")
            .or_else(|| state.strip_prefix("requested:"))
            .ok_or(PacketPumpError::InvalidControl)?
            .parse::<RotationId>()
            .map_err(|_| PacketPumpError::InvalidControl)?;
        let identity = zeroize::Zeroizing::new(read_identity_private_key(&adjacent_path(
            &self.identity_private_key_file,
            "next",
        ))?);
        let noise = zeroize::Zeroizing::new(read_identity_private_key(&adjacent_path(
            &self.private_key_file,
            "next",
        ))?);
        let wireguard = zeroize::Zeroizing::new(read_identity_private_key(&adjacent_path(
            &self.wireguard_private_key_file,
            "next",
        ))?);
        let identity_public_key = IdentitySigningKey::from_bytes(&identity)
            .verifying_key()
            .to_bytes();
        let session_public_key =
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(*noise)).to_bytes();
        let wireguard_public_key =
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(*wireguard)).to_bytes();
        if state.starts_with("staged:") {
            let credential = peerward_credentials::private_files::read_private(
                &adjacent_path(&self.credential_file, "next"),
                225,
            )?;
            let decoded = SubjectCredential::decode(&credential)
                .map_err(|_| PacketPumpError::InvalidControl)?;
            if decoded.mesh_id != self.mesh_id
                || decoded.subject != SubjectId::Peer(self.peer_id)
                || decoded.identity_public_key != identity_public_key
                || decoded.public_noise_key != session_public_key
                || decoded.wireguard_public_key != wireguard_public_key
                || decoded.serial == self.current.serial
            {
                return Err(PacketPumpError::InvalidControl);
            }
        }
        // Restore request identity only. A redelivered replacement still passes
        // current Root/revocation checks before activation or local commit.
        self.pending = Some(PendingCredentialRotation {
            id,
            sent: false,
            identity_private_key: *identity,
            identity_public_key,
            session_private_key: *noise,
            session_public_key,
            wireguard_private_key: *wireguard,
            wireguard_public_key,
        });
        Ok(())
    }

    async fn request_from_console<C: ControlSender>(
        &mut self,
        body: &[u8],
        relay: &C,
    ) -> Result<(), PacketPumpError> {
        if body.len() > 2048 {
            return Err(PacketPumpError::InvalidControl);
        }
        let signed: peerward_management::SignedCredentialRenewal =
            serde_json::from_slice(body).map_err(|_| PacketPumpError::InvalidControl)?;
        let binding = self
            .renewal_distribution
            .as_ref()
            .ok_or(PacketPumpError::InvalidControl)?;
        self.trust
            .verify_distribution(binding, UnixTime(wall_clock_seconds()))
            .map_err(|_| PacketPumpError::InvalidControl)?;
        signed
            .verify(
                &binding.directory_public_key,
                self.mesh_id,
                self.peer_id,
                self.current.serial,
                wall_clock_seconds(),
            )
            .map_err(|_| PacketPumpError::InvalidControl)?;
        // The existing journal reuses in-flight keys and survives repeated delivery/restarts.
        self.request_now(relay).await
    }

    async fn request_if_due<C: ControlSender>(&mut self, relay: &C) -> Result<(), PacketPumpError> {
        let now = wall_clock_seconds();
        let lifetime = self
            .current
            .not_after
            .0
            .saturating_sub(self.current.not_before.0);
        let threshold = (lifetime / 3).clamp(3_600, 86_400);
        if self.pending.is_some() {
            return self.send_pending(relay).await;
        }
        if self.pending_commit.is_some() || self.current.not_after.0.saturating_sub(now) > threshold
        {
            return Ok(());
        }
        self.request_now(relay).await
    }

    async fn request_now<C: ControlSender>(&mut self, relay: &C) -> Result<(), PacketPumpError> {
        if self.pending.is_some() {
            return self.send_pending(relay).await;
        }
        if self.pending_commit.is_some() {
            return Ok(());
        }
        let session_pair = snow::Builder::new(
            peerward_wire::IK_SUITE
                .parse()
                .map_err(|_| PacketPumpError::InvalidControl)?,
        )
        .generate_keypair()
        .map_err(|_| PacketPumpError::InvalidControl)?;
        let identity = IdentitySigningKey::generate(&mut OsRng);
        let wireguard = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let pending = PendingCredentialRotation {
            wireguard_private_key: wireguard.to_bytes(),
            wireguard_public_key: x25519_dalek::PublicKey::from(&wireguard).to_bytes(),
            id: RotationId::new(),
            sent: false,
            identity_private_key: identity.to_bytes(),
            identity_public_key: identity.verifying_key().to_bytes(),
            session_private_key: session_pair
                .private
                .try_into()
                .map_err(|_| PacketPumpError::InvalidControl)?,
            session_public_key: session_pair
                .public
                .try_into()
                .map_err(|_| PacketPumpError::InvalidControl)?,
        };
        stage_rotation_keys(
            &self.identity_private_key_file,
            &self.private_key_file,
            &self.wireguard_private_key_file,
            &pending.identity_private_key,
            &pending.session_private_key,
            &pending.wireguard_private_key,
        )?;
        write_secure(
            &adjacent_path(&self.private_key_file, "rotation"),
            format!("requested:{}", pending.id).as_bytes(),
        )?;
        self.pending = Some(pending);
        self.send_pending(relay).await
    }

    async fn send_pending<C: ControlSender>(&mut self, relay: &C) -> Result<(), PacketPumpError> {
        let Some(pending) = self.pending.as_mut().filter(|pending| !pending.sent) else {
            return Ok(());
        };
        let signature = sign_rotation_request(
            &self.current_identity_private_key,
            &RotationRequestProof {
                mesh_id: self.mesh_id,
                peer_id: self.peer_id,
                rotation_id: pending.id,
                current_serial: self.current.serial,
                identity_public_key: pending.identity_public_key,
                session_public_key: pending.session_public_key,
                wireguard_public_key: pending.wireguard_public_key,
            },
        )
        .map_err(|_| PacketPumpError::InvalidControl)?;
        relay
            .send_control(ControlEnvelope {
                trace_context: None,
                message: Some(ControlMessage::RotationRequest(Box::new(
                    CredentialRotationRequest {
                        mesh_id: self.mesh_id.as_bytes().to_vec(),
                        request_id: pending.id.as_bytes().to_vec(),
                        identity_public_key: pending.identity_public_key.to_vec(),
                        session_public_key: pending.session_public_key.to_vec(),
                        wireguard_public_key: pending.wireguard_public_key.to_vec(),
                        current_serial: self.current.serial.as_bytes().to_vec(),
                        signature: signature.to_vec(),
                    },
                ))),
            })
            .await?;
        pending.sent = true;
        Ok(())
    }

    async fn accept_replacement<C: ControlSender>(
        &mut self,
        replacement: &CredentialReplacement,
        relay: &C,
    ) -> Result<(), PacketPumpError> {
        let pending = self
            .pending
            .as_ref()
            .ok_or(PacketPumpError::InvalidControl)?;
        if replacement.mesh_id != self.mesh_id.as_bytes()
            || replacement.request_id != pending.id.as_bytes()
            || replacement.activation_challenge.len() != 32
        {
            return Err(PacketPumpError::InvalidControl);
        }
        let credential = SubjectCredential::decode(&replacement.credential)
            .map_err(|_| PacketPumpError::InvalidControl)?;
        self.trust
            .verify_subject(&credential, UnixTime(wall_clock_seconds()))
            .map_err(|_| PacketPumpError::InvalidControl)?;
        if credential.mesh_id != self.mesh_id
            || credential.subject != SubjectId::Peer(self.peer_id)
            || credential.identity_public_key != pending.identity_public_key
            || credential.public_noise_key != pending.session_public_key
            || credential.wireguard_public_key != pending.wireguard_public_key
            || credential.encode() != replacement.credential
        {
            return Err(PacketPumpError::InvalidControl);
        }
        if let Some(wireguard) = &self.wireguard {
            wireguard
                .lock()
                .await
                .stage(
                    credential.clone(),
                    x25519_dalek::StaticSecret::from(pending.wireguard_private_key),
                    UnixTime(wall_clock_seconds()),
                )
                .map_err(core_packet_error)?;
        }
        stage_peer_identity(
            &self.identity_private_key_file,
            &self.private_key_file,
            &self.wireguard_private_key_file,
            &self.credential_file,
            pending.id,
            &pending.identity_private_key,
            &pending.session_private_key,
            &pending.wireguard_private_key,
            &replacement.credential,
        )?;
        let challenge: [u8; 32] = replacement
            .activation_challenge
            .as_slice()
            .try_into()
            .map_err(|_| PacketPumpError::InvalidControl)?;
        let activation_signature = sign_rotation_activation(
            &pending.identity_private_key,
            &RotationActivationProof {
                mesh_id: self.mesh_id,
                peer_id: self.peer_id,
                rotation_id: pending.id,
                issued_serial: credential.serial,
                challenge,
            },
        );
        relay
            .send_control(ControlEnvelope {
                trace_context: None,
                message: Some(ControlMessage::Activation(CredentialActivation {
                    mesh_id: self.mesh_id.as_bytes().to_vec(),
                    request_id: pending.id.as_bytes().to_vec(),
                    issued_serial: credential.serial.as_bytes().to_vec(),
                    signature: activation_signature.to_vec(),
                })),
            })
            .await?;
        self.pending_commit = Some(PendingCredentialCommit {
            identity_private_key: pending.identity_private_key,
            session_private_key: pending.session_private_key,
            wireguard_private_key: pending.wireguard_private_key,
            credential: replacement.credential.clone(),
            decoded: credential,
        });
        self.pending = None;
        if let Some(published) = self.published.clone() {
            self.commit_if_published(&published)?;
        }
        Ok(())
    }

    fn commit_if_published(&mut self, published: &PeerEntry) -> Result<(), PacketPumpError> {
        self.published = Some(published.clone());
        let Some(pending) = self.pending_commit.as_ref() else {
            return Ok(());
        };
        if !published.enabled
            || published.credential_serial != pending.decoded.serial
            || published.identity_public_key != pending.decoded.identity_public_key
            || published.noise_public_key != pending.decoded.public_noise_key
            || published
                .credential(pending.decoded.serial)
                .is_none_or(|credential| {
                    credential.subject(self.mesh_id, self.peer_id) != pending.decoded
                        || !credential.valid_at(UnixTime(wall_clock_seconds()))
                        || credential.overlap_until.is_some()
                })
        {
            return Ok(());
        }
        self.trust
            .verify_subject(&pending.decoded, UnixTime(wall_clock_seconds()))
            .map_err(|_| PacketPumpError::InvalidControl)?;
        commit_staged_peer_identity(
            &self.identity_private_key_file,
            &self.private_key_file,
            &self.wireguard_private_key_file,
            &self.credential_file,
        )?;
        let identity = RelayIdentity {
            private_key: pending.session_private_key,
            credential: pending.credential.clone(),
        };
        self.identity
            .send(identity.clone())
            .map_err(|_| PacketPumpError::InvalidControl)?;
        self.current = pending.decoded.clone();
        self.current_identity_private_key = pending.identity_private_key;
        self.pending_commit = None;
        Ok(())
    }
}

include!("credential_rotation_files.rs");
