use peerward_wire::{CredentialReplacement, CredentialRotationRequest};
use std::time::{SystemTime, UNIX_EPOCH};

struct PendingMobileRotation {
    id: RotationId,
    identity_public_key: [u8; 32],
    session_public_key: [u8; 32],
    wireguard_public_key: [u8; 32],
    replacement: Option<SubjectCredential>,
    activation_challenge: Option<[u8; 32]>,
    local_commit_ready: bool,
}

impl NativeSession {
    /// Checks renewal eligibility before the platform creates keys or a durable journal.
    /// The same signed command and renewal window are checked again when issuing the request.
    pub fn rotation_due(&self, now: UnixTime) -> Result<bool, MobileError> {
        if matches!(self.state, State::Closed) {
            return Err(MobileError::InvalidState);
        }
        let lifetime = self
            .current_credential
            .not_after
            .0
            .saturating_sub(self.current_credential.not_before.0);
        let threshold = (lifetime / 3).clamp(3_600, 86_400);
        let requested = self.console_renewal.as_ref().is_some_and(|signed| {
            signed
                .verify(
                    &self.trust.binding.directory_public_key,
                    self.trust.mesh_id,
                    self.local_peer,
                    self.current_credential.serial,
                    now.0,
                )
                .is_ok()
        });
        Ok(requested || self.current_credential.not_after.0.saturating_sub(now.0) <= threshold)
    }

    /// Builds an authenticated rotation request when the current credential is
    /// inside its final renewal window. The replacement private key remains in
    /// `AndroidKeyStore` and only its public key enters this state machine.
    ///
    /// # Errors
    ///
    /// Rejects malformed/replaced request identities, mismatched keys, and
    /// calls made after the session has closed.
    pub fn rotation_request(
        &mut self,
        request_id: [u8; 16],
        identity_public_key: [u8; 32],
        session_public_key: [u8; 32],
        wireguard_public_key: [u8; 32],
        signature: [u8; 64],
        now: UnixTime,
    ) -> Result<Option<ControlEnvelope>, MobileError> {
        if matches!(self.state, State::Closed)
            || identity_public_key == [0; 32]
            || session_public_key == [0; 32]
            || wireguard_public_key == [0; 32]
            || wireguard_public_key == session_public_key
            || wireguard_public_key == identity_public_key
            || wireguard_public_key == self.current_credential.wireguard_public_key
        {
            return Err(MobileError::InvalidState);
        }
        if !self.rotation_due(now)? {
            return Ok(None);
        }
        let uuid = Uuid::from_slice(&request_id).map_err(|_| MobileError::InvalidInput)?;
        let id = RotationId::from_uuid(uuid).map_err(|_| MobileError::InvalidInput)?;
        verify_rotation_request(
            &self.current_credential.identity_public_key,
            &RotationRequestProof {
                mesh_id: self.trust.mesh_id,
                peer_id: self.local_peer,
                rotation_id: id,
                current_serial: self.current_credential.serial,
                identity_public_key,
                session_public_key,
                wireguard_public_key,
            },
            &signature,
        )?;
        if let Some(pending) = &self.pending_rotation {
            if pending.id != id
                || pending.identity_public_key != identity_public_key
                || pending.session_public_key != session_public_key
                || pending.wireguard_public_key != wireguard_public_key
            {
                return Err(MobileError::InvalidState);
            }
        } else {
            self.pending_rotation = Some(PendingMobileRotation {
                id,
                identity_public_key,
                session_public_key,
                wireguard_public_key,
                replacement: None,
                activation_challenge: None,
                local_commit_ready: false,
            });
        }
        Ok(Some(ControlEnvelope {
            trace_context: None,
            message: Some(ControlMessage::RotationRequest(Box::new(
                CredentialRotationRequest {
                    mesh_id: self.trust.mesh_id.as_bytes().to_vec(),
                    request_id: id.as_bytes().to_vec(),
                    identity_public_key: identity_public_key.to_vec(),
                    session_public_key: session_public_key.to_vec(),
                    wireguard_public_key: wireguard_public_key.to_vec(),
                    current_serial: self.current_credential.serial.as_bytes().to_vec(),
                    signature: signature.to_vec(),
                },
            ))),
        }))
    }

    /// Returns the canonical request transcript for the current certified
    /// identity to sign without duplicating Rust protocol encoding in Kotlin.
    ///
    /// # Errors
    ///
    /// Rejects a non-`UUIDv4` rotation ID, zero public key, or malformed
    /// canonical proof input.
    pub fn rotation_request_transcript(
        &self,
        request_id: [u8; 16],
        identity_public_key: [u8; 32],
        session_public_key: [u8; 32],
        wireguard_public_key: [u8; 32],
    ) -> Result<Vec<u8>, MobileError> {
        let id = RotationId::from_uuid(
            Uuid::from_slice(&request_id).map_err(|_| MobileError::InvalidInput)?,
        )
        .map_err(|_| MobileError::InvalidInput)?;
        Ok(rotation_request_transcript(&RotationRequestProof {
            mesh_id: self.trust.mesh_id,
            peer_id: self.local_peer,
            rotation_id: id,
            current_serial: self.current_credential.serial,
            identity_public_key,
            session_public_key,
            wireguard_public_key,
        })?)
    }

    /// Verifies the new identity's one-time proof and creates the activation
    /// envelope. Repeating the same proof is safe after a lost response.
    ///
    /// # Errors
    ///
    /// Rejects calls without an accepted staged credential or a signature
    /// that does not authenticate its exact issued serial and challenge.
    pub fn rotation_activation(&self, signature: [u8; 64]) -> Result<ControlEnvelope, MobileError> {
        let pending = self
            .pending_rotation
            .as_ref()
            .ok_or(MobileError::InvalidState)?;
        let replacement = pending
            .replacement
            .as_ref()
            .ok_or(MobileError::InvalidState)?;
        let challenge = pending
            .activation_challenge
            .ok_or(MobileError::InvalidState)?;
        let proof = RotationActivationProof {
            mesh_id: self.trust.mesh_id,
            peer_id: self.local_peer,
            rotation_id: pending.id,
            issued_serial: replacement.serial,
            challenge,
        };
        verify_rotation_activation(&pending.identity_public_key, &proof, &signature)?;
        Ok(ControlEnvelope {
            trace_context: None,
            message: Some(ControlMessage::Activation(CredentialActivation {
                mesh_id: self.trust.mesh_id.as_bytes().to_vec(),
                request_id: pending.id.as_bytes().to_vec(),
                issued_serial: replacement.serial.as_bytes().to_vec(),
                signature: signature.to_vec(),
            })),
        })
    }

    fn accept_credential_replacement(
        &mut self,
        replacement: &CredentialReplacement,
    ) -> Result<AcceptedUpdate, MobileError> {
        let pending = self
            .pending_rotation
            .as_ref()
            .ok_or(MobileError::InvalidState)?;
        if replacement.mesh_id != self.trust.mesh_id.as_bytes()
            || replacement.request_id != pending.id.as_bytes()
            || replacement.credential.len() > MAX_CONTROL
            || replacement.activation_challenge.len() != 32
        {
            return Err(MobileError::InvalidInput);
        }
        let credential = SubjectCredential::decode(&replacement.credential)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| MobileError::InvalidState)?
            .as_secs();
        self.trust
            .credentials
            .verify_subject(&credential, UnixTime(now))?;
        if credential.mesh_id != self.trust.mesh_id
            || credential.subject != SubjectId::Peer(self.local_peer)
            || credential.identity_public_key != pending.identity_public_key
            || credential.public_noise_key != pending.session_public_key
            || credential.wireguard_public_key != pending.wireguard_public_key
            || credential.encode() != replacement.credential
        {
            return Err(MobileError::InvalidInput);
        }
        let challenge: [u8; 32] = replacement
            .activation_challenge
            .as_slice()
            .try_into()
            .map_err(|_| MobileError::InvalidInput)?;
        if let Some(existing) = &pending.replacement
            && (existing != &credential || pending.activation_challenge != Some(challenge))
        {
            return Err(MobileError::InvalidState);
        }
        let activation_transcript = rotation_activation_transcript(&RotationActivationProof {
            mesh_id: self.trust.mesh_id,
            peer_id: self.local_peer,
            rotation_id: pending.id,
            issued_serial: credential.serial,
            challenge,
        });
        let pending = self
            .pending_rotation
            .as_mut()
            .ok_or(MobileError::InvalidState)?;
        pending.replacement = Some(credential);
        pending.activation_challenge = Some(challenge);
        Ok(AcceptedUpdate::CredentialReplacement(
            CredentialReplacementUpdate {
                credential: replacement.credential.clone(),
                activation_transcript,
            },
        ))
    }

    fn activated_credential_in_directory(
        &mut self,
        directory: &peerward_directory::SignedPeerDirectory,
    ) -> Option<Vec<u8>> {
        let pending = self.pending_rotation.as_mut()?;
        if pending.local_commit_ready {
            return None;
        }
        let replacement = pending.replacement.as_ref()?;
        let entry = directory
            .directory
            .entries
            .iter()
            .map(|signed| &signed.entry)
            .find(|entry| entry.peer_id == self.local_peer)?;
        if entry.enabled
            && entry.identity_public_key == pending.identity_public_key
            && entry.noise_public_key == pending.session_public_key
            && entry.credential_serial == replacement.serial
            && entry
                .credential(replacement.serial)
                .is_some_and(|credential| {
                    credential.wireguard_public_key == pending.wireguard_public_key
                })
        {
            pending.local_commit_ready = true;
            Some(replacement.encode())
        } else {
            None
        }
    }
}
