use crate::ManagementError;
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use peerward_types::{CredentialSerial, MeshId, PeerId};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// An administrator may request renewal; only the device can generate its replacement keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialRenewalCommand {
    pub request_id: Uuid,
    pub mesh_id: MeshId,
    pub peer_id: PeerId,
    pub current_serial: CredentialSerial,
    pub issued_at: u64,
    pub expires_at: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedCredentialRenewal {
    pub command: CredentialRenewalCommand,
    pub signature: Vec<u8>,
}
impl CredentialRenewalCommand {
    fn transcript(&self) -> Result<Vec<u8>, ManagementError> {
        if self.request_id.get_version_num() != 4
            || self.expires_at <= self.issued_at
            || self.expires_at - self.issued_at > 7 * 86400
        {
            return Err(ManagementError::Invalid("credential_renewal"));
        }
        let mut bytes = b"peerward/credential-renewal-command/v1\0".to_vec();
        bytes.extend(
            serde_json::to_vec(self).map_err(|_| ManagementError::Invalid("credential_renewal"))?,
        );
        Ok(bytes)
    }
}
impl SignedCredentialRenewal {
    pub fn sign(
        command: CredentialRenewalCommand,
        key: &SigningKey,
    ) -> Result<Self, ManagementError> {
        let signature = key.sign(&command.transcript()?).to_bytes().to_vec();
        Ok(Self { command, signature })
    }
    pub fn verify(
        &self,
        key: &[u8; 32],
        mesh: MeshId,
        peer: PeerId,
        serial: CredentialSerial,
        now: u64,
    ) -> Result<(), ManagementError> {
        if self.command.mesh_id != mesh
            || self.command.peer_id != peer
            || self.command.current_serial != serial
        {
            return Err(ManagementError::Invalid("credential_renewal.target"));
        }
        if self.command.issued_at > now.saturating_add(30) || now >= self.command.expires_at {
            return Err(ManagementError::Expired);
        }
        VerifyingKey::from_bytes(key)
            .map_err(|_| ManagementError::Signature)?
            .verify_strict(
                &self.command.transcript()?,
                &Signature::from_slice(&self.signature).map_err(|_| ManagementError::Signature)?,
            )
            .map_err(|_| ManagementError::Signature)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn renewal_is_bound_to_identity_generation_and_deadline() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let mesh = MeshId::new();
        let peer = PeerId::new();
        let serial = CredentialSerial::new();
        let signed = SignedCredentialRenewal::sign(
            CredentialRenewalCommand {
                request_id: Uuid::new_v4(),
                mesh_id: mesh,
                peer_id: peer,
                current_serial: serial,
                issued_at: 100,
                expires_at: 200,
            },
            &key,
        )
        .unwrap();
        let public = key.verifying_key().to_bytes();
        assert!(signed.verify(&public, mesh, peer, serial, 110).is_ok());
        assert!(
            signed
                .verify(&public, MeshId::new(), peer, serial, 110)
                .is_err()
        );
        assert!(
            signed
                .verify(&public, mesh, PeerId::new(), serial, 110)
                .is_err()
        );
        assert!(
            signed
                .verify(&public, mesh, peer, CredentialSerial::new(), 110)
                .is_err()
        );
        assert!(signed.verify(&public, mesh, peer, serial, 200).is_err());
        let mut forged = signed.clone();
        forged.command.request_id = Uuid::new_v4();
        assert!(forged.verify(&public, mesh, peer, serial, 110).is_err());
        assert!(
            signed
                .verify(
                    &SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes(),
                    mesh,
                    peer,
                    serial,
                    110
                )
                .is_err()
        );
    }
}
