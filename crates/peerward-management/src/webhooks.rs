use crate::ManagementError;
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use peerward_types::MeshId;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const WEBHOOK_BODY_LIMIT: usize = 16 * 1024;
pub const WEBHOOK_TIME_TOLERANCE: u64 = 300;
const DOMAIN: &[u8] = b"peerward/webhook-notification/v1\0";

/// Minimal event identity. Notifications deliberately exclude labels, audit
/// metadata, network payloads, invitation material and operator identities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookEvent {
    pub id: Uuid,
    pub sequence: u64,
    pub occurred_at: u64,
    pub kind: String,
    pub resource_kind: String,
    pub resource_id: Option<Uuid>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookNotification {
    pub version: u32,
    pub mesh_id: MeshId,
    pub webhook_id: Uuid,
    /// Stable across every retry; a receiver commits this ID with its side effect.
    pub delivery_id: Uuid,
    pub attempt: u32,
    /// Refreshed for each attempt; signatures do not extend authorization leases.
    pub sent_at: u64,
    pub event: WebhookEvent,
}

impl WebhookNotification {
    pub fn validate(&self) -> Result<(), ManagementError> {
        let token = |value: &str| {
            !value.is_empty()
                && value.len() <= 128
                && value
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        };
        if self.version != 1
            || self.webhook_id.get_version_num() != 4
            || self.delivery_id.get_version_num() != 4
            || self.event.id.get_version_num() != 4
            || self
                .event
                .resource_id
                .is_some_and(|id| id.get_version_num() != 4)
            || self.event.sequence == 0
            || !(1..=10).contains(&self.attempt)
            || self.sent_at < self.event.occurred_at
            || !token(&self.event.kind)
            || !token(&self.event.resource_kind)
        {
            return Err(ManagementError::Invalid("webhook.notification"));
        }
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>, ManagementError> {
        self.validate()?;
        let body =
            serde_json::to_vec(self).map_err(|_| ManagementError::Invalid("webhook.body"))?;
        if body.len() > WEBHOOK_BODY_LIMIT {
            return Err(ManagementError::Invalid("webhook.body"));
        }
        Ok(body)
    }
    /// Sign exact HTTP body bytes, under a distinct distribution-key domain.
    pub fn sign(&self, key: &SigningKey) -> Result<(Vec<u8>, [u8; 64]), ManagementError> {
        let body = self.encode()?;
        let signature = key.sign(&transcript(&body)).to_bytes();
        Ok((body, signature))
    }
    /// Verify the pinned Mesh/hook key and freshness BEFORE deduplicating the
    /// delivery ID. Receiver persistence, rather than this function, gives deduplication.
    pub fn verify(
        body: &[u8],
        signature: &[u8],
        key: &VerifyingKey,
        mesh: MeshId,
        webhook: Uuid,
        now: u64,
    ) -> Result<Self, ManagementError> {
        if body.len() > WEBHOOK_BODY_LIMIT {
            return Err(ManagementError::Invalid("webhook.body"));
        }
        key.verify_strict(
            &transcript(body),
            &Signature::from_slice(signature).map_err(|_| ManagementError::Signature)?,
        )
        .map_err(|_| ManagementError::Signature)?;
        let value: Self =
            serde_json::from_slice(body).map_err(|_| ManagementError::Invalid("webhook.body"))?;
        value.validate()?;
        if value.mesh_id != mesh || value.webhook_id != webhook {
            return Err(ManagementError::Signature);
        }
        if now.abs_diff(value.sent_at) > WEBHOOK_TIME_TOLERANCE {
            return Err(ManagementError::Expired);
        }
        Ok(value)
    }
}
fn transcript(body: &[u8]) -> Vec<u8> {
    let mut value = Vec::with_capacity(DOMAIN.len() + body.len());
    value.extend_from_slice(DOMAIN);
    value.extend_from_slice(body);
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shared_python_rust_signature_vector_is_byte_exact() {
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../examples/webhooks/signature-vector.json"
        ))
        .unwrap();
        let body = vector["body"].as_str().unwrap().as_bytes();
        let notice: WebhookNotification = serde_json::from_slice(body).unwrap();
        let key = SigningKey::from_bytes(&[7; 32]); // public test seed only
        let (encoded, signature) = notice.sign(&key).unwrap();
        assert_eq!(encoded, body);
        assert_eq!(
            serde_json::to_value(signature.to_vec()).unwrap(),
            vector["signature"]
        );
        assert_eq!(
            serde_json::to_value(key.verifying_key().to_bytes().to_vec()).unwrap(),
            vector["public_key"]
        );
        WebhookNotification::verify(
            body,
            &signature,
            &key.verifying_key(),
            notice.mesh_id,
            notice.webhook_id,
            vector["now"].as_u64().unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn signatures_pin_exact_body_time_mesh_and_hook_while_delivery_id_survives_retry() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let mut notice = WebhookNotification {
            version: 1,
            mesh_id: MeshId::new(),
            webhook_id: Uuid::new_v4(),
            delivery_id: Uuid::new_v4(),
            attempt: 1,
            sent_at: 500,
            event: WebhookEvent {
                id: Uuid::new_v4(),
                sequence: 1,
                occurred_at: 400,
                kind: "peer.disabled".into(),
                resource_kind: "peer".into(),
                resource_id: Some(Uuid::new_v4()),
            },
        };
        let (mut body, signature) = notice.sign(&key).unwrap();
        let verify = |body: &[u8], signature: &[u8], now| {
            WebhookNotification::verify(
                body,
                signature,
                &key.verifying_key(),
                notice.mesh_id,
                notice.webhook_id,
                now,
            )
        };
        assert_eq!(verify(&body, &signature, 600).unwrap(), notice);
        assert!(verify(&body, &signature, 801).is_err());
        assert!(verify(&body, &signature, 199).is_err());
        assert!(
            WebhookNotification::verify(
                &body,
                &signature,
                &key.verifying_key(),
                MeshId::new(),
                notice.webhook_id,
                500
            )
            .is_err()
        );
        assert!(
            WebhookNotification::verify(
                &body,
                &signature,
                &key.verifying_key(),
                notice.mesh_id,
                Uuid::new_v4(),
                500
            )
            .is_err()
        );
        body.push(b' ');
        assert!(verify(&body, &signature, 500).is_err());
        let id = notice.delivery_id;
        notice.attempt += 1;
        notice.sent_at = 650;
        assert_eq!(notice.delivery_id, id);
        assert!(notice.sign(&key).is_ok());
        notice.attempt = 11;
        assert!(notice.sign(&key).is_err());
    }
}
