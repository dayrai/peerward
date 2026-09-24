//! Offline root recovery using the existing RFC 9180 HPKE suite, with a
//! separate protocol domain and root-signed envelope. No online decryption key.
use crate::{WireError, audit::hpke_context_with_info};
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit,
    aead::{Aead, Payload},
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use peerward_types::MeshId;
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

const INFO: &[u8] = b"peerward/root-recovery/v1";
pub const ROOT_RECOVERY_LEN: usize = 196;

pub fn seal_root_recovery(
    mesh: MeshId,
    root: &[u8; 32],
    recipient: &[u8; 32],
) -> Result<Vec<u8>, WireError> {
    let ephemeral = StaticSecret::random_from_rng(OsRng);
    let enc = PublicKey::from(&ephemeral).to_bytes();
    let dh = Zeroizing::new(
        ephemeral
            .diffie_hellman(&PublicKey::from(*recipient))
            .to_bytes(),
    );
    if *dh == [0; 32] {
        return Err(WireError::Authentication);
    }
    let (key, nonce) = hpke_context_with_info(&dh, &enc, recipient, INFO)?;
    let key = Zeroizing::new(key);
    let signer = SigningKey::from_bytes(root);
    let mut bytes = b"RCV1".to_vec();
    bytes.extend_from_slice(mesh.as_bytes());
    bytes.extend_from_slice(signer.verifying_key().as_bytes());
    bytes.extend_from_slice(&enc);
    let ciphertext = ChaCha20Poly1305::new_from_slice(key.as_ref())
        .map_err(|_| WireError::Authentication)?
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: root,
                aad: &bytes,
            },
        )
        .map_err(|_| WireError::Authentication)?;
    bytes.extend_from_slice(&ciphertext);
    let signature = signer.sign(&bytes);
    bytes.extend_from_slice(&signature.to_bytes());
    Ok(bytes)
}

pub fn open_root_recovery(
    bytes: &[u8],
    mesh: MeshId,
    expected_root: &[u8; 32],
    recipient_private: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, WireError> {
    if bytes.len() != ROOT_RECOVERY_LEN || &bytes[..4] != b"RCV1" {
        return Err(WireError::InvalidLength);
    }
    if &bytes[4..20] != mesh.as_bytes() || &bytes[20..52] != expected_root {
        return Err(WireError::Authentication);
    }
    let signature = Signature::from_slice(&bytes[132..]).map_err(|_| WireError::Authentication)?;
    VerifyingKey::from_bytes(expected_root)
        .map_err(|_| WireError::Authentication)?
        .verify_strict(&bytes[..132], &signature)
        .map_err(|_| WireError::Authentication)?;
    let enc: [u8; 32] = bytes[52..84]
        .try_into()
        .map_err(|_| WireError::InvalidLength)?;
    let recipient = StaticSecret::from(*recipient_private);
    let public = PublicKey::from(&recipient).to_bytes();
    let dh = Zeroizing::new(recipient.diffie_hellman(&PublicKey::from(enc)).to_bytes());
    if *dh == [0; 32] {
        return Err(WireError::Authentication);
    }
    let (key, nonce) = hpke_context_with_info(&dh, &enc, &public, INFO)?;
    let key = Zeroizing::new(key);
    let plaintext = Zeroizing::new(
        ChaCha20Poly1305::new_from_slice(key.as_ref())
            .map_err(|_| WireError::Authentication)?
            .decrypt(
                (&nonce).into(),
                Payload {
                    msg: &bytes[84..132],
                    aad: &bytes[..84],
                },
            )
            .map_err(|_| WireError::Authentication)?,
    );
    let seed = Zeroizing::new(
        plaintext
            .as_slice()
            .try_into()
            .map_err(|_| WireError::InvalidLength)?,
    );
    if SigningKey::from_bytes(&seed).verifying_key().as_bytes() != expected_root {
        return Err(WireError::Authentication);
    }
    Ok(seed)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn recovery_rejects_substitution_corruption_and_wrong_recipient() {
        let mesh = MeshId::new();
        let root = [42; 32];
        let public = SigningKey::from_bytes(&root).verifying_key().to_bytes();
        let recipient = [13; 32];
        let sealed = seal_root_recovery(
            mesh,
            &root,
            &PublicKey::from(&StaticSecret::from(recipient)).to_bytes(),
        )
        .unwrap();
        assert_eq!(
            *open_root_recovery(&sealed, mesh, &public, &recipient).unwrap(),
            root
        );
        assert!(open_root_recovery(&sealed, MeshId::new(), &public, &recipient).is_err());
        assert!(open_root_recovery(&sealed, mesh, &public, &[14; 32]).is_err());
        for index in 0..sealed.len() {
            let mut bad = sealed.clone();
            bad[index] ^= 1;
            assert!(open_root_recovery(&bad, mesh, &public, &recipient).is_err());
        }
    }
}
