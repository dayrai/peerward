//! Bounded, authenticated demultiplexing for shared Relay listeners.

use peerward_types::{MeshId, RelayId};
use uuid::Uuid;

use crate::{HandshakeState, IK_SUITE, KK_SUITE, NOISE_PROLOGUE, WireError};

/// One fixed-size preface, before any length-prefixed Noise handshake bytes.
pub const RELAY_PREFACE_LEN: usize = 56;
const MAGIC: &[u8; 4] = b"PWR4";

/// An untrusted routing hint. Authorization still requires the complete Noise
/// handshake and the selected Mesh's credential checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayPreface {
    pub mesh_id: MeshId,
    pub target: RelayId,
    /// Present only on the backbone listener.
    pub source: Option<RelayId>,
}

impl RelayPreface {
    pub fn encode(self) -> [u8; RELAY_PREFACE_LEN] {
        let mut bytes = [0; RELAY_PREFACE_LEN];
        bytes[..4].copy_from_slice(MAGIC);
        bytes[4] = 4;
        bytes[5] = if self.source.is_some() { 2 } else { 1 };
        bytes[8..24].copy_from_slice(self.mesh_id.as_bytes());
        bytes[24..40].copy_from_slice(self.target.as_bytes());
        if let Some(source) = self.source {
            bytes[40..].copy_from_slice(source.as_bytes());
        }
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() != RELAY_PREFACE_LEN {
            return Err(WireError::InvalidLength);
        }
        if &bytes[..4] != MAGIC || bytes[4] != 4 {
            return Err(WireError::UnsupportedMajor);
        }
        if bytes[6..8] != [0, 0] {
            return Err(WireError::Unsupported);
        }
        let id = |range: std::ops::Range<usize>| {
            Uuid::from_slice(&bytes[range]).map_err(|_| WireError::KindMismatch)
        };
        let mesh_id = MeshId::from_uuid(id(8..24)?).map_err(|_| WireError::KindMismatch)?;
        let target = RelayId::from_uuid(id(24..40)?).map_err(|_| WireError::KindMismatch)?;
        let source = match bytes[5] {
            1 if bytes[40..] == [0; 16] => None,
            2 => Some(RelayId::from_uuid(id(40..56)?).map_err(|_| WireError::KindMismatch)?),
            _ => return Err(WireError::KindMismatch),
        };
        if source == Some(target) {
            return Err(WireError::KindMismatch);
        }
        Ok(Self {
            mesh_id,
            target,
            source,
        })
    }

    /// Both parties bind the exact canonical routing bytes into Noise.
    pub fn prologue(self) -> Vec<u8> {
        let mut bytes = NOISE_PROLOGUE.to_vec();
        bytes.extend_from_slice(b"/relay\0");
        bytes.extend_from_slice(&self.encode());
        bytes
    }

    pub fn handshake(
        self,
        initiator: bool,
        local_private: &[u8; 32],
        remote_public: Option<&[u8; 32]>,
    ) -> Result<HandshakeState, WireError> {
        // Validate programmatically constructed values as well as decoded input.
        Self::decode(&self.encode())?;
        let suite = if self.source.is_some() {
            KK_SUITE
        } else {
            IK_SUITE
        };
        crate::build_handshake_with_prologue(
            suite,
            initiator,
            local_private,
            remote_public,
            &self.prologue(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use x25519_dalek::{PublicKey, StaticSecret};

    #[test]
    fn preface_is_canonical_and_bounded() {
        let preface = RelayPreface {
            mesh_id: MeshId::new(),
            target: RelayId::new(),
            source: None,
        };
        let bytes = preface.encode();
        assert_eq!(RelayPreface::decode(&bytes).unwrap(), preface);
        for length in 0..RELAY_PREFACE_LEN {
            assert!(RelayPreface::decode(&bytes[..length]).is_err());
        }
        let mut extended = bytes.to_vec();
        extended.push(0);
        assert!(RelayPreface::decode(&extended).is_err());
        for offset in [4, 5, 6, 7, 40] {
            let mut invalid = bytes;
            invalid[offset] = 99;
            assert!(RelayPreface::decode(&invalid).is_err());
        }
    }

    #[test]
    fn mesh_target_and_backbone_source_are_cryptographically_bound() {
        let local = [7; 32];
        let remote = [9; 32];
        let public = PublicKey::from(&StaticSecret::from(remote)).to_bytes();
        let original = RelayPreface {
            mesh_id: MeshId::new(),
            target: RelayId::new(),
            source: None,
        };
        for modified in [
            original,
            RelayPreface {
                mesh_id: MeshId::new(),
                ..original
            },
            RelayPreface {
                target: RelayId::new(),
                ..original
            },
        ] {
            let mut sender = original.handshake(true, &local, Some(&public)).unwrap();
            let mut receiver = modified.handshake(false, &remote, None).unwrap();
            let mut encrypted = [0; 256];
            let mut plaintext = [0; 256];
            let length = sender.write_message(b"test", &mut encrypted).unwrap();
            assert_eq!(
                receiver
                    .read_message(&encrypted[..length], &mut plaintext)
                    .is_ok(),
                modified == original
            );
        }
        let source_public = PublicKey::from(&StaticSecret::from(local)).to_bytes();
        let original = RelayPreface {
            source: Some(RelayId::new()),
            ..original
        };
        let changed = RelayPreface {
            source: Some(RelayId::new()),
            ..original
        };
        let mut sender = original.handshake(true, &local, Some(&public)).unwrap();
        let mut receiver = changed
            .handshake(false, &remote, Some(&source_public))
            .unwrap();
        let mut encrypted = [0; 256];
        let mut plaintext = [0; 256];
        let length = sender.write_message(b"", &mut encrypted).unwrap();
        assert!(
            receiver
                .read_message(&encrypted[..length], &mut plaintext)
                .is_err()
        );
    }
}
