use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use super::*;
use ed25519_dalek::SigningKey as IdentitySigningKey;
use peerward_credentials::{
    AuthoritySigningKey, RootSigningKey, RotationActivationProof, RotationRequestProof,
    UnsignedAuthority, UnsignedSubject, rotation_activation_transcript, sign_rotation_activation,
    sign_rotation_request,
};
use peerward_directory::{DirectorySigningKey, PeerEntry};
use peerward_service::ServiceSnapshotSigningKey;
use peerward_types::{AttachmentId, CredentialSerial};
use peerward_wire::CredentialReplacement;

#[test]
#[allow(clippy::too_many_lines)] // One end-to-end trust transcript keeps every binding visible.
fn mobile_rotation_binds_pending_keystore_key_and_rooted_replacement() {
    mobile_rotation_case(false);
}
#[test]
fn console_requested_mobile_rotation_uses_existing_keystore_transaction() {
    mobile_rotation_case(true);
}
fn mobile_rotation_case(admin_requested: bool) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mesh = MeshId::new();
    let peer = PeerId::new();
    let root = RootSigningKey::generate();
    let authority = AuthoritySigningKey::generate();
    let authority_certificate = root
        .certify(UnsignedAuthority {
            mesh_id: mesh,
            serial: CredentialSerial::new(),
            public_key: authority.public_key(),
            not_before: UnixTime(now - 100),
            not_after: UnixTime(now + 86_400),
        })
        .unwrap();
    let provider = Arc::new(RawStaticDh::new([41; 32]));
    let current_identity = IdentitySigningKey::from_bytes(&[46; 32]);
    let current = authority
        .issue(UnsignedSubject {
            subject: SubjectId::Peer(peer),
            mesh_id: mesh,
            identity_public_key: current_identity.verifying_key().to_bytes(),
            public_noise_key: provider.public_key(),
            serial: CredentialSerial::new(),
            not_before: UnixTime(now - 100),
            not_after: UnixTime(now + if admin_requested { 86000 } else { 600 }),
            wireguard_public_key: [0x76; 32],
        })
        .unwrap();
    let mut credentials = TrustSet::new(root.public_key(), mesh);
    credentials
        .add_authority(authority_certificate, UnixTime(now))
        .unwrap();
    let directory = DirectorySigningKey::from_bytes(&[44; 32]);
    let services = ServiceSnapshotSigningKey::from_bytes(&[45; 32]);
    let binding = authority.certify_distribution(
        mesh,
        directory.public_key().to_bytes(),
        services.verifier().to_bytes(),
        [46; 32],
    );
    let trust = MobileTrust::new(
        mesh,
        credentials,
        directory.public_key(),
        services.verifier(),
        binding.audit_public_key,
        &binding,
        UnixTime(now),
    )
    .unwrap();
    let relay_public = RawStaticDh::new([42; 32]).public_key();
    let (mut session, _) = NativeSession::initiate(
        provider,
        relay_public,
        &current,
        *AttachmentId::new().as_bytes(),
        7,
        UnixTime(now),
        trust,
    )
    .unwrap();

    assert_eq!(
        session.rotation_due(UnixTime(now)).unwrap(),
        !admin_requested
    );
    assert!(session.pending_rotation.is_none());
    let request = RotationId::new();
    let replacement_public = RawStaticDh::new([43; 32]).public_key();
    let replacement_identity = IdentitySigningKey::from_bytes(&[47; 32]);
    let replacement_identity_public = replacement_identity.verifying_key().to_bytes();
    let signature = sign_rotation_request(
        &current_identity.to_bytes(),
        &RotationRequestProof {
            mesh_id: mesh,
            peer_id: peer,
            rotation_id: request,
            current_serial: current.serial,
            identity_public_key: replacement_identity_public,
            session_public_key: replacement_public,
            wireguard_public_key: [0x77; 32],
        },
    )
    .unwrap();
    if admin_requested {
        assert!(
            session
                .rotation_request(
                    *request.as_bytes(),
                    replacement_identity_public,
                    replacement_public,
                    [0x77; 32],
                    signature,
                    UnixTime(now)
                )
                .unwrap()
                .is_none()
        );
        let signed = directory
            .sign_credential_renewal(peerward_management::CredentialRenewalCommand {
                request_id: Uuid::new_v4(),
                mesh_id: mesh,
                peer_id: peer,
                current_serial: current.serial,
                issued_at: now,
                expires_at: now + 300,
            })
            .unwrap();
        let command = ControlEnvelope {
            trace_context: None,
            message: Some(ControlMessage::CredentialRenewal(
                peerward_wire::CredentialRenewal {
                    body: serde_json::to_vec(&signed).unwrap(),
                },
            )),
        };
        assert!(matches!(
            session.apply_control(&command).unwrap(),
            AcceptedUpdate::CredentialRenewalRequested
        ));
        assert!(session.rotation_due(UnixTime(now)).unwrap());
        assert!(!session.rotation_due(UnixTime(now + 301)).unwrap());
        assert!(matches!(
            session.apply_control(&command).unwrap(),
            AcceptedUpdate::CredentialRenewalRequested
        ));
        let mut forged = signed.clone();
        forged.command.current_serial = CredentialSerial::new();
        assert!(
            session
                .apply_control(&ControlEnvelope {
                    trace_context: None,
                    message: Some(ControlMessage::CredentialRenewal(
                        peerward_wire::CredentialRenewal {
                            body: serde_json::to_vec(&forged).unwrap()
                        }
                    ))
                })
                .is_err()
        );
    }
    let envelope = session
        .rotation_request(
            *request.as_bytes(),
            replacement_identity_public,
            replacement_public,
            [0x77; 32],
            signature,
            UnixTime(now),
        )
        .unwrap()
        .unwrap();
    let Some(ControlMessage::RotationRequest(encoded)) = envelope.message else {
        panic!("rotation request was not encoded")
    };
    assert_eq!(encoded.current_serial, current.serial.as_bytes());
    assert_eq!(encoded.identity_public_key, replacement_identity_public);
    assert_eq!(encoded.session_public_key, replacement_public);

    let replacement = authority
        .issue(UnsignedSubject {
            subject: SubjectId::Peer(peer),
            mesh_id: mesh,
            identity_public_key: replacement_identity_public,
            public_noise_key: replacement_public,
            serial: CredentialSerial::new(),
            not_before: UnixTime(now - 10),
            not_after: UnixTime(now + 86_400),
            wireguard_public_key: [0x77; 32],
        })
        .unwrap()
        .encode();
    let mut wrong_request = *request.as_bytes();
    wrong_request[0] ^= 1;
    assert!(
        session
            .apply_control(&ControlEnvelope {
                trace_context: None,
                message: Some(ControlMessage::Replacement(CredentialReplacement {
                    mesh_id: mesh.as_bytes().to_vec(),
                    request_id: wrong_request.to_vec(),
                    credential: replacement.clone(),
                    activation_challenge: [48; 32].to_vec(),
                })),
            })
            .is_err()
    );
    let accepted = session
        .apply_control(&ControlEnvelope {
            trace_context: None,
            message: Some(ControlMessage::Replacement(CredentialReplacement {
                mesh_id: mesh.as_bytes().to_vec(),
                request_id: request.as_bytes().to_vec(),
                credential: replacement.clone(),
                activation_challenge: [48; 32].to_vec(),
            })),
        })
        .unwrap();
    let decoded = SubjectCredential::decode(&replacement).unwrap();
    let activation_proof = RotationActivationProof {
        mesh_id: mesh,
        peer_id: peer,
        rotation_id: request,
        issued_serial: decoded.serial,
        challenge: [48; 32],
    };
    assert_eq!(
        accepted,
        AcceptedUpdate::CredentialReplacement(CredentialReplacementUpdate {
            credential: replacement.clone(),
            activation_transcript: rotation_activation_transcript(&activation_proof),
        }),
    );
    let activation_signature =
        sign_rotation_activation(&replacement_identity.to_bytes(), &activation_proof);
    let activation = session.rotation_activation(activation_signature).unwrap();
    let Some(ControlMessage::Activation(activation)) = activation.message else {
        panic!("rotation activation was not encoded")
    };
    assert_eq!(activation.request_id, request.as_bytes());
    assert_eq!(activation.issued_serial, decoded.serial.as_bytes());
    assert_eq!(activation.signature, activation_signature);

    let published = directory
        .sign_peers(
            mesh,
            1,
            vec![directory.sign_peer(PeerEntry {
                secondary_address: None,
                mesh_id: mesh,
                peer_id: peer,
                address: "10.42.0.9".parse().unwrap(),
                identity_public_key: replacement_identity_public,
                noise_public_key: replacement_public,
                credential_serial: decoded.serial,
                accepted_credentials: vec![
                    peerward_directory::PeerCredentialBinding::from_subject(&decoded, None),
                    peerward_directory::PeerCredentialBinding::from_subject(
                        &current,
                        Some(current.not_after),
                    ),
                ],
                enabled: true,
                labels: BTreeMap::new(),
                not_after: UnixTime(now + 86_400),
            })],
        )
        .unwrap();
    assert_eq!(
        session.activated_credential_in_directory(&published),
        Some(replacement),
    );
    assert_eq!(session.activated_credential_in_directory(&published), None);
    // A fresh credential must not stage the next rotation on every reconnect,
    // even if a command for the old serial remains in the previous session.
    session.current_credential = decoded;
    assert!(!session.rotation_due(UnixTime(now)).unwrap());
    assert!(session.rotation_due(UnixTime(now + 86_399)).unwrap());
    session.state = State::Closed;
    assert!(session.rotation_due(UnixTime(now)).is_err());
}
