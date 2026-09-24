use super::*;
use peerward_types::{CredentialSerial, MeshId, PeerId, RotationId};
use uuid::Uuid;

fn mesh() -> MeshId {
    MeshId::from_uuid(Uuid::parse_str("e4beb7cb-47c2-4b72-a914-a454f556af8b").unwrap()).unwrap()
}

fn peer() -> PeerId {
    PeerId::from_uuid(Uuid::parse_str("778f4317-0d08-4aab-9620-ca2c99a5ee3e").unwrap()).unwrap()
}

fn serial(value: u64) -> CredentialSerial {
    let mut bytes = [0_u8; 16];
    bytes[..8].copy_from_slice(&value.to_be_bytes());
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = 0x80;
    CredentialSerial::from_uuid(Uuid::from_bytes(bytes)).unwrap()
}

#[test]
fn rooted_credential_verifies_and_tampering_fails() {
    let root = RootSigningKey::from_bytes(&[7; 32]);
    let authority = AuthoritySigningKey::from_bytes(&[9; 32]);
    let cert = root
        .certify(UnsignedAuthority {
            mesh_id: mesh(),
            serial: serial(41),
            public_key: authority.public_key(),
            not_before: UnixTime(100),
            not_after: UnixTime(400),
        })
        .unwrap();
    let mut trust = TrustSet::new(root.public_key(), mesh());
    trust.add_authority(cert, UnixTime(200)).unwrap();
    let mut credential = authority
        .issue(UnsignedSubject {
            subject: SubjectId::Peer(peer()),
            mesh_id: mesh(),
            identity_public_key: [4; 32],
            public_noise_key: [3; 32],
            serial: serial(42),
            not_before: UnixTime(150),
            not_after: UnixTime(300),
            wireguard_public_key: [0x77; 32],
        })
        .unwrap();

    assert_eq!(trust.verify_subject(&credential, UnixTime(200)), Ok(()));
    let original = credential.clone();
    credential.wireguard_public_key[0] ^= 1;
    assert_eq!(
        trust.verify_subject(&credential, UnixTime(200)),
        Err(CredentialError::InvalidSignature)
    );
    credential = original;
    credential.public_noise_key[0] ^= 1;
    assert_eq!(
        trust.verify_subject(&credential, UnixTime(200)),
        Err(CredentialError::InvalidSignature)
    );
}

#[test]
fn authenticated_authority_verification_binds_every_subject_field_and_time() {
    let authority = AuthoritySigningKey::from_bytes(&[10; 32]);
    let credential = authority
        .issue(UnsignedSubject {
            subject: SubjectId::Peer(peer()),
            mesh_id: mesh(),
            identity_public_key: [6; 32],
            public_noise_key: [5; 32],
            serial: serial(43),
            not_before: UnixTime(100),
            not_after: UnixTime(200),
            wireguard_public_key: [0x77; 32],
        })
        .unwrap();
    assert_eq!(
        credential.verify_with_authority(&authority.public_key(), UnixTime(150)),
        Ok(())
    );
    assert_eq!(
        credential.verify_with_authority(&authority.public_key(), UnixTime(200)),
        Err(CredentialError::OutsideValidity)
    );
    assert_eq!(
        credential.verify_with_authority(
            &AuthoritySigningKey::from_bytes(&[11; 32]).public_key(),
            UnixTime(150),
        ),
        Err(CredentialError::InvalidSignature)
    );
    let mut tampered = credential;
    tampered.serial = serial(44);
    assert_eq!(
        tampered.verify_with_authority(&authority.public_key(), UnixTime(150)),
        Err(CredentialError::InvalidSignature)
    );
}

#[test]
fn revocation_is_exact_across_replacement() {
    let root = RootSigningKey::from_bytes(&[11; 32]);
    let authority = AuthoritySigningKey::from_bytes(&[12; 32]);
    let cert = root
        .certify(UnsignedAuthority {
            mesh_id: mesh(),
            serial: serial(1),
            public_key: authority.public_key(),
            not_before: UnixTime(0),
            not_after: UnixTime(1_000),
        })
        .unwrap();
    let mut trust = TrustSet::new(root.public_key(), mesh());
    trust.add_authority(cert, UnixTime(10)).unwrap();
    let issue = |value| {
        authority
            .issue(UnsignedSubject {
                subject: SubjectId::Peer(peer()),
                mesh_id: mesh(),
                identity_public_key: [9; 32],
                public_noise_key: [u8::try_from(value).unwrap(); 32],
                serial: serial(value),
                not_before: UnixTime(0),
                not_after: UnixTime(500),
                wireguard_public_key: [0x77; 32],
            })
            .unwrap()
    };
    let old = issue(20);
    let replacement = issue(21);
    trust.revoke_subject(serial(20));
    assert_eq!(
        trust.verify_subject(&old, UnixTime(30)),
        Err(CredentialError::Revoked)
    );
    assert_eq!(trust.verify_subject(&replacement, UnixTime(30)), Ok(()));
}

#[test]
fn authority_overlap_and_exact_revocation_preserve_new_issuer() {
    let root = RootSigningKey::from_bytes(&[21; 32]);
    let old_authority = AuthoritySigningKey::from_bytes(&[22; 32]);
    let new_authority = AuthoritySigningKey::from_bytes(&[23; 32]);
    let certify = |serial_value, public_key| {
        root.certify(UnsignedAuthority {
            mesh_id: mesh(),
            serial: serial(serial_value),
            public_key,
            not_before: UnixTime(0),
            not_after: UnixTime(500),
        })
        .unwrap()
    };
    let mut trust = TrustSet::new(root.public_key(), mesh());
    trust
        .add_authority(certify(30, old_authority.public_key()), UnixTime(10))
        .unwrap();
    trust
        .add_authority(certify(31, new_authority.public_key()), UnixTime(10))
        .unwrap();
    let issue = |authority: &AuthoritySigningKey, serial_value, key_byte| {
        authority
            .issue(UnsignedSubject {
                subject: SubjectId::Peer(peer()),
                mesh_id: mesh(),
                identity_public_key: [9; 32],
                public_noise_key: [key_byte; 32],
                serial: serial(serial_value),
                not_before: UnixTime(0),
                not_after: UnixTime(400),
                wireguard_public_key: [0x77; 32],
            })
            .unwrap()
    };
    let old = issue(&old_authority, 32, 1);
    let replacement = issue(&new_authority, 33, 2);
    assert_eq!(trust.verify_subject(&old, UnixTime(20)), Ok(()));
    assert_eq!(trust.verify_subject(&replacement, UnixTime(20)), Ok(()));
    trust.revoke_authority(serial(30));
    assert_eq!(
        trust.verify_subject(&old, UnixTime(20)),
        Err(CredentialError::InvalidSignature)
    );
    assert_eq!(trust.verify_subject(&replacement, UnixTime(20)), Ok(()));
}

#[test]
fn authority_bundle_rotates_trust_atomically_and_rejects_rollback() {
    let root = RootSigningKey::from_bytes(&[51; 32]);
    let old_authority = AuthoritySigningKey::from_bytes(&[52; 32]);
    let active_authority = AuthoritySigningKey::from_bytes(&[53; 32]);
    let certify = |serial_value, public_key| {
        root.certify(UnsignedAuthority {
            mesh_id: mesh(),
            serial: serial(serial_value),
            public_key,
            not_before: UnixTime(10),
            not_after: UnixTime(500),
        })
        .unwrap()
    };
    let old_certificate = certify(101, old_authority.public_key());
    let active_certificate = certify(102, active_authority.public_key());
    let signed = active_authority
        .sign_authority_bundle(
            mesh(),
            7,
            active_certificate.clone(),
            vec![old_certificate.clone()],
            vec![serial(100)],
        )
        .unwrap();
    let encoded = signed.encode().unwrap();
    let decoded = SignedAuthorityBundle::decode(&encoded).unwrap();
    assert_eq!(decoded, signed);

    let mut resumed = TrustSet::new(root.public_key(), mesh());
    resumed
        .add_authority(active_certificate.clone(), UnixTime(100))
        .unwrap();
    resumed
        .add_authority(old_certificate.clone(), UnixTime(100))
        .unwrap();
    resumed.resume_authority_revision(7).unwrap();
    resumed
        .install_authority_bundle_after_resume(&decoded, UnixTime(100))
        .unwrap();
    assert_eq!(resumed.authority_revision(), Some(7));
    assert_eq!(
        resumed.install_authority_bundle_after_resume(&decoded, UnixTime(100)),
        Err(CredentialError::Rollback)
    );

    let mut mismatched_resume = TrustSet::new(root.public_key(), mesh());
    mismatched_resume
        .add_authority(old_certificate.clone(), UnixTime(100))
        .unwrap();
    mismatched_resume.resume_authority_revision(7).unwrap();
    assert_eq!(
        mismatched_resume.install_authority_bundle_after_resume(&decoded, UnixTime(100)),
        Err(CredentialError::Rollback)
    );

    let mut trust = TrustSet::new(root.public_key(), mesh());
    trust
        .install_authority_bundle(&decoded, UnixTime(100))
        .unwrap();
    assert_eq!(trust.authority_revision(), Some(7));

    let issue = |authority: &AuthoritySigningKey, serial_value| {
        authority
            .issue(UnsignedSubject {
                subject: SubjectId::Peer(peer()),
                mesh_id: mesh(),
                identity_public_key: [9; 32],
                public_noise_key: [u8::try_from(serial_value).unwrap(); 32],
                serial: serial(serial_value),
                not_before: UnixTime(20),
                not_after: UnixTime(400),
                wireguard_public_key: [0x77; 32],
            })
            .unwrap()
    };
    assert_eq!(
        trust.verify_subject(&issue(&old_authority, 103), UnixTime(100)),
        Ok(())
    );
    assert_eq!(
        trust.verify_subject(&issue(&active_authority, 104), UnixTime(100)),
        Ok(())
    );
    assert_eq!(
        trust.install_authority_bundle(&decoded, UnixTime(100)),
        Err(CredentialError::Rollback)
    );

    let mut tampered = decoded;
    tampered.bundle.revision = 8;
    assert!(matches!(
        root.public_key()
            .verify_authority_bundle(&tampered, mesh(), Some(7), UnixTime(100)),
        Err(CredentialError::InvalidSignature)
    ));
}

#[test]
fn authority_bundle_golden_vector_is_stable() {
    let root = RootSigningKey::from_bytes(&[61; 32]);
    let authority = AuthoritySigningKey::from_bytes(&[62; 32]);
    let certificate = root
        .certify(UnsignedAuthority {
            mesh_id: mesh(),
            serial: serial(201),
            public_key: authority.public_key(),
            not_before: UnixTime(1_700_000_000),
            not_after: UnixTime(1_800_000_000),
        })
        .unwrap();
    let signed = authority
        .sign_authority_bundle(mesh(), 9, certificate, Vec::new(), vec![serial(199)])
        .unwrap();
    assert_eq!(
        hex::encode(authority_bundle_transcript(&signed.bundle)),
        "70656572776172642f617574686f726974792d62756e646c652f763100e4beb7cb47c24b72a914a454f556af8b0000000000000009e4beb7cb47c24b72a914a454f556af8b00000000000040c98000000000000000f95c6a5dff031fac7b1a6a54b6610caeb83b39f7e8a66be16ff5faa4a511ed2d000000006553f100000000006b49d2007841d9d47226fababeb511b7ee35e7125ab25174483ae76aaa23d04ba13ba1191975744c9f7e167c5d5c934d96134ea34496c3b66fcbeba5112610428d57d505000000000000000100000000000040c78000000000000000"
    );
    assert_eq!(
        hex::encode(signed.signature),
        "d43c2ec787491977a357087bb853e03cecc28d805ad7c3aaee380b9484c1dc332f0f5aea0fb1e1fa6a5bc410e05cbf1b9beba0fca4386d1f87b7bc3aa424980c"
    );
}

#[test]
fn golden_transcript_and_signatures_are_stable() {
    let root = RootSigningKey::from_bytes(&[1; 32]);
    let authority = AuthoritySigningKey::from_bytes(&[2; 32]);
    let unsigned_authority = UnsignedAuthority {
        mesh_id: mesh(),
        serial: serial(0x0102_0304_0506_0708),
        public_key: authority.public_key(),
        not_before: UnixTime(1_700_000_000),
        not_after: UnixTime(1_800_000_000),
    };
    let certificate = root.certify(unsigned_authority).unwrap();
    let unsigned_subject = UnsignedSubject {
        subject: SubjectId::Peer(peer()),
        mesh_id: mesh(),
        identity_public_key: [0x5a; 32],
        public_noise_key: [0xa5; 32],
        serial: serial(77),
        not_before: UnixTime(1_700_000_001),
        not_after: UnixTime(1_700_003_600),
        wireguard_public_key: [0x77; 32],
    };
    let credential = authority.issue(unsigned_subject).unwrap();

    assert_eq!(
        hex::encode(authority_transcript(&unsigned_authority)),
        "70656572776172642f726f6f742d617574686f726974792f763100e4beb7cb47c24b72a914a454f556af8b010203040506470880000000000000008139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394000000006553f100000000006b49d200"
    );
    assert_eq!(
        hex::encode(certificate.signature),
        "99143afb9204ad907059bd2b5ed16f18c0ba34f4d045d68a586cb077bc010d5ff0a741ec95c60b3c34390004367f548e0ee0e17b6e9bd5fdcb0dc0e8cc70d80b"
    );
    assert_eq!(
        hex::encode(subject_transcript(&unsigned_subject)),
        concat!(
            "70656572776172642f7375626a6563742d63726564656e7469616c2f76330001",
            "e4beb7cb47c24b72a914a454f556af8b778f43170d084aab9620ca2c99a5ee3e",
            "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a",
            "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5",
            "7777777777777777777777777777777777777777777777777777777777777777",
            "000000000000404d8000000000000000000000006553f101000000006553ff10",
        )
    );
    assert_eq!(
        hex::encode(credential.signature),
        "75ec44d4e6727f0d8bd9ce30eec5adab84e7b03341b7c01767e039e4ce9d506b5a421dcd91da62a041eff359856cc50efa559a873b07a6a3aedad938b76d5f0c"
    );
}

#[test]
fn handshake_credential_codec_is_exact_and_role_preserving() {
    let authority = AuthoritySigningKey::from_bytes(&[31; 32]);
    let credential = authority
        .issue(UnsignedSubject {
            subject: SubjectId::Peer(peer()),
            mesh_id: mesh(),
            identity_public_key: [45; 32],
            public_noise_key: [44; 32],
            serial: serial(90),
            not_before: UnixTime(10),
            not_after: UnixTime(20),
            wireguard_public_key: [0x77; 32],
        })
        .unwrap();
    let encoded = credential.encode();
    assert_eq!(encoded.len(), 225);
    assert_eq!(SubjectCredential::decode(&encoded).unwrap(), credential);
    let mut low_order = [0; 32];
    low_order[0] = 1;
    for key in [
        low_order,
        [0; 32],
        credential.identity_public_key,
        credential.public_noise_key,
    ] {
        let mut invalid = encoded.clone();
        invalid[97..129].copy_from_slice(&key);
        assert!(SubjectCredential::decode(&invalid).is_err());
    }
    assert_eq!(
        SubjectCredential::decode(&encoded[..193]),
        Err(CredentialError::Malformed)
    );
}

#[test]
fn distribution_keys_are_bound_to_a_rooted_authority() {
    let root = RootSigningKey::from_bytes(&[41; 32]);
    let authority = AuthoritySigningKey::from_bytes(&[42; 32]);
    let certificate = root
        .certify(UnsignedAuthority {
            mesh_id: mesh(),
            serial: serial(43),
            public_key: authority.public_key(),
            not_before: UnixTime(1),
            not_after: UnixTime(100),
        })
        .unwrap();
    let distribution = authority.certify_distribution(mesh(), [44; 32], [45; 32], [46; 32]);
    assert_eq!(
        DistributionCertificate::decode(&distribution.encode()).unwrap(),
        distribution
    );
    let mut trust = TrustSet::new(root.public_key(), mesh());
    trust.add_authority(certificate, UnixTime(50)).unwrap();
    assert_eq!(
        trust.verify_distribution(&distribution, UnixTime(50)),
        Ok(())
    );
    let mut tampered = distribution;
    tampered.service_public_key[0] ^= 1;
    assert_eq!(
        trust.verify_distribution(&tampered, UnixTime(50)),
        Err(CredentialError::InvalidSignature)
    );
    trust.revoke_authority(serial(43));
    assert_eq!(
        trust.verify_distribution(&distribution, UnixTime(50)),
        Err(CredentialError::Revoked)
    );
}

#[test]
fn join_claim_proves_all_three_keys_and_every_canonical_field() {
    let identity_private_key = [51; 32];
    let identity_public_key = SigningKey::from_bytes(&identity_private_key)
        .verifying_key()
        .to_bytes();
    let nonce = [52; 32];
    let proof = JoinClaimProof {
        schema_version: 2,
        claim_id: Uuid::parse_str("8a302ac6-bfe7-45d7-946c-638783c3ee42").unwrap(),
        ticket_digest: [53; 32],
        identity_public_key,
        session_public_key: [54; 32],
        client_version: "1.0.0",
        supported_wire_major: 2,
        nonce: &nonce,
        device_name: "peerward-test",
        device_model: "test-model",
        platform: "linux",
        platform_version: "6.12",
        wireguard_public_key: [0x77; 32],
    };
    let signature = sign_join_claim(&identity_private_key, &proof).unwrap();
    assert_eq!(verify_join_claim(&proof, &signature), Ok(()));

    let mut changed_wireguard = proof;
    changed_wireguard.wireguard_public_key[0] ^= 1;
    assert_eq!(
        verify_join_claim(&changed_wireguard, &signature),
        Err(CredentialError::InvalidSignature)
    );
    let mut legacy = proof;
    legacy.schema_version = 1;
    assert_eq!(
        join_claim_transcript(&legacy),
        Err(CredentialError::Malformed)
    );
    let mut reused = proof;
    reused.wireguard_public_key = proof.session_public_key;
    assert!(join_claim_transcript(&reused).is_err());
    let mut low_order = proof;
    low_order.wireguard_public_key = [0; 32];
    low_order.wireguard_public_key[0] = 1;
    assert!(sign_join_claim(&identity_private_key, &low_order).is_err());
    let mut changed_session = proof;
    changed_session.session_public_key[0] ^= 1;
    assert_eq!(
        verify_join_claim(&changed_session, &signature),
        Err(CredentialError::InvalidSignature)
    );
    let mut changed_ticket = proof;
    changed_ticket.ticket_digest[0] ^= 1;
    assert_eq!(
        verify_join_claim(&changed_ticket, &signature),
        Err(CredentialError::InvalidSignature)
    );
    let malformed = JoinClaimProof {
        nonce: &[0; 15],
        ..proof
    };
    assert_eq!(
        join_claim_transcript(&malformed),
        Err(CredentialError::Malformed)
    );
}

#[test]
fn rotation_requires_current_and_new_identity_proofs() {
    let current_private_key = [61; 32];
    let current_public_key = SigningKey::from_bytes(&current_private_key)
        .verifying_key()
        .to_bytes();
    let new_private_key = [62; 32];
    let new_public_key = SigningKey::from_bytes(&new_private_key)
        .verifying_key()
        .to_bytes();
    let rotation_id =
        RotationId::from_uuid(Uuid::parse_str("b37c5e62-2594-43b5-8e5c-4f0587955448").unwrap())
            .unwrap();
    let request = RotationRequestProof {
        mesh_id: mesh(),
        peer_id: peer(),
        rotation_id,
        current_serial: serial(91),
        identity_public_key: new_public_key,
        session_public_key: [63; 32],
        wireguard_public_key: [0x77; 32],
    };
    let request_signature = sign_rotation_request(&current_private_key, &request).unwrap();
    assert_eq!(
        verify_rotation_request(&current_public_key, &request, &request_signature),
        Ok(())
    );
    let mut changed_wireguard = request;
    changed_wireguard.wireguard_public_key[0] ^= 1;
    assert_eq!(
        verify_rotation_request(&current_public_key, &changed_wireguard, &request_signature),
        Err(CredentialError::InvalidSignature)
    );
    let mut low_order = request;
    low_order.wireguard_public_key = [0; 32];
    low_order.wireguard_public_key[0] = 1;
    assert!(sign_rotation_request(&current_private_key, &low_order).is_err());
    let mut changed_request = request;
    changed_request.session_public_key[0] ^= 1;
    assert_eq!(
        verify_rotation_request(&current_public_key, &changed_request, &request_signature),
        Err(CredentialError::InvalidSignature)
    );

    let activation = RotationActivationProof {
        mesh_id: mesh(),
        peer_id: peer(),
        rotation_id,
        issued_serial: serial(92),
        challenge: [64; 32],
    };
    let activation_signature = sign_rotation_activation(&new_private_key, &activation);
    assert_eq!(
        verify_rotation_activation(&new_public_key, &activation, &activation_signature),
        Ok(())
    );
    let mut replayed_for_other_challenge = activation;
    replayed_for_other_challenge.challenge[0] ^= 1;
    assert_eq!(
        verify_rotation_activation(
            &new_public_key,
            &replayed_for_other_challenge,
            &activation_signature,
        ),
        Err(CredentialError::InvalidSignature)
    );
}

#[test]
fn omitted_authority_revocations_never_reauthorize_an_old_certificate() {
    let root = RootSigningKey::from_bytes(&[61; 32]);
    let active = AuthoritySigningKey::from_bytes(&[62; 32]);
    let old = AuthoritySigningKey::from_bytes(&[63; 32]);
    let certify = |key: &AuthoritySigningKey, number| {
        root.certify(UnsignedAuthority {
            mesh_id: mesh(),
            serial: serial(number),
            public_key: key.public_key(),
            not_before: UnixTime(1),
            not_after: UnixTime(500),
        })
        .unwrap()
    };
    let certificate = certify(&active, 301);
    let retired = certify(&old, 300);
    let mut trust = TrustSet::new(root.public_key(), mesh());
    trust
        .install_authority_bundle(
            &active
                .sign_authority_bundle(mesh(), 1, certificate.clone(), vec![], vec![retired.serial])
                .unwrap(),
            UnixTime(100),
        )
        .unwrap();
    trust
        .install_authority_bundle(
            &active
                .sign_authority_bundle(mesh(), 2, certificate.clone(), vec![], vec![])
                .unwrap(),
            UnixTime(100),
        )
        .unwrap();
    let reintroduction = active
        .sign_authority_bundle(mesh(), 3, certificate, vec![retired], vec![])
        .unwrap();
    assert_eq!(
        trust.install_authority_bundle(&reintroduction, UnixTime(100)),
        Err(CredentialError::Revoked)
    );
    assert_eq!(trust.authority_revision(), Some(2));
}
