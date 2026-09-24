use super::*;
use peerward_credentials::{
    AuthoritySigningKey, RootSigningKey, UnsignedAuthority, UnsignedSubject,
};
use peerward_types::{CredentialSerial, PeerId, RelayId};

#[test]
fn enrollment_chain_time_boundaries_and_tampering_are_distinguished_without_accepting_invalid_state()
 {
    let mesh = MeshId::new();
    let peer = PeerId::new();
    let root = RootSigningKey::from_bytes(&[3; 32]);
    let authority = AuthoritySigningKey::from_bytes(&[4; 32]);
    let root_certificate = root
        .certify(UnsignedAuthority {
            mesh_id: mesh,
            serial: CredentialSerial::new(),
            public_key: authority.public_key(),
            not_before: UnixTime(10),
            not_after: UnixTime(10_000),
        })
        .unwrap();
    let identity = ed25519_dalek::SigningKey::from_bytes(&[5; 32])
        .verifying_key()
        .to_bytes();
    let noise = RawStaticDh::new([6; 32]).public_key();
    let wireguard = RawStaticDh::new([7; 32]).public_key();
    let credential = authority
        .issue(UnsignedSubject {
            subject: SubjectId::Peer(peer),
            mesh_id: mesh,
            identity_public_key: identity,
            public_noise_key: noise,
            wireguard_public_key: wireguard,
            serial: CredentialSerial::new(),
            not_before: UnixTime(100),
            not_after: UnixTime(1000),
        })
        .unwrap();
    let distribution = authority.certify_distribution(mesh, [8; 32], [9; 32], [10; 32]);
    let response = peerward_api::JoinResponse {
        profile_id: peer,
        mesh_id: mesh,
        peer_id: peer,
        mesh_name: "Phone fixture".into(),
        address: "10.7.0.2/32".into(),
        secondary_address: Some("fd70::2/128".into()),
        routes: vec!["10.7.0.0/24".into(), "fd70::/64".into()],
        dns_servers: vec!["10.7.0.1".into()],
        mtu: 1280,
        stun_servers: vec![],
        dns_suffix: "fixture.test".into(),
        credential: ENROLLMENT_BASE64.encode(credential.encode()),
        relays: vec![peerward_api::JoinRelayTarget {
            relay_id: RelayId::new(),
            endpoints: vec!["tcp://relay.example:443".parse().unwrap()],
            public_key: ENROLLMENT_BASE64.encode([11; 32]),
        }],
        root_public_key: ENROLLMENT_BASE64.encode(root.public_key().to_bytes()),
        authority_certificates: vec![ENROLLMENT_BASE64.encode(root_certificate.encode())],
        authority_revision: 1,
        distribution_public_key: ENROLLMENT_BASE64.encode([8; 32]),
        service_public_key: ENROLLMENT_BASE64.encode([9; 32]),
        audit_public_key: ENROLLMENT_BASE64.encode([10; 32]),
        distribution_certificate: ENROLLMENT_BASE64.encode(distribution.encode()),
    };
    let verify = |response: &peerward_api::JoinResponse, now| {
        verify_mobile_join_response(
            &serde_json::to_vec(response).unwrap(),
            Sha256::digest(root.public_key().to_bytes()).into(),
            identity,
            noise,
            wireguard,
            UnixTime(now),
        )
    };
    assert!(verify(&response, 100).is_ok());
    assert!(verify(&response, 999).is_ok());
    for now in [99, 1000] {
        assert!(matches!(
            verify(&response, now),
            Err(MobileError::Credential(CredentialError::OutsideValidity))
        ));
    }
    let mut tampered = response.clone();
    let mut signed = credential.encode();
    *signed.last_mut().unwrap() ^= 1;
    tampered.credential = ENROLLMENT_BASE64.encode(signed);
    assert!(matches!(
        verify(&tampered, 100),
        Err(MobileError::EnrollmentCredential(
            "subject",
            CredentialError::InvalidSignature
        ))
    ));
    let mut tampered = response.clone();
    let mut signed = distribution.encode();
    *signed.last_mut().unwrap() ^= 1;
    tampered.distribution_certificate = ENROLLMENT_BASE64.encode(signed);
    assert!(matches!(
        verify(&tampered, 100),
        Err(MobileError::EnrollmentCredential(
            "distribution",
            CredentialError::InvalidSignature
        ))
    ));
    let mut tampered = response;
    let mut signed = root_certificate.encode();
    *signed.last_mut().unwrap() ^= 1;
    tampered.authority_certificates = vec![ENROLLMENT_BASE64.encode(signed)];
    assert!(matches!(
        verify(&tampered, 100),
        Err(MobileError::EnrollmentCredential(
            "authority",
            CredentialError::InvalidSignature
        ))
    ));
}
