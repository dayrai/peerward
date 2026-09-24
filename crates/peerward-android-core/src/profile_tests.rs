use super::*;

#[test]
fn native_profile_blob_is_versioned_bounded_and_strict() {
    let json = br#"{"config_version":4,"profile_id":"profile","device_key_id":"device","mesh_id":"mesh","peer_id":"peer","mesh_name":"Mesh","address":"10.0.0.2/32","secondary_address":null,"dns_suffix":"mesh.test","credential":"credential","relays":[{"relay_id":"relay","endpoints":["tcp://relay.example:443"],"noise_public_key":""}],"stun_servers":[],"p2p_endpoints":[],"routes":["10.0.0.0/24"],"dns_servers":["10.0.0.1"],"mtu":1380,"local_identity_public":"","local_noise_public":"","local_wireguard_public":"BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ","root_public_key":"","authority_certificates":[],"authority_revision":0,"distribution_public_key":"","service_public_key":"","audit_public_key":"","distribution_certificate":"","previous_device_key_id":null,"pending_rotation_id":null,"pending_device_key_id":null,"pending_identity_public":null,"pending_noise_public":null,"pending_wireguard_public":null}"#;
    let blob = encode_mobile_profile(json).unwrap();
    assert_eq!(&blob[..5], b"PWMP\x04");
    assert_eq!(decode_mobile_profile(&blob).unwrap(), json);
    let dual = String::from_utf8(json.to_vec())
        .unwrap()
        .replace(
            "\"secondary_address\":null",
            "\"secondary_address\":\"fd20::2/128\"",
        )
        .replace(
            "\"routes\":[\"10.0.0.0/24\"]",
            "\"routes\":[\"10.0.0.0/24\",\"fd20::/64\"]",
        );
    let dual_blob = encode_mobile_profile(dual.as_bytes()).unwrap();
    assert_eq!(decode_mobile_profile(&dual_blob).unwrap(), dual.as_bytes());
    assert!(encode_mobile_profile(dual.replace("fd20::2/128", "10.0.0.3/32").as_bytes()).is_err());
    assert!(encode_mobile_profile(dual.replace("fd20::2/128", "fd21::2/128").as_bytes()).is_err());
    let mut legacy = blob.clone();
    legacy[4] = 3;
    assert!(decode_mobile_profile(&legacy).is_err());
    let enabled = String::from_utf8(json.to_vec()).unwrap().replace(
        "\"p2p_endpoints\":[]",
        "\"p2p_endpoints\":[],\"symmetric_nat_prediction\":true",
    );
    let enabled_blob = encode_mobile_profile(enabled.as_bytes()).unwrap();
    assert!(
        String::from_utf8(decode_mobile_profile(&enabled_blob).unwrap())
            .unwrap()
            .contains("\"symmetric_nat_prediction\":true")
    );
    let mapping_off = String::from_utf8(json.to_vec()).unwrap().replace(
        "\"p2p_endpoints\":[]",
        "\"p2p_endpoints\":[],\"nat_mapping\":\"off\"",
    );
    let mapping_off_blob = encode_mobile_profile(mapping_off.as_bytes()).unwrap();
    assert!(
        String::from_utf8(decode_mobile_profile(&mapping_off_blob).unwrap())
            .unwrap()
            .contains("\"nat_mapping\":\"off\"")
    );
    let mesh = peerward_types::MeshId::new();
    let peer = peerward_types::PeerId::new();
    let mut profile = parse_profile_blob(&blob).unwrap();
    profile.mesh_id = mesh.to_string();
    profile.peer_id = peer.to_string();
    let blob = encode_profile_document(&profile).unwrap();
    let plan = plan_mobile_rotation(&blob).unwrap();
    assert!(plan.staged_blob.is_some());
    let staged = plan.staged_blob.unwrap();
    let staged = install_mobile_rotation_publics(
        &staged,
        plan.request_id,
        &plan.key_id,
        [1; 32],
        [2; 32],
        [3; 32],
    )
    .unwrap();
    let recovered = plan_mobile_rotation(&staged).unwrap();
    assert_eq!(recovered.expected_identity, Some([1; 32]));
    assert_eq!(recovered.expected_noise, Some([2; 32]));
    assert_eq!(recovered.expected_wireguard, Some([3; 32]));
    let authority = peerward_credentials::AuthoritySigningKey::generate();
    let replacement = authority
        .issue(peerward_credentials::UnsignedSubject {
            subject: peerward_credentials::SubjectId::Peer(peer),
            mesh_id: mesh,
            identity_public_key: [1; 32],
            public_noise_key: [2; 32],
            wireguard_public_key: [3; 32],
            serial: peerward_types::CredentialSerial::new(),
            not_before: peerward_types::UnixTime(1),
            not_after: peerward_types::UnixTime(2),
        })
        .unwrap()
        .encode();
    assert!(mobile_rotation_recovery(&staged, &[]).unwrap().is_empty());
    let durable = mobile_rotation_recovery(&staged, &replacement).unwrap();
    assert_eq!(
        parse_profile_blob(&durable).unwrap().device_key_id,
        "device"
    );
    assert_eq!(
        parse_profile_blob(&durable).unwrap().credential,
        profile.credential
    );
    assert_eq!(
        mobile_rotation_recovery(&durable, &replacement).unwrap(),
        durable
    );
    let mut conflicting = replacement.clone();
    conflicting[129] ^= 1; // Different issued serial cannot replace a staged transaction.
    assert!(mobile_rotation_recovery(&durable, &conflicting).is_err());
    let recovered_profile = mobile_rotation_recovery(&durable, &[]).unwrap();
    let committed = commit_mobile_rotation(&durable, &replacement).unwrap();
    assert_eq!(recovered_profile, committed);
    assert!(
        parse_profile_blob(&committed)
            .unwrap()
            .pending_credential
            .is_none()
    );
    let committed_profile = parse_profile_blob(&committed).unwrap();
    assert_eq!(committed_profile.device_key_id, plan.key_id);
    assert_eq!(
        committed_profile.previous_device_key_id.as_deref(),
        Some("device")
    );
    let cleanup = clean_mobile_previous_key(&committed, &plan.key_id)
        .unwrap()
        .unwrap();
    assert_eq!(cleanup.key_id, "device");
    assert!(
        parse_profile_blob(&cleanup.cleaned_blob)
            .unwrap()
            .previous_device_key_id
            .is_none()
    );
    assert!(
        clean_mobile_previous_key(&blob, "device")
            .unwrap()
            .is_none()
    );
    let installed = install_mobile_authorities(&blob, 1, &[[3; 144]]).unwrap();
    assert_eq!(
        install_mobile_authorities(&installed, 1, &[[3; 144]]).unwrap(),
        installed
    );
    assert!(install_mobile_authorities(&installed, 1, &[[4; 144]]).is_err());
    assert!(install_mobile_authorities(&installed, 0, &[[3; 144]]).is_err());

    let mut trailing = blob;
    trailing.push(0);
    assert!(decode_mobile_profile(&trailing).is_err());
    assert!(encode_mobile_profile(&vec![b'{'; MAX_MOBILE_PROFILE_BYTES + 1]).is_err());
}
