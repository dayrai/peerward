use clap::{CommandFactory, Parser};

use super::*;
use peerward_types::PeerId;

#[test]
fn control_startup_error_preserves_actionable_safe_database_reason() {
    let error =
        peerward_control::ApiError::from(peerward_store::StoreError::LegacySchemaUnsupported);
    let text = error.to_string();
    assert!(text.contains("legacy_schema_unsupported"));
    assert!(text.contains("Schema 4 / Wire 5"));
    assert!(text.contains("has not been modified"));
    assert!(text.contains("new installation directory"));
}

#[test]
fn runtime_error_includes_nested_socket_cause() {
    let error = peerward_peer::PeerError::Io(std::io::Error::from_raw_os_error(98));
    let failure = peer_runtime_error("peer transport failed", &error);
    assert!(failure.message.contains("peer relay socket failed"));
    assert!(
        failure
            .message
            .contains(&std::io::Error::from_raw_os_error(98).to_string())
    );
}

#[test]
fn runtime_failure_survives_failed_network_rollback() {
    let original = CliError::unavailable("relay attachment");
    let message = original.message.clone();
    let failure = finish_peer_runtime(
        Err(original),
        Err(peerward_platform::PlatformError::Rollback),
    )
    .unwrap_err();
    assert_eq!(failure.code, EXIT_UNAVAILABLE);
    assert!(failure.message.starts_with(&message));
    assert!(failure.message.contains("Linux data plane rollback failed"));
}

#[test]
fn rollback_failure_is_reported_after_successful_runtime() {
    let failure = finish_peer_runtime(
        Ok(()),
        Err(peerward_platform::PlatformError::OwnershipConflict),
    )
    .unwrap_err();
    assert_eq!(failure.code, EXIT_FAILURE);
    assert!(failure.message.contains("ownership changed"));
}

#[test]
fn successful_rollback_preserves_runtime_outcome() {
    assert!(finish_peer_runtime(Ok(()), Ok(())).is_ok());
    let failure = finish_peer_runtime(Err(CliError::auth("revoked")), Ok(())).unwrap_err();
    assert_eq!(failure.code, EXIT_AUTH);
    assert_eq!(failure.message, "revoked");
}

#[test]
fn command_tree_is_internally_consistent() {
    Cli::command().debug_assert();
}

#[test]
fn client_preferences_commands_require_an_explicit_profile_and_support_boolean_values() {
    for arguments in [
        vec!["peerward", "client", "preferences", "--config", "peer.toml"],
        vec![
            "peerward",
            "client",
            "set",
            "--config",
            "peer.toml",
            "--dns",
            "false",
            "--inbound",
            "false",
        ],
        vec![
            "peerward",
            "client",
            "exit",
            "select",
            "--config",
            "peer.toml",
            "--resource",
            "home",
            "--allow-local-lan",
        ],
        vec![
            "peerward",
            "client",
            "exit",
            "off",
            "--config",
            "peer.toml",
            "--offline",
        ],
    ] {
        Cli::try_parse_from(arguments).unwrap();
    }
    assert!(Cli::try_parse_from(["peerward", "client", "exit", "off", "--offline"]).is_err());
}

#[test]
fn parses_every_documented_command_shape() {
    let commands = [
        vec!["peerward", "control", "run", "--config", "control.toml"],
        vec!["peerward", "relay", "run", "--config", "relay.toml"],
        vec!["peerward", "peer", "run", "--config", "peer.toml"],
        vec![
            "peerward",
            "db",
            "migrate",
            "--database-url",
            "postgres://db",
        ],
        vec![
            "peerward",
            "identity",
            "verify",
            "--root-public",
            "root.pub",
            "--mesh-id",
            "970a3f18-1c6f-4da6-a223-f9623958a928",
            "--authority-certificate",
            "authority.cert",
            "--credential",
            "peer.credential",
            "--distribution-certificate",
            "distribution.cert",
        ],
        vec![
            "peerward",
            "identity",
            "root",
            "generate",
            "--private",
            "root.key",
            "--public",
            "root.pub",
        ],
        vec![
            "peerward",
            "identity",
            "authority",
            "issue",
            "--root-private",
            "root.key",
            "--mesh-id",
            "970a3f18-1c6f-4da6-a223-f9623958a928",
            "--authority-public",
            "authority.pub",
            "--output",
            "authority.cert",
        ],
        vec![
            "peerward",
            "identity",
            "noise",
            "generate",
            "--private",
            "noise.key",
            "--public",
            "noise.pub",
        ],
        vec![
            "peerward",
            "join",
            "accept",
            "peerward://join?bundle=x",
            "--output-dir",
            "profile",
        ],
        vec![
            "peerward",
            "service",
            "publish",
            "--listen-port",
            "443",
            "--target",
            "127.0.0.1:8443",
            "--protocol",
            "both",
            "--name",
            "web",
        ],
        vec!["peerward", "service", "list"],
        vec![
            "peerward",
            "service",
            "remove",
            "970a3f18-1c6f-4da6-a223-f9623958a928",
        ],
        vec![
            "peerward",
            "config",
            "check",
            "--role",
            "peer",
            "--online",
            "peer.toml",
        ],
        vec!["peerward", "doctor", "--config", "peer.toml", "--json"],
        vec!["peerward", "health"],
        vec!["peerward", "status"],
        vec!["peerward", "metrics"],
        vec![
            "peerward",
            "update",
            "check",
            "--manifest",
            "manifest.json",
            "--signature",
            "manifest.sig",
            "--public-key",
            "update.pub",
        ],
        vec![
            "peerward",
            "update",
            "apply",
            "--manifest",
            "manifest.json",
            "--signature",
            "manifest.sig",
            "--public-key",
            "update.pub",
            "--channel",
            "beta",
            "--install-path",
            "/usr/local/bin/peerward",
        ],
        vec![
            "peerward",
            "update",
            "rollback",
            "--install-path",
            "/usr/local/bin/peerward",
        ],
    ];
    for command in commands {
        Cli::try_parse_from(command).unwrap();
    }
}

#[test]
fn exit_codes_match_contract() {
    assert_eq!(EXIT_SUCCESS, 0);
    assert_eq!(EXIT_FAILURE, 1);
    assert_eq!(EXIT_INVALID, 2);
    assert_eq!(EXIT_UNAVAILABLE, 3);
    assert_eq!(EXIT_AUTH, 4);
}

#[test]
fn join_bundle_requires_pinned_root_and_rejects_unknown_fields() {
    let mesh = MeshId::new();
    let root = [9_u8; 32];
    let uri = format!(
        "peerward://join?control=http%3A%2F%2F127.0.0.1%3A8080&token={}&mesh_id={mesh}&root_public_key={}",
        URL_SAFE_NO_PAD.encode([7_u8; 32]),
        URL_SAFE_NO_PAD.encode(root),
    );
    let parsed = parse_join_bundle(&uri).unwrap();
    assert_eq!(parsed.mesh_id, mesh);
    assert_eq!(parsed.root_pin, RootPin::PublicKey(root));
    assert_eq!(
        parsed.claim_url.as_str(),
        format!(
            "http://127.0.0.1:8080/api/v1/join/{}/claim",
            URL_SAFE_NO_PAD.encode([7_u8; 32])
        )
    );
    assert!(parse_join_bundle(&format!("{uri}&surprise=true")).is_err());
    assert!(parse_join_bundle("https://example.test/join").is_err());
}

#[test]
fn parses_console_join_bundle_and_rejects_invalid_envelopes() {
    let mesh = MeshId::new();
    let token = URL_SAFE_NO_PAD.encode([7_u8; 32]);
    let fingerprint = [11_u8; 32];
    let expires_at = current_unix_time().unwrap() + 600;
    let body = serde_json::json!({
        "claim_url": format!("http://127.0.0.1:28081/api/v1/join/{token}/claim"),
        "root_fingerprint": hex::encode(fingerprint),
        "expires_at": expires_at,
        "nonce": URL_SAFE_NO_PAD.encode([12_u8; 16]),
        "mesh_id": mesh,
    });
    let encoded = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&body).unwrap());
    let uri = format!("peerward://join?bundle={encoded}");

    let parsed = parse_join_bundle(&uri).unwrap();
    assert_eq!(parsed.mesh_id, mesh);
    assert_eq!(parsed.token, token);
    assert_eq!(parsed.root_pin, RootPin::Fingerprint(fingerprint));
    assert_eq!(
        parsed.claim_url.as_str(),
        format!("http://127.0.0.1:28081/api/v1/join/{token}/claim")
    );

    assert!(parse_join_bundle(&format!("{uri}&bundle=again")).is_err());
    let mut invalid = body.clone();
    invalid["extra"] = serde_json::Value::Bool(true);
    let invalid = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&invalid).unwrap());
    assert!(parse_join_bundle(&format!("peerward://join?bundle={invalid}")).is_err());
    let mut expired = body;
    expired["expires_at"] = serde_json::Value::from(current_unix_time().unwrap() - 1);
    let expired = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&expired).unwrap());
    assert!(parse_join_bundle(&format!("peerward://join?bundle={expired}")).is_err());
}

#[test]
fn verified_join_profile_is_committed_atomically_and_parses() {
    let mesh = MeshId::new();
    let peer = PeerId::new();
    let relay = RelayId::new();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let root = RootSigningKey::from_bytes(&[21; 32]);
    let authority = peerward_credentials::AuthoritySigningKey::from_bytes(&[22; 32]);
    let authority_certificate = root
        .certify(UnsignedAuthority {
            mesh_id: mesh,
            serial: CredentialSerial::new(),
            public_key: authority.public_key(),
            not_before: UnixTime(now - 60),
            not_after: UnixTime(now + 3_600),
        })
        .unwrap();
    let private = StaticSecret::from([23; 32]);
    let public = NoisePublicKey::from(&private).to_bytes();
    let credential = authority
        .issue(peerward_credentials::UnsignedSubject {
            subject: SubjectId::Peer(peer),
            mesh_id: mesh,
            identity_public_key: [26; 32],
            public_noise_key: public,
            serial: CredentialSerial::new(),
            not_before: UnixTime(now - 60),
            not_after: UnixTime(now + 3_600),
            wireguard_public_key: [0x77; 32],
        })
        .unwrap();
    let distribution = authority.certify_distribution(mesh, [24; 32], [25; 32], [27; 32]);
    let response = JoinResponse {
        secondary_address: Some("fd20::2/128".into()),
        profile_id: peer,
        mesh_id: mesh,
        peer_id: peer,
        mesh_name: "test mesh".into(),
        address: "10.20.0.2/32".into(),
        routes: vec!["10.20.0.0/24".into(), "fd20::/64".into()],
        dns_servers: vec!["10.20.0.1".into()],
        mtu: 1_380,
        stun_servers: vec!["STUN.Example:3478".into(), "[2001:db8::1]:3478".into()],
        dns_suffix: "test.mesh".into(),
        credential: URL_SAFE_NO_PAD.encode(credential.encode()),
        relays: vec![peerward_api::JoinRelayTarget {
            relay_id: relay,
            endpoints: vec!["tcp://127.0.0.1:7777".parse().unwrap()],
            public_key: URL_SAFE_NO_PAD.encode([26; 32]),
        }],
        root_public_key: URL_SAFE_NO_PAD.encode(root.public_key().to_bytes()),
        authority_certificates: vec![URL_SAFE_NO_PAD.encode(authority_certificate.encode())],
        authority_revision: 1,
        distribution_public_key: URL_SAFE_NO_PAD.encode([24; 32]),
        service_public_key: URL_SAFE_NO_PAD.encode([25; 32]),
        audit_public_key: URL_SAFE_NO_PAD.encode([27; 32]),
        distribution_certificate: URL_SAFE_NO_PAD.encode(distribution.encode()),
    };
    let bundle = ParsedJoinBundle {
        claim_url: Url::parse(&format!(
            "https://control.test/api/v1/join/{}/claim",
            URL_SAFE_NO_PAD.encode([27; 32])
        ))
        .unwrap(),
        token: URL_SAFE_NO_PAD.encode([27; 32]),
        mesh_id: mesh,
        root_pin: RootPin::Fingerprint(Sha256::digest(root.public_key().to_bytes()).into()),
    };
    let verified = verify_join_response(&bundle, &response, [26; 32], public, [0x77; 32]).unwrap();
    let mut missing_family = response.clone();
    missing_family.secondary_address = None;
    assert!(verify_join_response(&bundle, &missing_family, [26; 32], public, [0x77; 32]).is_err());
    missing_family.secondary_address = Some("10.20.0.3/32".into());
    assert!(verify_join_response(&bundle, &missing_family, [26; 32], public, [0x77; 32]).is_err());
    let mismatched_bundle = ParsedJoinBundle {
        root_pin: RootPin::Fingerprint([0; 32]),
        ..bundle
    };
    assert!(
        verify_join_response(&mismatched_bundle, &response, [26; 32], public, [0x77; 32]).is_err()
    );
    let temporary = std::env::temp_dir().join(format!("peerward-join-test-{}", Uuid::new_v4()));
    let output = temporary.join("profile");
    persist_join_profile(
        &output,
        &response,
        &verified,
        &[9_u8; 32],
        &private.to_bytes(),
        &[10_u8; 32],
    )
    .unwrap();
    let profile_path = output.join("peer.toml");
    let contents = fs::read_to_string(&profile_path).unwrap();
    let parsed = PeerConfig::parse(&contents, &profile_path).unwrap();
    assert_eq!(parsed.mesh_id, mesh);
    assert_eq!(parsed.peer_id, peer);
    assert_eq!(
        parsed.linux.as_ref().unwrap().secondary_address,
        Some("fd20::2/128".parse().unwrap())
    );
    assert_eq!(parsed.relays[0].relay_id, relay);
    assert!(matches!(
        parsed.linux.as_ref().unwrap().dns_backend,
        peerward_peer::LinuxDnsBackend::Auto
    ));
    let service_key = hex::encode([25; 32]);
    assert_eq!(
        parsed.service_distribution_public_key.as_deref(),
        Some(service_key.as_str())
    );
    verify_identity(&IdentityVerifyArgs {
        root_public: output.join("root.pub"),
        mesh_id: mesh.into_uuid(),
        authority_certificates: vec![output.join("authority-0.cert")],
        credentials: vec![output.join("peer.credential")],
        distribution_certificate: Some(output.join("distribution.cert")),
    })
    .unwrap();
    fs::remove_dir_all(temporary).unwrap();
}

#[test]
fn packaged_config_examples_parse_with_current_role_schemas() {
    let database = Some("postgres://localhost/peerward_test".to_owned());
    ControlConfig::parse(
        include_str!("../../../examples/config/control.toml"),
        database.clone(),
    )
    .unwrap();
    RelayConfig::parse(
        include_str!("../../../examples/config/relay.toml"),
        Path::new("/etc/peerward/relay.toml"),
        database,
    )
    .unwrap();
    let peer = PeerConfig::parse(
        include_str!("../../../examples/config/peer.toml"),
        Path::new("/etc/peerward/peer.toml"),
    )
    .unwrap();
    assert_ne!(peer.private_key_file, peer.wireguard_private_key_file);
    assert_ne!(
        peer.identity_private_key_file,
        peer.wireguard_private_key_file
    );
}
