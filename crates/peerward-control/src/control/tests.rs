#[cfg(test)]
mod tests {
    #[test]
    fn console_diagnostics_never_promote_missing_or_offline_evidence_to_healthy() {
        use peerward_types::{DiagnosticCode, RuntimeDiagnostic};
        let offline = super::console_runtime_diagnostics(false, Some(200), Some(100), vec![]);
        assert_eq!(offline, vec![RuntimeDiagnostic::new(DiagnosticCode::DeviceOffline, Some(200))]);
        let missing = super::console_runtime_diagnostics(true, Some(200), None, vec![]);
        assert_eq!(missing, vec![RuntimeDiagnostic::new(DiagnosticCode::ObservationUnavailable, None)]);
        let current = super::console_runtime_diagnostics(true, Some(200), Some(199), vec!["dns_degraded".into()]);
        assert_eq!(current, vec![RuntimeDiagnostic::new(DiagnosticCode::DnsDegraded, Some(199))]);
        assert!(super::console_runtime_diagnostics(true, Some(200), Some(199), vec![]).is_empty());
    }
    use super::*;

    #[test]
    fn native_rollback_receipt_requires_original_role_version_and_artifact() {
        let mut preview = json!({"upgrade":{"role":"relay","current_version":"1.0.0","version":"1.0.1",
            "manifest_sha256":"a".repeat(64),"artifact_sha256":"b".repeat(64),"artifact_bytes":100,"rollback_floor":"1.0.0","repair":false}});
        let report = json!({"task_id":Uuid::new_v4(),"local_version":1,"status":"failed","stage":"rolled_back",
            "error_code":"native_upgrade_rolled_back","artifact":{"sha256":"c".repeat(64),"bytes":90,"files":1},
            "upgrade":{"role":"relay","version":"1.0.0","manifest_sha256":"a".repeat(64),"current_sha256":"c".repeat(64),
            "state":"rolled_back","runtime_checked":true}});
        let decode = |value| serde_json::from_value::<DeploymentTaskReport>(value).unwrap();
        assert!(
            validate_native_upgrade_report("native_upgrade", &preview, &decode(report.clone()))
                .is_ok()
        );
        for change in [
            json!({"version":"0.9.0"}),
            json!({"current_sha256":"d".repeat(64)}),
            json!({"runtime_checked":false}),
        ] {
            let mut invalid = report.clone();
            for (key, value) in change.as_object().unwrap() {
                invalid["upgrade"][key] = value.clone();
            }
            assert!(
                validate_native_upgrade_report("native_upgrade", &preview, &decode(invalid))
                    .is_err()
            );
        }
        preview["upgrade"]["role"] = json!("control");
        let mut invalid = report;
        invalid["upgrade"]["role"] = json!("control");
        assert!(
            validate_native_upgrade_report("native_upgrade", &preview, &decode(invalid)).is_err()
        );
    }

    #[cfg(feature = "postgres-integration")]
    #[tokio::test]
    async fn publisher_failure_does_not_refresh_last_complete_pass() {
        let database = std::env::var("PEERWARD_TEST_DATABASE_URL").unwrap();
        assert!(database.parse::<sqlx::postgres::PgConnectOptions>()
            .is_ok_and(|options| options.get_database() == Some("peerward_test")));
        let store = Store::connect(&database, 4).await.unwrap();
        store.migrate().await.unwrap();
        let mesh = store
            .create_mesh(
                &NewMesh {
                    name: "publisher-failure".into(),
                    address_cidr: "10.97.0.0/24".parse().unwrap(),
                    gateway: "10.97.0.1".parse().unwrap(),
                    dns_suffix: "publisher.test".into(),
                    mtu: 1280,
                    reserved: Vec::new(),
                    default_policy: DefaultPolicy::Deny,
                    quarantine_seconds: 60,
                    rotation_overlap_seconds: 60,
                },
                "test",
            )
            .await
            .unwrap();
        // A live Mesh with no usable online issuer is a failed publication,
        // even when expiry reconciliation and every other Mesh succeed.
        let issuers = IssuerRegistry::default();
        issuers.install(mesh.id, Vec::new());
        let metrics = Arc::new(ControlMetrics::default());
        metrics.publisher_last_success.store(123, Ordering::Relaxed);
        let (_signal, receiver) = watch::channel(0);
        let task = tokio::spawn(run_publisher(store, issuers, metrics.clone(), receiver));
        let observed = tokio::time::timeout(Duration::from_secs(10), async {
            while metrics.publisher_failures.load(Ordering::Relaxed) == 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            // The publisher has returned to its next tick/event wait.
            tokio::task::yield_now().await;
        })
        .await;
        task.abort();
        let _ = task.await;
        observed.unwrap();
        assert_eq!(metrics.publisher_last_success.load(Ordering::Relaxed), 123);
    }

    #[test]
    fn dynamic_stun_reload_preserves_persisted_mesh_identity() {
        let base = std::env::temp_dir().join(format!("peerward-stun-config-{}", Uuid::new_v4()));
        private_dir(&base).unwrap();
        let mut config: DynamicMeshConfig = serde_json::from_value(json!({
            "state_directory": base.join("meshes"), "recovery_directory": base.join("recovery"),
            "recovery_public_key": "01".repeat(32), "host_address": "127.0.0.1:9091",
            "ca_file": "ca.pem", "certificate_file": "tls.pem", "private_key_file": "tls.key",
            "stun_servers": ["STUN.Example:3478", "[2001:db8::1]:3478"]
        }))
        .unwrap();
        let mesh = MeshId::new();
        let created = prepare_managed_bundle(&config, mesh).unwrap();
        assert_eq!(created.issuer.stun_servers, config.stun_servers);
        let path = config.bundle_path(mesh);
        let original = Zeroizing::new(read_private(&path, 65_536).unwrap());
        config.stun_servers = vec!["new.example:443".parse().unwrap()];
        let updated = prepare_managed_bundle(&config, mesh).unwrap();
        assert_eq!(updated.issuer.stun_servers, config.stun_servers);
        assert_eq!(
            updated.issuer.root_public_key,
            created.issuer.root_public_key
        );
        assert_eq!(updated.issuer.authority_id, created.issuer.authority_id);
        assert_eq!(
            updated.issuer.authority_private_key,
            created.issuer.authority_private_key
        );
        assert_eq!(updated.recovery, created.recovery);
        assert_eq!(
            read_private(&path, 65_536).unwrap().as_slice(),
            original.as_slice()
        );
        config.stun_servers.clear();
        assert!(
            read_managed_bundle(&config, mesh)
                .unwrap()
                .issuer
                .stun_servers
                .is_empty()
        );
        config.stun_servers = vec!["stun.example:3478".parse().unwrap(); 9];
        assert!(read_managed_bundle(&config, mesh).is_err());
        assert_eq!(
            read_private(&path, 65_536).unwrap().as_slice(),
            original.as_slice()
        );
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn configuration_denies_unknown_fields_and_requires_version() {
        let valid = "config_version=1\ndatabase_url='postgres://localhost/test'\n";
        assert!(ControlConfig::parse(valid, None).is_ok());
        assert!(
            ControlConfig::parse(&valid.replace("config_version=1", "config_version=2"), None)
                .is_ok()
        );
        assert!(ControlConfig::parse("config_version=3\ndatabase_url='x'", None).is_err());
        assert!(
            ControlConfig::parse("config_version=1\ndatabase_url='x'\nextra=true", None).is_err()
        );
        assert!(
            ControlConfig::parse(
                "config_version=1\ndatabase_url='postgres://localhost/test'\nmax_connections=1",
                None,
            )
            .is_err()
        );
    }

    #[test]
    fn public_resource_names_are_bounded_before_database_access() {
        assert!(valid_display_name("Relay 上海"));
        assert!(!valid_display_name("   "));
        assert!(!valid_display_name(&"界".repeat(43)));
        assert!(valid_dns_label("peer-01"));
        assert!(!valid_dns_label("Peer with spaces"));
    }

    #[test]
    fn public_enrollment_origin_rejects_unsafe_or_ambiguous_urls() {
        for origin in ["https://mesh.example.test", "http://127.0.0.1:8081", "http://[::1]:8081"] {
            assert!(ControlConfig::parse(&format!("config_version=2\ndatabase_url='x'\npublic_url='{origin}'"), None).is_ok());
        }
        for origin in ["http://mesh.example.test", "https://user:secret@mesh.example.test", "https://mesh.example.test/path", "https://mesh.example.test/?q=x", "https://mesh.example.test/#fragment"] {
            assert!(ControlConfig::parse(&format!("config_version=2\ndatabase_url='x'\npublic_url='{origin}'"), None).is_err());
        }
    }

    #[test]
    fn request_log_path_redacts_join_ticket_secrets() {
        assert_eq!(
            request_log_path("/api/v1/join/super-secret-ticket/claim"),
            "/api/v1/join/{ticket}/claim"
        );
        assert_eq!(
            request_log_path("/api/v1/meshes/00000000-0000-4000-8000-000000000001"),
            "/api/v1/meshes/{id}"
        );
    }

    #[test]
    fn capability_matrix_and_csrf_are_separate() {
        let headers = HeaderMap::new();
        let viewer = AuthContext {
            actor: "v".into(),
            role: Role::Viewer,
            source: AuthSource::Bearer,
        };
        assert!(authorize(&viewer, &headers, Capability::ResourceRead, false).is_ok());
        assert!(authorize(&viewer, &headers, Capability::ResourceWrite, false).is_err());
        let auditor = AuthContext {
            actor: "a".into(),
            role: Role::Auditor,
            source: AuthSource::Bearer,
        };
        assert!(authorize(&auditor, &headers, Capability::StatusAuditRead, false).is_ok());
        assert!(authorize(&auditor, &headers, Capability::ResourceRead, false).is_err());
        let token = "csrf";
        let session = AuthContext {
            actor: "s".into(),
            role: Role::Admin,
            source: AuthSource::Session(secret_digest(token.as_bytes())),
        };
        assert!(authorize(&session, &headers, Capability::ResourceWrite, true).is_err());
        let mut supplied = HeaderMap::new();
        supplied.insert("x-csrf-token", token.parse().unwrap());
        assert!(authorize(&session, &supplied, Capability::TrustManage, true).is_ok());
    }

    #[test]
    fn sparse_topology_structural_fallback_bypasses_health_throttle() {
        let mesh = MeshId::new();
        let nodes = (0..8)
            .map(|_| RelayTopologyNodeV1 {
                relay_id: RelayId::new(),
                region: "default".into(),
                routing_weight: 100,
                capabilities: SPARSE_BACKBONE_V1_CAPABILITY,
            })
            .collect::<Vec<_>>();
        let sparse =
            RelayTopologyV1::build(mesh, 1, nodes.clone(), 8, SPARSE_BACKBONE_V1_CAPABILITY)
                .unwrap();
        let mut mixed = nodes;
        mixed[0].capabilities = 0;
        let full =
            RelayTopologyV1::build(mesh, 2, mixed, 8, SPARSE_BACKBONE_V1_CAPABILITY).unwrap();
        let now = OffsetDateTime::now_utc();
        assert!(relay_topology_publication_due(&sparse, &full, now, now));

        let mut health_only = sparse.clone();
        health_only.revision += 1;
        health_only.edges[0].rtt_millis = 10;
        health_only.edges[0].loss_permyriad = 0;
        assert!(!relay_topology_publication_due(
            &sparse,
            &health_only,
            now,
            now,
        ));
        assert!(relay_topology_publication_due(
            &sparse,
            &health_only,
            now - TimeDuration::seconds(31),
            now,
        ));
    }

    #[test]
    fn pkce_s256_uses_unpadded_url_safe_encoding() {
        let verifier = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-._~";
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        assert!(!challenge.contains('='));
        assert_eq!(challenge.len(), 43);
    }

    #[test]
    fn oidc_group_mapping_is_deterministic_and_admin_wins() {
        let configuration = OidcConfig {
            issuer_url: Url::parse("https://identity.example").unwrap(),
            client_id: "peerward".into(),
            client_secret: None,
            redirect_uri: Url::parse("https://console.example/auth/callback").unwrap(),
            scopes: "openid".into(),
            groups_claim: "groups".into(),
            operator_groups: vec!["operators".into(), "shared".into()],
            auditor_groups: vec!["auditors".into()],
            admin_groups: vec!["admins".into(), "shared".into()],
        };
        assert_eq!(mapped_role(&[], &configuration), Role::Viewer);
        assert_eq!(
            mapped_role(&["operators".into()], &configuration),
            Role::Operator
        );
        assert_eq!(
            mapped_role(&["auditors".into()], &configuration),
            Role::Auditor
        );
        assert_eq!(mapped_role(&["shared".into()], &configuration), Role::Admin);
    }

    #[test]
    fn error_envelope_has_stable_shape() {
        let response = ApiError::invalid("bad_value", "bad value").into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
    }

    #[test]
    fn strong_etag_precondition_is_required_and_strict() {
        let missing = require_if_match(&HeaderMap::new())
            .unwrap_err()
            .into_response();
        assert_eq!(missing.status(), StatusCode::PRECONDITION_REQUIRED);
        let mut headers = HeaderMap::new();
        headers.insert(header::IF_MATCH, "W/\"7\"".parse().unwrap());
        assert_eq!(
            require_if_match(&headers)
                .unwrap_err()
                .into_response()
                .status(),
            StatusCode::BAD_REQUEST
        );
        headers.insert(header::IF_MATCH, "\"7\"".parse().unwrap());
        assert_eq!(require_if_match(&headers).unwrap(), 7);
        assert_eq!(etag_headers(7).unwrap()[header::ETAG], "\"7\"");
    }

    #[test]
    fn bulk_request_is_same_family_bounded_and_versioned() {
        let item = peerward_api::BulkResourceItem {
            id: Uuid::new_v4(),
            version: 1,
        };
        let valid = BulkRequest {
            family: BulkResourceFamily::Peer,
            items: vec![item.clone()],
        };
        assert!(validate_bulk_request(&valid).is_ok());
        let duplicate = BulkRequest {
            family: BulkResourceFamily::Peer,
            items: vec![item.clone(), item],
        };
        assert!(validate_bulk_request(&duplicate).is_err());
        let oversized = BulkRequest {
            family: BulkResourceFamily::Service,
            items: (0..=MAX_BULK_ITEMS)
                .map(|_| peerward_api::BulkResourceItem {
                    id: Uuid::new_v4(),
                    version: 1,
                })
                .collect(),
        };
        assert!(validate_bulk_request(&oversized).is_err());
    }

    #[test]
    fn join_claim_requires_independent_wireguard_key_signature_version_and_idempotency_id() {
        let public = json!({
            "schema_version": 2,
            "claim_id": Uuid::new_v4(),
            "identity_public_key": URL_SAFE_NO_PAD.encode([1; 32]),
            "session_public_key": URL_SAFE_NO_PAD.encode([2; 32]),
            "wireguard_public_key": URL_SAFE_NO_PAD.encode([6; 32]),
            "client_version": "1.0.0",
            "supported_wire_major": peerward_wire::PROTOCOL_MAJOR,
            "device_name": "phone",
            "device_model": "emulator",
            "platform": "android",
            "platform_version": "34",
            "nonce": URL_SAFE_NO_PAD.encode([3; 32]),
            "signature": URL_SAFE_NO_PAD.encode([4; 64]),
        });
        assert!(serde_json::from_value::<JoinClaimRequest>(public.clone()).is_ok());
        let mut legacy = public;
        legacy["noise_public_key"] = Value::String(URL_SAFE_NO_PAD.encode([5; 32]));
        assert!(serde_json::from_value::<JoinClaimRequest>(legacy).is_err());
        assert!(
            enrollment_peer_name("Alice's Android Phone", &[9; 32])
                .starts_with("alices-android-phone-")
        );
        assert!(enrollment_peer_name("---", &[9; 32]).starts_with("device-"));
    }

    #[test]
    fn policy_editor_normalization_is_deterministic_and_canonical() {
        let mut policy: PolicyPutRequest = serde_json::from_value(json!({
            "revision": 7,
            "default_action": "deny",
            "rules": [
                {
                    "id": "00000000-0000-4000-8000-000000000012",
                    "priority": 20,
                    "action": "allow",
                    "source": {
                        "peer_ids": [
                            "00000000-0000-4000-8000-000000000022",
                            "00000000-0000-4000-8000-000000000021"
                        ],
                        "cidrs": ["2001:db8:2::/64", "10.2.0.0/16"]
                    },
                    "destination": {},
                    "protocol": "tcp",
                    "destination_ports": [
                        {"first": 443, "last": 443},
                        {"first": 80, "last": 80}
                    ]
                },
                {
                    "id": "00000000-0000-4000-8000-000000000011",
                    "priority": 10,
                    "action": "deny",
                    "source": {},
                    "destination": {},
                    "protocol": "any"
                }
            ]
        }))
        .unwrap();
        let canonical_before = canonical_policy_document(&policy).unwrap();
        normalize_policy_request(&mut policy);
        assert_eq!(policy.rules[0].priority, 10);
        assert_eq!(policy.rules[1].destination_ports[0].first, 80);
        assert!(
            policy.rules[1].source.peer_ids[0] < policy.rules[1].source.peer_ids[1],
            "peer alternatives are returned in stable identity order"
        );
        assert_eq!(
            canonical_before,
            canonical_policy_document(&policy).unwrap()
        );
    }
}

#[cfg(all(test, unix))]
mod managed_issuer_tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    #[test]
    fn managed_issuers_load_after_restart_and_reject_unsafe_or_duplicate_fragments() {
        let directory = std::env::temp_dir().join(format!("peerward-issuers-{}", Uuid::new_v4()));
        assert!(
            read_managed_issuer_configs(&[], Some(&directory))
                .unwrap()
                .is_empty()
        );
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mesh = MeshId::new();
        let authority_id = Uuid::new_v4();
        let root = peerward_credentials::RootSigningKey::from_bytes(&[11; 32]);
        let authority = AuthoritySigningKey::from_bytes(&[12; 32]);
        let now = u64::try_from(OffsetDateTime::now_utc().unix_timestamp()).unwrap();
        let certificate = root
            .certify(peerward_credentials::UnsignedAuthority {
                mesh_id: mesh,
                serial: CredentialSerial::new(),
                public_key: authority.public_key(),
                not_before: UnixTime(now - 60),
                not_after: UnixTime(now + 3600),
            })
            .unwrap();
        let keys = directory.with_extension("keys");
        let key_mesh = keys.join(mesh.to_string());
        std::fs::create_dir_all(&key_mesh).unwrap();
        let key_path = key_mesh.join(format!("{authority_id}.key"));
        std::fs::write(&key_path, hex::encode([12; 32])).unwrap();
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let fragment = json!({"mesh_id":mesh,"authority_id":authority_id,
            "root_public_key":hex::encode(root.public_key().to_bytes()), "authority_certificate":URL_SAFE_NO_PAD.encode(certificate.encode()),
            "directory_private_key":"01".repeat(32),"service_private_key":"02".repeat(32),
            "audit_private_key":"03".repeat(32)});
        let path = directory.join(format!("{mesh}.json"));
        std::fs::write(&path, fragment.to_string()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let first = read_managed_issuer_configs(&[], Some(&directory)).unwrap();
        let second = read_managed_issuer_configs(&[], Some(&directory)).unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].mesh_id, second[0].mesh_id);
        assert_eq!(first[0].authority_id, authority_id);
        assert!(read_managed_issuer_configs(&first, Some(&directory)).is_err());
        assert_eq!(load_join_issuers(&first, Some(&keys)).unwrap().len(), 1);
        assert_eq!(load_join_issuers(&second, Some(&keys)).unwrap().len(), 1);
        std::fs::write(&key_path, hex::encode([99; 32])).unwrap();
        assert!(load_join_issuers(&first, Some(&keys)).is_err());
        std::fs::remove_dir_all(&keys).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_managed_issuer_configs(&[], Some(&directory)).is_err());
        std::fs::remove_file(&path).unwrap();
        symlink("/dev/null", &path).unwrap();
        assert!(read_managed_issuer_configs(&[], Some(&directory)).is_err());
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_dir(&directory).unwrap();
    }
}
