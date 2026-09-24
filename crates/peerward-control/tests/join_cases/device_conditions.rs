async fn verify_device_conditions(
    store: &Store,
    application: &axum::Router,
    mesh: peerward_types::MeshId,
    peer: peerward_types::PeerId,
    credential: &SubjectCredential,
    identity: &IdentitySigningKey,
    issuer: &JoinIssuerConfig,
) {
    use peerward_management::*;
    let path = format!("/api/v1/meshes/{mesh}/device-conditions");
    let observation_path = format!("/api/v1/meshes/{mesh}/peers/{peer}/device-condition");
    let read = |path: String| async move {
        let response = application
            .clone()
            .oneshot(
                Request::get(path)
                    .header("authorization", "Bearer rotation-admin")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        serde_json::from_slice::<Value>(&response.into_body().collect().await.unwrap().to_bytes())
            .unwrap()
    };
    let save = |body: DeviceConditions, version: u64| {
        let path = path.clone();
        async move {
            application
                .clone()
                .oneshot(
                    Request::put(path)
                        .header("authorization", "Bearer rotation-admin")
                        .header("content-type", "application/json")
                        .header("if-match", format!("\"{version}\""))
                        .body(Body::from(serde_json::to_vec(&body).unwrap()))
                        .unwrap(),
                )
                .await
                .unwrap()
        }
    };
    let definition = DeviceConditions {
        enabled: true,
        minimum_version: Some(env!("CARGO_PKG_VERSION").into()),
        scope: DeviceSelector {
            peers: [peer].into(),
            ..Default::default()
        },
        ..Default::default()
    };
    let initial = read(path.clone()).await;
    assert_eq!(initial["definition"]["enabled"], false);
    assert_eq!(
        save(definition.clone(), initial["version"].as_u64().unwrap())
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        save(definition.clone(), initial["version"].as_u64().unwrap())
            .await
            .status(),
        StatusCode::CONFLICT
    );
    let observation = read(observation_path.clone()).await;
    assert_eq!(observation["decision"]["allowed"], false);
    assert!(
        observation["decision"]["reasons"]
            .as_array()
            .unwrap()
            .contains(&json!("evidence_unavailable"))
    );
    let mut command = PeerCommand {
        mesh_id: mesh,
        peer_id: peer,
        credential_serial: credential.serial,
        request_id: Uuid::new_v4(),
        sequence: 500,
        issued_at: u64::try_from(OffsetDateTime::now_utc().unix_timestamp()).unwrap(),
        operation: PeerOperation::DeviceEvidence {
            evidence: DeviceEvidence::current(DevicePlatform::Linux),
        },
    };
    let signed = SignedPeerCommand::sign(command.clone(), identity).unwrap();
    let mut forged = signed.clone();
    forged.signature[0] ^= 1;
    assert!(store.apply_peer_command(&forged).await.is_err());
    assert!(store.apply_peer_command(&signed).await.unwrap());
    assert!(!store.apply_peer_command(&signed).await.unwrap());
    assert_eq!(
        read(observation_path.clone()).await["decision"]["allowed"],
        true
    );
    publish_enrollment_state(store, std::slice::from_ref(issuer))
        .await
        .unwrap();
    let before: ConfigurationDelivery = serde_json::from_slice(
        &store
            .latest_signed_state(mesh, SignedStateKind::Configuration)
            .await
            .unwrap()
            .body,
    )
    .unwrap();
    assert!(before.resources.admission.permits(peer, command.issued_at));
    // Simulate age without sleeping 15 minutes; duplicate cannot extend this evidence.
    sqlx::query("UPDATE device_evidence SET observed_at=statement_timestamp()-interval '902 seconds',valid_until=statement_timestamp()-interval '2 seconds' WHERE mesh_id=$1 AND peer_id=$2").bind(mesh.into_uuid()).bind(peer.into_uuid()).execute(store.pool()).await.unwrap();
    assert!(!store.apply_peer_command(&signed).await.unwrap());
    assert_eq!(
        read(observation_path.clone()).await["decision"]["allowed"],
        false
    );
    publish_enrollment_state(store, std::slice::from_ref(issuer))
        .await
        .unwrap();
    let after: ConfigurationDelivery = serde_json::from_slice(
        &store
            .latest_signed_state(mesh, SignedStateKind::Configuration)
            .await
            .unwrap()
            .body,
    )
    .unwrap();
    assert!(!after.resources.admission.permits(peer, command.issued_at));
    assert!(
        after.manifest.manifest.parts[&ConfigurationPart::Resources].version
            > before.manifest.manifest.parts[&ConfigurationPart::Resources].version,
        "expiry must change component version with its digest"
    );
    let mut stale = command.clone();
    stale.sequence += 1;
    stale.request_id = Uuid::new_v4();
    stale.issued_at -= 31;
    assert!(
        store
            .apply_peer_command(&SignedPeerCommand::sign(stale, identity).unwrap())
            .await
            .is_err()
    );
    command.sequence += 1;
    command.request_id = Uuid::new_v4();
    assert!(
        store
            .apply_peer_command(&SignedPeerCommand::sign(command.clone(), identity).unwrap())
            .await
            .unwrap()
    );
    assert_eq!(
        read(observation_path.clone()).await["decision"]["allowed"],
        true
    );
    let mut stronger = definition.clone();
    stronger.minimum_version = Some("9.0.0".into());
    let version = read(path.clone()).await["version"].as_u64().unwrap();
    assert_eq!(save(stronger, version).await.status(), StatusCode::OK);
    assert_eq!(
        read(observation_path.clone()).await["decision"]["reasons"],
        json!(["version"])
    );
    // Declarations preserve condition intent without exporting live evidence.
    let export = read(format!("/api/v1/meshes/{mesh}/configuration/export")).await;
    assert_eq!(
        export["document"]["device_conditions"]["minimum_version"],
        "9.0.0"
    );
    assert!(export["document"].get("device_evidence").is_none());
    let version = read(path.clone()).await["version"].as_u64().unwrap();
    assert_eq!(
        save(DeviceConditions::default(), version).await.status(),
        StatusCode::OK
    );
    assert_eq!(read(observation_path).await["decision"]["allowed"], true);
}
