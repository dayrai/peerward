async fn verify_management_receipts(
    store: &Store,
    application: &axum::Router,
    issuer: &JoinIssuerConfig,
    mesh: peerward_types::MeshId,
    peer: peerward_types::PeerId,
    credential: &SubjectCredential,
    identity: &IdentitySigningKey,
) {
    use peerward_management::*;
    let configuration = store
        .latest_signed_state(mesh, SignedStateKind::Configuration)
        .await
        .unwrap();
    let delivery: ConfigurationDelivery = serde_json::from_slice(&configuration.body).unwrap();
    let command = PeerCommand {
        mesh_id: mesh,
        peer_id: peer,
        credential_serial: credential.serial,
        request_id: Uuid::new_v4(),
        sequence: 41,
        issued_at: u64::try_from(OffsetDateTime::now_utc().unix_timestamp()).unwrap(),
        operation: PeerOperation::Applied {
            category: ApplicationCategory::Core,
            configuration_version: delivery.manifest.manifest.version,
            configuration_digest: delivery.lease.lease.configuration_digest,
            lease_sequence: delivery.lease.lease.sequence,
            result: ApplicationResult::Applied,
            reason: None,
        },
    };
    let signed = SignedPeerCommand::sign(command, identity).unwrap();
    assert!(store.apply_peer_command(&signed).await.unwrap());
    assert!(!store.apply_peer_command(&signed).await.unwrap());
    let mut changed = signed.command.clone();
    changed.request_id = Uuid::new_v4();
    assert!(
        store
            .apply_peer_command(&SignedPeerCommand::sign(changed.clone(), identity).unwrap())
            .await
            .is_err(),
        "new request cannot reuse an operation number"
    );
    changed.sequence = 42;
    let mut tampered = SignedPeerCommand::sign(changed, identity).unwrap();
    tampered.signature[0] ^= 1;
    assert!(store.apply_peer_command(&tampered).await.is_err());
    let rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM peer_management_requests WHERE mesh_id=$1 AND peer_id=$2",
    )
    .bind(mesh.into_uuid())
    .bind(peer.into_uuid())
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(
        rows, 1,
        "failed and duplicate requests must not create partial audit/receipt state"
    );
    let response = application
        .clone()
        .oneshot(
            Request::get(format!(
                "/api/v1/meshes/{mesh}/peers/{peer}/configuration-receipts"
            ))
            .header("authorization", "Bearer rotation-admin")
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let value: Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(value["categories"]["core"]["status"], "applied");
    for category in ["dns", "routes", "firewall"] {
        assert_eq!(value["categories"][category]["status"], "unknown");
    }
    assert_eq!(value["connectivity"], "unknown");
    let mut refresh = signed.command.clone();
    refresh.request_id = Uuid::new_v4();
    refresh.sequence = 43;
    if let PeerOperation::Applied { result, reason, .. } = &mut refresh.operation {
        *result = ApplicationResult::Rejected;
        *reason = Some(FRESH_AUTHORIZATION_REQUIRED.into());
    }
    let refresh = SignedPeerCommand::sign(refresh, identity).unwrap();
    assert!(store.apply_peer_command(&refresh).await.unwrap());
    assert_eq!(
        publish_enrollment_state(store, std::slice::from_ref(issuer))
            .await
            .unwrap(),
        1
    );
    let read_delivery = || async {
        let state = store
            .latest_signed_state(mesh, SignedStateKind::Configuration)
            .await
            .unwrap();
        serde_json::from_slice::<ConfigurationDelivery>(&state.body).unwrap()
    };
    let renewed = read_delivery().await;
    assert_eq!(
        renewed.lease.lease.sequence,
        delivery.lease.lease.sequence + 1
    );
    assert_eq!(
        renewed.manifest, delivery.manifest,
        "refresh must not change grants or configuration"
    );
    assert_eq!(renewed.resources, delivery.resources);
    assert_eq!(renewed.dns, delivery.dns);
    assert!(!store.apply_peer_command(&refresh).await.unwrap());
    assert_eq!(
        publish_enrollment_state(store, std::slice::from_ref(issuer))
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        read_delivery().await.lease,
        renewed.lease,
        "duplicate/stale rejection cannot keep renewing"
    );
    let mut unrelated = refresh.command.clone();
    unrelated.sequence = 44;
    unrelated.request_id = Uuid::new_v4();
    if let PeerOperation::Applied {
        lease_sequence,
        reason,
        ..
    } = &mut unrelated.operation
    {
        *lease_sequence = renewed.lease.lease.sequence;
        *reason = Some("local_configuration_error".into());
    }
    assert!(
        store
            .apply_peer_command(&SignedPeerCommand::sign(unrelated, identity).unwrap())
            .await
            .unwrap()
    );
    assert_eq!(
        publish_enrollment_state(store, std::slice::from_ref(issuer))
            .await
            .unwrap(),
        0
    );
    verify_target_health(store, application, mesh, peer, credential, identity).await;
}
