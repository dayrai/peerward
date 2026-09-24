async fn verify_target_health(
    store: &Store,
    application: &axum::Router,
    mesh: peerward_types::MeshId,
    peer: peerward_types::PeerId,
    credential: &SubjectCredential,
    identity: &IdentitySigningKey,
) {
    use peerward_management::*;
    let resource = Uuid::new_v4();
    let binding = Uuid::new_v4();
    let definition = json!({"name":"Health target","target":{"kind":"subnet","prefix":"192.168.238.2/32","site_id":Uuid::new_v4()},"health_probe":{"address":"192.168.238.2","port":631}});
    sqlx::query("INSERT INTO network_resources(mesh_id,id,definition) VALUES($1,$2,$3)")
        .bind(mesh.into_uuid())
        .bind(resource)
        .bind(&definition)
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query("INSERT INTO gateway_bindings(mesh_id,id,resource_id,peer_id,approved,priority,forwarding,return_route_confirmed,approval_source) VALUES($1,$2,$3,$4,true,100,'snat',false,'{\"kind\":\"manual\"}')")
        .bind(mesh.into_uuid()).bind(binding).bind(resource).bind(peer.into_uuid()).execute(store.pool()).await.unwrap();
    let path = format!("/api/v1/meshes/{mesh}/network-resources/{resource}/health");
    let read = || async {
        let response = application
            .clone()
            .oneshot(
                Request::get(&path)
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
    let sharing_path = format!("/api/v1/meshes/{mesh}/console/sharing?resource={resource}");
    let read_sharing = || async {
        let response = application
            .clone()
            .oneshot(
                Request::get(&sharing_path)
                    .header("authorization", "Bearer rotation-admin")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let value: Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        value["items"][0]["reachability"].clone()
    };
    assert_eq!(read().await["bindings"][0]["status"], "unknown");
    assert_eq!(read_sharing().await["state"], "unknown");
    let mut command = PeerCommand {
        mesh_id: mesh,
        peer_id: peer,
        credential_serial: credential.serial,
        request_id: Uuid::new_v4(),
        sequence: 100,
        issued_at: u64::try_from(OffsetDateTime::now_utc().unix_timestamp()).unwrap(),
        operation: PeerOperation::TargetHealth {
            binding_id: binding,
            binding_version: 1,
            resource_version: 1,
            result: TargetProbeResult::Reachable,
        },
    };
    let signed = SignedPeerCommand::sign(command.clone(), identity).unwrap();
    assert!(store.apply_peer_command(&signed).await.unwrap());
    assert!(!store.apply_peer_command(&signed).await.unwrap());
    assert_eq!(read().await["bindings"][0]["status"], "reachable");
    let evidence = read_sharing().await;
    assert_eq!(evidence["state"], "ready");
    assert_eq!(
        evidence["observed_at"],
        read().await["bindings"][0]["observed_at"]
    );
    assert_eq!(read().await["application_authentication"], "not_tested");
    command.sequence += 1;
    command.request_id = Uuid::new_v4();
    assert!(
        store
            .apply_peer_command(
                &SignedPeerCommand::sign(
                    command.clone(),
                    &IdentitySigningKey::from_bytes(&[249; 32])
                )
                .unwrap()
            )
            .await
            .is_err()
    );
    sqlx::query("UPDATE target_health_observations SET valid_until=clock_timestamp()-interval '1 second' WHERE mesh_id=$1 AND binding_id=$2")
        .bind(mesh.into_uuid()).bind(binding).execute(store.pool()).await.unwrap();
    assert_eq!(read().await["bindings"][0]["status"], "unknown");
    let evidence = read_sharing().await;
    assert_eq!(evidence["state"], "unknown");
    assert!(
        evidence["observed_at"].is_null(),
        "expired evidence cannot appear current"
    );
    assert!(!store.apply_peer_command(&signed).await.unwrap());
    assert_eq!(
        read().await["bindings"][0]["status"],
        "unknown",
        "duplicate cannot refresh expired evidence"
    );
    let mut stale = command.clone();
    stale.issued_at -= 31;
    assert!(
        store
            .apply_peer_command(&SignedPeerCommand::sign(stale, identity).unwrap())
            .await
            .is_err()
    );
    assert!(
        store
            .apply_peer_command(&SignedPeerCommand::sign(command.clone(), identity).unwrap())
            .await
            .unwrap()
    );
    sqlx::query("UPDATE network_resources SET definition=jsonb_set(definition,'{name}','\"Changed health target\"') WHERE mesh_id=$1 AND id=$2")
        .bind(mesh.into_uuid()).bind(resource).execute(store.pool()).await.unwrap();
    assert_eq!(read().await["bindings"][0]["status"], "unknown");
    command.sequence += 1;
    command.request_id = Uuid::new_v4();
    assert!(
        store
            .apply_peer_command(&SignedPeerCommand::sign(command.clone(), identity).unwrap())
            .await
            .is_err()
    );
    if let PeerOperation::TargetHealth {
        resource_version,
        result,
        ..
    } = &mut command.operation
    {
        *resource_version = 2;
        *result = TargetProbeResult::Refused;
    }
    assert!(
        store
            .apply_peer_command(&SignedPeerCommand::sign(command.clone(), identity).unwrap())
            .await
            .unwrap()
    );
    assert_eq!(read().await["bindings"][0]["status"], "refused");
    let evidence = read_sharing().await;
    assert_eq!(evidence["state"], "blocked");
    assert_eq!(evidence["reason"], "gateway_probe_failed");
    assert!(
        evidence["observed_at"].is_string(),
        "failed probes need their real observation time"
    );
    assert_eq!(
        evidence["observed_at"],
        read().await["bindings"][0]["observed_at"]
    );
    sqlx::query("UPDATE gateway_bindings SET approved=false WHERE mesh_id=$1 AND id=$2")
        .bind(mesh.into_uuid())
        .bind(binding)
        .execute(store.pool())
        .await
        .unwrap();
    assert_eq!(read().await["bindings"][0]["status"], "unknown");
    command.sequence += 1;
    command.request_id = Uuid::new_v4();
    if let PeerOperation::TargetHealth {
        binding_version, ..
    } = &mut command.operation
    {
        *binding_version = 2;
    }
    assert!(
        store
            .apply_peer_command(&SignedPeerCommand::sign(command, identity).unwrap())
            .await
            .is_err()
    );
}
