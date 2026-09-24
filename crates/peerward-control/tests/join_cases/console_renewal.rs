use super::*;
async fn call(
    app: &axum::Router,
    method: &str,
    path: &str,
    version: Option<u64>,
    body: Value,
) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", "Bearer rotation-admin")
        .header("content-type", "application/json");
    if let Some(v) = version {
        request = request.header("if-match", format!("\"{v}\""));
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    (
        status,
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap(),
    )
}
pub async fn begin(
    store: &Store,
    app: &axum::Router,
    mesh: peerward_types::MeshId,
    peer: peerward_types::PeerId,
    serial: CredentialSerial,
) -> Uuid {
    let path = format!("/api/v1/meshes/{mesh}/console/devices/{peer}/renewals");
    let (_, device) = call(
        app,
        "GET",
        &format!("/api/v1/meshes/{mesh}/peers/{peer}"),
        None,
        Value::Null,
    )
    .await;
    let id = Uuid::new_v4();
    let body = json!({"request_id":id,"current_serial":serial,"valid_for_seconds":3600,"reason":"planned renewal"});
    let (status, created) =
        call(app, "POST", &path, device["version"].as_u64(), body.clone()).await;
    assert_eq!(status, StatusCode::OK, "{created}");
    assert_ne!(created["state"], "completed");
    assert_eq!(
        call(app, "POST", &path, device["version"].as_u64(), body.clone())
            .await
            .1,
        created,
        "exact retries reuse identity"
    );
    let mut reused = body.clone();
    reused["reason"] = json!("different");
    assert_eq!(
        call(app, "POST", &path, device["version"].as_u64(), reused)
            .await
            .0,
        StatusCode::CONFLICT
    );
    store
        .observe_peer_renewal_capability(mesh, peer, serial, false)
        .await
        .unwrap();
    assert_eq!(
        call(app, "GET", &path, None, Value::Null).await.1["items"][0]["state"],
        "upgrade_required"
    );
    store
        .observe_peer_renewal_capability(mesh, peer, serial, true)
        .await
        .unwrap();
    let command = store
        .pending_credential_renewal(mesh, peer, serial)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(command.command.request_id, id);
    assert!(
        store
            .pending_credential_renewal(mesh, peer, CredentialSerial::new())
            .await
            .unwrap()
            .is_none()
    );
    store
        .mark_credential_renewal_delivered(mesh, peer, id)
        .await
        .unwrap();
    id
}
pub async fn finish(
    store: &Store,
    app: &axum::Router,
    mesh: peerward_types::MeshId,
    peer: peerward_types::PeerId,
    old: CredentialSerial,
    new: CredentialSerial,
    id: Uuid,
) {
    let path = format!("/api/v1/meshes/{mesh}/console/devices/{peer}/renewals");
    assert_eq!(
        call(app, "GET", &path, None, Value::Null).await.1["items"][0]["state"],
        "awaiting_reconnect"
    );
    store
        .observe_peer_renewal_capability(mesh, peer, old, true)
        .await
        .unwrap();
    assert_eq!(
        call(app, "GET", &path, None, Value::Null).await.1["items"][0]["state"],
        "awaiting_reconnect"
    );
    store
        .observe_peer_renewal_capability(mesh, peer, new, true)
        .await
        .unwrap();
    let (_, view) = call(app, "GET", &path, None, Value::Null).await;
    assert_eq!(view["items"][0]["id"], id.to_string());
    assert_eq!(view["items"][0]["state"], "completed");
    assert_eq!(view["items"][0]["completed_serial"], new.to_string());
    assert!(
        store
            .pending_credential_renewal(mesh, peer, old)
            .await
            .unwrap()
            .is_none()
    );
}
