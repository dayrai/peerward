use super::machine_credentials::machine;
use super::*;

pub async fn verify(store: &Store, app: &Router, mesh: Uuid) {
    let base = format!("/api/v1/meshes/{mesh}");
    let path = format!("{base}/configuration/ownership");
    let read = || request(app, "GET", &path, None, Value::Null);
    let initial = json_body(read().await).await;
    assert!(initial["owner_machine_id"].is_null());
    let id = Uuid::new_v4();
    let created=request(app,"POST",&format!("{base}/machine-credentials"),None,json!({"id":id,"name":"declaration-owner","ttl_seconds":3600,"capabilities":["resource_read","resource_write"]})).await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let issued = json_body(created).await;
    let token = issued["token"].as_str().unwrap();
    assert_eq!(
        request(app, "PUT", &path, None, json!({"owner_machine_id":id}))
            .await
            .status(),
        StatusCode::PRECONDITION_REQUIRED
    );
    assert_eq!(
        machine(
            app,
            token,
            "PUT",
            &path,
            initial["version"].as_u64(),
            json!({"owner_machine_id":id})
        )
        .await
        .status(),
        StatusCode::FORBIDDEN,
        "a machine cannot claim ownership itself"
    );
    let assigned = request(
        app,
        "PUT",
        &path,
        initial["version"].as_u64(),
        json!({"owner_machine_id":id}),
    )
    .await;
    assert_eq!(assigned.status(), StatusCode::OK);
    let assigned = json_body(assigned).await;
    assert_eq!(assigned["owner_machine_id"], json!(id));
    assert_eq!(assigned["owner_active"], true);
    let resource = Uuid::new_v4();
    let resource_path = format!("{base}/network-resources");
    let body = json!({"id":resource,"definition":{"name":"Owned declaration target","target":{"kind":"subnet","prefix":"192.168.243.50/32","site_id":Uuid::new_v4()}}});
    let blocked = request(app, "POST", &resource_path, None, body.clone()).await;
    assert_eq!(blocked.status(), StatusCode::CONFLICT);
    assert_eq!(
        json_body(blocked).await["error"]["code"],
        "configuration_owned"
    );
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM network_resources WHERE id=$1)")
            .bind(resource)
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert!(!exists, "ownership rejection rolls back staged records");
    assert_eq!(
        json_body(read().await).await["version"],
        assigned["version"],
        "a rejected mutation does not advance the configuration"
    );
    // Even a privileged OIDC subject named exactly like the owner is a separate
    // authenticated actor. CSRF is valid so the rejection must be ownership.
    let session = peerward_store::NewSession {
        token: format!("session-{}", Uuid::new_v4()),
        csrf_token: "isolated-csrf".into(),
        subject: format!("machine:{id}"),
        role: peerward_store::Role::Admin,
        expires_at: time::OffsetDateTime::now_utc() + time::Duration::hours(1),
    };
    store.create_session(&session).await.unwrap();
    let collision = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(&resource_path)
                .header("content-type", "application/json")
                .header("cookie", format!("peerward_session={}", session.token))
                .header("x-csrf-token", &session.csrf_token)
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(collision.status(), StatusCode::CONFLICT);
    assert_eq!(
        json_body(collision).await["error"]["code"],
        "configuration_owned"
    );
    assert_eq!(
        machine(app, token, "POST", &resource_path, None, body)
            .await
            .status(),
        StatusCode::CREATED
    );
    let after = json_body(read().await).await;
    assert!(after["version"].as_u64() > assigned["version"].as_u64());
    assert_eq!(
        request(
            app,
            "PUT",
            &path,
            assigned["version"].as_u64(),
            json!({"owner_machine_id":null})
        )
        .await
        .status(),
        StatusCode::CONFLICT
    );
    // Live identity retirement is never delegated to a declaration owner.
    let peer = json_body(
        request(
            app,
            "POST",
            &format!("{base}/peers"),
            None,
            json!({"name":"ownership-retirement"}),
        )
        .await,
    )
    .await;
    let peer_path = format!("{base}/peers/{}", peer["id"].as_str().unwrap());
    let stopped = request(
        app,
        "DELETE",
        &peer_path,
        peer["version"].as_u64(),
        Value::Null,
    )
    .await;
    assert_eq!(stopped.status(), StatusCode::NO_CONTENT);
    let after = json_body(read().await).await;
    assert_eq!(after["owner_machine_id"], json!(id));
    assert_eq!(
        request(
            app,
            "PUT",
            &path,
            after["version"].as_u64(),
            json!({"owner_machine_id":null})
        )
        .await
        .status(),
        StatusCode::OK
    );
    let current = json_body(
        request(
            app,
            "GET",
            &format!("{resource_path}/{resource}"),
            None,
            Value::Null,
        )
        .await,
    )
    .await;
    assert_eq!(
        machine(
            app,
            token,
            "DELETE",
            &format!("{resource_path}/{resource}"),
            current["version"].as_u64(),
            Value::Null
        )
        .await
        .status(),
        StatusCode::CONFLICT,
        "returning to manual management removes the previous machine's write ownership"
    );
    assert_eq!(
        request(
            app,
            "DELETE",
            &format!("{resource_path}/{resource}"),
            current["version"].as_u64(),
            Value::Null
        )
        .await
        .status(),
        StatusCode::NO_CONTENT
    );
}
