use super::*;

pub async fn verify(store: &Store, app: &Router, mesh: Uuid) {
    let base = format!("/api/v1/meshes/{mesh}");
    let path = format!("{base}/webhooks");
    let id = Uuid::new_v4();
    let item = format!("{path}/{id}");
    let body = json!({"id":id,"name":"Operations notifications","endpoint":"https://events.example.com/peerward","event_types":["peer.created"]});
    let response = request(app, "POST", &path, None, body.clone()).await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let created = json_body(response).await;
    assert_eq!(created["enabled"], false);
    assert_eq!(created["pending_deliveries"], 0);
    assert!(
        created["signing_public_key"].is_null(),
        "this API-only fixture has no online signer"
    );
    assert_eq!(
        request(app, "POST", &path, None, body.clone())
            .await
            .status(),
        StatusCode::OK
    );
    let mut other = body.clone();
    other["name"] = json!("Different");
    assert_eq!(
        request(app, "POST", &path, None, other).await.status(),
        StatusCode::CONFLICT
    );
    for endpoint in [
        "http://events.example.com/",
        "https://127.0.0.1/",
        "https://[::1]/",
        "https://events.example.com/?token=secret",
    ] {
        let mut invalid = body.clone();
        invalid["id"] = json!(Uuid::new_v4());
        invalid["endpoint"] = json!(endpoint);
        assert_eq!(
            request(app, "POST", &path, None, invalid).await.status(),
            StatusCode::BAD_REQUEST
        );
    }
    let update = json!({"name":"Operations notifications","endpoint":"https://events.example.com/peerward","enabled":true,"event_types":["peer.created"]});
    assert_eq!(
        request(app, "PUT", &item, None, update.clone())
            .await
            .status(),
        StatusCode::PRECONDITION_REQUIRED
    );
    assert_eq!(
        request(app, "PUT", &item, Some(1), update.clone())
            .await
            .status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "enabling requires an active signing key"
    );
    let token_response=request(app,"POST",&format!("{base}/machine-credentials"),None,json!({"id":Uuid::new_v4(),"name":"cannot-send-events","ttl_seconds":3600,"capabilities":["resource_read","resource_write"]})).await;
    assert_eq!(token_response.status(), StatusCode::CREATED);
    let token = json_body(token_response).await;
    assert_eq!(
        super::machine_credentials::machine(
            app,
            token["token"].as_str().unwrap(),
            "POST",
            &path,
            None,
            body
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    // Enable only the isolated database fixture to exercise transactional enqueue;
    // there is no worker and no outbound HTTP in this test.
    sqlx::query("UPDATE webhooks SET enabled=true WHERE mesh_id=$1 AND id=$2")
        .bind(mesh)
        .bind(id)
        .execute(store.pool())
        .await
        .unwrap();
    let peer = request(
        app,
        "POST",
        &format!("{base}/peers"),
        None,
        json!({"name":"private-device-name","labels":{"private":"must-not-be-in-webhook"}}),
    )
    .await;
    assert_eq!(peer.status(), StatusCode::CREATED);
    let deliveries_path = format!("{item}/deliveries");
    let rows = json_body(request(app, "GET", &deliveries_path, None, Value::Null).await).await;
    assert_eq!(rows["items"].as_array().unwrap().len(), 1);
    let delivery = &rows["items"][0];
    assert_eq!(delivery["status"], "queued");
    assert_eq!(delivery["attempts"], 0);
    let encoded = delivery.to_string();
    assert!(!encoded.contains("private-device-name"));
    assert!(!encoded.contains("must-not-be-in-webhook"));
    let delivery_id = Uuid::parse_str(delivery["id"].as_str().unwrap()).unwrap();
    let retry = format!("{deliveries_path}/{delivery_id}/retry");
    assert_eq!(
        request(app, "POST", &retry, Some(1), Value::Null)
            .await
            .status(),
        StatusCode::CONFLICT,
        "queued work cannot be duplicated"
    );
    sqlx::query("UPDATE webhook_deliveries SET status='failed',attempts=10,result_code='delivery_timeout',completed_at=clock_timestamp() WHERE mesh_id=$1 AND id=$2")
        .bind(mesh).bind(delivery_id).execute(store.pool()).await.unwrap();
    assert_eq!(
        request(app, "POST", &retry, Some(1), Value::Null)
            .await
            .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        request(app, "POST", &retry, Some(2), Value::Null)
            .await
            .status(),
        StatusCode::ACCEPTED
    );
    assert_eq!(
        request(app, "POST", &retry, Some(2), Value::Null)
            .await
            .status(),
        StatusCode::CONFLICT
    );
    let rows = json_body(request(app, "GET", &deliveries_path, None, Value::Null).await).await;
    assert_eq!(rows["items"][0]["id"], json!(delivery_id));
    assert_eq!(rows["items"][0]["attempts"], 0);
    // Editing/disable cancels queued or in-flight old-version notifications.
    let mut disabled = update;
    disabled["enabled"] = json!(false);
    let changed = request(app, "PUT", &item, Some(1), disabled).await;
    assert_eq!(changed.status(), StatusCode::OK);
    let version = json_body(changed).await["version"].as_u64().unwrap();
    assert_eq!(version, 2);
    let rows = json_body(request(app, "GET", &deliveries_path, None, Value::Null).await).await;
    assert_eq!(rows["items"][0]["status"], "cancelled");
    assert_eq!(
        request(app, "POST", &retry, Some(4), Value::Null)
            .await
            .status(),
        StatusCode::CONFLICT
    );
    // Rollback cannot leave a notification for a mutation that did not commit.
    sqlx::query("UPDATE webhooks SET enabled=true WHERE mesh_id=$1 AND id=$2")
        .bind(mesh)
        .bind(id)
        .execute(store.pool())
        .await
        .unwrap();
    let mut tx = store.begin_mutation().await.unwrap();
    sqlx::query("INSERT INTO event_outbox(cursor,mesh_id,event_type,resource_type,payload) VALUES($1,$2,'peer.created','peer','{}')")
        .bind(Uuid::new_v4()).bind(mesh).execute(&mut *tx).await.unwrap();
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM webhook_deliveries WHERE mesh_id=$1 AND webhook_id=$2",
    )
    .bind(mesh)
    .bind(id)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert_eq!(count, 2);
    tx.rollback().await.unwrap();
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM webhook_deliveries WHERE mesh_id=$1 AND webhook_id=$2",
    )
    .bind(mesh)
    .bind(id)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(count, 1);
    // A full bounded queue reports drops and still commits the ordinary event.
    sqlx::query("INSERT INTO webhook_deliveries(mesh_id,webhook_id,webhook_version,event_sequence,event) SELECT $1,$2,2, -n, '{}'::jsonb FROM generate_series(1,9999) n")
        .bind(mesh).bind(id).execute(store.pool()).await.unwrap();
    sqlx::query("INSERT INTO event_outbox(cursor,mesh_id,event_type,resource_type,payload) VALUES($1,$2,'peer.created','peer','{}')")
        .bind(Uuid::new_v4()).bind(mesh).execute(store.pool()).await.unwrap();
    let full = json_body(request(app, "GET", &item, None, Value::Null).await).await;
    assert_eq!(full["dropped_events"], 1);
    assert_eq!(
        request(app, "DELETE", &item, Some(1), Value::Null)
            .await
            .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        request(app, "DELETE", &item, Some(version), Value::Null)
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM webhook_deliveries WHERE mesh_id=$1 AND webhook_id=$2",
    )
    .bind(mesh)
    .bind(id)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(count, 0);
}
