use super::*;

async fn runner_request(
    app: &Router,
    token: &str,
    method: &str,
    path: &str,
    body: Value,
) -> Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
}

pub async fn verify(store: &Store, app: &Router) {
    verify_native_upgrade(store, app).await;
    let id = Uuid::new_v4();
    let profile = "a".repeat(64);
    let preview_digest = "b".repeat(64);
    let registered = request(
        app,
        "POST",
        "/api/v1/deployment-runners",
        None,
        json!({"id":id,"name":"isolated-deployment","profile_digest":profile,"ttl_seconds":3600}),
    )
    .await;
    assert_eq!(registered.status(), StatusCode::CREATED);
    assert_eq!(registered.headers()["cache-control"], "no-store");
    let registered = json_body(registered).await;
    let token = registered["token"].as_str().unwrap();
    assert_eq!(token.len(), 54);
    let path = format!("/api/v1/deployment-runners/{id}/exchange");
    for (method, route) in [
        ("GET", "/api/v1/deployment-runners"),
        ("POST", "/api/v1/deployment-tasks"),
        ("GET", "/auth/session"),
    ] {
        assert_eq!(
            runner_request(app, token, method, route, json!({}))
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }
    let mut body = json!({"sequence":1,"profile_digest":profile,"preview":{"digest":preview_digest,"services_to_pause":["control","relay"],"online_files":10,"meshes":1,"relay_hosts":1},"reports":[]});
    assert_eq!(
        request(app, "POST", &path, None, body.clone())
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        runner_request(
            app,
            token,
            "POST",
            &format!("/api/v1/deployment-runners/{}/exchange", Uuid::new_v4()),
            body.clone()
        )
        .await
        .status(),
        StatusCode::UNAUTHORIZED
    );
    let first = json_body(runner_request(app, token, "POST", &path, body.clone()).await).await;
    assert!(first["task"].is_null());
    assert_eq!(
        json_body(runner_request(app, token, "POST", &path, body.clone()).await).await,
        first
    );
    let mut altered = body.clone();
    altered["preview"] = Value::Null;
    assert_eq!(
        runner_request(app, token, "POST", &path, altered)
            .await
            .status(),
        StatusCode::CONFLICT
    );
    let task = Uuid::new_v4();
    let create = json!({"id":task,"runner_id":id,"preview_digest":preview_digest});
    let mut stale = create.clone();
    stale["preview_digest"] = json!("c".repeat(64));
    assert_eq!(
        request(app, "POST", "/api/v1/deployment-tasks", None, stale)
            .await
            .status(),
        StatusCode::CONFLICT
    );
    let (one, two) = tokio::join!(
        request(
            app,
            "POST",
            "/api/v1/deployment-tasks",
            None,
            create.clone()
        ),
        request(
            app,
            "POST",
            "/api/v1/deployment-tasks",
            None,
            create.clone()
        )
    );
    assert!([one.status(), two.status()].contains(&StatusCode::ACCEPTED));
    assert!([one.status(), two.status()].contains(&StatusCode::OK));
    body["sequence"] = json!(2);
    let assigned = json_body(runner_request(app, token, "POST", &path, body.clone()).await).await;
    assert_eq!(assigned["task"]["id"], task.to_string());
    assert_eq!(assigned["task"]["status"], "running");
    assert_eq!(
        request(
            app,
            "POST",
            &format!("/api/v1/deployment-tasks/{task}/cancel"),
            Some(2),
            Value::Null
        )
        .await
        .status(),
        StatusCode::CONFLICT
    );
    body["sequence"] = json!(3);
    let redelivered =
        json_body(runner_request(app, token, "POST", &path, body.clone()).await).await;
    assert_eq!(redelivered["task"]["id"], task.to_string());
    body["sequence"] = json!(4);
    body["reports"] = json!([{"task_id":task,"local_version":8,"status":"succeeded","stage":"complete","error_code":null,"artifact":{"sha256":"d".repeat(64),"bytes":4096,"files":10}}]);
    let mut invalid = body.clone();
    invalid["reports"][0]["artifact"] = Value::Null;
    assert_eq!(
        runner_request(app, token, "POST", &path, invalid)
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    let complete = json_body(runner_request(app, token, "POST", &path, body.clone()).await).await;
    assert!(complete["task"].is_null());
    body["sequence"] = json!(5);
    assert_eq!(
        runner_request(app, token, "POST", &path, body.clone())
            .await
            .status(),
        StatusCode::OK
    );
    body["sequence"] = json!(6);
    body["reports"][0]["local_version"] = json!(9);
    body["reports"][0]["status"] = json!("running");
    assert_eq!(
        runner_request(app, token, "POST", &path, body.clone())
            .await
            .status(),
        StatusCode::CONFLICT
    );
    let listed =
        json_body(request(app, "GET", "/api/v1/deployment-runners", None, Value::Null).await).await;
    assert!(!listed.to_string().contains(token) && !listed.to_string().contains("token_digest"));
    assert_eq!(
        listed["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["id"] == id.to_string())
            .unwrap()["ready"],
        true
    );
    sqlx::query("UPDATE deployment_runners SET last_seen=clock_timestamp()-interval '31 seconds' WHERE id=$1").bind(id).execute(store.pool()).await.unwrap();
    let stale_list =
        json_body(request(app, "GET", "/api/v1/deployment-runners", None, Value::Null).await).await;
    assert_eq!(
        stale_list["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["id"] == id.to_string())
            .unwrap()["ready"],
        false
    );
    sqlx::query("UPDATE deployment_runners SET last_seen=clock_timestamp() WHERE id=$1")
        .bind(id)
        .execute(store.pool())
        .await
        .unwrap();
    let expired = Uuid::new_v4();
    assert_eq!(
        request(
            app,
            "POST",
            "/api/v1/deployment-tasks",
            None,
            json!({"id":expired,"runner_id":id,"preview_digest":preview_digest})
        )
        .await
        .status(),
        StatusCode::ACCEPTED
    );
    sqlx::query("UPDATE deployment_tasks SET created_at=clock_timestamp()-interval '16 minutes' WHERE id=$1").bind(expired).execute(store.pool()).await.unwrap();
    body["reports"] = json!([]);
    assert_eq!(
        runner_request(app, token, "POST", &path, body.clone())
            .await
            .status(),
        StatusCode::OK
    );
    let expired_result = json_body(
        request(
            app,
            "GET",
            &format!("/api/v1/deployment-tasks/{expired}"),
            None,
            Value::Null,
        )
        .await,
    )
    .await;
    assert_eq!(expired_result["stage"], "queue_expired");
    body["sequence"] = json!(7);
    let queued = Uuid::new_v4();
    let create = json!({"id":queued,"runner_id":id,"preview_digest":preview_digest});
    assert_eq!(
        request(app, "POST", "/api/v1/deployment-tasks", None, create)
            .await
            .status(),
        StatusCode::ACCEPTED
    );
    assert_eq!(
        request(
            app,
            "DELETE",
            &format!("/api/v1/deployment-runners/{id}"),
            Some(1),
            Value::Null
        )
        .await
        .status(),
        StatusCode::OK
    );
    assert_eq!(
        runner_request(app, token, "POST", &path, body)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let cancelled = json_body(
        request(
            app,
            "GET",
            &format!("/api/v1/deployment-tasks/{queued}"),
            None,
            Value::Null,
        )
        .await,
    )
    .await;
    assert_eq!(cancelled["status"], "cancelled");
    let audits: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE action LIKE 'deployment.%'")
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert!(audits >= 4);
}

async fn verify_native_upgrade(store: &Store, app: &Router) {
    let id = Uuid::new_v4();
    let digest = "d".repeat(64);
    let registered=json_body(request(app,"POST","/api/v1/deployment-runners",None,
        json!({"id":id,"name":"native-upgrade","profile_digest":"c".repeat(64),"ttl_seconds":3600})).await).await;
    let token = registered["token"].as_str().unwrap();
    let path = format!("/api/v1/deployment-runners/{id}/exchange");
    let preview = json!({"digest":digest,"services_to_pause":["relay"],"online_files":1,"meshes":0,"relay_hosts":0,
        "upgrade":{"role":"relay","current_version":"1.0.0","version":"1.0.1","manifest_sha256":"e".repeat(64),
        "artifact_sha256":"f".repeat(64),"artifact_bytes":100,"rollback_floor":"1.0.0","repair":false}});
    let body = json!({"sequence":1,"profile_digest":"c".repeat(64),"preview":preview,"reports":[]});
    assert_eq!(
        runner_request(app, token, "POST", &path, body.clone())
            .await
            .status(),
        StatusCode::OK
    );
    let task = Uuid::new_v4();
    let mut create = json!({"id":task,"runner_id":id,"preview_digest":digest});
    // The previous backup request shape cannot silently approve an upgrade.
    assert_eq!(
        request(
            app,
            "POST",
            "/api/v1/deployment-tasks",
            None,
            create.clone()
        )
        .await
        .status(),
        StatusCode::CONFLICT
    );
    create["operation"] = json!("native_upgrade");
    let (left, right) = tokio::join!(
        request(
            app,
            "POST",
            "/api/v1/deployment-tasks",
            None,
            create.clone()
        ),
        request(
            app,
            "POST",
            "/api/v1/deployment-tasks",
            None,
            create.clone()
        )
    );
    assert!(matches!(
        left.status(),
        StatusCode::ACCEPTED | StatusCode::OK
    ));
    assert!(matches!(
        right.status(),
        StatusCode::ACCEPTED | StatusCode::OK
    ));
    let mut body = body;
    body["sequence"] = json!(2);
    let assigned = json_body(runner_request(app, token, "POST", &path, body.clone()).await).await;
    assert_eq!(assigned["task"]["operation"], "native_upgrade");
    assert_eq!(assigned["task"]["id"], task.to_string());
    body["sequence"] = json!(3);
    body["preview"] = Value::Null;
    body["reports"] = json!([{"task_id":task,"local_version":1,"status":"recovery_required","stage":"native_recovery_required","error_code":"native_recovery_required","artifact":null}]);
    let waiting = json_body(runner_request(app, token, "POST", &path, body.clone()).await).await;
    let version = waiting["task"]["version"].as_u64().unwrap();
    let recovery_path = format!("/api/v1/deployment-tasks/{task}/recover");
    let recovery = json!({"request_id":Uuid::new_v4()});
    assert_eq!(
        runner_request(app, token, "POST", &recovery_path, recovery.clone())
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        request(
            app,
            "POST",
            &recovery_path,
            Some(version - 1),
            recovery.clone()
        )
        .await
        .status(),
        StatusCode::CONFLICT
    );
    sqlx::query(
        "UPDATE deployment_runners SET last_seen=clock_timestamp()-interval '1 minute' WHERE id=$1",
    )
    .bind(id)
    .execute(store.pool())
    .await
    .unwrap();
    assert_eq!(
        request(app, "POST", &recovery_path, Some(version), recovery.clone())
            .await
            .status(),
        StatusCode::CONFLICT
    );
    body["sequence"] = json!(4);
    assert_eq!(
        runner_request(app, token, "POST", &path, body.clone())
            .await
            .status(),
        StatusCode::OK
    );
    // A fresh connection suffices for explicit recovery even with no new release preview.
    let (one, two) = tokio::join!(
        request(app, "POST", &recovery_path, Some(version), recovery.clone()),
        request(app, "POST", &recovery_path, Some(version), recovery.clone())
    );
    assert_eq!(one.status(), StatusCode::OK);
    assert_eq!(two.status(), StatusCode::OK);
    let requested = json_body(one).await;
    assert_eq!(requested["recovery_generation"], 1);
    assert_eq!(requested["status"], "running");
    assert_eq!(json_body(two).await["recovery_generation"], 1);
    assert_eq!(
        request(
            app,
            "POST",
            &recovery_path,
            Some(version + 1),
            recovery.clone()
        )
        .await
        .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        request(
            app,
            "POST",
            &recovery_path,
            Some(version + 1),
            json!({"request_id":Uuid::new_v4()})
        )
        .await
        .status(),
        StatusCode::CONFLICT
    );
    // Losing the recovery response cannot increment its generation on retry, even offline.
    sqlx::query("UPDATE deployment_runners SET last_seen=NULL WHERE id=$1")
        .bind(id)
        .execute(store.pool())
        .await
        .unwrap();
    assert_eq!(
        json_body(request(app, "POST", &recovery_path, Some(version), recovery).await).await["recovery_generation"],
        1
    );
    body["sequence"] = json!(5);
    let report = json!({"task_id":task,"local_version":2,"status":"succeeded","stage":"succeeded","error_code":null,
        "artifact":{"sha256":"f".repeat(64),"bytes":100,"files":1}});
    body["reports"] = json!([report]);
    // A backup-shaped receipt is insufficient for native readiness.
    assert_eq!(
        runner_request(app, token, "POST", &path, body.clone())
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    body["reports"][0]["upgrade"] = json!({"role":"relay","version":"1.0.1","manifest_sha256":"e".repeat(64),
        "current_sha256":"f".repeat(64),"state":"succeeded","runtime_checked":false});
    assert_eq!(
        runner_request(app, token, "POST", &path, body.clone())
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    body["reports"][0]["upgrade"]["runtime_checked"] = json!(true);
    body["reports"][0]["upgrade"]["version"] = json!("1.0.0");
    assert_eq!(
        runner_request(app, token, "POST", &path, body.clone())
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    body["reports"][0]["upgrade"]["version"] = json!("1.0.1");
    assert_eq!(
        runner_request(app, token, "POST", &path, body.clone())
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        runner_request(app, token, "POST", &path, body.clone())
            .await
            .status(),
        StatusCode::OK
    );
    let value =
        json_body(request(app, "GET", "/api/v1/operations/status", None, Value::Null).await).await;
    assert!(
        value["latest_successful_backup"].is_null(),
        "an upgrade is never a backup receipt"
    );
    let operation: String =
        sqlx::query_scalar("SELECT operation FROM deployment_tasks WHERE id=$1")
            .bind(task)
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert_eq!(operation, "native_upgrade");
}
