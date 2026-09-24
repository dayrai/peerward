use super::*;

pub async fn verify(store: &Store, app: &Router, mesh: Uuid) {
    use peerward_store::{NewSession, Role};
    let token = Uuid::new_v4().to_string();
    store
        .create_session(&NewSession {
            token: token.clone(),
            csrf_token: "lease-setting-test".into(),
            subject: "lease-operator-test".into(),
            role: Role::Operator,
            expires_at: time::OffsetDateTime::now_utc() + time::Duration::hours(1),
        })
        .await
        .unwrap();
    let path = format!("/api/v1/meshes/{mesh}");
    let current = json_body(request(app, "GET", &path, None, Value::Null).await).await;
    let version = current["version"].as_u64().unwrap();
    for (csrf, seconds, status) in [
        (false, 300, StatusCode::FORBIDDEN),
        (true, 3600, StatusCode::FORBIDDEN),
        (true, 300, StatusCode::OK),
    ] {
        let mut builder = Request::patch(&path)
            .header("cookie", format!("peerward_session={token}"))
            .header("content-type", "application/json")
            .header("if-match", format!("\"{version}\""));
        if csrf {
            builder = builder.header("x-csrf-token", "lease-setting-test");
        }
        let response = app
            .clone()
            .oneshot(
                builder
                    .body(Body::from(json!({"lease_seconds":seconds}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), status, "{}", json_body(response).await);
    }
    let after = json_body(request(app, "GET", &path, None, Value::Null).await).await;
    assert_eq!(
        after["lease_seconds"], 300,
        "operator may preserve, but cannot extend or shorten, the trust limit"
    );
}
