use super::*;

pub(super) async fn machine(
    app: &Router,
    token: &str,
    method: &str,
    path: &str,
    version: Option<u64>,
    body: Value,
) -> Response {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json");
    if let Some(version) = version {
        request = request.header("if-match", format!("\"{version}\""));
    }
    app.clone()
        .oneshot(request.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap()
}
pub async fn verify(store: &Store, app: &Router, mesh: Uuid) {
    let path = format!("/api/v1/meshes/{mesh}/machine-credentials");
    let id = Uuid::new_v4();
    let mut body = json!({"id":id,"name":"automation-reader","capabilities":["resource_read"],"ttl_seconds":3600});
    let mut invalid = body.clone();
    invalid["capabilities"] = json!(["trust_manage"]);
    assert_eq!(
        request(app, "POST", &path, None, invalid).await.status(),
        StatusCode::BAD_REQUEST
    );
    let response = request(app, "POST", &path, None, body.clone()).await;
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let issued = json_body(response).await;
    let token = issued["token"].as_str().unwrap();
    let production = router(
        store.clone(),
        AuthConfig {
            development_bearer_token: None,
            bootstrap_token: None,
            oidc: Some(peerward_control::OidcConfig {
                issuer_url: "https://identity.example.test".parse().unwrap(),
                client_id: "unused-machine-test".into(),
                client_secret: None,
                redirect_uri: "https://control.example.test/auth/callback"
                    .parse()
                    .unwrap(),
                scopes: "openid".into(),
                groups_claim: "groups".into(),
                operator_groups: vec![],
                auditor_groups: vec![],
                admin_groups: vec![],
            }),
        },
    );
    assert_eq!(
        machine(
            &production,
            token,
            "GET",
            &format!("/api/v1/meshes/{mesh}"),
            None,
            Value::Null
        )
        .await
        .status(),
        StatusCode::OK,
        "machine authentication works with production OIDC without enabling the development bearer"
    );
    assert!(issued["credential"].get("token_digest").is_none());
    assert_eq!(
        request(app, "POST", &path, None, body.clone())
            .await
            .status(),
        StatusCode::CONFLICT
    );
    let mesh_path = format!("/api/v1/meshes/{mesh}");
    for (target, expected) in [
        (mesh_path.as_str(), StatusCode::OK),
        ("/api/v1/meshes", StatusCode::FORBIDDEN),
        ("/auth/session", StatusCode::FORBIDDEN),
        (&path, StatusCode::FORBIDDEN),
        (
            &format!("/api/v1/meshes/{}", Uuid::new_v4()),
            StatusCode::FORBIDDEN,
        ),
    ] {
        assert_eq!(
            machine(app, token, "GET", target, None, Value::Null)
                .await
                .status(),
            expected,
            "request scope: {target}"
        );
    }
    let resources = format!("{mesh_path}/network-resources");
    let resource = json!({"id":Uuid::new_v4(),"definition":{"name":"automation-resource","target":{"kind":"subnet","prefix":"192.168.244.0/24","site_id":Uuid::new_v4()}}});
    assert_eq!(
        machine(app, token, "POST", &resources, None, resource.clone())
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    let list = json_body(request(app, "GET", &path, None, Value::Null).await).await;
    assert!(!list.to_string().contains(token));
    assert!(!list.to_string().contains("token_digest"));
    let target = format!("{path}/{id}");
    assert_eq!(
        request(app, "DELETE", &target, Some(99), Value::Null)
            .await
            .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        request(app, "DELETE", &target, Some(1), Value::Null)
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        request(app, "DELETE", &target, Some(1), Value::Null)
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        machine(app, token, "GET", &mesh_path, None, Value::Null)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    body["id"] = json!(Uuid::new_v4());
    body["name"] = json!("automation-writer");
    body["capabilities"] = json!(["resource_read", "resource_write"]);
    let issued = json_body(request(app, "POST", &path, None, body).await).await;
    let token = issued["token"].as_str().unwrap();
    assert_eq!(
        machine(app, token, "POST", &resources, None, resource.clone())
            .await
            .status(),
        StatusCode::CONFLICT,
        "write capability does not automatically acquire configuration ownership"
    );
    let ownership_path = format!("{mesh_path}/configuration/ownership");
    let ownership = json_body(request(app, "GET", &ownership_path, None, Value::Null).await).await;
    assert_eq!(
        request(
            app,
            "PUT",
            &ownership_path,
            ownership["version"].as_u64(),
            json!({"owner_machine_id":issued["credential"]["id"]})
        )
        .await
        .status(),
        StatusCode::OK
    );
    assert_eq!(
        machine(app, token, "POST", &resources, None, resource)
            .await
            .status(),
        StatusCode::CREATED
    );
    let settings = json_body(request(app, "GET", &mesh_path, None, Value::Null).await).await;
    assert_eq!(
        machine(
            app,
            token,
            "PATCH",
            &mesh_path,
            settings["version"].as_u64(),
            json!({"lease_seconds":3600})
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    let credential = Uuid::parse_str(issued["credential"]["id"].as_str().unwrap()).unwrap();
    sqlx::query("UPDATE machine_credentials SET created_at=clock_timestamp()-interval '2 hours',expires_at=clock_timestamp()-interval '1 hour' WHERE id=$1")
        .bind(credential).execute(store.pool()).await.unwrap();
    assert_eq!(
        machine(app, token, "GET", &mesh_path, None, Value::Null)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let ownership = json_body(request(app, "GET", &ownership_path, None, Value::Null).await).await;
    assert_eq!(
        request(
            app,
            "PUT",
            &ownership_path,
            ownership["version"].as_u64(),
            json!({"owner_machine_id":null})
        )
        .await
        .status(),
        StatusCode::OK
    );
}
