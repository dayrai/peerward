#[tokio::test]
async fn device_details_preserve_identity_labels_and_show_only_assigned_mesh_addresses() {
    let url = std::env::var("PEERWARD_TEST_DATABASE_URL").unwrap();
    assert!(url.parse::<sqlx::postgres::PgConnectOptions>()
            .is_ok_and(|options| options.get_database() == Some("peerward_test")));
    let store = Store::connect(&url, 4).await.unwrap();
    store.migrate().await.unwrap();
    let mesh = store.create_mesh(&NewMesh {
        name: format!("devices-{}", Uuid::new_v4()),
        address_cidr: "10.94.0.0/24".parse().unwrap(), gateway: "10.94.0.1".parse().unwrap(),
        dns_suffix: "devices.test".into(), mtu: 1380, reserved: Vec::new(),
        default_policy: DefaultPolicy::Deny, quarantine_seconds: 60, rotation_overlap_seconds: 3600,
    }, "admin").await.unwrap();
    let app = router(store.clone(), AuthConfig {
        development_bearer_token: Some("delete-test".into()), oidc: None, bootstrap_token: None,
    });
    let collection = format!("/api/v1/meshes/{}/peers", mesh.id);
    let created = request(&app, "POST", &collection, None, json!({
        "name":"home-nas", "display_name":"家庭记忆库", "location":"家中书房",
        "labels":{"platform":"linux","role":"storage"}
    })).await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let peer = json_body(created).await;
    let id = Uuid::parse_str(peer["id"].as_str().unwrap()).unwrap();
    let member = format!("{collection}/{id}");
    assert_eq!(peer["mesh_addresses"], json!([]));
    for (address, state) in [("10.94.0.2", "active"), ("10.94.0.3", "quarantine"), ("10.94.0.4", "released")] {
        sqlx::query("INSERT INTO peer_addresses(id,mesh_id,peer_id,address,state) VALUES($1,$2,$3,$4::text::inet,$5)")
            .bind(Uuid::new_v4()).bind(mesh.id.into_uuid()).bind(id).bind(address).bind(state)
            .execute(store.pool()).await.unwrap();
    }
    let listed = json_body(request(&app, "GET", &collection, None, json!({})).await).await;
    assert_eq!(listed["items"][0]["mesh_addresses"], json!(["10.94.0.2"]));
    assert_eq!(listed["items"][0]["online"], false);
    assert_eq!(listed["items"][0]["display_name"], "家庭记忆库");
    let response = request(&app, "PATCH", &member, Some(1), json!({"display_name":"我的 NAS","location":""})).await;
    assert_eq!(response.status(), StatusCode::OK);
    let updated = json_body(response).await;
    assert_eq!(updated["name"], "home-nas");
    assert_eq!(updated["display_name"], "我的 NAS");
    assert_eq!(updated["location"], "");
    assert_eq!(updated["labels"], peer["labels"]);
    assert_eq!(updated["version"], 2);
    assert_eq!(request(&app, "PATCH", &member, Some(1), json!({"location":"stale"})).await.status(), StatusCode::CONFLICT);
    for invalid in ["x".repeat(129), "line\nbreak".into()] {
        assert_eq!(request(&app, "PATCH", &member, Some(2), json!({"location":invalid})).await.status(), StatusCode::BAD_REQUEST);
    }
    let ordinary_edit = request(&app, "PATCH", &member, Some(2), json!({"labels":{"role":"storage"}})).await;
    assert_eq!(ordinary_edit.status(), StatusCode::OK);
    assert_eq!(json_body(ordinary_edit).await["display_name"], "我的 NAS");
    sqlx::query("UPDATE meshes SET lifecycle='deleted',lifecycle_revision=lifecycle_revision+1 WHERE id=$1")
        .bind(mesh.id.into_uuid()).execute(store.pool()).await.unwrap();
    let meshes = json_body(request(&app, "GET", "/api/v1/meshes?limit=100", None, json!({})).await).await;
    assert!(!meshes["items"].as_array().unwrap().iter().any(|item| item["id"] == mesh.id.to_string()));
}
