use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
    response::Response,
};
use http_body_util::BodyExt as _;
use peerward_control::{AuthConfig, router};
use peerward_store::{DefaultPolicy, NewMesh, Store, StoreError};
use serde_json::{Value, json};
use tower::ServiceExt as _;
use uuid::Uuid;
#[path = "network_cases/authorization_settings.rs"]
mod authorization_settings;
#[path = "network_cases/auto_approval.rs"]
mod auto_approval;
#[path = "network_cases/collections.rs"]
mod collections;
#[path = "network_cases/configuration_apply.rs"]
mod configuration_apply;
#[path = "network_cases/configuration_ownership.rs"]
mod configuration_ownership;
#[path = "network_cases/console.rs"]
mod console;
#[path = "network_cases/console_access.rs"]
mod console_access;
#[path = "network_cases/deployment_tasks.rs"]
mod deployment_tasks;
#[path = "network_cases/dns_names.rs"]
mod dns_names;
#[path = "network_cases/gateway_priority.rs"]
mod gateway_priority;
#[path = "network_cases/machine_credentials.rs"]
mod machine_credentials;
#[path = "network_cases/relay_maintenance.rs"]
mod relay_maintenance;
#[path = "network_cases/resource_aliases.rs"]
mod resource_aliases;
#[path = "network_cases/webhooks.rs"]
mod webhooks;

async fn request(
    app: &Router,
    method: &str,
    path: &str,
    version: Option<u64>,
    body: Value,
) -> Response {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", "Bearer isolated-network-test")
        .header("content-type", "application/json");
    if let Some(version) = version {
        builder = builder.header("if-match", format!("\"{version}\""));
    }
    app.clone()
        .oneshot(builder.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap()
}
async fn json_body(response: Response) -> Value {
    serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
}

#[tokio::test]
async fn resources_and_approvals_are_scoped_versioned_atomic_and_audited() {
    let url = std::env::var("PEERWARD_TEST_DATABASE_URL").unwrap();
    assert!(
        url.parse::<sqlx::postgres::PgConnectOptions>()
            .is_ok_and(|options| options.get_database() == Some("peerward_test"))
    );
    let store = Store::connect(&url, 12).await.unwrap();
    store.migrate().await.unwrap();
    store.migrate().await.unwrap();
    let mesh = store
        .create_mesh(
            &NewMesh {
                name: format!("network-{}", Uuid::new_v4()),
                address_cidr: "10.92.0.0/24".parse().unwrap(),
                gateway: "10.92.0.1".parse().unwrap(),
                dns_suffix: "network.test".into(),
                mtu: 1280,
                reserved: vec![],
                default_policy: DefaultPolicy::Deny,
                quarantine_seconds: 3600,
                rotation_overlap_seconds: 3600,
            },
            "test",
        )
        .await
        .unwrap();
    let app = router(
        store.clone(),
        AuthConfig {
            development_bearer_token: Some("isolated-network-test".into()),
            oidc: None,
            bootstrap_token: None,
        },
    );
    let collection = format!("/api/v1/meshes/{}/network-resources", mesh.id);
    let mesh_path = format!("/api/v1/meshes/{}", mesh.id);
    let settings = json_body(request(&app, "GET", &mesh_path, None, Value::Null).await).await;
    assert_eq!(settings["lease_seconds"], 900);
    assert_eq!(
        request(
            &app,
            "PATCH",
            &mesh_path,
            settings["version"].as_u64(),
            json!({"lease_seconds":60})
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );
    let changed = request(
        &app,
        "PATCH",
        &mesh_path,
        settings["version"].as_u64(),
        json!({"lease_seconds":300}),
    )
    .await;
    assert_eq!(changed.status(), StatusCode::OK);
    assert_eq!(json_body(changed).await["lease_seconds"], 300);
    assert_eq!(
        request(
            &app,
            "PATCH",
            &mesh_path,
            settings["version"].as_u64(),
            json!({"lease_seconds":3600})
        )
        .await
        .status(),
        StatusCode::CONFLICT
    );
    authorization_settings::verify(&store, &app, mesh.id.into_uuid()).await;
    let unauth = app
        .clone()
        .oneshot(Request::get(&collection).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(unauth.status(), StatusCode::UNAUTHORIZED);
    let id = Uuid::new_v4();
    let site = Uuid::new_v4();
    let definition = json!({"name":"Printer","target":{"kind":"subnet","prefix":"192.168.45.10/32","site_id":site}});
    let body = json!({"id":id,"definition":definition});
    let (first, second) = tokio::join!(
        request(&app, "POST", &collection, None, body.clone()),
        request(&app, "POST", &collection, None, body.clone())
    );
    assert!([first.status(), second.status()].contains(&StatusCode::CREATED));
    assert!([first.status(), second.status()].contains(&StatusCode::OK));
    let listed = json_body(request(&app, "GET", &collection, None, Value::Null).await).await;
    assert_eq!(listed["items"].as_array().unwrap().len(), 1);
    let mut invalid = body.clone();
    invalid["approved"] = json!(true);
    assert_eq!(
        request(&app, "POST", &collection, None, invalid)
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    let mut conflict = body.clone();
    conflict["id"] = json!(Uuid::new_v4());
    conflict["definition"]["name"] = json!("Other site");
    conflict["definition"]["target"]["site_id"] = json!(Uuid::new_v4());
    assert_eq!(
        request(&app, "POST", &collection, None, conflict)
            .await
            .status(),
        StatusCode::CONFLICT
    );
    let mut pool_conflict = body.clone();
    pool_conflict["id"] = json!(Uuid::new_v4());
    pool_conflict["definition"]["target"]["prefix"] = json!("10.92.0.10/32");
    assert_eq!(
        request(&app, "POST", &collection, None, pool_conflict)
            .await
            .status(),
        StatusCode::CONFLICT
    );
    let peer = json_body(
        request(
            &app,
            "POST",
            &format!("/api/v1/meshes/{}/peers", mesh.id),
            None,
            json!({"name":"gateway"}),
        )
        .await,
    )
    .await;
    assert!(peer["id"].is_string(), "peer creation failed: {peer}");
    let bindings = format!("/api/v1/meshes/{}/gateway-bindings", mesh.id);
    let binding = Uuid::new_v4();
    let created = request(
        &app,
        "POST",
        &bindings,
        None,
        json!({"id":binding,"resource_id":id,"peer_id":peer["id"],"priority":100}),
    )
    .await;
    assert_eq!(created.status(), StatusCode::CREATED);
    assert_eq!(json_body(created).await["approved"], false);
    let approval = format!("{bindings}/{binding}/approval");
    assert_eq!(
        request(&app, "PUT", &approval, None, json!({"approved":true}))
            .await
            .status(),
        StatusCode::PRECONDITION_REQUIRED
    );
    let approved = request(&app, "PUT", &approval, Some(1), json!({"approved":true})).await;
    assert_eq!(approved.status(), StatusCode::OK);
    assert_eq!(json_body(approved).await["approved"], true);
    assert_eq!(
        request(&app, "PUT", &approval, Some(1), json!({"approved":false}))
            .await
            .status(),
        StatusCode::CONFLICT
    );
    // A database fixture represents an assigned device address; this is API validation,
    gateway_priority::verify(&store, &app, mesh.id.into_uuid(), binding).await;
    // not evidence that the physical gateway has joined or installed forwarding.
    let source = Uuid::parse_str(peer["id"].as_str().unwrap()).unwrap();
    sqlx::query("INSERT INTO peer_addresses(id,mesh_id,peer_id,address,state) VALUES($1,$2,$3,'10.92.0.2','active')")
        .bind(Uuid::new_v4()).bind(mesh.id.into_uuid()).bind(source).execute(store.pool()).await.unwrap();
    let dns_collection = format!("/api/v1/meshes/{}/dns-profiles", mesh.id);
    let dns = json_body(request(&app, "GET", &dns_collection, None, Value::Null).await).await;
    assert_eq!(dns["items"].as_array().unwrap().len(), 1);
    let default_path = format!("{dns_collection}/{}", mesh.id);
    assert_eq!(
        request(&app, "DELETE", &default_path, Some(1), Value::Null)
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    let mut profile = dns["items"][0]["profile"].clone();
    profile["routes"] = json!([{"suffix":"office.test","upstreams":["10.92.0.53:53"]}]);
    profile["records"] = json!({"printer.office.test":[{"type":"A","value":"192.168.45.10"}]});
    assert_eq!(
        request(&app, "PUT", &default_path, Some(1), profile.clone())
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        request(&app, "PUT", &default_path, Some(1), profile.clone())
            .await
            .status(),
        StatusCode::CONFLICT
    );
    let preview = json_body(
        request(
            &app,
            "POST",
            &format!("/api/v1/meshes/{}/dns/preview", mesh.id),
            None,
            json!({"peer_id":source}),
        )
        .await,
    )
    .await;
    assert_eq!(preview["routes"][0]["suffix"], "office.test");
    profile["id"] = json!(Uuid::new_v4());
    profile["routes"][0]["upstreams"] = json!(["1.1.1.1:53"]);
    assert_eq!(
        request(&app, "POST", &dns_collection, None, profile)
            .await
            .status(),
        StatusCode::CONFLICT
    );
    let policy_path = format!("/api/v1/meshes/{}/resource-policy", mesh.id);
    let test_id = Uuid::new_v4();
    let rule = json!({"id":Uuid::new_v4(),"priority":100,"enabled":true,"action":"allow","source":{"peers":[],"labels":{},"cidrs":[]},
        "resources":[id],"providers":[],"protocol":6,"destination_ports":[[631,631]],"not_after":null});
    let assertion = json!({"id":test_id,"name":"printing allowed","source_peer_id":source,"resource_id":id,"provider_peer_id":source,
        "address":"192.168.45.10","protocol":6,"destination_port":631,"expected":"allow"});
    let document = json!({"rules":[rule],"tests":[assertion]});
    let published = request(&app, "PUT", &policy_path, Some(1), document.clone()).await;
    assert_eq!(
        published.status(),
        StatusCode::OK,
        "{}",
        json_body(published).await
    );
    let simulation = json!({"source_peer_id":source,"target":{"kind":"resource","resource_id":id,"address":"192.168.45.10","provider_peer_id":source},
        "protocol":6,"destination_port":631});
    let simulated = json_body(
        request(
            &app,
            "POST",
            &format!("/api/v1/meshes/{}/policy/simulate", mesh.id),
            None,
            simulation,
        )
        .await,
    )
    .await;
    assert_eq!(simulated["allowed"], true);
    let mut unsafe_change = document.clone();
    unsafe_change["rules"][0]["destination_ports"] = json!([[80, 80]]);
    assert_eq!(
        request(&app, "PUT", &policy_path, Some(2), unsafe_change)
            .await
            .status(),
        StatusCode::CONFLICT
    );
    let revoked = json_body(
        request(
            &app,
            "PUT",
            &policy_path,
            Some(2),
            json!({"rules":[],"tests":document["tests"]}),
        )
        .await,
    )
    .await;
    assert_eq!(revoked["version"], 3);
    assert_eq!(
        revoked["failed_tests"],
        json!([test_id]),
        "positive assertions must not block removal of grants"
    );
    let historical = json_body(
        request(
            &app,
            "GET",
            &format!("{policy_path}/history/2"),
            None,
            Value::Null,
        )
        .await,
    )
    .await;
    assert_eq!(historical["document"]["rules"].as_array().unwrap().len(), 1);
    let path = format!("{collection}/{id}");
    let mut changed = definition.clone();
    changed["target"]["prefix"] = json!("192.168.45.11/32");
    assert_eq!(
        request(&app, "PUT", &path, Some(1), changed).await.status(),
        StatusCode::OK
    );
    let binding = json_body(
        request(
            &app,
            "GET",
            &format!("{bindings}/{binding}"),
            None,
            Value::Null,
        )
        .await,
    )
    .await;
    assert_eq!(
        binding["approved"], false,
        "address replacement must revoke old approval"
    );
    assert_eq!(
        request(&app, "DELETE", &path, Some(1), Value::Null)
            .await
            .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        request(&app, "DELETE", &path, Some(2), Value::Null)
            .await
            .status(),
        StatusCode::CONFLICT,
        "current saved assertions must not become dangling references"
    );
    assert_eq!(
        request(
            &app,
            "PUT",
            &policy_path,
            Some(3),
            json!({"rules":[],"tests":[]})
        )
        .await
        .status(),
        StatusCode::OK
    );
    assert_eq!(
        request(&app, "DELETE", &path, Some(2), Value::Null)
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    let grants: i64 = sqlx::query_scalar("SELECT count(*) FROM gateway_bindings WHERE mesh_id=$1")
        .bind(mesh.id.into_uuid())
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(grants, 0);
    let audits:i64=sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE retained_mesh_id=$1 AND action LIKE 'network_resource.%'").bind(mesh.id.into_uuid()).fetch_one(store.pool()).await.unwrap();
    assert_eq!(audits, 3);
    let withdrawn: Vec<Value> = sqlx::query_scalar(
        "SELECT target FROM resource_withdrawals WHERE mesh_id=$1 ORDER BY target::text",
    )
    .bind(mesh.id.into_uuid())
    .fetch_all(store.pool())
    .await
    .unwrap();
    assert_eq!(
        withdrawn.len(),
        2,
        "old and deleted addresses must both retain a signed deny shadow"
    );
    let former: Vec<Value> = sqlx::query_scalar(
        "SELECT providers FROM resource_withdrawals WHERE mesh_id=$1 ORDER BY target::text",
    )
    .bind(mesh.id.into_uuid())
    .fetch_all(store.pool())
    .await
    .unwrap();
    assert!(
        former.iter().all(|providers| providers == &json!([source])),
        "retarget and delete retain gateway identity before bindings cascade away"
    );
    let replacement = Uuid::new_v4();
    assert_eq!(
        request(
            &app,
            "POST",
            &collection,
            None,
            json!({"id":replacement,"definition":definition})
        )
        .await
        .status(),
        StatusCode::CREATED
    );
    let replacement_binding = Uuid::new_v4();
    let result = request(&app,"POST",&bindings,None,json!({"id":replacement_binding,"resource_id":replacement,"peer_id":peer["id"],"priority":100,"forwarding":"snat","return_route_confirmed":false})).await;
    assert_eq!(result.status(), StatusCode::CREATED);
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM resource_withdrawals WHERE mesh_id=$1")
            .bind(mesh.id.into_uuid())
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert_eq!(
        count, 2,
        "creating a resource or a binding cannot clear a withdrawal"
    );
    assert_eq!(
        request(
            &app,
            "PUT",
            &format!("{bindings}/{replacement_binding}/approval"),
            Some(1),
            json!({"approved":true})
        )
        .await
        .status(),
        StatusCode::OK
    );
    let remaining: Vec<Value> =
        sqlx::query_scalar("SELECT target FROM resource_withdrawals WHERE mesh_id=$1")
            .bind(mesh.id.into_uuid())
            .fetch_all(store.pool())
            .await
            .unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(
        remaining[0]["prefix"], "192.168.45.11/32",
        "approval only releases its exact target"
    );
    collections::verify(&store, &app, mesh.id.into_uuid(), source, replacement).await;
    dns_names::verify(&app, mesh.id.into_uuid(), source).await;
    machine_credentials::verify(&store, &app, mesh.id.into_uuid()).await;
    auto_approval::verify(&store, &app, mesh.id.into_uuid(), source).await;
    configuration_ownership::verify(&store, &app, mesh.id.into_uuid()).await;
    configuration_apply::verify(&store, &app).await;
    webhooks::verify(&store, &app, mesh.id.into_uuid()).await;
    resource_aliases::verify(&store, &app).await;
    relay_maintenance::verify(&store, &app, mesh.id.into_uuid()).await;
    deployment_tasks::verify(&store, &app).await;
    console::verify(&store, &app).await;
    // This database belongs only to this test invocation. Prove old installs are rejected without migration writes.
    sqlx::raw_sql("ALTER TABLE peerward_installation DROP CONSTRAINT peerward_installation_wire_major_check; UPDATE peerward_installation SET wire_major=4").execute(store.pool()).await.unwrap();
    assert!(matches!(
        store.migrate().await,
        Err(StoreError::LegacySchemaUnsupported)
    ));
    let wire: i32 = sqlx::query_scalar("SELECT wire_major FROM peerward_installation")
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(wire, 4);
    // Restore this isolated database for the rest of the PostgreSQL gate.
    sqlx::raw_sql("UPDATE peerward_installation SET wire_major=5; ALTER TABLE peerward_installation ADD CONSTRAINT peerward_installation_wire_major_check CHECK(wire_major=5)")
        .execute(store.pool()).await.unwrap();
    store.migrate().await.unwrap();
}
