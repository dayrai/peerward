#![cfg(feature = "postgres-integration")]

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt as _;
use peerward_control::{AuthConfig, router};
use peerward_store::{DefaultPolicy, NewMesh, NewSession, Role, Store};
use serde_json::{Value, json};
use tower::ServiceExt as _;
use uuid::Uuid;

async fn request(app: &axum::Router, method: &str, path: &str, body: Value) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .header("authorization", "Bearer test-admin")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&bytes).unwrap())
}

#[tokio::test]
async fn durable_jobs_are_idempotent_audited_retryable_and_guard_existing_identities() {
    let url = std::env::var("PEERWARD_TEST_DATABASE_URL").unwrap();
    assert!(
        url.parse::<sqlx::postgres::PgConnectOptions>()
            .is_ok_and(|options| options.get_database() == Some("peerward_test"))
    );
    let store = Store::connect(&url, 8).await.unwrap();
    store.migrate().await.unwrap();
    sqlx::query("INSERT INTO relay_hosts(id,name,certificate_sha256,peer_endpoints,backbone_endpoints,is_default)
        VALUES($1,'test-host',$2,ARRAY['tcp://127.0.0.1:7777'],ARRAY['tcp://127.0.0.1:7778'],true)
        ON CONFLICT DO NOTHING")
        .bind(Uuid::new_v4()).bind(vec![19_u8;32]).execute(store.pool()).await.unwrap();
    let app = router(
        store.clone(),
        AuthConfig {
            oidc: None,
            development_bearer_token: Some("test-admin".into()),
            bootstrap_token: None,
        },
    );
    for role in [Role::Admin, Role::Operator] {
        let token = Uuid::new_v4().to_string();
        store
            .create_session(&NewSession {
                token: token.clone(),
                csrf_token: "test-csrf".into(),
                subject: "provisioning-session-test".into(),
                role,
                expires_at: time::OffsetDateTime::now_utc() + time::Duration::hours(1),
            })
            .await
            .unwrap();
        for csrf in [None, Some("test-csrf")] {
            if role == Role::Admin && csrf.is_some() {
                continue;
            }
            let mut builder = Request::post("/api/v1/mesh-provisioning")
                .header("cookie", format!("peerward_session={token}"))
                .header("content-type", "application/json");
            if let Some(csrf) = csrf {
                builder = builder.header("x-csrf-token", csrf);
            }
            let response = app
                .clone()
                .oneshot(
                    builder
                        .body(Body::from(
                            json!({
                                "request_id":Uuid::new_v4(),"name":"unauthorized"
                            })
                            .to_string(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
        }
    }
    let id = Uuid::new_v4();
    let path = format!("/api/v1/mesh-provisioning/{id}");
    let input = json!({"request_id":id,"name":"Managed test"});
    let (status, initial) = request(&app, "POST", "/api/v1/mesh-provisioning", input.clone()).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{initial}");
    assert_eq!(initial["status"], "queued");
    assert_eq!(initial["stage"], "queued");
    assert!(initial["error_code"].is_null());
    assert!(initial.get("actor").is_none());
    let (left, right) = tokio::join!(
        request(&app, "POST", "/api/v1/mesh-provisioning", input.clone()),
        request(&app, "POST", "/api/v1/mesh-provisioning", input.clone())
    );
    assert_eq!(left, (StatusCode::OK, initial.clone()));
    assert_eq!(right, (StatusCode::OK, initial.clone()));
    assert_eq!(
        request(&app, "GET", &path, json!({})).await,
        (StatusCode::OK, initial.clone())
    );
    let concurrent = json!({"request_id":Uuid::new_v4(),"name":"Concurrent first submission"});
    let (first, second) = tokio::join!(
        request(
            &app,
            "POST",
            "/api/v1/mesh-provisioning",
            concurrent.clone()
        ),
        request(&app, "POST", "/api/v1/mesh-provisioning", concurrent)
    );
    assert!(matches!(
        (first.0, second.0),
        (StatusCode::ACCEPTED, StatusCode::OK) | (StatusCode::OK, StatusCode::ACCEPTED)
    ));
    assert_eq!(first.1, second.1);
    let mismatch = json!({"request_id":id,"name":"Other"});
    assert_eq!(
        request(&app, "POST", "/api/v1/mesh-provisioning", mismatch)
            .await
            .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        request(&app, "POST", &format!("{path}/retry"), json!({}))
            .await
            .0,
        StatusCode::CONFLICT
    );
    sqlx::query("UPDATE mesh_lifecycle_jobs SET status='failed',stage='health',error_code='relay_unhealthy',attempt=1 WHERE id=$1")
        .bind(id).execute(store.pool()).await.unwrap();
    let (status, retry) = request(&app, "POST", &format!("{path}/retry"), json!({})).await;
    assert_eq!(status, StatusCode::OK, "{retry}");
    assert_eq!(retry["mesh_id"], initial["mesh_id"]);
    assert_eq!(retry["stage"], "health");
    assert_eq!(retry["status"], "queued");
    assert!(retry["error_code"].is_null());
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_log WHERE target_id=$1 AND action='mesh.lifecycle.retry'",
    )
    .bind(id)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(count, 1);
    let (_, page) = request(&app, "GET", "/api/v1/mesh-provisioning?limit=1", json!({})).await;
    assert_eq!(page["items"].as_array().unwrap().len(), 1);
    let cursor = page["next_cursor"].as_str().unwrap();
    let (status, next) = request(
        &app,
        "GET",
        &format!("/api/v1/mesh-provisioning?limit=1&cursor={cursor}"),
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_ne!(next["items"][0]["id"], page["items"][0]["id"]);
    let mesh = store
        .create_mesh(
            &NewMesh {
                name: format!("Empty {id}"),
                address_cidr: "10.222.0.0/24".parse().unwrap(),
                gateway: "10.222.0.1".parse().unwrap(),
                dns_suffix: "test.mesh".into(),
                mtu: 1380,
                reserved: vec![],
                default_policy: DefaultPolicy::Deny,
                quarantine_seconds: 60,
                rotation_overlap_seconds: 3600,
            },
            "test",
        )
        .await
        .unwrap();
    let completion =
        json!({"request_id":Uuid::new_v4(),"name":mesh.name,"existing_mesh_id":mesh.id});
    let (status, job) = request(&app, "POST", "/api/v1/mesh-provisioning", completion).await;
    assert_eq!(status, StatusCode::CONFLICT, "{job}");
    assert_eq!(job["error"]["code"], "mesh_not_managed");

    // Optional human identifiers remain separate from UUID and survive retries.
    let slug = format!("office-{}", Uuid::new_v4().simple());
    let named = json!({"request_id":Uuid::new_v4(),"name":"Office","network_identifier":slug});
    let (left, right) = tokio::join!(
        request(&app, "POST", "/api/v1/mesh-provisioning", named.clone()),
        request(&app, "POST", "/api/v1/mesh-provisioning", named.clone())
    );
    assert!(matches!(
        (left.0, right.0),
        (StatusCode::ACCEPTED, StatusCode::OK) | (StatusCode::OK, StatusCode::ACCEPTED)
    ));
    assert_eq!(left.1, right.1);
    let (_, saved) = request(
        &app,
        "GET",
        &format!("/api/v1/meshes/{}", left.1["mesh_id"].as_str().unwrap()),
        json!({}),
    )
    .await;
    assert_eq!(saved["network_identifier"], slug);
    let mut changed = named.clone();
    changed["network_identifier"] = json!("different-slug");
    assert_eq!(
        request(&app, "POST", "/api/v1/mesh-provisioning", changed)
            .await
            .0,
        StatusCode::CONFLICT
    );
    let mut duplicate = named.clone();
    duplicate["request_id"] = json!(Uuid::new_v4());
    let result = request(&app, "POST", "/api/v1/mesh-provisioning", duplicate).await;
    assert_eq!(result.0, StatusCode::CONFLICT);
    assert_eq!(result.1["error"]["code"], "network_identifier_exists");
    for invalid in [
        "",
        "UPPER",
        "-start",
        "end-",
        "with space",
        "中文",
        &"x".repeat(64),
    ] {
        let result = request(
            &app,
            "POST",
            "/api/v1/mesh-provisioning",
            json!({"request_id":Uuid::new_v4(),"name":"Invalid","network_identifier":invalid}),
        )
        .await;
        assert_eq!(result.0, StatusCode::BAD_REQUEST, "{invalid}: {}", result.1);
    }
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM meshes WHERE network_identifier=$1")
        .bind(&slug)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(count, 1);

    // Lease fencing: an expired worker cannot acknowledge a newer claim.
    sqlx::query("UPDATE mesh_lifecycle_jobs SET status='succeeded' WHERE id<>$1")
        .bind(id)
        .execute(store.pool())
        .await
        .unwrap();
    let owner = Uuid::new_v4();
    let claimed = store
        .claim_mesh_jobs(owner, 1)
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(claimed.id, id);
    assert!(
        store
            .claim_mesh_jobs(Uuid::new_v4(), 1)
            .await
            .unwrap()
            .is_empty()
    );
    sqlx::query("UPDATE mesh_lifecycle_jobs SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1")
        .bind(id).execute(store.pool()).await.unwrap();
    let next_owner = Uuid::new_v4();
    let next = store
        .claim_mesh_jobs(next_owner, 1)
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert!(next.generation > claimed.generation);
    assert!(
        store
            .finish_mesh_job_step(&claimed, owner, "ready", "succeeded", None)
            .await
            .is_err()
    );
    store
        .finish_mesh_job_step(&next, next_owner, "waiting_for_relay", "waiting", None)
        .await
        .unwrap();
    assert_eq!(store.mesh_job(id).await.unwrap().consecutive_failures, 0);
}
