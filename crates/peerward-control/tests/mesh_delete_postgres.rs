use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt as _;
use peerward_control::{AuthConfig, router};
use peerward_store::{DefaultPolicy, MeshRecord, NewMesh, NewSession, Role, Store};
use serde_json::{Value, json};
use time::{Duration, OffsetDateTime};
use tower::ServiceExt as _;
use uuid::Uuid;

fn auth() -> AuthConfig {
    AuthConfig {
        development_bearer_token: Some("mesh-delete-test".into()),
        oidc: None,
        bootstrap_token: None,
    }
}

async fn setup() -> (Store, Router, MeshRecord) {
    let url = std::env::var("PEERWARD_TEST_DATABASE_URL").unwrap();
    assert!(
        url.parse::<sqlx::postgres::PgConnectOptions>()
            .is_ok_and(|options| options.get_database() == Some("peerward_test")),
        "requires an ephemeral test database"
    );
    let store = Store::connect(&url, 8).await.unwrap();
    store.migrate().await.unwrap();
    let mesh = store
        .create_mesh(
            &NewMesh {
                name: format!("Delete Mesh {}", Uuid::new_v4()),
                address_cidr: "10.96.0.0/24".parse().unwrap(),
                gateway: "10.96.0.1".parse().unwrap(),
                dns_suffix: "delete.test".into(),
                mtu: 1380,
                reserved: Vec::new(),
                default_policy: DefaultPolicy::Deny,
                quarantine_seconds: 60,
                rotation_overlap_seconds: 3600,
            },
            "test-admin",
        )
        .await
        .unwrap();
    let app = router(store.clone(), auth());
    (store, app, mesh)
}

async fn request(
    app: &Router,
    method: &str,
    path: &str,
    version: Option<u64>,
    body: Value,
) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", "Bearer mesh-delete-test")
        .header("content-type", "application/json");
    if let Some(version) = version {
        request = request.header("if-match", format!("\"{version}\""));
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn delete(app: &Router, mesh: &MeshRecord) -> (StatusCode, Value) {
    request(
        app,
        "DELETE",
        &format!("/api/v1/meshes/{}", mesh.id),
        Some(mesh.version),
        json!({"confirmation_name":mesh.name}),
    )
    .await
}

#[tokio::test]
async fn empty_mesh_deletion_requires_exact_confirmation_and_version_and_preserves_history() {
    let (store, app, mut mesh) = setup().await;
    let path = format!("/api/v1/meshes/{}", mesh.id);
    let (_, patched) = request(
        &app,
        "PATCH",
        &path,
        Some(mesh.version),
        json!({"name":mesh.name}),
    )
    .await;
    mesh.version = patched["version"].as_u64().unwrap();
    for (version, name, status, code) in [
        (
            None,
            mesh.name.clone(),
            StatusCode::PRECONDITION_REQUIRED,
            "precondition_required",
        ),
        (
            Some(1),
            mesh.name.clone(),
            StatusCode::CONFLICT,
            "revision_conflict",
        ),
        (
            Some(mesh.version),
            mesh.name.to_lowercase(),
            StatusCode::BAD_REQUEST,
            "confirmation_mismatch",
        ),
        (
            Some(mesh.version),
            format!("{} ", mesh.name),
            StatusCode::BAD_REQUEST,
            "confirmation_mismatch",
        ),
    ] {
        let response = request(
            &app,
            "DELETE",
            &path,
            version,
            json!({"confirmation_name":name}),
        )
        .await;
        assert_eq!(response.0, status, "{response:?}");
        assert_eq!(response.1["error"]["code"], code);
    }
    let old_audit: Vec<Value> = sqlx::query_scalar(
        "SELECT to_jsonb(a) FROM audit_log a WHERE retained_mesh_id=$1 ORDER BY occurred_at,id",
    )
    .bind(mesh.id.into_uuid())
    .fetch_all(store.pool())
    .await
    .unwrap();
    let old_events: Vec<Value> = sqlx::query_scalar(
        "SELECT to_jsonb(e) FROM event_outbox e WHERE mesh_id=$1 ORDER BY sequence",
    )
    .bind(mesh.id.into_uuid())
    .fetch_all(store.pool())
    .await
    .unwrap();
    let response = delete(&app, &mesh).await;
    assert_eq!(response.0, StatusCode::ACCEPTED, "{response:?}");
    assert_eq!(delete(&app, &mesh).await, response);
    let (_, current) = request(&app, "GET", &path, None, json!({})).await;
    assert_eq!(current["lifecycle"], "deleting");
    assert_eq!(current["lifecycle_job"], response.1["job_id"]);
    let audit: Vec<Value> = sqlx::query_scalar(
        "SELECT to_jsonb(a) FROM audit_log a WHERE retained_mesh_id=$1 ORDER BY occurred_at,id",
    )
    .bind(mesh.id.into_uuid())
    .fetch_all(store.pool())
    .await
    .unwrap();
    assert_eq!(&audit[..old_audit.len()], &old_audit);
    assert_eq!(audit.len(), old_audit.len() + 1);
    assert_eq!(audit.last().unwrap()["action"], "mesh.delete.request");
    let events: Vec<Value> = sqlx::query_scalar(
        "SELECT to_jsonb(e) FROM event_outbox e WHERE mesh_id=$1 ORDER BY sequence",
    )
    .bind(mesh.id.into_uuid())
    .fetch_all(store.pool())
    .await
    .unwrap();
    assert_eq!(&events[..old_events.len()], &old_events);
    assert_eq!(events.last().unwrap()["event_type"], "mesh.deleting");
    assert!(
        sqlx::query("UPDATE audit_log SET metadata='{}' WHERE retained_mesh_id=$1")
            .bind(mesh.id.into_uuid())
            .execute(store.pool())
            .await
            .is_err()
    );
    // State changes are fenced at the database as well as the HTTP boundary.
    assert!(sqlx::query("UPDATE meshes SET lifecycle='active',lifecycle_revision=lifecycle_revision+1 WHERE id=$1")
        .bind(mesh.id.into_uuid()).execute(store.pool()).await.is_err());
    assert!(
        store
            .create_join_ticket(
                mesh.id,
                &[7; 32],
                OffsetDateTime::now_utc() + Duration::hours(1),
                "test"
            )
            .await
            .is_err()
    );
    assert_eq!(
        request(
            &app,
            "PATCH",
            &path,
            Some(current["version"].as_u64().unwrap()),
            json!({"name":"revived"})
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
}

#[tokio::test]
async fn only_admin_with_csrf_can_delete_and_anonymous_is_rejected() {
    let (store, app, mesh) = setup().await;
    let path = format!("/api/v1/meshes/{}", mesh.id);
    let body = json!({"confirmation_name":mesh.name}).to_string();
    let anonymous = app
        .clone()
        .oneshot(
            Request::delete(&path)
                .header("content-type", "application/json")
                .header("if-match", "\"1\"")
                .body(Body::from(body.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);
    for (role, csrf, expected) in [
        (Role::Viewer, true, StatusCode::FORBIDDEN),
        (Role::Auditor, true, StatusCode::FORBIDDEN),
        (Role::Operator, true, StatusCode::FORBIDDEN),
        (Role::Admin, false, StatusCode::FORBIDDEN),
        (Role::Admin, true, StatusCode::ACCEPTED),
    ] {
        let token = Uuid::new_v4().to_string();
        store
            .create_session(&NewSession {
                token: token.clone(),
                csrf_token: "test-csrf".into(),
                subject: "delete-role-test".into(),
                role,
                expires_at: OffsetDateTime::now_utc() + Duration::hours(1),
            })
            .await
            .unwrap();
        let mut builder = Request::delete(&path)
            .header("cookie", format!("peerward_session={token}"))
            .header("content-type", "application/json")
            .header("if-match", "\"1\"");
        if csrf {
            builder = builder.header("x-csrf-token", "test-csrf");
        }
        let response = app
            .clone()
            .oneshot(builder.body(Body::from(body.clone())).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), expected, "{role:?}, csrf={csrf}");
    }
}

#[tokio::test]
async fn concurrent_deletions_return_the_same_task() {
    let (_store, app, mesh) = setup().await;
    let (left, right) = tokio::join!(delete(&app, &mesh), delete(&app, &mesh));
    assert_eq!(left.0, StatusCode::ACCEPTED, "{left:?}");
    assert_eq!(left, right);
}

#[tokio::test]
async fn deletion_serializes_with_inflight_insert_and_fences_new_writes() {
    let (store, app, mesh) = setup().await;
    let mut transaction = store.begin_mutation().await.unwrap();
    sqlx::query("INSERT INTO peers(id,mesh_id,name) VALUES(gen_random_uuid(),$1,'inflight-peer')")
        .bind(mesh.id.into_uuid())
        .execute(&mut *transaction)
        .await
        .unwrap();
    let mut deletion = Box::pin(delete(&app, &mesh));
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), &mut deletion)
            .await
            .is_err()
    );
    transaction.commit().await.unwrap();
    let response = deletion.await;
    // Peer membership publication advances the Mesh version. Waiting for the
    // writer must not let a deletion with a stale confirmation bypass its ETag.
    assert_eq!(response.0, StatusCode::CONFLICT, "{response:?}");
    assert_eq!(response.1["error"]["code"], "revision_conflict");
    let current = store.mesh(mesh.id).await.unwrap();
    assert!(current.version > mesh.version);
    let response = delete(&app, &current).await;
    assert_eq!(response.0, StatusCode::ACCEPTED, "{response:?}");
    assert!(
        sqlx::query("INSERT INTO peers(id,mesh_id,name) VALUES(gen_random_uuid(),$1,'late-peer')")
            .bind(mesh.id.into_uuid())
            .execute(store.pool())
            .await
            .is_err()
    );
    let peers: i64 = sqlx::query_scalar("SELECT count(*) FROM peers WHERE mesh_id=$1")
        .bind(mesh.id.into_uuid())
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(peers, 1);
}

#[tokio::test]
async fn deletion_can_cancel_a_mesh_which_has_not_finished_creating() {
    let (store, app, mut mesh) = setup().await;
    sqlx::query("UPDATE meshes SET lifecycle='creating',lifecycle_revision=lifecycle_revision+1 WHERE id=$1")
        .bind(mesh.id.into_uuid())
        .execute(store.pool())
        .await
        .unwrap();
    mesh = store.mesh(mesh.id).await.unwrap();
    let (status, job) = delete(&app, &mesh).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{job}");
    let state: String = sqlx::query_scalar("SELECT lifecycle FROM meshes WHERE id=$1")
        .bind(mesh.id.into_uuid())
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(state, "deleting");
    assert_eq!(delete(&app, &mesh).await.1["job_id"], job["job_id"]);
}
