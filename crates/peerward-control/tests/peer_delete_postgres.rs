use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
    response::Response,
};
use http_body_util::BodyExt as _;
use peerward_control::{AuthConfig, router};
use peerward_store::{DefaultPolicy, NewMesh, PresenceLease, PresenceRole, Store};
use peerward_types::{AttachmentId, PeerId, RelayId};
use serde_json::{Value, json};
use time::{Duration, OffsetDateTime};
use tower::ServiceExt as _;
use uuid::Uuid;

include!("peer_device_details/mod.rs");

async fn request(
    app: &Router,
    method: &str,
    path: &str,
    version: Option<i64>,
    body: Value,
) -> Response {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", "Bearer delete-test")
        .header("content-type", "application/json");
    if let Some(version) = version {
        request = request.header("if-match", format!("\"{version}\""));
    }
    app.clone()
        .oneshot(request.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap()
}

async fn json_body(response: Response) -> Value {
    serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
}

#[tokio::test]
async fn deletion_requires_disabled_peer_and_hides_it_without_erasing_history() {
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
                name: format!("delete-{}", Uuid::new_v4()),
                address_cidr: "10.95.0.0/24".parse().unwrap(),
                gateway: "10.95.0.1".parse().unwrap(),
                dns_suffix: "delete.test".into(),
                mtu: 1380,
                reserved: Vec::new(),
                default_policy: DefaultPolicy::Deny,
                quarantine_seconds: 60,
                rotation_overlap_seconds: 3600,
            },
            "admin",
        )
        .await
        .unwrap();
    let app = router(
        store.clone(),
        AuthConfig {
            development_bearer_token: Some("delete-test".into()),
            oidc: None,
            bootstrap_token: None,
        },
    );
    let collection = format!("/api/v1/meshes/{}/peers", mesh.id);
    let created = request(
        &app,
        "POST",
        &collection,
        None,
        json!({"name":"retired-peer"}),
    )
    .await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let peer = json_body(created).await;
    let peer_id = Uuid::parse_str(peer["id"].as_str().unwrap()).unwrap();
    let member = format!("{collection}/{peer_id}");
    let deletion = format!("{member}/delete");
    let confirmation = json!({"name":"retired-peer"});
    let relay = request(&app, "POST", &format!("/api/v1/meshes/{}/relays", mesh.id), None,
        json!({"name":"delete-relay","peer_endpoints":["tcp://127.0.0.1:7777"],"backbone_endpoints":["tcp://127.0.0.1:7778"]})).await;
    assert_eq!(relay.status(), StatusCode::CREATED);
    let relay = json_body(relay).await;
    let lease = PresenceLease {
        mesh_id: mesh.id,
        peer_id: PeerId::from_uuid(peer_id).unwrap(),
        relay_id: RelayId::from_uuid(Uuid::parse_str(relay["id"].as_str().unwrap()).unwrap())
            .unwrap(),
        attachment_id: AttachmentId::new(),
        role: PresenceRole::Primary,
        lease_deadline: OffsetDateTime::now_utc() + Duration::minutes(1),
    };
    store.acquire_presence(&lease).await.unwrap();
    store
        .acquire_presence(&PresenceLease {
            role: PresenceRole::Standby,
            ..lease.clone()
        })
        .await
        .unwrap();

    let anonymous = app
        .clone()
        .oneshot(
            Request::post(&deletion)
                .header("content-type", "application/json")
                .header("if-match", "\"1\"")
                .body(Body::from(confirmation.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);

    let response = request(&app, "POST", &deletion, Some(1), confirmation.clone()).await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(
        json_body(response).await["error"]["code"],
        "peer_must_be_disabled"
    );
    // Editing administrative state can leave credentials, services and addresses behind.
    let disabled = request(
        &app,
        "PATCH",
        &member,
        Some(1),
        json!({"administrative_state":"disabled"}),
    )
    .await;
    assert_eq!(disabled.status(), StatusCode::OK);
    let version = json_body(disabled).await["version"].as_i64().unwrap();
    for (expected, name, status, code) in [
        (
            None,
            "retired-peer",
            StatusCode::PRECONDITION_REQUIRED,
            "precondition_required",
        ),
        (
            Some(1),
            "retired-peer",
            StatusCode::CONFLICT,
            "revision_conflict",
        ),
        (
            Some(version),
            "wrong-name",
            StatusCode::BAD_REQUEST,
            "confirmation_mismatch",
        ),
    ] {
        let response = request(&app, "POST", &deletion, expected, json!({"name":name})).await;
        assert_eq!(response.status(), status);
        assert_eq!(json_body(response).await["error"]["code"], code);
    }

    let authority = Uuid::new_v4();
    sqlx::query("INSERT INTO mesh_authorities(id,mesh_id,serial,public_key,not_before,not_after,lifecycle,certificate) VALUES($1,$2,$3,$4,clock_timestamp(),clock_timestamp()+interval '1 day','active',$5)")
        .bind(authority).bind(mesh.id.into_uuid()).bind(Uuid::new_v4())
        .bind(vec![1_u8;32]).bind(vec![1_u8;64]).execute(store.pool()).await.unwrap();
    let serial = Uuid::new_v4();
    sqlx::query("INSERT INTO peer_credentials(id,mesh_id,peer_id,authority_id,serial,public_key,identity_public_key,not_before,not_after,lifecycle,signature) VALUES($1,$2,$3,$4,$5,$6,$6,clock_timestamp(),clock_timestamp()+interval '1 hour','active',$7)")
        .bind(Uuid::new_v4()).bind(mesh.id.into_uuid()).bind(peer_id).bind(authority).bind(serial)
        .bind(vec![2_u8;32]).bind(vec![3_u8;64]).execute(store.pool()).await.unwrap();
    let service = Uuid::new_v4();
    sqlx::query("INSERT INTO services(id,mesh_id,peer_id,protocols,listen_port) VALUES($1,$2,$3,ARRAY['tcp'],8080)")
        .bind(service).bind(mesh.id.into_uuid()).bind(peer_id).execute(store.pool()).await.unwrap();
    sqlx::query("INSERT INTO peer_addresses(id,mesh_id,peer_id,address,state) VALUES(gen_random_uuid(),$1,$2,'10.95.0.2','active')")
        .bind(mesh.id.into_uuid()).bind(peer_id).execute(store.pool()).await.unwrap();
    let revisions = store.mesh(mesh.id).await.unwrap();
    sqlx::query("INSERT INTO current_peer_runtime_health(mesh_id,peer_id,sequence,observed_at,expires_at,direct_path_count,relay_packets,direct_packets,degraded_reasons,signed_revision) VALUES($1,$2,1,clock_timestamp(),clock_timestamp()+interval '90 seconds',0,0,0,ARRAY[]::text[],1)")
        .bind(mesh.id.into_uuid()).bind(peer_id).execute(store.pool()).await.unwrap();
    let rotation = Uuid::new_v4();
    sqlx::query("INSERT INTO peer_credential_rotation_requests(id,mesh_id,peer_id,authenticated_serial,requested_identity_public_key,requested_session_public_key,request_signature,activation_challenge) VALUES($1,$2,$3,$4,$5,$5,$6,$5)")
        .bind(rotation).bind(mesh.id.into_uuid()).bind(peer_id).bind(serial)
        .bind(vec![4_u8;32]).bind(vec![5_u8;64]).execute(store.pool()).await.unwrap();
    let response = request(&app, "POST", &deletion, Some(version), confirmation.clone()).await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let deleted_version = response.headers()["etag"]
        .to_str()
        .unwrap()
        .trim_matches('"')
        .parse::<i64>()
        .unwrap();
    assert!(deleted_version > version);

    let state: String = sqlx::query_scalar("SELECT administrative_state FROM peers WHERE id=$1")
        .bind(peer_id)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(state, "deleted");
    let lifecycle: String =
        sqlx::query_scalar("SELECT lifecycle FROM peer_credentials WHERE serial=$1")
            .bind(serial)
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert_eq!(lifecycle, "revoked");
    let service_state: String = sqlx::query_scalar("SELECT state FROM services WHERE id=$1")
        .bind(service)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(service_state, "disabled");
    let quarantined: bool = sqlx::query_scalar("SELECT state='quarantine' AND released_at IS NOT NULL AND quarantine_until>clock_timestamp() FROM peer_addresses WHERE peer_id=$1")
        .bind(peer_id).fetch_one(store.pool()).await.unwrap();
    assert!(quarantined);
    let health_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM current_peer_runtime_health WHERE peer_id=$1")
            .bind(peer_id)
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert_eq!(health_count, 0);
    let rotation_cancelled: bool = sqlx::query_scalar("SELECT status='cancelled' AND cancelled_at IS NOT NULL FROM peer_credential_rotation_requests WHERE id=$1")
        .bind(rotation).fetch_one(store.pool()).await.unwrap();
    assert!(rotation_cancelled);
    let updated = store.mesh(mesh.id).await.unwrap();
    assert!(updated.directory_revision > revisions.directory_revision);
    assert!(updated.service_revision > revisions.service_revision);
    assert!(updated.revocation_revision > revisions.revocation_revision);
    let audit: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE target_id=$1 AND action IN ('peer.create','peer.update','peer.delete')")
        .bind(peer_id).fetch_one(store.pool()).await.unwrap();
    assert_eq!(audit, 3);
    for role in [PresenceRole::Primary, PresenceRole::Standby] {
        assert!(
            store
                .acquire_presence(&PresenceLease {
                    role,
                    ..lease.clone()
                })
                .await
                .is_err(),
            "a late Relay attachment must not recreate deleted Peer presence"
        );
    }
    let presence_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM relay_presence_all WHERE peer_id=$1")
            .bind(peer_id)
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert_eq!(presence_count, 0);
    let service_response = request(
        &app,
        "POST",
        &format!("/api/v1/meshes/{}/services", mesh.id),
        None,
        json!({"peer_id":peer_id,"protocols":["tcp"],"listen_port":8081}),
    )
    .await;
    assert_eq!(service_response.status(), StatusCode::NOT_FOUND);
    let bulk = json!({"family":"peer","items":[{"id":peer_id,"version":deleted_version}]});
    let preview = request(
        &app,
        "POST",
        &format!("/api/v1/meshes/{}/bulk/preview", mesh.id),
        None,
        bulk.clone(),
    )
    .await;
    assert_eq!(preview.status(), StatusCode::OK);
    assert_eq!(
        json_body(preview).await["items"][0]["error_code"],
        "not_found"
    );
    let commit = request(
        &app,
        "POST",
        &format!("/api/v1/meshes/{}/bulk/commit", mesh.id),
        None,
        bulk,
    )
    .await;
    assert_eq!(commit.status(), StatusCode::NOT_FOUND);

    for (method, path, body) in [
        ("GET", member.clone(), json!({})),
        (
            "PATCH",
            member.clone(),
            json!({"administrative_state":"enabled"}),
        ),
        ("DELETE", member.clone(), json!({})),
        ("POST", deletion.clone(), confirmation),
        ("GET", format!("{member}/credentials"), json!({})),
        ("POST", format!("{member}/credentials/{serial}"), json!({})),
    ] {
        let response = request(&app, method, &path, Some(deleted_version), body).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{method} {path}");
    }
    let listed = json_body(request(&app, "GET", &collection, None, json!({})).await).await;
    assert_eq!(listed["items"], json!([]));
    assert!(listed["next_cursor"].is_null());
    let topology = format!("/api/v1/meshes/{}/topology", mesh.id);
    let summary =
        json_body(request(&app, "GET", &format!("{topology}/summary"), None, json!({})).await)
            .await;
    assert_eq!(summary["peer_count"], 0);
    let nodes = json_body(
        request(
            &app,
            "GET",
            &format!("{topology}/nodes?kind=peer"),
            None,
            json!({}),
        )
        .await,
    )
    .await;
    assert_eq!(nodes["items"], json!([]));
    let graph_response = request(&app, "GET", &topology, None, json!({})).await;
    assert_eq!(graph_response.status(), StatusCode::OK);
    assert_eq!(json_body(graph_response).await["peers"], json!([]));

    // Name reuse creates a new identity; the retained record cannot be resurrected.
    let replacement = request(
        &app,
        "POST",
        &collection,
        None,
        json!({"name":"retired-peer"}),
    )
    .await;
    assert_eq!(replacement.status(), StatusCode::CREATED);
    assert_ne!(json_body(replacement).await["id"], peer["id"]);
}
