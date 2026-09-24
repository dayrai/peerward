use axum::{
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use http_body_util::BodyExt;
use peerward_control::{AuthConfig, management_router, router};
use peerward_store::Store;
use serde_json::Value;
use tower::ServiceExt;
use uuid::Uuid;

fn application() -> axum::Router {
    let store = Store::connect_lazy("postgres://127.0.0.1:1/unavailable", 1).unwrap();
    router(
        store,
        AuthConfig {
            oidc: None,
            development_bearer_token: Some("development-test-token".into()),
            bootstrap_token: Some("bootstrap-test-token".into()),
        },
    )
}

fn management() -> axum::Router {
    let store = Store::connect_lazy("postgres://127.0.0.1:1/unavailable", 1).unwrap();
    management_router(
        store,
        AuthConfig {
            oidc: None,
            development_bearer_token: None,
            bootstrap_token: None,
        },
    )
}

#[tokio::test]
async fn live_and_error_envelope_are_stable() {
    let response = management()
        .oneshot(Request::get("/livez").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = application()
        .oneshot(Request::get("/api/v1/live").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let request_id = response.headers()["x-request-id"]
        .to_str()
        .unwrap()
        .to_owned();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let envelope: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(envelope["error"]["code"], "not_found");
    assert_eq!(envelope["error"]["request_id"], request_id);

    let response = application()
        .oneshot(
            Request::post("/api/v1/status")
                .header(header::AUTHORIZATION, "Bearer development-test-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let envelope: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(envelope["error"]["code"], "method_not_allowed");

    let request_id = "12345678-1234-4abc-8def-1234567890ab";
    let response = application()
        .oneshot(
            Request::get("/api/v1/meshes")
                .header("x-request-id", request_id)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(response.headers()["x-request-id"], request_id);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let envelope: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(envelope["error"]["code"], "missing_credentials");
    assert_eq!(envelope["error"]["request_id"], request_id);
    assert!(Uuid::parse_str(envelope["error"]["request_id"].as_str().unwrap()).is_ok());
}

#[tokio::test]
async fn valid_traceparent_keeps_the_trace_and_creates_a_server_child() {
    let request_id = Uuid::new_v4();
    let parent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
    let response = application()
        .oneshot(
            Request::get("/api/v1/meshes")
                .header("x-request-id", request_id.to_string())
                .header("traceparent", parent)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let child = response.headers()["traceparent"].to_str().unwrap();
    assert_eq!(&child[..36], &parent[..36]);
    assert_ne!(&child[36..52], &parent[36..52]);
    assert_eq!(response.headers()["x-request-id"], request_id.to_string());
}

#[tokio::test]
async fn every_protected_contract_route_is_registered() {
    let mesh = Uuid::new_v4();
    let resource = Uuid::new_v4();
    let routes = [
        (Method::GET, "/api/v1/status".to_string()),
        (Method::GET, "/api/v1/meshes".to_string()),
        (Method::POST, "/api/v1/meshes".to_string()),
        (Method::GET, format!("/api/v1/meshes/{mesh}")),
        (Method::PATCH, format!("/api/v1/meshes/{mesh}")),
        (Method::GET, format!("/api/v1/meshes/{mesh}/authorities")),
        (Method::POST, format!("/api/v1/meshes/{mesh}/authorities")),
        (
            Method::POST,
            format!("/api/v1/meshes/{mesh}/authorities/{resource}/activate"),
        ),
        (
            Method::DELETE,
            format!("/api/v1/meshes/{mesh}/authorities/{resource}"),
        ),
        (Method::GET, format!("/api/v1/meshes/{mesh}/peers")),
        (Method::POST, format!("/api/v1/meshes/{mesh}/peers")),
        (
            Method::GET,
            format!("/api/v1/meshes/{mesh}/peers/{resource}"),
        ),
        (
            Method::PATCH,
            format!("/api/v1/meshes/{mesh}/peers/{resource}"),
        ),
        (
            Method::DELETE,
            format!("/api/v1/meshes/{mesh}/peers/{resource}"),
        ),
        (
            Method::GET,
            format!("/api/v1/meshes/{mesh}/peers/{resource}/credentials"),
        ),
        (
            Method::POST,
            format!("/api/v1/meshes/{mesh}/peers/{resource}/credentials/{resource}"),
        ),
        (
            Method::DELETE,
            format!("/api/v1/meshes/{mesh}/peers/{resource}/credentials/{resource}"),
        ),
        (Method::GET, format!("/api/v1/meshes/{mesh}/relays")),
        (Method::POST, format!("/api/v1/meshes/{mesh}/relays")),
        (
            Method::PATCH,
            format!("/api/v1/meshes/{mesh}/relays/{resource}"),
        ),
        (
            Method::DELETE,
            format!("/api/v1/meshes/{mesh}/relays/{resource}"),
        ),
        (
            Method::POST,
            format!("/api/v1/meshes/{mesh}/relays/{resource}/credentials/rotate"),
        ),
        (
            Method::GET,
            format!("/api/v1/meshes/{mesh}/relays/{resource}/credentials"),
        ),
        (
            Method::POST,
            format!("/api/v1/meshes/{mesh}/relays/{resource}/credentials/{resource}"),
        ),
        (
            Method::DELETE,
            format!("/api/v1/meshes/{mesh}/relays/{resource}/credentials/{resource}"),
        ),
        (Method::GET, format!("/api/v1/meshes/{mesh}/join-tickets")),
        (Method::POST, format!("/api/v1/meshes/{mesh}/join-tickets")),
        (
            Method::DELETE,
            format!("/api/v1/meshes/{mesh}/join-tickets/{resource}"),
        ),
        (Method::GET, format!("/api/v1/meshes/{mesh}/policy")),
        (Method::PUT, format!("/api/v1/meshes/{mesh}/policy")),
        (
            Method::POST,
            format!("/api/v1/meshes/{mesh}/policy/validate"),
        ),
        (Method::GET, format!("/api/v1/meshes/{mesh}/services")),
        (Method::POST, format!("/api/v1/meshes/{mesh}/services")),
        (
            Method::DELETE,
            format!("/api/v1/meshes/{mesh}/services/{resource}"),
        ),
        (Method::GET, format!("/api/v1/meshes/{mesh}/audit")),
        (Method::GET, "/api/v1/events".to_string()),
        (Method::GET, "/auth/session".to_string()),
        (Method::POST, "/auth/logout".to_string()),
    ];
    for (method, uri) in routes {
        let response = application()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(&uri)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "route {uri}");
    }
}

#[tokio::test]
async fn oidc_disabled_rejects_login_and_bearer_reaches_handler() {
    let response = application()
        .oneshot(
            Request::get("/api/v1/auth/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let response = application()
        .oneshot(
            Request::get("/api/v1/status")
                .header(header::AUTHORIZATION, "Bearer development-test-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = application()
        .oneshot(
            Request::get("/auth/session")
                .header(header::AUTHORIZATION, "Bearer development-test-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let session: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(session["authenticated"], true);
    assert_eq!(session["role"], "admin");
    assert!(session["csrf_token"].is_null());
}

#[tokio::test]
async fn request_and_cursor_failures_use_stable_codes() {
    let oversized = application()
        .oneshot(
            Request::post("/api/v1/meshes")
                .header(header::AUTHORIZATION, "Bearer development-test-token")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(vec![b' '; 2 * 1024 * 1024 + 1]))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let envelope: Value =
        serde_json::from_slice(&oversized.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(envelope["error"]["code"], "request_too_large");

    let invalid_page = application()
        .oneshot(
            Request::get("/api/v1/meshes?cursor=not-base64")
                .header(header::AUTHORIZATION, "Bearer development-test-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(invalid_page.status(), StatusCode::BAD_REQUEST);
    let envelope: Value =
        serde_json::from_slice(&invalid_page.into_body().collect().await.unwrap().to_bytes())
            .unwrap();
    assert_eq!(envelope["error"]["code"], "invalid_cursor");

    let invalid_event = application()
        .oneshot(
            Request::get("/api/v1/events")
                .header(header::AUTHORIZATION, "Bearer development-test-token")
                .header("last-event-id", "not-a-uuid")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(invalid_event.status(), StatusCode::BAD_REQUEST);
    let envelope: Value = serde_json::from_slice(
        &invalid_event
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes(),
    )
    .unwrap();
    assert_eq!(envelope["error"]["code"], "invalid_event_cursor");
}

#[tokio::test]
async fn mesh_provisioning_requires_authentication_and_rejects_invalid_input() {
    for path in [
        "/api/v1/mesh-provisioning",
        "/api/v1/mesh-provisioning/12345678-1234-4abc-8def-1234567890ab",
    ] {
        let response = application()
            .oneshot(Request::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    for body in [
        serde_json::json!({"request_id": Uuid::nil(), "name": "test"}),
        serde_json::json!({"request_id": Uuid::new_v4(), "name": " "}),
    ] {
        let response = application()
            .oneshot(
                Request::post("/api/v1/mesh-provisioning")
                    .header(header::AUTHORIZATION, "Bearer development-test-token")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
