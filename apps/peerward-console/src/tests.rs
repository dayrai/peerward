use std::{
    fmt::Write as _,
    sync::{Arc, Mutex},
};

use axum::{
    Json, Router,
    body::{Body, Bytes},
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header as axum_header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use reqwest::header;

use super::*;

#[test]
fn dedicated_forms_emit_only_the_selected_typed_contract() {
    let mut document = default_editor_document(ConsoleRoute::Peers);
    let mut value: Value = serde_json::from_str(&document).unwrap();
    value["labels"] = json!("role=edge, region=west");
    value["public_key"] = json!("11".repeat(32));
    value["serial"] = json!(uuid::Uuid::new_v4().to_string());
    document = value.to_string();

    let create = operation_body(
        ConsoleRoute::Peers,
        BrowserOperation::Create,
        "edge-one",
        &document,
    )
    .unwrap();
    assert_eq!(create["name"], "edge-one");
    assert_eq!(create["labels"]["role"], "edge");
    assert!(create.get("public_key").is_none());
    assert!(create.get("serial").is_none());

    assert!(
        operation_body(
            ConsoleRoute::Peers,
            BrowserOperation::Rotate,
            "ignored",
            &document,
        )
        .is_err()
    );
    let rotate = operation_body(
        ConsoleRoute::Relays,
        BrowserOperation::Rotate,
        "ignored",
        &document,
    )
    .unwrap();
    assert_eq!(rotate, json!({"public_key": "11".repeat(32)}));
}

#[test]
fn credential_selector_is_derived_from_the_selected_resource_lifecycle() {
    let pending = uuid::Uuid::new_v4().to_string();
    let active = uuid::Uuid::new_v4().to_string();
    let overlap = uuid::Uuid::new_v4().to_string();
    let resource = ResourceSummary {
        id: uuid::Uuid::new_v4().to_string(),
        name: "edge-one".into(),
        details: BTreeMap::from([(
            "credentials".into(),
            json!({
                "pending": {"serial": pending},
                "active": {"serial": active},
                "overlap": [{"serial": overlap}]
            }),
        )]),
    };
    let document = editor_document_for_resource(ConsoleRoute::Peers, &resource);
    assert_eq!(editor_value(&document, "serial"), pending);
    let choices: Vec<Value> =
        serde_json::from_str(&editor_value(&document, "credential_serials")).unwrap();
    assert_eq!(choices.len(), 3);
    assert!(choices.iter().any(|choice| choice["serial"] == active));
    assert!(choices.iter().any(|choice| choice["serial"] == overlap));
}

#[test]
fn console_fluent_catalogs_have_identical_keys_and_real_translations() {
    assert!(console_catalog_complete());
    assert_eq!(
        console_message(Locale::EnUs, "resource-actions"),
        "Resource actions"
    );
    assert_eq!(
        console_message(Locale::ZhCn, "resource-actions"),
        "资源操作"
    );
    assert_ne!(
        console_message(Locale::EnUs, "policy-help"),
        console_message(Locale::ZhCn, "policy-help")
    );
}

#[test]
fn policy_validation_and_replace_share_the_strict_typed_document() {
    let document = serde_json::json!({
        "revision": "2",
        "default_action": "deny",
        "rules": "[]"
    })
    .to_string();
    let validation = operation_body(
        ConsoleRoute::Policy,
        BrowserOperation::ValidatePolicy,
        "",
        &document,
    )
    .unwrap();
    let replacement = operation_body(
        ConsoleRoute::Policy,
        BrowserOperation::ReplacePolicy,
        "",
        &document,
    )
    .unwrap();
    assert_eq!(validation, replacement);
    assert!(serde_json::from_value::<PolicyPutRequest>(validation).is_ok());
}

#[test]
fn every_workflow_has_a_server_rendered_accessible_route() {
    for route in [
        ConsoleRoute::Overview,
        ConsoleRoute::Meshes,
        ConsoleRoute::Networks,
        ConsoleRoute::Authorities,
        ConsoleRoute::Peers,
        ConsoleRoute::Relays,
        ConsoleRoute::JoinTickets,
        ConsoleRoute::Policy,
        ConsoleRoute::Services,
        ConsoleRoute::Audit,
        ConsoleRoute::Operations,
        ConsoleRoute::Webhooks,
    ] {
        let html = render_route(route, ConsoleSnapshot::sample());
        assert!(html.contains("Peerward"));
        let heading = match route {
            ConsoleRoute::Meshes => "Network settings",
            ConsoleRoute::Networks => "All networks",
            ConsoleRoute::Audit => "Activity log",
            ConsoleRoute::Relays => "System maintenance",
            ConsoleRoute::Authorities => "Credentials and authorities",
            ConsoleRoute::JoinTickets => "Devices",
            ConsoleRoute::Services => "Sharing",
            ConsoleRoute::Policy => "Access",
            ConsoleRoute::Operations => "Issues and maintenance",
            ConsoleRoute::Webhooks => "Webhook notifications",
            _ => route.label(),
        };
        assert!(
            html.contains(&format!("<h1>{heading}</h1>")),
            "{route:?}: expected {heading}"
        );
        assert!(html.contains("aria-label=\"Primary navigation\""));
        assert!(!html.contains("private_key"));
    }
}

#[test]
fn resource_actions_render_inside_the_workspace_and_bulk_stays_with_the_list() {
    let mut snapshot = ConsoleSnapshot::sample();
    snapshot.role = "operator".into();
    snapshot.capabilities.push("resource_write".into());

    let html = render_document(ConsoleRoute::JoinTickets, snapshot);
    let wizard = html.find("添加设备步骤").unwrap();
    let advanced = html.find("邀请记录与高级选项").unwrap();
    let main_end = html.find("</main>").unwrap();
    assert!(wizard < advanced && advanced < main_end);
    assert!(html.contains("data-browser-ready"));
    assert!(!html[main_end..].contains("action-panel"));
}

#[test]
fn hydrated_console_document_has_consistent_default_locale_and_versioned_assets() {
    let html = render_document(ConsoleRoute::Meshes, ConsoleSnapshot::sample());

    assert!(html.contains("<html lang=\"zh-CN\">"));
    assert!(html.contains("<title>Meshes · Peerward Console</title>"));
    assert!(html.contains("Peerward"));
    assert!(html.contains(console_message(Locale::ZhCn, "network-settings")));
    assert!(html.contains(HASHED_STYLESHEET_PATH));
    assert!(html.contains(&format!(
        "/assets/peerward-console-web.js?v={CLIENT_ASSET_VERSION}"
    )));
    assert!(html.contains(&format!(
        "/assets/peerward-console-web_bg.wasm?v={CLIENT_ASSET_VERSION}"
    )));
}

#[tokio::test]
async fn client_navigation_reuses_cached_meshes_and_clears_unscoped_resources() {
    let api = ApiClient::new("http://127.0.0.1:1").unwrap();
    let current = ConsoleSnapshot::sample();

    let meshes = api
        .route_resource_snapshot(ConsoleRoute::Meshes, &current, None, None)
        .await
        .unwrap();
    assert_eq!(meshes.resources, current.meshes);

    let peers = api
        .route_resource_snapshot(ConsoleRoute::Peers, &current, None, None)
        .await
        .unwrap();
    assert!(peers.resources.is_empty());
    assert!(peers.next_cursor.is_none());
}

#[test]
fn join_ticket_resource_selector_exposes_an_explicit_create_mode() {
    let mut snapshot = ConsoleSnapshot::sample();
    snapshot.role = "operator".into();
    snapshot.capabilities.push("resource_write".into());

    let html = render_document(ConsoleRoute::JoinTickets, snapshot);

    let selector = html.find("id=\"live-resource-selection\"").unwrap();
    let selector_end = selector + html[selector..].find("</select>").unwrap();
    assert!(html[selector..selector_end].contains("新建加入凭证"));
    assert!(console_catalog_complete());
    assert_eq!(
        console_message(Locale::ZhCn, "new-join-ticket"),
        "新建加入凭证"
    );
    assert_eq!(
        console_message(Locale::ZhCn, "select-new-join-ticket-to-create"),
        "如需创建新凭证，请在资源中选择“新建加入凭证”。"
    );
}

#[test]
fn selecting_an_existing_resource_disables_create_actions() {
    assert!(!create_action_disabled(false, false));
    assert!(create_action_disabled(false, true));
    assert!(create_action_disabled(true, false));
}

#[test]
fn timestamp_details_use_machine_readable_time_elements() {
    let mut snapshot = ConsoleSnapshot::sample();
    snapshot.resources[0].details.insert(
        "expires_at".into(),
        json!("2026-09-04T09:21:07.669498+00:00"),
    );

    let html = render_route(ConsoleRoute::JoinTickets, snapshot);

    assert!(html.contains(
        "<time datetime=\"2026-09-04T09:21:07.669498+00:00\" title=\"2026-09-04T09:21:07.669498+00:00\">"
    ));
}

#[test]
fn console_documents_and_api_responses_are_never_cached() {
    for path in [
        "/meshes",
        "/join-tickets",
        "/api/v1/events",
        "/api/v1/meshes",
        "/auth/session",
    ] {
        assert!(server::console_response_requires_no_store(path));
    }
    for path in [
        "/assets/main-f0b535bc.css",
        "/manifest.webmanifest",
        "/service-worker.js",
    ] {
        assert!(!server::console_response_requires_no_store(path));
    }

    for path in [
        "/assets/peerward-console-web.js",
        "/assets/peerward-console-web_bg.wasm",
    ] {
        assert!(server::console_response_is_immutable(path));
        assert!(!server::console_response_requires_no_store(path));
    }
}

#[test]
fn ten_thousand_peer_snapshot_keeps_server_rendered_dom_bounded() {
    let resources = (0..10_000)
        .map(|index| ResourceSummary {
            id: format!("00000000-0000-4000-8000-{index:012}"),
            name: format!("peer-{index:05}"),
            details: BTreeMap::from([("online".into(), json!(index % 2 == 0))]),
        })
        .collect();
    let snapshot = ConsoleSnapshot {
        resources,
        ..ConsoleSnapshot::sample()
    };

    let html = render_route(ConsoleRoute::Peers, snapshot);
    let rendered_rows = html.matches("data-peer=").count();
    assert!(rendered_rows <= 50);
    assert!(html.contains("peer-00049"));
    assert!(!html.contains("peer-09999"));
}

#[test]
fn peer_page_cache_is_deduplicated_and_bounded_to_one_thousand_rows() {
    let current = ConsoleSnapshot {
        resources: (0..990)
            .map(|index| ResourceSummary {
                id: format!("peer-{index:04}"),
                name: format!("old-{index:04}"),
                details: BTreeMap::new(),
            })
            .collect(),
        mesh_id: "mesh-a".into(),
        ..ConsoleSnapshot::default()
    };
    let page = ConsoleSnapshot {
        resources: (980..1_050)
            .map(|index| ResourceSummary {
                id: format!("peer-{index:04}"),
                name: format!("new-{index:04}"),
                details: BTreeMap::new(),
            })
            .collect(),
        mesh_id: "mesh-a".into(),
        next_cursor: Some("next".into()),
        ..ConsoleSnapshot::default()
    };
    let merged = append_resource_page(&current, page);
    assert_eq!(merged.resources.len(), 1_000);
    assert_eq!(merged.resources.first().unwrap().id, "peer-0050");
    assert_eq!(
        merged
            .resources
            .iter()
            .find(|resource| resource.id == "peer-0980")
            .unwrap()
            .name,
        "new-0980"
    );
    assert_eq!(merged.next_cursor.as_deref(), Some("next"));
}

#[test]
fn stable_error_and_empty_states_are_visible_to_assistive_technology() {
    let snapshot = ConsoleSnapshot {
        error: Some(ApiErrorBody {
            code: "forbidden".into(),
            message: "Operator role required".into(),
            request_id: "00000000-0000-4000-8000-000000000009".into(),
            field_errors: BTreeMap::new(),
            retryable: false,
        }),
        ..ConsoleSnapshot::default()
    };
    let html = render_route(ConsoleRoute::Services, snapshot);
    assert!(html.contains("role=\"alert\""));
    assert!(html.contains("Operator role required"));
    assert!(html.contains("Select a network first"));
}

#[test]
fn sse_chunks_replay_exact_cursor_and_backoff_is_bounded() {
    let mut parser = SseParser::default();
    assert!(
        parser
            .push(b"id: 41\r\nevent: peer\r\nda")
            .unwrap()
            .is_empty()
    );
    let events = parser.push(b"ta: added\r\ndata: safely\r\n\r\n").unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].id.as_deref(), Some("41"));
    assert_eq!(events[0].data, "added\nsafely");
    let mut replay = EventReplay::default();
    assert!(replay.delivered(&events[0]));
    assert!(!replay.delivered(&events[0]));
    assert_eq!(replay.cursor(), Some("41"));
    for _ in 0..20 {
        assert!(replay.failed() <= 8_000);
    }

    replay.reset();
    for index in 0..=1_024 {
        assert!(replay.delivered(&SseEvent {
            id: Some(index.to_string()),
            event: Some("peer.updated".into()),
            data: "{}".into(),
        }));
    }
    assert!(!replay.delivered(&SseEvent {
        id: Some("1024".into()),
        event: None,
        data: String::new(),
    }));
    assert!(replay.delivered(&SseEvent {
        id: Some("0".into()),
        event: None,
        data: String::new(),
    }));
}

#[test]
fn sse_parser_preserves_split_utf8_and_rejects_oversized_events() {
    let mut parser = SseParser::default();
    let document = "data: 中文\n\n".as_bytes();
    let split = document.iter().position(|byte| *byte >= 0x80).unwrap() + 1;
    assert!(parser.push(&document[..split]).unwrap().is_empty());
    let events = parser.push(&document[split..]).unwrap();
    assert_eq!(events[0].data, "中文");

    let mut parser = SseParser::default();
    assert_eq!(
        parser.push(&vec![b'x'; MAX_SSE_EVENT_BYTES + 1]),
        Err(SseParseError::TooLarge)
    );

    let mut burst = String::new();
    for index in 0..1_000 {
        write!(
            burst,
            "id: {index}\r\nevent: peer.updated\r\ndata: {{}}\r\n\r\n"
        )
        .unwrap();
    }
    let mut parser = SseParser::default();
    let events = parser.push(burst.as_bytes()).unwrap();
    assert_eq!(events.len(), 1_000);
    assert_eq!(
        events.first().and_then(|event| event.id.as_deref()),
        Some("0")
    );
    assert_eq!(
        events.last().and_then(|event| event.id.as_deref()),
        Some("999")
    );
}

#[derive(Clone, Default)]
struct Observed(Arc<Mutex<Vec<(String, String)>>>);

async fn meshes(headers: HeaderMap) -> impl IntoResponse {
    let authorization = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if authorization != "Bearer development-token" {
        return (
            StatusCode::UNAUTHORIZED,
            Json(
                json!({"error":{"code":"unauthorized","message":"sign in","request_id":"00000000-0000-4000-8000-000000000001"}}),
            ),
        );
    }
    (
        StatusCode::OK,
        Json(json!({"items":[{
                "id":"00000000-0000-4000-8000-000000000002",
                "name":"blue",
                "version":1,
                "address_cidr":"10.42.0.0/24",
                "secondary_cidr":"fd42::/64","secondary_gateway":"fd42::1",
                "gateway":"10.42.0.1",
                "dns_suffix":"blue.peerward",
                "mtu":1380,
                "default_policy":"deny",
                "policy_revision":1,
                "authority_revision":1,
                "directory_revision":1,
                "relay_revision":1,
                "service_revision":1,
                "revocation_revision":1
            }],"next_cursor":"next-1"})),
    )
}

async fn create_mesh(
    State(observed): State<Observed>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    observed.0.lock().unwrap().push((
        headers
            .get("x-csrf-token")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned(),
        body["name"].as_str().unwrap_or_default().to_owned(),
    ));
    Json(json!({
        "id":"00000000-0000-4000-8000-000000000003",
        "version":1,
        "name":body["name"],"address_cidr":"10.43.0.0/24","gateway":"10.43.0.1",
        "secondary_cidr":"fd43::/64","secondary_gateway":"fd43::1",
        "dns_suffix":"green.peerward","mtu":1380,"default_policy":"deny",
        "policy_revision":1,"authority_revision":1,"directory_revision":1,
        "relay_revision":1,"service_revision":1,"revocation_revision":1
    }))
}

async fn rotate_relay_credential(
    State(observed): State<Observed>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    observed.0.lock().unwrap().push((
        headers
            .get("x-csrf-token")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned(),
        body["public_key"].as_str().unwrap_or_default().to_owned(),
    ));
    Json(json!({
        "id":"00000000-0000-4000-8000-000000000005",
        "serial":"00000000-0000-4000-8000-000000000006",
        "authority_id":"00000000-0000-4000-8000-000000000007",
        "public_key":body["public_key"],"not_before":"2026-01-01T00:00:00Z",
        "not_after":"2026-01-02T00:00:00Z","lifecycle":"staged",
        "replacement_id":null,"overlap_deadline":null
    }))
}

async fn activate_peer_credential(
    State(observed): State<Observed>,
    Path((_mesh, _peer, serial)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> impl IntoResponse {
    observed.0.lock().unwrap().push((
        headers
            .get("x-csrf-token")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned(),
        format!("activate:{serial}"),
    ));
    StatusCode::NO_CONTENT
}

async fn revoke_peer_credential(
    State(observed): State<Observed>,
    Path((_mesh, _peer, serial)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> impl IntoResponse {
    observed.0.lock().unwrap().push((
        headers
            .get("x-csrf-token")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned(),
        format!("revoke:{serial}"),
    ));
    StatusCode::NO_CONTENT
}

async fn activate_authority(
    State(observed): State<Observed>,
    Path((_mesh, authority)): Path<(String, String)>,
    headers: HeaderMap,
) -> impl IntoResponse {
    observed.0.lock().unwrap().push((
        headers
            .get("x-csrf-token")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned(),
        format!("authority:{authority}"),
    ));
    StatusCode::NO_CONTENT
}

async fn events(headers: HeaderMap) -> impl IntoResponse {
    let cursor = headers
        .get("Last-Event-ID")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    (
        [(header::CONTENT_TYPE, "text/event-stream")],
        format!("id: {cursor}\ndata: replayed\n\n"),
    )
}

async fn oversized_declared_response() -> Response {
    (
        [(axum_header::CONTENT_TYPE, "application/json")],
        vec![b'x'; 2 * 1024 * 1024 + 1],
    )
        .into_response()
}

async fn oversized_streamed_response() -> Response {
    let chunks = futures_util::stream::iter([
        Ok::<_, std::convert::Infallible>(Bytes::from(vec![b'x'; 1024 * 1024])),
        Ok(Bytes::from(vec![b'x'; 1024 * 1024 + 1])),
    ]);
    Response::builder()
        .header(axum_header::CONTENT_TYPE, "application/json")
        .body(Body::from_stream(chunks))
        .unwrap()
}

async fn auth_session(headers: HeaderMap) -> impl IntoResponse {
    let cookie = headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    Json(json!({
        "authenticated": cookie == "peerward_session=session-token; peerward_csrf=csrf-cookie",
        "actor": "playwright-admin",
        "role": "admin",
        "csrf_token": "csrf-cookie",
    }))
}

#[test]
fn proxy_connection_header_tokens_are_case_insensitive_and_trimmed() {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONNECTION,
        "Keep-Alive, Content-Type, x-private-hop".parse().unwrap(),
    );
    headers.append(header::CONNECTION, "X-Second-Hop".parse().unwrap());
    assert_eq!(
        server::connection_header_names(&headers),
        [
            "keep-alive",
            "content-type",
            "x-private-hop",
            "x-second-hop"
        ]
    );
}

#[tokio::test]
async fn typed_client_handles_pagination_auth_csrf_errors_and_sse_replay() {
    let observed = Observed::default();
    let app = Router::new()
        .route("/api/v1/meshes", get(meshes).post(create_mesh))
        .route(
            "/api/v1/meshes/{mesh_id}/relays/{relay_id}/credentials/rotate",
            post(rotate_relay_credential),
        )
        .route(
            "/api/v1/meshes/{mesh_id}/peers/{peer_id}/credentials/{serial}",
            post(activate_peer_credential).delete(revoke_peer_credential),
        )
        .route(
            "/api/v1/meshes/{mesh_id}/authorities/{authority_id}/activate",
            post(activate_authority),
        )
        .route("/auth/session", get(auth_session))
        .route("/api/v1/events", get(events))
        .route(
            "/api/v1/oversized-declared",
            get(oversized_declared_response),
        )
        .route(
            "/api/v1/oversized-streamed",
            get(oversized_streamed_response),
        )
        .route(
            "/api/v1/fail",
            post(|| async {
                (
                    StatusCode::FORBIDDEN,
                    Json(json!({"error":{"code":"forbidden","message":"denied","request_id":"00000000-0000-4000-8000-000000000004"}})),
                )
            }),
        )
        .with_state(observed.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let client = ApiClient::new(format!("http://{address}"))
        .unwrap()
        .with_development_bearer("development-token")
        .with_csrf("csrf-value");
    let session = ApiClient::new(format!("http://{address}"))
        .unwrap()
        .with_cookie_header("peerward_session=session-token; peerward_csrf=csrf-cookie")
        .auth_session()
        .await
        .unwrap();
    assert!(session.authenticated);
    assert_eq!(session.actor, "playwright-admin");
    assert_eq!(session.csrf_token.as_deref(), Some("csrf-cookie"));
    let page = client.meshes(None, 900).await.unwrap();
    assert_eq!(page.items[0].name, "blue");
    assert_eq!(page.next_cursor.as_deref(), Some("next-1"));
    let unselected = client
        .route_snapshot(ConsoleRoute::Peers, None, None)
        .await
        .unwrap();
    assert!(unselected.mesh_id.is_empty());
    assert!(unselected.resources.is_empty());
    assert_eq!(unselected.mesh_name, "No mesh selected");
    let mesh: MeshCreateRequest = serde_json::from_value(json!({
        "name":"green","address_cidr":"10.43.0.0/24","gateway":"10.43.0.1",
        "dns_suffix":"green.peerward","mtu":1380,"reserved":[],
        "default_policy":"deny","quarantine_seconds":300,
        "rotation_overlap_seconds":3600
    }))
    .unwrap();
    client.create_mesh(&mesh).await.unwrap();
    let rotation = CredentialRotationRequest {
        public_key: "signed-public-key".into(),
    };
    client
        .rotate_credential(
            "00000000-0000-4000-8000-000000000002",
            CredentialSubject::Relay,
            "00000000-0000-4000-8000-000000000003",
            &rotation,
            1,
        )
        .await
        .unwrap();
    client
        .activate_credential(
            "00000000-0000-4000-8000-000000000002",
            CredentialSubject::Peer,
            "00000000-0000-4000-8000-000000000003",
            "00000000-0000-4000-8000-000000000004",
            1,
        )
        .await
        .unwrap();
    client
        .revoke_credential(
            "00000000-0000-4000-8000-000000000002",
            CredentialSubject::Peer,
            "00000000-0000-4000-8000-000000000003",
            "00000000-0000-4000-8000-000000000004",
            1,
        )
        .await
        .unwrap();
    client
        .activate_authority(
            "00000000-0000-4000-8000-000000000002",
            "00000000-0000-4000-8000-000000000005",
            1,
        )
        .await
        .unwrap();
    assert_eq!(
        observed.0.lock().unwrap().as_slice(),
        &[
            ("csrf-value".into(), "green".into()),
            ("csrf-value".into(), "signed-public-key".into()),
            (
                "csrf-value".into(),
                "activate:00000000-0000-4000-8000-000000000004".into(),
            ),
            (
                "csrf-value".into(),
                "revoke:00000000-0000-4000-8000-000000000004".into(),
            ),
            (
                "csrf-value".into(),
                "authority:00000000-0000-4000-8000-000000000005".into(),
            ),
        ]
    );
    let response = client.events(Some("evt-9")).await.unwrap();
    assert!(response.text().await.unwrap().contains("id: evt-9"));
    let failure: Result<Value, _> = client
        .request(Method::POST, "/api/v1/fail", Some(json!({})))
        .await;
    assert!(matches!(
        failure,
        Err(ConsoleApiError::Server(ApiErrorBody { code, .. })) if code == "forbidden"
    ));
    for path in ["/api/v1/oversized-declared", "/api/v1/oversized-streamed"] {
        let oversized: Result<Value, _> = client.request(Method::GET, path, None::<Value>).await;
        assert!(matches!(oversized, Err(ConsoleApiError::ResponseTooLarge)));
    }
    server.abort();
}

#[test]
fn one_time_ticket_builds_local_bundle_and_svg_qr() {
    let client = ApiClient::new("https://console.example").unwrap();
    let mut ticket = peerward_api::JoinTicketCreateResponse {
        version: 1,
        id: uuid::Uuid::new_v4(),
        mesh_id: "00000000-0000-4000-8000-000000000002".parse().unwrap(),
        expires_at: "2030-01-01T00:00:00Z".into(),
        expires_at_unix: 1_893_456_000,
        token: "AQIDBA".into(),
        claim_url: None,
        root_fingerprint: "11".repeat(32),
    };
    let link = client.join_link(&ticket).unwrap();
    let encoded = link.strip_prefix("peerward://join?bundle=").unwrap();
    let decoded = URL_SAFE_NO_PAD.decode(encoded).unwrap();
    let bundle: serde_json::Value = serde_json::from_slice(&decoded).unwrap();
    assert_eq!(
        bundle["claim_url"],
        "https://console.example/api/v1/join/AQIDBA/claim"
    );
    assert_eq!(bundle["root_fingerprint"], "11".repeat(32));
    assert_eq!(bundle["mesh_id"], "00000000-0000-4000-8000-000000000002");
    let svg = join_qr_svg(&link, Locale::EnUs).unwrap();
    assert!(svg.starts_with("<svg"));
    assert!(svg.contains("<path"));
    ticket.claim_url = Some("https://devices.example/api/v1/join/AQIDBA/claim".into());
    let link = client.join_link(&ticket).unwrap();
    let decoded = URL_SAFE_NO_PAD
        .decode(link.strip_prefix("peerward://join?bundle=").unwrap())
        .unwrap();
    let bundle: serde_json::Value = serde_json::from_slice(&decoded).unwrap();
    assert_eq!(bundle["claim_url"], ticket.claim_url.as_deref().unwrap());
    for invalid in [
        "http://devices.example/api/v1/join/AQIDBA/claim",
        "https://user:secret@devices.example/api/v1/join/AQIDBA/claim",
        "https://devices.example/api/v1/join/other/claim",
        "https://devices.example/api/v1/join/AQIDBA/claim?secret=x",
    ] {
        ticket.claim_url = Some(invalid.into());
        assert!(client.join_link(&ticket).is_err());
    }
    ticket.claim_url = None;
    ticket.token = "../bad".into();
    assert!(client.join_link(&ticket).is_err());
}

#[test]
fn served_stylesheet_contains_shared_light_and_dark_tokens() {
    let css = stylesheet();
    assert!(css.contains("--pw-bg: #f5f7fb"));
    assert!(css.contains(":root[data-theme=\"dark\"]"));
    assert!(css.contains(".shell {"));
    assert!(css.contains(".resource-workspace {"));
    assert!(css.contains(".action-panel input, .action-panel select, .action-panel textarea"));
    assert!(css.contains(".action-panel-primary-grid, .resource-editor--compact"));
    assert!(css.contains("grid-template-areas: \"actions resources\" \"actions extras\""));
    assert!(css.contains("grid-template-areas: \"resources\" \"actions\" \"extras\""));
}

#[test]
fn mesh_list_refreshes_for_deletion_outside_the_selected_mesh() {
    let event = SseEvent {
        id: Some("mesh-deletion".into()),
        event: Some("mesh.deleted".into()),
        data: json!({"resource_type": "mesh", "mesh_id": "other-mesh"}).to_string(),
    };
    assert!(event_affects_route(
        &event,
        ConsoleRoute::Meshes,
        "selected-mesh"
    ));
    assert!(!event_affects_route(
        &event,
        ConsoleRoute::Peers,
        "selected-mesh"
    ));
}

#[test]
fn mesh_delete_preserves_exact_confirmation_whitespace() {
    let body = operation_body(
        ConsoleRoute::Meshes,
        BrowserOperation::DeleteMesh,
        "  Saved Mesh  ",
        &default_editor_document(ConsoleRoute::Meshes),
    )
    .unwrap();
    assert_eq!(body, json!({"confirmation_name": "  Saved Mesh  "}));
}

include!("mesh_selection_tests.rs");

#[path = "topology_route_tests.rs"]
mod topology_route_tests;

include!("device_presentation_tests.rs");

include!("console_issue_tests.rs");

include!("sharing_draft_tests.rs");
