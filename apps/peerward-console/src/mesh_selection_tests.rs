#[tokio::test]
async fn mesh_selection_recovers_after_a_mesh_is_deleted() {
    let app = Router::new()
        .route(
            "/api/v1/meshes",
            get(|| async { Json(json!({"items": [], "next_cursor": null})) }),
        )
        .route(
            "/api/v1/meshes/{mesh}",
            get(|| async {
                (
                    StatusCode::NOT_FOUND,
                    Json(json!({"error": {
                        "code": "not_found", "message": "Mesh not found", "request_id": "deleted",
                        "field_errors": {}, "retryable": false
                    }})),
                )
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = ApiClient::new(format!("http://{}", listener.local_addr().unwrap())).unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let page = client
        .mesh_page_with_selection(Some("deleted-mesh"))
        .await
        .unwrap();
    assert!(page.items.is_empty());
    server.abort();
}

#[tokio::test]
async fn route_refresh_loads_a_selected_mesh_outside_the_selector_cache() {
    let id = uuid::Uuid::new_v4().to_string();
    let value = json!({"id":id,"version":1,"name":"outside-first-page","address_cidr":"10.43.0.0/24","gateway":"10.43.0.1",
        "secondary_cidr":"fd43::/64","secondary_gateway":"fd43::1","dns_suffix":"green.peerward","mtu":1380,"default_policy":"deny",
        "policy_revision":1,"authority_revision":1,"directory_revision":1,"relay_revision":1,"service_revision":1,"revocation_revision":1});
    let app = Router::new().route(
        "/api/v1/meshes/{mesh}",
        get(move || {
            let value = value.clone();
            async move { Json(value) }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = ApiClient::new(format!("http://{}", listener.local_addr().unwrap())).unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let mut current = ConsoleSnapshot::sample();
    current.meshes = (0..110)
        .map(|i| ResourceSummary {
            id: uuid::Uuid::new_v4().to_string(),
            name: format!("cached-{i}"),
            details: BTreeMap::new(),
        })
        .collect();
    let selected = client
        .route_resource_snapshot(ConsoleRoute::Overview, &current, Some(&id), None)
        .await
        .unwrap();
    assert_eq!(selected.mesh_id, id);
    assert_eq!(selected.mesh_name, "outside-first-page");
    assert_eq!(selected.meshes.len(), 101);
    assert!(
        selected
            .meshes
            .iter()
            .any(|m| m.id == id && m.details["lifecycle"] == "active")
    );
    server.abort();
}
