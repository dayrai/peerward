use super::*;

#[tokio::test]
async fn topology_is_loaded_for_operations_on_initial_load_and_refresh() {
    let mesh = json!({
        "id":"00000000-0000-4000-8000-000000000001", "version":1, "name":"blue",
        "address_cidr":"10.43.0.0/24", "gateway":"10.43.0.1", "dns_suffix":"blue.peerward",
        "secondary_cidr":"fd43::/64", "secondary_gateway":"fd43::1", "mtu":1380, "default_policy":"deny", "policy_revision":1, "authority_revision":1,
        "directory_revision":1, "relay_revision":1, "service_revision":1, "revocation_revision":1
    });
    let mesh_id = mesh["id"].as_str().unwrap().to_owned();
    let observed = Arc::new(Mutex::new(Vec::new()));
    let app = Router::new()
        .route("/auth/session", get(|| async {
            Json(json!({"authenticated":true,"actor":"operator","role":"viewer",
                "capabilities":["resource_read"],"csrf_token":null}))
        }))
        .route("/api/v1/meshes", get(move || {
            let mesh = mesh.clone();
            async move { Json(json!({"items":[mesh],"next_cursor":null})) }
        }))
        .route("/api/v1/meshes/{mesh}/topology/{kind}", get({
            let observed = observed.clone();
            move |Path((_mesh, kind)): Path<(String, String)>| {
                let observed = observed.clone();
                async move {
                    observed.lock().unwrap().push(kind.clone());
                    Json(match kind.as_str() {
                        "summary" => json!({"peer_count":4,"online_peer_count":3,"relay_count":1,
                            "online_relay_count":1,"presence_count":3,"regions":[{"region":"west",
                                "relay_count":1,"online_relay_count":1,"presence_count":3}],
                            "backbone_revision":null,"backbone_mode":null,"backbone_edge_count":0}),
                        "nodes" => json!({"items":[{"kind":"relay",
                            "id":"00000000-0000-4000-8000-000000000002","name":"west-relay",
                            "online":true,"administrative_state":"enabled","credential_status":"healthy",
                            "region":"west","routing_weight":100,"presence_count":3}],"next_cursor":null}),
                        "edges" => json!({"items":[],"next_cursor":null}),
                        _ => panic!("unexpected topology request"),
                    })
                }
            }
        }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = ApiClient::new(format!("http://{}", listener.local_addr().unwrap())).unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let overview = client
        .route_snapshot(ConsoleRoute::Overview, Some(&mesh_id), None)
        .await
        .unwrap();
    assert!(overview.resources.is_empty());
    assert!(observed.lock().unwrap().is_empty());
    let operations = client
        .route_snapshot(ConsoleRoute::Operations, Some(&mesh_id), None)
        .await
        .unwrap();
    assert_eq!(operations.resources.len(), 3);
    assert_eq!(operations.resources[0].details["peer_count"], 4);
    assert!(render_route(ConsoleRoute::Operations, operations.clone()).contains("west-relay"));
    let refreshed = client
        .route_resource_snapshot(ConsoleRoute::Operations, &operations, Some(&mesh_id), None)
        .await
        .unwrap();
    assert_eq!(refreshed.resources, operations.resources);
    let overview = client
        .route_resource_snapshot(ConsoleRoute::Overview, &refreshed, Some(&mesh_id), None)
        .await
        .unwrap();
    assert!(overview.resources.is_empty());
    let unselected = client
        .route_snapshot(ConsoleRoute::Operations, None, None)
        .await
        .unwrap();
    assert!(unselected.resources.is_empty());
    assert_eq!(
        *observed.lock().unwrap(),
        ["summary", "nodes", "edges", "summary", "nodes", "edges"]
    );
    server.abort();
}
