use super::*;

pub async fn verify(store: &Store, app: &Router, mesh: Uuid, source: Uuid, resource: Uuid) {
    let base = format!("/api/v1/meshes/{mesh}");
    let path = format!("{base}/collections");
    let devices = Uuid::new_v4();
    let targets = Uuid::new_v4();
    let device_definition =
        json!({"name":"Finance devices","kind":"devices","members":[],"labels":{"team":"finance"}});
    let target_definition =
        json!({"name":"Printers","kind":"resources","members":[resource],"labels":{}});
    for (id, definition) in [
        (devices, device_definition.clone()),
        (targets, target_definition),
    ] {
        let body = json!({"id":id,"definition":definition});
        assert_eq!(
            request(app, "POST", &path, None, body.clone())
                .await
                .status(),
            StatusCode::CREATED
        );
        assert_eq!(
            request(app, "POST", &path, None, body).await.status(),
            StatusCode::OK
        );
    }
    let invalid = json!({"id":Uuid::new_v4(),"definition":{"name":"wrong kind","kind":"resources","members":[source]}});
    assert_eq!(
        request(app, "POST", &path, None, invalid).await.status(),
        StatusCode::BAD_REQUEST
    );
    let policy_path = format!("{base}/resource-policy");
    let current = json_body(request(app, "GET", &policy_path, None, Value::Null).await).await;
    let rule = json!({"id":Uuid::new_v4(),"priority":100,"enabled":true,"action":"allow","source":{"peers":[],"labels":{},"cidrs":[]},
        "resources":[],"source_collections":[devices],"resource_collections":[targets],"providers":[],"protocol":6,"destination_ports":[[631,631]],"not_after":null});
    let mut document = json!({"rules":[rule],"tests":[]});
    assert_eq!(
        request(
            app,
            "PUT",
            &policy_path,
            current["version"].as_u64(),
            document.clone()
        )
        .await
        .status(),
        StatusCode::OK
    );
    let simulation_path = format!("{base}/policy/simulate");
    let packet = json!({"source_peer_id":source,"target":{"kind":"resource","resource_id":resource,"address":"192.168.45.10","provider_peer_id":source},"protocol":6,"destination_port":631});
    assert_eq!(
        json_body(request(app, "POST", &simulation_path, None, packet.clone()).await).await["allowed"],
        false
    );
    let peer_path = format!("{base}/peers/{source}");
    let peer = json_body(request(app, "GET", &peer_path, None, Value::Null).await).await;
    let before: i64 = sqlx::query_scalar("SELECT management_revision FROM meshes WHERE id=$1")
        .bind(mesh)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(
        request(
            app,
            "PATCH",
            &peer_path,
            peer["version"].as_u64(),
            json!({"labels":{"team":"finance"}})
        )
        .await
        .status(),
        StatusCode::OK
    );
    let after: i64 = sqlx::query_scalar("SELECT management_revision FROM meshes WHERE id=$1")
        .bind(mesh)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert!(
        after > before,
        "directory-driven collection changes need a new signed component version"
    );
    assert_eq!(
        json_body(request(app, "POST", &simulation_path, None, packet.clone()).await).await["allowed"],
        true
    );
    document["tests"] = json!([{"id":Uuid::new_v4(),"name":"Finance printing","source_peer_id":source,"resource_id":resource,"provider_peer_id":source,"address":"192.168.45.10","protocol":6,"destination_port":631,"expected":"allow"}]);
    let current = json_body(request(app, "GET", &policy_path, None, Value::Null).await).await;
    assert_eq!(
        request(
            app,
            "PUT",
            &policy_path,
            current["version"].as_u64(),
            document
        )
        .await
        .status(),
        StatusCode::OK
    );
    let collection_path = format!("{path}/{devices}");
    let mut empty = device_definition;
    empty["labels"] = json!({});
    assert_eq!(
        request(app, "PUT", &collection_path, Some(1), empty.clone())
            .await
            .status(),
        StatusCode::OK,
        "emptying membership must not be prevented by a positive assertion"
    );
    assert_eq!(
        request(app, "PUT", &collection_path, Some(1), empty)
            .await
            .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        json_body(request(app, "POST", &simulation_path, None, packet).await).await["allowed"],
        false
    );
    assert_eq!(
        request(app, "DELETE", &collection_path, Some(2), Value::Null)
            .await
            .status(),
        StatusCode::CONFLICT,
        "referenced collections cannot be deleted"
    );
    let resource_path = format!("{base}/network-resources/{resource}");
    assert_eq!(
        request(app, "DELETE", &resource_path, Some(1), Value::Null)
            .await
            .status(),
        StatusCode::CONFLICT,
        "explicit resource members and assertions retain references"
    );
}
