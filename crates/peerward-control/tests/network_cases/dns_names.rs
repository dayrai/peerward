use super::*;

pub async fn verify(app: &Router, mesh: Uuid, provider: Uuid) {
    let base = format!("/api/v1/meshes/{mesh}");
    let path = format!("{base}/dns-profiles/{mesh}");
    let current = json_body(request(app, "GET", &path, None, Value::Null).await).await;
    let version = current["version"].as_u64().unwrap();
    let mut profile = current["profile"].clone();
    profile["records"]["gateway.network.test"] = json!([{"type":"A","value":"192.168.45.20"}]);
    let conflict = request(app, "PUT", &path, Some(version), profile.clone()).await;
    assert_eq!(conflict.status(), StatusCode::CONFLICT);
    assert_eq!(
        json_body(conflict).await["error"]["code"],
        "dns_reserved_name"
    );
    profile["records"]
        .as_object_mut()
        .unwrap()
        .remove("gateway.network.test");
    let original_routes = profile["routes"].clone();
    profile["routes"] = json!([{"suffix":"gateway.network.test","upstreams":["192.168.45.53:53"]}]);
    let conflict = request(app, "PUT", &path, Some(version), profile.clone()).await;
    assert_eq!(conflict.status(), StatusCode::CONFLICT);
    profile["routes"] = original_routes;
    profile["routes"]
        .as_array_mut()
        .unwrap()
        .push(json!({"suffix":"delegated.network.test","upstreams":["192.168.45.53:53"]}));
    profile["records"]["reserved.network.test"] = json!([{"type":"A","value":"192.168.45.20"}]);
    profile["records"]["gateway.moved.test"] = json!([{"type":"A","value":"192.168.45.21"}]);
    let saved = request(app, "PUT", &path, Some(version), profile.clone()).await;
    assert_eq!(saved.status(), StatusCode::OK, "{}", json_body(saved).await);
    let delegation_collision = request(
        app,
        "POST",
        &format!("{base}/peers"),
        None,
        json!({"name":"delegated"}),
    )
    .await;
    assert_eq!(delegation_collision.status(), StatusCode::CONFLICT);
    let collision = request(
        app,
        "POST",
        &format!("{base}/peers"),
        None,
        json!({"name":"reserved"}),
    )
    .await;
    assert_eq!(collision.status(), StatusCode::CONFLICT);
    let collision = request(app,"POST",&format!("{base}/services"),None,json!({"peer_id":provider,"protocols":["tcp"],"listen_port":631,"alias":"reserved","labels":{}})).await;
    assert_eq!(collision.status(), StatusCode::CONFLICT);
    let mesh_current = json_body(request(app, "GET", &base, None, Value::Null).await).await;
    let collision = request(
        app,
        "PATCH",
        &base,
        mesh_current["version"].as_u64(),
        json!({"dns_suffix":"moved.test"}),
    )
    .await;
    assert_eq!(
        collision.status(),
        StatusCode::CONFLICT,
        "changing the Mesh suffix must preserve the same reservation rules"
    );
    let mesh_after = json_body(request(app, "GET", &base, None, Value::Null).await).await;
    assert_eq!(mesh_after["dns_suffix"], "network.test");
    profile["records"]["racing.network.test"] = json!([{"type":"A","value":"192.168.45.22"}]);
    let peers_path = format!("{base}/peers");
    let (dns, peer) = tokio::join!(
        request(app, "PUT", &path, Some(version + 1), profile),
        request(app, "POST", &peers_path, None, json!({"name":"racing"})),
    );
    assert!(
        (dns.status() == StatusCode::OK && peer.status() == StatusCode::CONFLICT)
            || (dns.status() == StatusCode::CONFLICT && peer.status() == StatusCode::CREATED),
        "one atomic name owner must win: DNS={}, Peer={}",
        dns.status(),
        peer.status()
    );
}
