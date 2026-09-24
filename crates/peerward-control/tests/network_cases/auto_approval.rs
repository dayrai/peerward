use super::*;

async fn send(
    app: &Router,
    method: &str,
    path: &str,
    version: Option<u64>,
    body: Value,
    expected: StatusCode,
) -> Value {
    let response = request(app, method, path, version, body).await;
    let status = response.status();
    if status == StatusCode::NO_CONTENT {
        assert_eq!(status, expected, "{method} {path}");
        return Value::Null;
    }
    let value = json_body(response).await;
    assert_eq!(status, expected, "{method} {path}: {value}");
    value
}
async fn get(app: &Router, path: &str) -> Value {
    send(app, "GET", path, None, Value::Null, StatusCode::OK).await
}
async fn put(app: &Router, path: &str, body: Value) -> Value {
    let current = get(app, path).await;
    send(
        app,
        "PUT",
        path,
        current["version"].as_u64(),
        body,
        StatusCode::OK,
    )
    .await
}
async fn approval(app: &Router, binding: &str, approved: bool) -> Value {
    let current = get(app, binding).await;
    send(
        app,
        "PUT",
        &format!("{binding}/approval"),
        current["version"].as_u64(),
        json!({"approved":approved}),
        StatusCode::OK,
    )
    .await
}
async fn automatic(app: &Router, binding: &str) -> Value {
    let current = get(app, binding).await;
    send(
        app,
        "POST",
        &format!("{binding}/automatic-approval"),
        current["version"].as_u64(),
        json!({}),
        StatusCode::OK,
    )
    .await
}

pub async fn verify(store: &Store, app: &Router, mesh: Uuid, peer: Uuid) {
    let base = format!("/api/v1/meshes/{mesh}");
    let site = Uuid::new_v4();
    let resource = Uuid::new_v4();
    let binding = Uuid::new_v4();
    let group = Uuid::new_v4();
    let rule = Uuid::new_v4();
    let resources = format!("{base}/network-resources");
    let binding_path = format!("{base}/gateway-bindings/{binding}");
    let resource_path = format!("{resources}/{resource}");
    let groups = format!("{base}/collections");
    let group_path = format!("{groups}/{group}");
    let rules = format!("{base}/auto-approval-rules");
    let rule_path = format!("{rules}/{rule}");
    let mut target = json!({"name":"Automatic LAN","target":{"kind":"subnet","prefix":"192.168.90.50/32","site_id":site}});
    send(
        app,
        "POST",
        &resources,
        None,
        json!({"id":resource,"definition":target}),
        StatusCode::CREATED,
    )
    .await;
    let mut collection =
        json!({"name":"Controlled routers","kind":"devices","members":[peer],"labels":{}});
    send(
        app,
        "POST",
        &groups,
        None,
        json!({"id":group,"definition":collection}),
        StatusCode::CREATED,
    )
    .await;
    send(
        app,
        "POST",
        &format!("{base}/gateway-bindings"),
        None,
        json!({"id":binding,"resource_id":resource,"peer_id":peer,"priority":100}),
        StatusCode::CREATED,
    )
    .await;
    let mut definition = json!({"name":"Office approval","device_collection":group,"site_id":site,"prefixes":["192.168.90.0/24"]});
    let created = send(
        app,
        "POST",
        &rules,
        None,
        json!({"id":rule,"definition":definition}),
        StatusCode::CREATED,
    )
    .await;
    assert_eq!(created["definition"]["enabled"], false);
    assert_eq!(get(app, &binding_path).await["approved"], false);
    definition["enabled"] = json!(true);
    send(
        app,
        "PUT",
        &rule_path,
        None,
        definition.clone(),
        StatusCode::PRECONDITION_REQUIRED,
    )
    .await;
    let mut invalid = definition.clone();
    invalid["prefixes"] = json!(["0.0.0.0/0"]);
    send(
        app,
        "PUT",
        &rule_path,
        Some(1),
        invalid,
        StatusCode::BAD_REQUEST,
    )
    .await;
    invalid = definition.clone();
    invalid["device_collection"] = json!(Uuid::new_v4());
    send(
        app,
        "PUT",
        &rule_path,
        Some(1),
        invalid,
        StatusCode::BAD_REQUEST,
    )
    .await;
    invalid = definition.clone();
    invalid["approved"] = json!(true);
    send(
        app,
        "PUT",
        &rule_path,
        Some(1),
        invalid,
        StatusCode::BAD_REQUEST,
    )
    .await;
    let policy_before = get(app, &format!("{base}/resource-policy")).await;
    let mut wrong_site = definition.clone();
    wrong_site["site_id"] = json!(Uuid::new_v4());
    send(
        app,
        "PUT",
        &rule_path,
        Some(1),
        wrong_site,
        StatusCode::BAD_REQUEST,
    )
    .await;
    let (first, second) = tokio::join!(
        request(app, "PUT", &rule_path, Some(1), definition.clone()),
        request(app, "PUT", &rule_path, Some(1), definition.clone()),
    );
    assert!([first.status(), second.status()].contains(&StatusCode::OK));
    assert!([first.status(), second.status()].contains(&StatusCode::CONFLICT));
    let current = get(app, &binding_path).await;
    assert_eq!(current["approved"], true);
    assert_eq!(
        current["approval_source"],
        json!({"kind":"automatic","rule_id":rule,"rule_version":2})
    );
    assert_eq!(
        get(app, &format!("{base}/resource-policy")).await,
        policy_before,
        "route authority cannot create traffic permission"
    );
    let packet = json!({"source_peer_id":peer,"target":{"kind":"resource","resource_id":resource,"address":"192.168.90.50","provider_peer_id":peer},"protocol":6,"destination_port":631});
    let simulation = send(
        app,
        "POST",
        &format!("{base}/policy/simulate"),
        None,
        packet,
        StatusCode::OK,
    )
    .await;
    assert_eq!(
        simulation["allowed"], false,
        "automatic route approval alone is not access authorization"
    );
    approval(app, &binding_path, false).await;
    put(app, &rule_path, definition.clone()).await;
    assert_eq!(
        get(app, &binding_path).await["approved"],
        false,
        "manual withdrawal is not resurrected by rule edits"
    );
    assert_eq!(automatic(app, &binding_path).await["approved"], true);
    definition["prefixes"] = json!(["192.168.90.0/27"]);
    put(app, &rule_path, definition.clone()).await;
    assert_eq!(
        get(app, &binding_path).await["approved"],
        false,
        "tightening scope revokes within the same transaction"
    );
    definition["prefixes"] = json!(["192.168.90.0/24"]);
    put(app, &rule_path, definition.clone()).await;
    assert_eq!(get(app, &binding_path).await["approved"], true);
    collection["members"] = json!([]);
    put(app, &group_path, collection.clone()).await;
    assert_eq!(
        get(app, &binding_path).await["approved"],
        false,
        "collection membership is re-evaluated"
    );
    collection["labels"] = json!({"router":"office"});
    put(app, &group_path, collection.clone()).await;
    let peer_path = format!("{base}/peers/{peer}");
    let current_peer = get(app, &peer_path).await;
    send(
        app,
        "PATCH",
        &peer_path,
        current_peer["version"].as_u64(),
        json!({"labels":{"router":"office"}}),
        StatusCode::OK,
    )
    .await;
    assert_eq!(
        get(app, &binding_path).await["approved"],
        true,
        "controlled peer labels are re-evaluated"
    );
    let current_peer = get(app, &peer_path).await;
    send(
        app,
        "PATCH",
        &peer_path,
        current_peer["version"].as_u64(),
        json!({"labels":{}}),
        StatusCode::OK,
    )
    .await;
    assert_eq!(get(app, &binding_path).await["approved"], false);
    collection["members"] = json!([peer]);
    put(app, &group_path, collection.clone()).await;
    assert_eq!(get(app, &binding_path).await["approved"], true);
    target["target"]["prefix"] = json!("192.168.90.51/32");
    put(app, &resource_path, target).await;
    assert_eq!(
        get(app, &binding_path).await["approved"],
        false,
        "retargeting requires renewed authority even inside the old permitted prefix"
    );
    put(app, &rule_path, definition.clone()).await;
    assert_eq!(get(app, &binding_path).await["approved"], false);
    automatic(app, &binding_path).await;
    let group_version = get(app, &group_path).await["version"].as_u64();
    send(
        app,
        "DELETE",
        &group_path,
        group_version,
        Value::Null,
        StatusCode::CONFLICT,
    )
    .await;
    let current_rule = get(app, &rule_path).await;
    send(
        app,
        "DELETE",
        &rule_path,
        current_rule["version"].as_u64(),
        Value::Null,
        StatusCode::NO_CONTENT,
    )
    .await;
    assert_eq!(
        get(app, &binding_path).await["approved"],
        false,
        "deleting the only authority revokes its approvals"
    );
    let audit_count:i64=sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE mesh_id=$1 AND target_id=$2 AND action='auto_approval.changed' AND metadata->'approval_source'->>'rule_id'=$3")
        .bind(mesh).bind(binding).bind(rule.to_string()).fetch_one(store.pool()).await.unwrap();
    assert!(
        audit_count >= 10,
        "automatic decisions include source rule/version evidence"
    );
    approval(app, &binding_path, true).await;
    let new_rule = Uuid::new_v4();
    send(
        app,
        "POST",
        &rules,
        None,
        json!({"id":new_rule,"definition":definition}),
        StatusCode::CREATED,
    )
    .await;
    definition["prefixes"] = json!(["192.168.90.0/27"]);
    put(app, &format!("{rules}/{new_rule}"), definition).await;
    assert_eq!(
        get(app, &binding_path).await["approval_source"],
        json!({"kind":"manual"})
    );
    assert_eq!(
        get(app, &binding_path).await["approved"],
        true,
        "manual grants do not inherit automatic authority"
    );
    let current_rule = get(app, &format!("{rules}/{new_rule}")).await;
    let mut widened = current_rule["definition"].clone();
    widened["prefixes"] = json!(["192.168.90.0/24"]);
    put(app, &format!("{rules}/{new_rule}"), widened).await;
    for (index, target) in [
        json!({"kind":"subnet","prefix":"192.168.90.52/32","site_id":site}),
        json!({"kind":"internet","ipv4":true,"ipv6":true}),
        json!({"kind":"subnet","prefix":"192.168.91.50/32","site_id":Uuid::new_v4()}),
    ]
    .into_iter()
    .enumerate()
    {
        let id = Uuid::new_v4();
        let path_id = Uuid::new_v4();
        send(app,"POST",&resources,None,json!({"id":id,"definition":{"name":format!("Manual boundary {index}"),"target":target}}),StatusCode::CREATED).await;
        let body = json!({"id":path_id,"resource_id":id,"peer_id":peer,"priority":100,"forwarding":if index==0{"preserve_source"}else{"snat"},"return_route_confirmed":index==0});
        let created = send(
            app,
            "POST",
            &format!("{base}/gateway-bindings"),
            None,
            body,
            StatusCode::CREATED,
        )
        .await;
        assert_eq!(
            created["approved"], false,
            "preserved-source, exit and different-site paths do not inherit SNAT scope"
        );
        assert_eq!(
            automatic(app, &format!("{base}/gateway-bindings/{path_id}")).await["approved"],
            false
        );
    }
}
