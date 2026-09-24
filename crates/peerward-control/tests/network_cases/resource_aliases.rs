use super::*;

pub async fn verify(store: &Store, app: &Router) {
    let mesh = store
        .create_mesh(
            &NewMesh {
                name: "alias-lab".into(),
                address_cidr: "10.123.0.0/24".parse().unwrap(),
                gateway: "10.123.0.1".parse().unwrap(),
                dns_suffix: "alias.test".into(),
                mtu: 1280,
                reserved: vec![],
                default_policy: DefaultPolicy::Deny,
                quarantine_seconds: 3600,
                rotation_overlap_seconds: 3600,
            },
            "test",
        )
        .await
        .unwrap()
        .id
        .into_uuid();
    let base = format!("/api/v1/meshes/{mesh}");
    let mut devices = vec![];
    for name in ["consumer", "gateway"] {
        let response = request(
            app,
            "POST",
            &format!("{base}/peers"),
            None,
            json!({"name":name,"labels":{}}),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        devices.push(Uuid::parse_str(json_body(response).await["id"].as_str().unwrap()).unwrap());
    }
    let (source, provider) = (devices[0], devices[1]);
    sqlx::query("INSERT INTO peer_addresses(id,mesh_id,peer_id,address,state) VALUES($1,$2,$3,'10.123.0.2','active')").bind(Uuid::new_v4()).bind(mesh).bind(source).execute(store.pool()).await.unwrap();
    let actual = Uuid::parse_str("ffffffff-ffff-4fff-bfff-ffffffffffff").unwrap();
    let alias = Uuid::parse_str("00000000-0000-4000-8000-000000000001").unwrap();
    let site = Uuid::new_v4();
    for id in [actual, alias] {
        assert_eq!(request(app,"POST",&format!("{base}/network-resources"),None,json!({"id":id,"definition":{"name":id.to_string(),"target":{"kind":"subnet","prefix":"192.168.219.50/32","site_id":site}}})).await.status(),StatusCode::CREATED);
    }
    let binding = Uuid::new_v4();
    assert_eq!(request(app,"POST",&format!("{base}/gateway-bindings"),None,json!({"id":binding,"resource_id":actual,"peer_id":provider,"priority":100,"forwarding":"snat","return_route_confirmed":false})).await.status(),StatusCode::CREATED);
    assert_eq!(
        request(
            app,
            "PUT",
            &format!("{base}/gateway-bindings/{binding}/approval"),
            Some(1),
            json!({"approved":true})
        )
        .await
        .status(),
        StatusCode::OK
    );
    let allow = Uuid::new_v4();
    let deny = Uuid::new_v4();
    let rule = json!({"id":allow,"priority":100,"enabled":true,"action":"allow","source":{"peers":[source]},"resources":[actual],"providers":[provider],"protocol":6,"destination_ports":[[631,631]],"not_after":null});
    let path = format!("{base}/resource-policy");
    let current = json_body(request(app, "GET", &path, None, Value::Null).await).await;
    let mut document = json!({"rules":[rule],"tests":[{"id":Uuid::new_v4(),"name":"printing via either name","source_peer_id":source,"resource_id":alias,"provider_peer_id":provider,"address":"192.168.219.50","protocol":6,"destination_port":631,"expected":"allow"}]});
    let published = request(
        app,
        "PUT",
        &path,
        current["version"].as_u64(),
        document.clone(),
    )
    .await;
    assert_eq!(
        published.status(),
        StatusCode::OK,
        "{}",
        json_body(published).await
    );
    for id in [actual, alias] {
        let packet = json!({"source_peer_id":source,"target":{"kind":"resource","resource_id":id,"address":"192.168.219.50","provider_peer_id":provider},"protocol":6,"destination_port":631});
        let result = json_body(
            request(
                app,
                "POST",
                &format!("{base}/policy/simulate"),
                None,
                packet,
            )
            .await,
        )
        .await;
        assert_eq!(result["allowed"], true, "{result}");
        assert_eq!(result["matched_rule_id"], json!(allow));
        assert!(
            result["warnings"]
                .as_array()
                .unwrap()
                .contains(&json!("equal_prefix_aliases_share_policy_order"))
        );
    }
    let mut denial = document["rules"][0].clone();
    denial["id"] = json!(deny);
    denial["resources"] = json!([alias]);
    denial["action"] = json!("deny");
    document["rules"].as_array_mut().unwrap().push(denial);
    document["tests"][0]["expected"] = json!("deny");
    let current = json_body(request(app, "GET", &path, None, Value::Null).await).await;
    assert_eq!(
        request(app, "PUT", &path, current["version"].as_u64(), document)
            .await
            .status(),
        StatusCode::OK
    );
    for id in [actual, alias] {
        let packet = json!({"source_peer_id":source,"target":{"kind":"resource","resource_id":id,"address":"192.168.219.50","provider_peer_id":provider},"protocol":6,"destination_port":631});
        let result = json_body(
            request(
                app,
                "POST",
                &format!("{base}/policy/simulate"),
                None,
                packet,
            )
            .await,
        )
        .await;
        assert_eq!(result["allowed"], false, "{result}");
        assert_eq!(result["matched_rule_id"], json!(deny));
    }
    verify_collection_withdrawal(app, &base, source, actual, alias, provider).await;
}

async fn configuration_review(app: &Router, base: &str, document: &Value, apply: bool) -> Value {
    let path = format!("{base}/configuration");
    let current =
        json_body(request(app, "GET", &format!("{path}/export"), None, Value::Null).await).await;
    let response = request(
        app,
        "POST",
        &format!("{path}/preview"),
        current["version"].as_u64(),
        document.clone(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let preview = json_body(response).await;
    if apply {
        let response=request(app,"POST",&format!("{path}/apply"),current["version"].as_u64(),json!({"request_id":Uuid::new_v4(),"document":document,"preview_digest":preview["preview_digest"]})).await;
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "{}",
            json_body(response).await
        );
    }
    preview
}

async fn verify_collection_withdrawal(
    app: &Router,
    base: &str,
    source: Uuid,
    target: Uuid,
    alias: Uuid,
    provider: Uuid,
) {
    let collection = Uuid::new_v4();
    let snapshot = json_body(
        request(
            app,
            "GET",
            &format!("{base}/configuration/export"),
            None,
            Value::Null,
        )
        .await,
    )
    .await;
    let mut document = snapshot["document"].clone();
    document["collections"] = json!([{"id":collection,"definition":{"name":"approved source","kind":"devices","members":[source],"labels":{}}}]);
    let allow = json!({"id":Uuid::new_v4(),"priority":100,"enabled":true,"action":"allow","source":{"peers":[source]},"source_collections":[collection],"resources":[target],"providers":[provider],"protocol":6,"destination_ports":[[631,631]],"not_after":null});
    let assertion = Uuid::new_v4();
    document["resource_policy"] = json!({"rules":[allow],"tests":[{"id":assertion,"name":"source must print","source_peer_id":source,"resource_id":alias,"provider_peer_id":provider,"address":"192.168.219.50","protocol":6,"destination_port":631,"expected":"allow"}]});
    configuration_review(app, base, &document, true).await;
    document["collections"][0]["definition"]["members"] = json!([]);
    let withdrawn = configuration_review(app, base, &document, true).await;
    assert_eq!(withdrawn["only_removes_grants"], true);
    assert_eq!(withdrawn["failed_tests"], json!([assertion]));
    assert_eq!(
        withdrawn["can_apply"], true,
        "positive assertions cannot prevent this proven withdrawal"
    );

    // The same member removal from a Deny can expose a later Allow. That is
    // not a withdrawal and a failed negative assertion must reject publication.
    document["collections"][0]["definition"]["members"] = json!([source]);
    let mut denial = document["resource_policy"]["rules"][0].clone();
    denial["id"] = json!(Uuid::new_v4());
    denial["action"] = json!("deny");
    denial["priority"] = json!(0);
    document["resource_policy"]["rules"][0]["source_collections"] = json!([]);
    document["resource_policy"]["rules"]
        .as_array_mut()
        .unwrap()
        .push(denial);
    document["resource_policy"]["tests"][0]["expected"] = json!("deny");
    configuration_review(app, base, &document, true).await;
    document["collections"][0]["definition"]["members"] = json!([]);
    let rejected = configuration_review(app, base, &document, false).await;
    assert_eq!(rejected["only_removes_grants"], false);
    assert_eq!(rejected["can_apply"], false);
}
