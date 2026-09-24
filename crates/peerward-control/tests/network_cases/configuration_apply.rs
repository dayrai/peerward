use super::*;

async fn read(app: &Router, base: &str) -> Value {
    let response = request(app, "GET", &format!("{base}/export"), None, Value::Null).await;
    assert_eq!(response.status(), StatusCode::OK);
    json_body(response).await
}
async fn preview(app: &Router, base: &str, snapshot: &Value, document: &Value) -> Value {
    let response = request(
        app,
        "POST",
        &format!("{base}/preview"),
        snapshot["version"].as_u64(),
        document.clone(),
    )
    .await;
    let status = response.status();
    let body = json_body(response).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body
}
fn application(document: &Value, preview: &Value) -> Value {
    json!({"request_id":Uuid::new_v4(),"document":document,"preview_digest":preview["preview_digest"]})
}

pub async fn verify(store: &Store, app: &Router) {
    let mesh = store
        .create_mesh(
            &NewMesh {
                name: "declaration-lab".into(),
                address_cidr: "10.121.0.0/24".parse().unwrap(),
                gateway: "10.121.0.1".parse().unwrap(),
                dns_suffix: "declaration.test".into(),
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
    let base = format!("/api/v1/meshes/{mesh}/configuration");
    let initial = read(app, &base).await;
    assert_eq!(initial["document"]["schema_version"], 4);
    assert_eq!(initial["document"]["wire_version"], 5);
    for forbidden in [
        "tickets",
        "credentials",
        "leases",
        "advertisements",
        "addresses",
        "private_key",
    ] {
        assert!(initial["document"].get(forbidden).is_none());
    }
    let nochange = preview(app, &base, &initial, &initial["document"]).await;
    assert_eq!(nochange["changes"], json!([]));
    assert_eq!(nochange["can_apply"], true);
    assert_eq!(
        read(app, &base).await,
        initial,
        "preview must roll back every staged write"
    );
    let noop = application(&initial["document"], &nochange);
    let applied = request(
        app,
        "POST",
        &format!("{base}/apply"),
        initial["version"].as_u64(),
        noop.clone(),
    )
    .await;
    assert_eq!(applied.status(), StatusCode::OK);
    let applied = json_body(applied).await;
    assert_eq!(applied["version"], initial["version"]);
    assert_eq!(applied["applied"], true);
    assert_eq!(
        json_body(
            request(
                app,
                "POST",
                &format!("{base}/apply"),
                initial["version"].as_u64(),
                noop.clone()
            )
            .await
        )
        .await,
        applied
    );
    assert_eq!(
        read(app, &base).await,
        initial,
        "idempotent no-op must not advance any resource version"
    );

    // Age a committed no-op: its old If-Match is still current. Compaction must
    // therefore preserve the request identity, not merely rely on version checks.
    sqlx::query("UPDATE configuration_applications SET created_at=clock_timestamp()-interval '31 days' WHERE mesh_id=$1")
        .bind(mesh).execute(store.pool()).await.unwrap();
    store
        .maintain(peerward_store::MaintenancePolicy {
            batch_size: 100,
            event_retention_seconds: 3600,
            event_max_rows: 10000,
            signed_state_versions: 2,
            terminal_retention_seconds: 3600,
        })
        .await
        .unwrap();
    let archived = request(
        app,
        "POST",
        &format!("{base}/apply"),
        initial["version"].as_u64(),
        noop.clone(),
    )
    .await;
    assert_eq!(archived.status(), StatusCode::GONE);
    assert_eq!(
        json_body(archived).await["error"]["code"],
        "configuration_response_archived"
    );
    assert_eq!(read(app, &base).await, initial);
    let mut reused_noop = noop.clone();
    reused_noop["preview_digest"] = json!("0".repeat(64));
    assert_eq!(
        request(
            app,
            "POST",
            &format!("{base}/apply"),
            initial["version"].as_u64(),
            reused_noop
        )
        .await
        .status(),
        StatusCode::CONFLICT
    );

    let resource = Uuid::new_v4();
    let collection = Uuid::new_v4();
    let mut document = initial["document"].clone();
    document["resources"] = json!([{"id":resource,"definition":{"name":"Declaration printer","target":{"kind":"subnet","prefix":"192.168.249.50/32","site_id":Uuid::new_v4()}}}]);
    document["collections"] = json!([{"id":collection,"definition":{"name":"Declared printers","kind":"resources","members":[resource]}}]);
    let candidate = preview(app, &base, &initial, &document).await;
    assert_eq!(candidate["changes"].as_array().unwrap().len(), 2);
    assert_eq!(read(app, &base).await, initial);
    let body = application(&document, &candidate);
    let missing = request(app, "POST", &format!("{base}/apply"), None, body.clone()).await;
    assert_eq!(missing.status(), StatusCode::PRECONDITION_REQUIRED);
    let mut wrong = body.clone();
    wrong["preview_digest"] = json!("0".repeat(64));
    assert_eq!(
        request(
            app,
            "POST",
            &format!("{base}/apply"),
            initial["version"].as_u64(),
            wrong
        )
        .await
        .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        read(app, &base).await,
        initial,
        "failed preview binding rolls back new resources and collections"
    );
    let apply_path = format!("{base}/apply");
    let (first, second) = tokio::join!(
        request(
            app,
            "POST",
            &apply_path,
            initial["version"].as_u64(),
            body.clone()
        ),
        request(
            app,
            "POST",
            &apply_path,
            initial["version"].as_u64(),
            body.clone()
        )
    );
    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(second.status(), StatusCode::OK);
    assert_eq!(
        json_body(first).await,
        json_body(second).await,
        "concurrent retries return the persisted response"
    );
    let saved = read(app, &base).await;
    assert_eq!(
        saved["version"].as_u64(),
        initial["version"].as_u64().map(|x| x + 1)
    );
    assert_eq!(saved["document"]["resources"][0]["id"], json!(resource));
    let mut reused = body.clone();
    reused["document"]["resources"][0]["definition"]["name"] = json!("different request");
    assert_eq!(
        request(
            app,
            "POST",
            &format!("{base}/apply"),
            initial["version"].as_u64(),
            reused
        )
        .await
        .status(),
        StatusCode::CONFLICT
    );
    let mut fresh = body.clone();
    fresh["request_id"] = json!(Uuid::new_v4());
    assert_eq!(
        request(
            app,
            "POST",
            &format!("{base}/apply"),
            initial["version"].as_u64(),
            fresh
        )
        .await
        .status(),
        StatusCode::CONFLICT
    );
    let mut invalid = saved["document"].clone();
    invalid["collections"][0]["definition"]["members"] = json!([Uuid::new_v4()]);
    assert_eq!(
        request(app, "POST", &format!("{base}/validate"), None, invalid)
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    let mut invalid = saved["document"].clone();
    let duplicate = invalid["resources"][0].clone();
    invalid["resources"].as_array_mut().unwrap().push(duplicate);
    assert_eq!(
        request(app, "POST", &format!("{base}/validate"), None, invalid)
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    let mut invalid = saved["document"].clone();
    invalid["private_key"] = json!("must-reject-unknown-fields");
    assert_eq!(
        request(app, "POST", &format!("{base}/validate"), None, invalid)
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(read(app, &base).await, saved);
    // Restoration creates a new declarative revision and never revives old leases.
    let restore = preview(app, &base, &saved, &initial["document"]).await;
    let restore = request(
        app,
        "POST",
        &format!("{base}/apply"),
        saved["version"].as_u64(),
        application(&initial["document"], &restore),
    )
    .await;
    assert_eq!(restore.status(), StatusCode::OK);
    let restored = read(app, &base).await;
    assert_eq!(restored["document"], initial["document"]);
    assert!(restored["version"].as_u64() > saved["version"].as_u64());
    let audit: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_log WHERE mesh_id=$1 AND action='configuration.apply'",
    )
    .bind(mesh)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(audit, 2, "exactly one audit per changed atomic application");
    verify_grants_and_provider_removal(store, app, mesh, &base).await;
}

async fn verify_grants_and_provider_removal(store: &Store, app: &Router, mesh: Uuid, base: &str) {
    let peers = format!("/api/v1/meshes/{mesh}/peers");
    let source = json_body(
        request(
            app,
            "POST",
            &peers,
            None,
            json!({"name":"declaration-client"}),
        )
        .await,
    )
    .await;
    let provider = json_body(
        request(
            app,
            "POST",
            &peers,
            None,
            json!({"name":"declaration-gateway"}),
        )
        .await,
    )
    .await;
    let source_id = Uuid::parse_str(source["id"].as_str().unwrap()).unwrap();
    let provider_id = Uuid::parse_str(provider["id"].as_str().unwrap()).unwrap();
    sqlx::query("INSERT INTO peer_addresses(id,mesh_id,peer_id,address,state) VALUES($1,$2,$3,'10.121.0.2','active')").bind(Uuid::new_v4()).bind(mesh).bind(source_id).execute(store.pool()).await.unwrap();
    let initial = read(app, base).await;
    let mut document = initial["document"].clone();
    let resource = Uuid::new_v4();
    let binding = Uuid::new_v4();
    let site = Uuid::new_v4();
    let positive = Uuid::new_v4();
    let negative = Uuid::new_v4();
    document["resources"] = json!([{"id":resource,"definition":{"name":"Tested printer","target":{"kind":"subnet","prefix":"192.168.248.50/32","site_id":site}}}]);
    document["bindings"] = json!([{"id":binding,"resource_id":resource,"peer_id":provider_id,"priority":100,"forwarding":"snat","return_route_confirmed":false,"approval":{"kind":"manual","approved":true}}]);
    document["dns_profiles"][0]["records"] =
        json!({"printer.declaration.test":[{"type":"A","value":"192.168.248.50"}]});
    document["resource_policy"] = json!({"rules":[{"id":Uuid::new_v4(),"priority":100,"enabled":true,"action":"allow","source":{"peers":[source_id]},"resources":[resource],"providers":[provider_id],"protocol":6,"destination_ports":[[631,631]],"not_after":null}],"tests":[
        {"id":positive,"name":"printing allowed","source_peer_id":source_id,"provider_peer_id":provider_id,"resource_id":resource,"address":"192.168.248.50","protocol":6,"destination_port":631,"expected":"allow"},
        {"id":negative,"name":"admin denied","source_peer_id":source_id,"provider_peer_id":provider_id,"resource_id":resource,"address":"192.168.248.50","protocol":6,"destination_port":80,"expected":"deny"}]});
    let proposed = preview(app, base, &initial, &document).await;
    assert_eq!(proposed["can_apply"], true);
    assert_eq!(proposed["failed_tests"], json!([]));
    assert_eq!(
        request(
            app,
            "POST",
            &format!("{base}/apply"),
            initial["version"].as_u64(),
            application(&document, &proposed)
        )
        .await
        .status(),
        StatusCode::OK
    );
    let saved = read(app, base).await;
    let nochange = preview(app, base, &saved, &saved["document"]).await;
    assert_eq!(nochange["changes"], json!([]));
    let mut broader = saved["document"].clone();
    broader["resource_policy"]["rules"][0]["destination_ports"] = json!([]);
    let rejected = preview(app, base, &saved, &broader).await;
    assert_eq!(rejected["can_apply"], false);
    assert_eq!(rejected["failed_tests"], json!([negative]));
    assert_eq!(
        request(
            app,
            "POST",
            &format!("{base}/apply"),
            saved["version"].as_u64(),
            application(&broader, &rejected)
        )
        .await
        .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(read(app, base).await, saved);
    let mut revoked = saved["document"].clone();
    revoked["bindings"][0]["approval"]["approved"] = json!(false);
    let withdrawal = preview(app, base, &saved, &revoked).await;
    assert_eq!(withdrawal["can_apply"], true);
    assert_eq!(withdrawal["only_removes_grants"], true);
    assert_eq!(withdrawal["failed_tests"], json!([positive]));
    assert_eq!(
        request(
            app,
            "POST",
            &format!("{base}/apply"),
            saved["version"].as_u64(),
            application(&revoked, &withdrawal)
        )
        .await
        .status(),
        StatusCode::OK
    );
    let withdrawn = read(app, base).await;
    let mut removed = withdrawn["document"].clone();
    removed["bindings"] = json!([]);
    let removal = preview(app, base, &withdrawn, &removed).await;
    assert_eq!(removal["can_apply"], true);
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM provider_capture_exclusions WHERE mesh_id=$1")
            .bind(mesh)
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert_eq!(count, 0, "preview rolls back capture history too");
    assert_eq!(
        request(
            app,
            "POST",
            &format!("{base}/apply"),
            withdrawn["version"].as_u64(),
            application(&removed, &removal)
        )
        .await
        .status(),
        StatusCode::OK
    );
    let history: Value =
        sqlx::query_scalar("SELECT providers FROM provider_capture_exclusions WHERE mesh_id=$1")
            .bind(mesh)
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert_eq!(history, json!([provider_id]));
    let latest = read(app, base).await;
    let mut automatic = saved["document"].clone();
    let group = Uuid::new_v4();
    automatic["collections"] = json!([{"id":group,"definition":{"name":"controlled gateways","kind":"devices","members":[provider_id]}}]);
    automatic["auto_approval_rules"] = json!([{"id":Uuid::new_v4(),"definition":{"name":"printer automatic path","enabled":true,"device_collection":group,"site_id":site,"prefixes":["192.168.248.0/24"]}}]);
    automatic["bindings"][0]["approval"] = json!({"kind":"automatic"});
    let proposed = preview(app, base, &latest, &automatic).await;
    assert_eq!(proposed["can_apply"], true);
    assert_eq!(
        request(
            app,
            "POST",
            &format!("{base}/apply"),
            latest["version"].as_u64(),
            application(&automatic, &proposed)
        )
        .await
        .status(),
        StatusCode::OK
    );
    let automatic_saved = read(app, base).await;
    assert_eq!(
        automatic_saved["document"]["bindings"][0]["approval"],
        json!({"kind":"automatic"})
    );
    assert_eq!(
        preview(app, base, &automatic_saved, &automatic_saved["document"]).await["changes"],
        json!([]),
        "automatic approval source and version survive an export/preview round trip"
    );
    let mut disabled = automatic_saved["document"].clone();
    disabled["auto_approval_rules"][0]["definition"]["enabled"] = json!(false);
    let disabling = preview(app, base, &automatic_saved, &disabled).await;
    assert_eq!(
        disabling["can_apply"], true,
        "disabling automatic grants must not be blocked by positive tests"
    );
    assert_eq!(
        request(
            app,
            "POST",
            &format!("{base}/apply"),
            automatic_saved["version"].as_u64(),
            application(&disabled, &disabling)
        )
        .await
        .status(),
        StatusCode::OK
    );
}
