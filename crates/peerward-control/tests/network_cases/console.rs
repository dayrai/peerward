use super::*;

pub(super) async fn ok(
    app: &Router,
    method: &str,
    path: &str,
    version: Option<u64>,
    body: Value,
) -> Value {
    let response = request(app, method, path, version, body).await;
    let status = response.status();
    let body = if status == StatusCode::NO_CONTENT {
        Value::Null
    } else {
        json_body(response).await
    };
    assert!(status.is_success(), "{method} {path}: {status} {body}");
    body
}

pub async fn verify(store: &Store, app: &Router) {
    let mesh = store
        .create_mesh(
            &NewMesh {
                name: "console-lab".into(),
                address_cidr: "10.125.0.0/24".parse().unwrap(),
                gateway: "10.125.0.1".parse().unwrap(),
                dns_suffix: "console.test".into(),
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
    let mut peers = vec![];
    for (i, name) in ["consumer", "provider"].iter().enumerate() {
        let peer = ok(
            app,
            "POST",
            &format!("{base}/peers"),
            None,
            json!({"name":name,"labels":{"platform":"linux"}}),
        )
        .await;
        let id = Uuid::parse_str(peer["id"].as_str().unwrap()).unwrap();
        peers.push(id);
        sqlx::query("INSERT INTO peer_addresses(id,mesh_id,peer_id,address,state) VALUES($1,$2,$3,$4::inet,'active')")
            .bind(Uuid::new_v4()).bind(mesh).bind(id).bind(format!("10.125.0.{}",i+2)).execute(store.pool()).await.unwrap();
    }
    let overview = ok(
        app,
        "GET",
        &format!("{base}/console/overview"),
        None,
        Value::Null,
    )
    .await;
    assert_eq!(overview["devices"], 2);
    assert_eq!(overview["online_devices"], 0);
    let page = ok(
        app,
        "GET",
        &format!("{base}/console/devices?limit=1&platform=linux"),
        None,
        Value::Null,
    )
    .await;
    assert_eq!(page["total"], 2);
    assert!(page["next_cursor"].is_string());
    let past_end = ok(app, "GET", &format!("{base}/console/devices?limit=1&platform=linux&cursor=ffffffff-ffff-ffff-ffff-ffffffffffff"), None, Value::Null).await;
    assert_eq!(past_end["total"], 2);
    let no_relay = ok(
        app,
        "GET",
        &format!("{base}/console/devices?relay_id={}", Uuid::new_v4()),
        None,
        Value::Null,
    )
    .await;
    assert_eq!(no_relay["total"], 0);
    assert!(past_end["items"].as_array().unwrap().is_empty());
    let search = ok(
        app,
        "GET",
        &format!("/api/v1/console/search?mesh={mesh}&q=consumer"),
        None,
        Value::Null,
    )
    .await;
    assert_eq!(search["items"].as_array().unwrap().len(), 1);
    let issue = overview["issues"][0].clone();
    ok(
        app,
        "PATCH",
        &format!("{base}/console/notices"),
        None,
        json!({"id":issue["id"],"fingerprint":issue["fingerprint"],"known":true,"read":true}),
    )
    .await;
    let overview = ok(
        app,
        "GET",
        &format!("{base}/console/overview"),
        None,
        Value::Null,
    )
    .await;
    assert_eq!(overview["issue_count"], 2);
    assert_eq!(overview["open_issue_count"], 1);
    assert_eq!(overview["unread_notice_count"], 1);
    assert!(
        overview["issues"]
            .as_array()
            .unwrap()
            .iter()
            .all(|i| i["id"] != issue["id"])
    );
    for status in ["open", "known", "unread", "read"] {
        let page = ok(
            app,
            "GET",
            &format!("{base}/console/issues?status={status}&limit=1"),
            None,
            Value::Null,
        )
        .await;
        assert_eq!(page["total"], 1, "filter before pagination: {status}");
        assert_eq!(page["all_count"], 2);
        assert_eq!(page["items"].as_array().unwrap().len(), 1);
        assert_eq!(
            page["items"][0]["id"] == issue["id"],
            matches!(status, "known" | "read")
        );
    }
    let past = ok(
        app,
        "GET",
        &format!("{base}/console/issues?cursor=zzzz&limit=1"),
        None,
        Value::Null,
    )
    .await;
    assert_eq!(past["total"], 2, "total does not shrink after the cursor");
    assert_eq!(past["open_count"], 1);
    assert!(past["items"].as_array().unwrap().is_empty());
    assert_eq!(
        request(
            app,
            "GET",
            &format!("{base}/console/issues?status=misspelled"),
            None,
            Value::Null
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );
    let group = Uuid::new_v4();
    ok(app,"POST",&format!("{base}/collections"),None,json!({"id":group,"definition":{"kind":"devices","name":"Operators","members":[peers[0]],"labels":{}}})).await;
    sqlx::query("INSERT INTO network_collections(id,mesh_id,definition) SELECT gen_random_uuid(),$1,jsonb_build_object('kind','devices','name','extra-group-'||n::text,'members','[]'::jsonb,'labels','{}'::jsonb) FROM generate_series(1,55) AS n")
        .bind(mesh).execute(store.pool()).await.unwrap();
    let groups = ok(
        app,
        "GET",
        &format!("/api/v1/console/search?mesh={mesh}&kind=group&q=extra-group-55&limit=1"),
        None,
        Value::Null,
    )
    .await;
    assert_eq!(groups["items"].as_array().unwrap().len(), 1);
    assert_eq!(groups["items"][0]["name"], "extra-group-55");
    assert!(
        groups["items"][0]["href"]
            .as_str()
            .unwrap()
            .contains("&source=group:")
    );
    let group_page = ok(
        app,
        "GET",
        &format!("/api/v1/console/search?mesh={mesh}&kind=group&limit=1"),
        None,
        Value::Null,
    )
    .await;
    assert!(group_page["next_cursor"].is_string());
    let mesh_search = ok(
        app,
        "GET",
        "/api/v1/console/search?kind=mesh&q=console-lab",
        None,
        Value::Null,
    )
    .await;
    assert_eq!(mesh_search["items"].as_array().unwrap().len(), 1);
    assert_eq!(mesh_search["items"][0]["id"], mesh.to_string());
    let service = Uuid::new_v4();
    let draft = json!({"request_id":service,"name":"Files","provider":peers[1],"target":{"kind":"service","protocols":["tcp"],"port":443,"alias":"files"},"source":{"kind":"collection","id":group},"protocol":6,"port":443,"reason":"test"});
    let preview = ok(
        app,
        "POST",
        &format!("{base}/console/sharing/preview"),
        None,
        draft.clone(),
    )
    .await;
    assert_eq!(preview["affected_sources"], 1);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM services WHERE id=$1")
            .bind(service)
            .fetch_one(store.pool())
            .await
            .unwrap(),
        0,
        "preview rolls back"
    );
    let apply = json!({"draft":draft,"preview_digest":preview["digest"]});
    let saved = ok(
        app,
        "POST",
        &format!("{base}/console/sharing/apply"),
        preview["version"].as_u64(),
        apply.clone(),
    )
    .await;
    assert_eq!(saved["applied"], true);
    assert_eq!(
        saved,
        ok(
            app,
            "POST",
            &format!("{base}/console/sharing/apply"),
            preview["version"].as_u64(),
            apply.clone()
        )
        .await,
        "exact retry"
    );
    let mut wrong = apply.clone();
    wrong["draft"]["name"] = json!("Different");
    assert_eq!(
        request(
            app,
            "POST",
            &format!("{base}/console/sharing/apply"),
            preview["version"].as_u64(),
            wrong
        )
        .await
        .status(),
        StatusCode::CONFLICT
    );
    let simulation =
        json!({"source_peer_id":peers[0],"target_service_id":service,"protocol":"tcp"});
    assert_eq!(
        ok(
            app,
            "POST",
            &format!("{base}/policy/simulate"),
            None,
            simulation.clone()
        )
        .await["allowed"],
        true
    );
    let managed = ok(
        app,
        "GET",
        &format!("{base}/console/services/{service}/grants"),
        None,
        Value::Null,
    )
    .await;
    assert_eq!(managed["items"][0]["source_names"], json!(["Operators"]));
    let grant_id = managed["items"][0]["id"].as_str().unwrap();
    ok(
        app,
        "PUT",
        &format!("{base}/console/services/{service}/grants/{grant_id}"),
        Some(1),
        json!({"enabled":false,"reason":"remove access"}),
    )
    .await;
    assert_eq!(
        ok(
            app,
            "POST",
            &format!("{base}/policy/simulate"),
            None,
            simulation.clone()
        )
        .await["allowed"],
        false
    );
    assert_eq!(
        request(
            app,
            "PUT",
            &format!("{base}/console/services/{service}/grants/{grant_id}"),
            Some(1),
            json!({"enabled":true,"reason":"stale restore"})
        )
        .await
        .status(),
        StatusCode::CONFLICT
    );
    ok(
        app,
        "PUT",
        &format!("{base}/console/services/{service}/grants/{grant_id}"),
        Some(2),
        json!({"enabled":true,"reason":"restore reviewed source"}),
    )
    .await;
    assert_eq!(
        ok(
            app,
            "POST",
            &format!("{base}/policy/simulate"),
            None,
            simulation.clone()
        )
        .await["allowed"],
        true
    );
    let raw = ok(app, "GET", &format!("{base}/policy"), None, Value::Null).await;
    assert_eq!(
        raw["rules"],
        json!([]),
        "managed grants must not rewrite advanced rules"
    );
    let mut ordered = raw.clone();
    ordered["revision"] = json!(raw["revision"].as_u64().unwrap() + 1);
    ordered["rules"] = json!([{"id":Uuid::new_v4(),"priority":1,"action":"deny","enabled":true,"log":false,"source":{"peer_ids":[peers[1]],"labels":{},"cidrs":[]},"destination":{"peer_ids":[peers[1]],"labels":{},"cidrs":[]},"protocol":"tcp","destination_ports":[{"first":443,"last":443}]}]);
    ok(
        app,
        "PUT",
        &format!("{base}/policy"),
        raw["revision"].as_u64(),
        ordered.clone(),
    )
    .await;
    ok(
        app,
        "PUT",
        &format!("{base}/collections/{group}"),
        Some(1),
        json!({"name":"Operators","kind":"devices","members":peers,"labels":{}}),
    )
    .await;
    let matrix=ok(app,"POST",&format!("{base}/console/matrix"),None,json!({"source":{"kind":"collection","id":group},"targets":[{"kind":"service","id":service}]})).await;
    assert_eq!(matrix["cells"][0]["outcome"], "partial");
    assert_eq!(matrix["cells"][0]["allowed_sources"], 1);
    let edit = json!({"display_name":"Files","alias":"files","protocols":["tcp"],"listen_port":443,"paused":true,"reason":"maintenance"});
    let paused = ok(
        app,
        "PATCH",
        &format!("{base}/console/services/{service}"),
        Some(1),
        edit.clone(),
    )
    .await;
    assert_eq!(
        ok(
            app,
            "POST",
            &format!("{base}/policy/simulate"),
            None,
            simulation.clone()
        )
        .await["allowed"],
        false
    );
    let mut resume = edit;
    resume["paused"] = json!(false);
    ok(
        app,
        "PATCH",
        &format!("{base}/console/services/{service}"),
        paused["version"].as_u64(),
        resume,
    )
    .await;
    assert_eq!(
        ok(
            app,
            "POST",
            &format!("{base}/policy/simulate"),
            None,
            simulation.clone()
        )
        .await["allowed"],
        true
    );
    ok(
        app,
        "PUT",
        &format!("{base}/collections/{group}"),
        Some(2),
        json!({"name":"Operators","kind":"devices","members":[],"labels":{}}),
    )
    .await;
    assert_eq!(
        ok(
            app,
            "POST",
            &format!("{base}/policy/simulate"),
            None,
            simulation.clone()
        )
        .await["allowed"],
        false,
        "empty collection never grants everyone"
    );
    let resource = Uuid::new_v4();
    let draft = json!({"request_id":resource,"name":"Printer","provider":peers[1],"target":{"kind":"network","definition":{"name":"Printer","target":{"kind":"subnet","prefix":"192.168.245.10/32","site_id":Uuid::new_v4()}},"dns_name":"printer.console.test","dns_address":"192.168.245.10"},"source":{"kind":"peer","id":peers[0]},"protocol":6,"port":631,"reason":"test"});
    let preview = ok(
        app,
        "POST",
        &format!("{base}/console/sharing/preview"),
        None,
        draft.clone(),
    )
    .await;
    ok(
        app,
        "POST",
        &format!("{base}/console/sharing/apply"),
        preview["version"].as_u64(),
        json!({"draft":draft,"preview_digest":preview["digest"]}),
    )
    .await;
    let simulation = json!({"source_peer_id":peers[0],"target":{"kind":"resource","resource_id":resource,"address":"192.168.245.10","provider_peer_id":peers[1]},"protocol":6,"destination_port":631});
    assert_eq!(
        ok(
            app,
            "POST",
            &format!("{base}/policy/simulate"),
            None,
            simulation.clone()
        )
        .await["allowed"],
        true
    );
    let matrix=ok(app,"POST",&format!("{base}/console/matrix"),None,json!({"source":{"kind":"peer","id":peers[0]},"targets":[{"kind":"network","id":resource,"address":null,"provider":null,"protocol":null,"port":null}]})).await;
    assert_eq!(matrix["cells"][0]["outcome"], "conditions");
    let grants = ok(
        app,
        "GET",
        &format!("{base}/resource-policy"),
        None,
        Value::Null,
    )
    .await;
    for (version, paused, allowed) in [(1, true, false), (2, false, true)] {
        assert_eq!(
            request(
                app,
                "PUT",
                &format!("{base}/console/resources/{resource}/state"),
                Some(version),
                json!({"paused":paused,"reason":"test"})
            )
            .await
            .status(),
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            ok(
                app,
                "POST",
                &format!("{base}/policy/simulate"),
                None,
                simulation.clone()
            )
            .await["allowed"],
            allowed
        );
        assert_eq!(
            ok(
                app,
                "GET",
                &format!("{base}/resource-policy"),
                None,
                Value::Null
            )
            .await,
            grants
        );
    }
    let shares = ok(
        app,
        "GET",
        &format!("{base}/console/sharing"),
        None,
        Value::Null,
    )
    .await;
    assert_eq!(shares["items"].as_array().unwrap().len(), 2);
    assert!(
        shares["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|s| s["reachability"]["state"] == "unknown")
    );
    let issues = ok(
        app,
        "GET",
        &format!("{base}/console/issues"),
        None,
        Value::Null,
    )
    .await;
    assert!(
        issues["items"].as_array().unwrap().iter().any(
            |i| i["kind"] == "gateway_path_missing" && i["resource_id"] == resource.to_string()
        )
    );
    assert_eq!(
        request(
            app,
            "PATCH",
            &format!("{base}/console/notices"),
            None,
            json!({"id":issue["id"],"fingerprint":"invented","known":true,"read":false})
        )
        .await
        .status(),
        StatusCode::CONFLICT
    );
    super::console_access::verify(store, app, &base, &peers, resource).await;
    verify_network_edit(store, app, &base, resource).await;
    let provider = ok(
        app,
        "GET",
        &format!("{base}/peers/{}", peers[1]),
        None,
        Value::Null,
    )
    .await;
    assert_eq!(
        request(
            app,
            "POST",
            &format!("{base}/console/devices/{}/retire", peers[1]),
            provider["version"].as_u64(),
            json!({"name":"wrong-name","reason":"decommission"})
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );
    ok(
        app,
        "POST",
        &format!("{base}/console/devices/{}/retire", peers[1]),
        provider["version"].as_u64(),
        json!({"name":"provider","reason":"decommission"}),
    )
    .await;
    assert_eq!(
        ok(
            app,
            "GET",
            &format!("{base}/peers/{}", peers[1]),
            None,
            Value::Null
        )
        .await["administrative_state"],
        "disabled"
    );
    let activity = ok(
        app,
        "GET",
        &format!("{base}/console/devices/{}/activity", peers[1]),
        None,
        Value::Null,
    )
    .await;
    assert!(
        activity["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["action"] == "peer.retire")
    );
    let provided = ok(
        app,
        "GET",
        &format!("{base}/console/sharing?provider={}", peers[1]),
        None,
        Value::Null,
    )
    .await;
    assert!(!provided["items"].as_array().unwrap().is_empty());
    let foreign = Uuid::new_v4();
    assert_eq!(
        request(
            app,
            "GET",
            &format!("/api/v1/meshes/{foreign}/console/sharing/service/{service}/impact"),
            None,
            Value::Null
        )
        .await
        .status(),
        StatusCode::NOT_FOUND
    );
}

async fn verify_network_edit(store: &Store, app: &Router, base: &str, id: Uuid) {
    let original = ok(
        app,
        "GET",
        &format!("{base}/network-resources/{id}"),
        None,
        Value::Null,
    )
    .await;
    let policy = ok(
        app,
        "GET",
        &format!("{base}/resource-policy"),
        None,
        Value::Null,
    )
    .await;
    let dns = ok(
        app,
        "GET",
        &format!("{base}/dns-profiles"),
        None,
        Value::Null,
    )
    .await;
    let mut definition = original["definition"].clone();
    definition["name"] = json!("Updated printer");
    definition["target"]["prefix"] = json!("192.168.245.11/32");
    definition["health_probe"] = json!({"address":"192.168.245.11","port":631});
    let draft = json!({"request_id":Uuid::new_v4(), "resource_version":original["version"], "definition":definition, "reason":"Printer address changed"});
    let path = format!("{base}/console/network-resources/{id}");
    let preview = ok(app, "POST", &format!("{path}/preview"), None, draft.clone()).await;
    assert_eq!(preview["target_changed"], true);
    assert_eq!(preview["gateways_requiring_approval"], 1);
    assert_eq!(
        ok(
            app,
            "GET",
            &format!("{base}/network-resources/{id}"),
            None,
            Value::Null
        )
        .await,
        original,
        "preview rolled back"
    );
    let body = json!({"draft":draft, "preview_digest":preview["digest"]});
    let mut wrong = body.clone();
    wrong["preview_digest"] = json!("invalid");
    assert_eq!(
        request(
            app,
            "POST",
            &format!("{path}/apply"),
            preview["version"].as_u64(),
            wrong
        )
        .await
        .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        ok(
            app,
            "GET",
            &format!("{base}/network-resources/{id}"),
            None,
            Value::Null
        )
        .await,
        original,
        "failed compound write rolled back"
    );
    let applied = ok(
        app,
        "POST",
        &format!("{path}/apply"),
        preview["version"].as_u64(),
        body.clone(),
    )
    .await;
    assert_eq!(applied["applied"], true);
    assert_eq!(
        ok(
            app,
            "POST",
            &format!("{path}/apply"),
            preview["version"].as_u64(),
            body
        )
        .await,
        applied,
        "idempotent edit"
    );
    let updated = ok(
        app,
        "GET",
        &format!("{base}/network-resources/{id}"),
        None,
        Value::Null,
    )
    .await;
    assert_eq!(updated["definition"], definition);
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM gateway_bindings WHERE resource_id=$1 AND approved"
        )
        .bind(id)
        .fetch_one(store.pool())
        .await
        .unwrap(),
        0,
        "target change requires explicit gateway reapproval"
    );
    assert_eq!(
        ok(
            app,
            "GET",
            &format!("{base}/resource-policy"),
            None,
            Value::Null
        )
        .await,
        policy,
        "advanced grants retained"
    );
    assert_eq!(
        ok(
            app,
            "GET",
            &format!("{base}/dns-profiles"),
            None,
            Value::Null
        )
        .await,
        dns,
        "DNS not silently rewritten"
    );
    assert_eq!(
        request(app, "POST", &format!("{path}/preview"), None, draft)
            .await
            .status(),
        StatusCode::CONFLICT,
        "stale editor rejected"
    );
    let gateways = ok(
        app,
        "GET",
        &format!("{path}/gateways?limit=1"),
        None,
        Value::Null,
    )
    .await;
    let binding = &gateways["items"][0]["binding"];
    let gateway_draft = json!({"request_id":Uuid::new_v4(), "resource_version":updated["version"], "definition":definition, "reason":"Approve reviewed printer address", "gateways":[{"id":binding["id"],"version":binding["version"],"priority":50,"approved":true}]});
    let review = ok(
        app,
        "POST",
        &format!("{path}/preview"),
        None,
        gateway_draft.clone(),
    )
    .await;
    assert_eq!(review["gateways_changed"], 1);
    assert_eq!(review["target_changed"], false);
    ok(
        app,
        "POST",
        &format!("{path}/apply"),
        review["version"].as_u64(),
        json!({"draft":gateway_draft,"preview_digest":review["digest"]}),
    )
    .await;
    let gateways = ok(
        app,
        "GET",
        &format!("{path}/gateways?limit=1"),
        None,
        Value::Null,
    )
    .await;
    assert_eq!(gateways["items"][0]["binding"]["approved"], true);
    assert_eq!(gateways["items"][0]["binding"]["priority"], 50);
    verify_evidence_generations(store, id).await;
    let audit: Value = sqlx::query_scalar("SELECT metadata FROM audit_log WHERE target_id=$1 AND action='network_resource.edit' AND metadata->>'reason'='Printer address changed' ORDER BY occurred_at DESC LIMIT 1").bind(id).fetch_one(store.pool()).await.unwrap();
    assert_eq!(audit["reason"], "Printer address changed");
    assert_eq!(audit["impact"]["gateways_requiring_approval"], 1);
}

async fn verify_evidence_generations(store: &Store, resource: Uuid) {
    let (mesh, binding, peer, version): (Uuid, Uuid, Uuid, i64) = sqlx::query_as(
        "SELECT mesh_id,id,peer_id,version FROM gateway_bindings WHERE resource_id=$1 LIMIT 1",
    )
    .bind(resource)
    .fetch_one(store.pool())
    .await
    .unwrap();
    let first: Uuid = sqlx::query_scalar("INSERT INTO target_health_observations(mesh_id,binding_id,binding_version,resource_version,credential_serial,sequence,result) VALUES($1,$2,$3,1,$4,1,'refused') RETURNING evidence_generation")
        .bind(mesh).bind(binding).bind(version).bind(Uuid::new_v4()).fetch_one(store.pool()).await.unwrap();
    let same: Uuid = sqlx::query_scalar("UPDATE target_health_observations SET sequence=2,observed_at=clock_timestamp() WHERE mesh_id=$1 AND binding_id=$2 RETURNING evidence_generation").bind(mesh).bind(binding).fetch_one(store.pool()).await.unwrap();
    assert_eq!(
        first, same,
        "repeated failure samples do not reopen acknowledgement"
    );
    sqlx::query("UPDATE target_health_observations SET result='reachable' WHERE mesh_id=$1 AND binding_id=$2").bind(mesh).bind(binding).execute(store.pool()).await.unwrap();
    let again: Uuid = sqlx::query_scalar("UPDATE target_health_observations SET result='refused' WHERE mesh_id=$1 AND binding_id=$2 RETURNING evidence_generation").bind(mesh).bind(binding).fetch_one(store.pool()).await.unwrap();
    assert_ne!(first, again, "failure after recovery is a new incident");
    let first: Uuid = sqlx::query_scalar("INSERT INTO route_advertisements(mesh_id,binding_id,peer_id,sequence,published,forwarding_ready,valid_until,binding_version) VALUES($1,$2,$3,1,true,false,clock_timestamp()+interval '1 minute',$4) RETURNING evidence_generation").bind(mesh).bind(binding).bind(peer).bind(version).fetch_one(store.pool()).await.unwrap();
    let same: Uuid = sqlx::query_scalar("UPDATE route_advertisements SET sequence=2,updated_at=clock_timestamp() WHERE mesh_id=$1 AND binding_id=$2 RETURNING evidence_generation").bind(mesh).bind(binding).fetch_one(store.pool()).await.unwrap();
    assert_eq!(first, same, "periodic route refresh is the same condition");
    sqlx::query(
        "UPDATE route_advertisements SET forwarding_ready=true WHERE mesh_id=$1 AND binding_id=$2",
    )
    .bind(mesh)
    .bind(binding)
    .execute(store.pool())
    .await
    .unwrap();
    let again: Uuid = sqlx::query_scalar("UPDATE route_advertisements SET forwarding_ready=false WHERE mesh_id=$1 AND binding_id=$2 RETURNING evidence_generation").bind(mesh).bind(binding).fetch_one(store.pool()).await.unwrap();
    assert_ne!(
        first, again,
        "path failure after recovery reopens acknowledgement"
    );
}
