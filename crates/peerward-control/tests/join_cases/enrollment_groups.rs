async fn group_invite(
    app: &axum::Router,
    base: &str,
    groups: Value,
    mode: &str,
) -> (StatusCode, Value) {
    request_json(app, "POST", &format!("{base}/join-tickets"), json!({
        "expires_in_seconds":300,"settings":{"device_groups":groups,"display_name":"分组设备","mode":{"kind":mode}}
    }), None, true).await
}

async fn enrollment_group(app: &axum::Router, base: &str, kind: &str) -> Value {
    let (status, group) = request_json(
        app,
        "POST",
        &format!("{base}/collections"),
        json!({"id":Uuid::new_v4(),"definition":{"name":Uuid::new_v4().to_string(),"kind":kind,"members":[],"labels":{}}}),
        None,
        true,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{group}");
    group
}

async fn exercise_enrollment_groups(
    store: &Store,
    app: &axum::Router,
    mesh: peerward_types::MeshId,
) {
    let base = format!("/api/v1/meshes/{mesh}");
    let a = enrollment_group(app, &base, "devices").await;
    let b = enrollment_group(app, &base, "devices").await;
    let resources = enrollment_group(app, &base, "resources").await;
    for ids in [
        json!([Uuid::new_v4()]),
        json!([resources["id"]]),
        json!([Uuid::nil()]),
    ] {
        assert_eq!(
            group_invite(app, &base, ids, "bearer").await.0,
            StatusCode::BAD_REQUEST
        );
    }
    // A valid device group in another mesh cannot be selected.
    let other = store
        .create_mesh(
            &NewMesh {
                name: "other-group-mesh".into(),
                address_cidr: "10.96.0.0/24".parse().unwrap(),
                gateway: "10.96.0.1".parse().unwrap(),
                dns_suffix: "groups.test".into(),
                mtu: 1380,
                reserved: vec![],
                default_policy: DefaultPolicy::Deny,
                quarantine_seconds: 60,
                rotation_overlap_seconds: 3600,
            },
            "admin",
        )
        .await
        .unwrap();
    let foreign = enrollment_group(app, &format!("/api/v1/meshes/{}", other.id), "devices").await;
    assert_eq!(
        group_invite(app, &base, json!([foreign["id"]]), "bearer")
            .await
            .0,
        StatusCode::BAD_REQUEST
    );

    let (status, ticket) = group_invite(app, &base, json!([a["id"], b["id"]]), "approval").await;
    assert_eq!(status, StatusCode::CREATED, "{ticket}");
    let token = ticket["token"].as_str().unwrap();
    let path = format!("/api/v1/join/{token}/claim");
    let claim = claim_document(token, 150);
    let (status, pending) = request_json(app, "POST", &path, claim.clone(), None, false).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let (_, current) = request_json(
        app,
        "GET",
        &format!("{base}/collections/{}", a["id"].as_str().unwrap()),
        Value::Null,
        None,
        true,
    )
    .await;
    assert_eq!(
        current["definition"]["members"],
        json!([]),
        "no group membership before approval"
    );
    let approval = &pending["application"];
    let (status, joined) = request_json(
        app,
        "POST",
        &format!(
            "{base}/join-applications/{}/approve",
            approval["id"].as_str().unwrap()
        ),
        json!({"identity_fingerprint":approval["identity_fingerprint"]}),
        approval["version"].as_u64(),
        true,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{joined}");
    let (_, joined) = request_json(app, "POST", &path, claim.clone(), None, false).await;
    let peer = joined["peer_id"].as_str().unwrap();
    for group in [&a, &b] {
        let (_, current) = request_json(
            app,
            "GET",
            &format!("{base}/collections/{}", group["id"].as_str().unwrap()),
            Value::Null,
            None,
            true,
        )
        .await;
        assert_eq!(current["definition"]["members"], json!([peer]));
    }
    // Simultaneous bearer enrollments merge into the current membership.
    let (_, first) = group_invite(app, &base, json!([a["id"]]), "bearer").await;
    let (_, second) = group_invite(app, &base, json!([a["id"]]), "bearer").await;
    let first_path = format!("/api/v1/join/{}/claim", first["token"].as_str().unwrap());
    let second_path = format!("/api/v1/join/{}/claim", second["token"].as_str().unwrap());
    let (x, y) = tokio::join!(
        request_json(
            app,
            "POST",
            &first_path,
            claim_document(first["token"].as_str().unwrap(), 155),
            None,
            false
        ),
        request_json(
            app,
            "POST",
            &second_path,
            claim_document(second["token"].as_str().unwrap(), 160),
            None,
            false
        )
    );
    assert_eq!(x.0, StatusCode::CREATED, "{}", x.1);
    assert_eq!(y.0, StatusCode::CREATED, "{}", y.1);
    let (_, current) = request_json(
        app,
        "GET",
        &format!("{base}/collections/{}", a["id"].as_str().unwrap()),
        Value::Null,
        None,
        true,
    )
    .await;
    let members = current["definition"]["members"].as_array().unwrap();
    assert_eq!(members.len(), 3);
    assert!(
        members.contains(&json!(peer))
            && members.contains(&x.1["peer_id"])
            && members.contains(&y.1["peer_id"])
    );
    assert_group_grant_preview(store, app, mesh, &a, peer).await;
    assert_resource_group_preview(store, app, mesh, &a).await;

    // A group disappearing after issuance rolls back enrollment, including the
    // earlier valid group in the same ticket and any allocated identity/address.
    let gone = enrollment_group(app, &base, "devices").await;
    let (_, ticket) = group_invite(app, &base, json!([b["id"], gone["id"]]), "bearer").await;
    assert_eq!(
        request_json(
            app,
            "DELETE",
            &format!("{base}/collections/{}", gone["id"].as_str().unwrap()),
            Value::Null,
            gone["version"].as_u64(),
            true
        )
        .await
        .0,
        StatusCode::NO_CONTENT
    );
    let counts_before = enrollment_counts(store, mesh).await;
    let failed_path = format!("/api/v1/join/{}/claim", ticket["token"].as_str().unwrap());
    assert!(
        !request_json(
            app,
            "POST",
            &failed_path,
            claim_document(ticket["token"].as_str().unwrap(), 165),
            None,
            false
        )
        .await
        .0
        .is_success()
    );
    assert_eq!(enrollment_counts(store, mesh).await, counts_before);
    let consumed: bool =
        sqlx::query_scalar("SELECT consumed_at IS NOT NULL FROM join_tickets WHERE id=$1")
            .bind(Uuid::parse_str(ticket["id"].as_str().unwrap()).unwrap())
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert!(!consumed);
    // Successful replay remains idempotent even after an administrator removes a group.
    assert_eq!(
        request_json(
            app,
            "DELETE",
            &format!("{base}/collections/{}", b["id"].as_str().unwrap()),
            Value::Null,
            Some(2),
            true
        )
        .await
        .0,
        StatusCode::NO_CONTENT
    );
    let (_, replay) = request_json(app, "POST", &path, claim, None, false).await;
    assert_eq!(replay, joined);
}

async fn enrollment_counts(store: &Store, mesh: peerward_types::MeshId) -> (i64, i64, i64) {
    sqlx::query_as("SELECT (SELECT count(*) FROM peers WHERE mesh_id=$1),(SELECT count(*) FROM peer_addresses WHERE mesh_id=$1),(SELECT count(*) FROM peer_credentials WHERE mesh_id=$1)").bind(mesh.into_uuid()).fetch_one(store.pool()).await.unwrap()
}

async fn assert_group_grant_preview(
    store: &Store,
    app: &axum::Router,
    mesh: peerward_types::MeshId,
    group: &Value,
    peer: &str,
) {
    let service = Uuid::new_v4();
    let group_id = Uuid::parse_str(group["id"].as_str().unwrap()).unwrap();
    sqlx::query("INSERT INTO services(id,mesh_id,peer_id,display_name,protocols,listen_port) VALUES($1,$2,$3,'分组 NAS',ARRAY['tcp','udp'],445)")
        .bind(service).bind(mesh.into_uuid()).bind(Uuid::parse_str(peer).unwrap()).execute(store.pool()).await.unwrap();
    sqlx::query("INSERT INTO console_service_grants(mesh_id,id,service_id,source,source_collections) VALUES($1,$2,$3,$4,$5)")
        .bind(mesh.into_uuid()).bind(Uuid::new_v4()).bind(service).bind(json!({"peers":[],"labels":{},"cidrs":[]})).bind(vec![group_id]).execute(store.pool()).await.unwrap();
    let (status, preview) = request_json(
        app,
        "GET",
        &format!("/api/v1/meshes/{mesh}/console/enrollment-groups"),
        Value::Null,
        None,
        true,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{preview}");
    let grants = &preview
        .as_array()
        .unwrap()
        .iter()
        .find(|value| value["id"] == group["id"])
        .unwrap()["grants"];
    assert_eq!(
        *grants,
        json!([
            {"name":"分组 NAS","protocol":6,"destination_ports":[[445,445]],"conditional":false},
            {"name":"分组 NAS","protocol":17,"destination_ports":[[445,445]],"conditional":false}
        ])
    );
}

async fn assert_purpose_migration(store: &Store, app: &axum::Router, mesh: peerward_types::MeshId) {
    let ticket = new_invite(app, mesh, json!({"kind":"bearer"}), "legacy-purpose-device").await;
    let id = Uuid::parse_str(ticket["id"].as_str().unwrap()).unwrap();
    // Restore the exact predecessor's columns/function, retaining real issued
    // tickets and existing identities, then exercise the forward migration.
    sqlx::raw_sql("ALTER TABLE public.peers ADD COLUMN purpose text CHECK(purpose IN ('personal','managed','service','test'));
        CREATE OR REPLACE FUNCTION public.peerward_peer_api_json(peer public.peers) RETURNS jsonb
        LANGUAGE sql STABLE SET search_path=pg_catalog,public,pg_temp AS $$
        SELECT public.peerward_peer_api_json_before_purpose(peer) || jsonb_build_object('purpose',peer.purpose) $$;
        DELETE FROM public.peerward_schema_migrations WHERE version=54;
        UPDATE public.peers SET purpose='personal';")
        .execute(store.pool()).await.unwrap();
    sqlx::query("UPDATE join_tickets SET settings=settings || '{\"purpose\":\"managed\"}'::jsonb WHERE id=$1")
        .bind(id).execute(store.pool()).await.unwrap();
    let before: Value =
        sqlx::query_scalar("SELECT settings-'purpose' FROM join_tickets WHERE id=$1")
            .bind(id)
            .fetch_one(store.pool())
            .await
            .unwrap();
    store.migrate().await.unwrap();
    let after: Value = sqlx::query_scalar("SELECT settings FROM join_tickets WHERE id=$1")
        .bind(id)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(after, before);
    let token = ticket["token"].as_str().unwrap();
    let (status, joined) = request_json(
        app,
        "POST",
        &format!("/api/v1/join/{token}/claim"),
        claim_document(token, 175),
        None,
        false,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{joined}");
    assert_device_information(app, mesh, &joined).await;
}

async fn assert_resource_group_preview(
    store: &Store,
    app: &axum::Router,
    mesh: peerward_types::MeshId,
    group: &Value,
) {
    let resource = Uuid::new_v4();
    let targets = Uuid::new_v4();
    sqlx::query("INSERT INTO network_resources(id,mesh_id,definition) VALUES($1,$2,$3)")
        .bind(resource).bind(mesh.into_uuid()).bind(json!({"name":"打印机","target":{"kind":"subnet","prefix":"192.168.75.12/32","site_id":Uuid::new_v4()}}))
        .execute(store.pool()).await.unwrap();
    sqlx::query("INSERT INTO network_collections(id,mesh_id,definition) VALUES($1,$2,$3)")
        .bind(targets)
        .bind(mesh.into_uuid())
        .bind(json!({"name":"共享目标","kind":"resources","members":[resource],"labels":{}}))
        .execute(store.pool())
        .await
        .unwrap();
    for (enabled, action, until) in [
        (true, "allow", None),
        (false, "allow", None),
        (true, "deny", None),
        (true, "allow", Some(1_u64)),
    ] {
        let id = Uuid::new_v4();
        let rule = json!({"id":id,"priority":1000,"enabled":enabled,"action":action,"source":{"peers":[],"labels":{"site":"home"},"cidrs":[]},"source_collections":[group["id"]],"resources":[],"resource_collections":[targets],"providers":[],"protocol":6,"destination_ports":[[9100,9100]],"not_after":until});
        sqlx::query("INSERT INTO resource_rules(id,mesh_id,rule) VALUES($1,$2,$3)")
            .bind(id)
            .bind(mesh.into_uuid())
            .bind(rule)
            .execute(store.pool())
            .await
            .unwrap();
    }
    let endpoint = format!("/api/v1/meshes/{mesh}/console/enrollment-groups");
    assert_eq!(
        request_json(app, "GET", &endpoint, Value::Null, None, false)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    let (status, preview) = request_json(app, "GET", &endpoint, Value::Null, None, true).await;
    assert_eq!(status, StatusCode::OK, "{preview}");
    let grants = preview
        .as_array()
        .unwrap()
        .iter()
        .find(|value| value["id"] == group["id"])
        .unwrap()["grants"]
        .as_array()
        .unwrap();
    assert_eq!(
        grants.len(),
        3,
        "two service transports and one enabled resource allow rule"
    );
    assert!(grants.contains(
        &json!({"name":"打印机","protocol":6,"destination_ports":[[9100,9100]],"conditional":true})
    ));
    assert!(
        preview
            .as_array()
            .unwrap()
            .iter()
            .all(|value| value["id"] != json!(targets)),
        "resource collections are not selectable device groups"
    );
}
