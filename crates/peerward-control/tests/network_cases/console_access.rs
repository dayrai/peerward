use super::console::ok;
use super::*;

pub async fn verify(store: &Store, app: &Router, base: &str, peers: &[Uuid], resource: Uuid) {
    let path = format!("{base}/console/network-resources/{resource}/grants");
    let rules = ok(
        app,
        "GET",
        &format!("{base}/resource-policy"),
        None,
        Value::Null,
    )
    .await;
    let page = ok(app, "GET", &path, None, Value::Null).await;
    let grant = &page["items"][0];
    assert_eq!(grant["advanced"], false);
    assert_eq!(grant["protocol"], 6);
    assert_eq!(grant["destination_ports"], json!([[631, 631]]));
    let id = grant["id"].as_str().unwrap();
    let target = format!("{path}/{id}");
    let simulation = json!({"source":{"kind":"peer","id":peers[0]},"targets":[{"kind":"network","id":resource,"address":"192.168.245.10","provider":peers[1],"protocol":6,"port":631}]});
    for enabled in [false, true] {
        let current = ok(app, "GET", &path, None, Value::Null).await;
        ok(
            app,
            "PUT",
            &target,
            current["items"][0]["version"].as_u64(),
            json!({"enabled":enabled,"reason":"reviewed source change"}),
        )
        .await;
        let result = ok(
            app,
            "POST",
            &format!("{base}/console/matrix"),
            None,
            simulation.clone(),
        )
        .await;
        assert_eq!(
            result["cells"][0]["outcome"],
            if enabled { "allowed" } else { "denied" }
        );
    }
    assert_eq!(
        request(
            app,
            "PUT",
            &target,
            grant["version"].as_u64(),
            json!({"enabled":false,"reason":"stale"})
        )
        .await
        .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        ok(
            app,
            "GET",
            &format!("{base}/resource-policy"),
            None,
            Value::Null
        )
        .await["document"],
        rules["document"],
        "restoring only enabled preserves every existing rule and condition"
    );
    let other = format!(
        "{base}/console/network-resources/{}/grants/{id}",
        Uuid::new_v4()
    );
    let fresh = ok(app, "GET", &path, None, Value::Null).await;
    assert_eq!(
        request(
            app,
            "PUT",
            &other,
            fresh["items"][0]["version"].as_u64(),
            json!({"enabled":false,"reason":"wrong target"})
        )
        .await
        .status(),
        StatusCode::NOT_FOUND
    );
    let foreign = format!(
        "/api/v1/meshes/{}/console/network-resources/{resource}/grants",
        Uuid::new_v4()
    );
    assert_eq!(
        request(app, "GET", &foreign, None, Value::Null)
            .await
            .status(),
        StatusCode::NOT_FOUND
    );

    // A deny or multi-target rule cannot silently become a simple allow grant.
    let mut advanced = rules["document"].clone();
    advanced["rules"][0]["providers"] = json!([peers[1]]);
    let current = ok(
        app,
        "GET",
        &format!("{base}/resource-policy"),
        None,
        Value::Null,
    )
    .await;
    ok(
        app,
        "PUT",
        &format!("{base}/resource-policy"),
        current["version"].as_u64(),
        advanced,
    )
    .await;
    let page = ok(app, "GET", &path, None, Value::Null).await;
    assert_eq!(page["items"][0]["advanced"], true);
    assert_eq!(
        request(
            app,
            "PUT",
            &target,
            page["items"][0]["version"].as_u64(),
            json!({"enabled":false,"reason":"unsafe simplification"})
        )
        .await
        .status(),
        StatusCode::CONFLICT
    );
    let current = ok(
        app,
        "GET",
        &format!("{base}/resource-policy"),
        None,
        Value::Null,
    )
    .await;
    ok(
        app,
        "PUT",
        &format!("{base}/resource-policy"),
        current["version"].as_u64(),
        rules["document"].clone(),
    )
    .await;

    let service = Uuid::new_v4();
    let draft = json!({"request_id":service,"name":"Transport-specific","provider":peers[1],"target":{"kind":"service","protocols":["tcp","udp"],"port":19999,"alias":null},"source":{"kind":"none"},"protocol":6,"port":19999,"reason":"conditional simulation"});
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
    let old = ok(app, "GET", &format!("{base}/policy"), None, Value::Null).await;
    let mut policy = old.clone();
    policy["revision"] = json!(old["revision"].as_u64().unwrap() + 1);
    policy["rules"].as_array_mut().unwrap().push(json!({"id":Uuid::new_v4(),"priority":42,"action":"allow","enabled":true,"log":false,"source":{"peer_ids":[peers[0]],"labels":{},"cidrs":[]},"destination":{"peer_ids":[peers[1]],"labels":{},"cidrs":[]},"protocol":"tcp","destination_ports":[{"first":19999,"last":19999}]}));
    ok(
        app,
        "PUT",
        &format!("{base}/policy"),
        old["revision"].as_u64(),
        policy,
    )
    .await;
    let matrix_path = format!("{base}/console/matrix");
    for (protocol, outcome) in [
        (None, "partial"),
        (Some(6), "allowed"),
        (Some(17), "denied"),
    ] {
        let result=ok(app,"POST",&matrix_path,None,json!({"source":{"kind":"peer","id":peers[0]},"targets":[{"kind":"service","id":service,"protocol":protocol,"address":"10.125.0.3"}]})).await;
        assert_eq!(result["cells"][0]["outcome"], outcome);
    }
    for (protocol, address) in [(6, "10.125.0.222"), (1, "10.125.0.3")] {
        assert_eq!(request(app,"POST",&matrix_path,None,json!({"source":{"kind":"peer","id":peers[0]},"targets":[{"kind":"service","id":service,"protocol":protocol,"address":address}]})).await.status(),StatusCode::BAD_REQUEST);
    }
    let mesh = Uuid::parse_str(base.rsplit('/').next().unwrap()).unwrap();
    let audited:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM audit_log WHERE mesh_id=$1::uuid AND action='sharing.grant.state' AND metadata->>'reason'='reviewed source change')").bind(mesh).fetch_one(store.pool()).await.unwrap();
    assert!(audited);
}
