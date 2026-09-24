async fn request_json(
    app: &axum::Router,
    method: &str,
    path: &str,
    body: Value,
    version: Option<u64>,
    admin: bool,
) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json");
    if admin {
        request = request.header("authorization", "Bearer rotation-admin");
    }
    if let Some(version) = version {
        request = request.header("if-match", format!("\"{version}\""));
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap()
        },
    )
}
fn claim_document(token: &str, seed: u8) -> Value {
    let identity = SigningKey::from_bytes(&[seed; 32]);
    let public = identity.verifying_key().to_bytes();
    let claim = Uuid::new_v4();
    let nonce = [seed; 32];
    let proof = JoinClaimProof {
        schema_version: 2,
        claim_id: claim,
        ticket_digest: secret_digest(&URL_SAFE_NO_PAD.decode(token).unwrap()),
        identity_public_key: public,
        session_public_key: [seed.wrapping_add(1); 32],
        wireguard_public_key: [seed.wrapping_add(2); 32],
        client_version: "1.0.0-test",
        supported_wire_major: peerward_wire::PROTOCOL_MAJOR,
        nonce: &nonce,
        device_name: "Requested device",
        device_model: "test",
        platform: "linux",
        platform_version: "test",
    };
    let signature = sign_join_claim(&identity.to_bytes(), &proof).unwrap();
    json!({"schema_version":2,"claim_id":claim,"identity_public_key":URL_SAFE_NO_PAD.encode(public),
        "session_public_key":URL_SAFE_NO_PAD.encode(proof.session_public_key),"wireguard_public_key":URL_SAFE_NO_PAD.encode(proof.wireguard_public_key),
        "client_version":proof.client_version,"supported_wire_major":proof.supported_wire_major,"nonce":URL_SAFE_NO_PAD.encode(nonce),
        "device_name":proof.device_name,"device_model":proof.device_model,"platform":proof.platform,"platform_version":proof.platform_version,
        "signature":URL_SAFE_NO_PAD.encode(signature)})
}
async fn new_invite(
    app: &axum::Router,
    mesh: peerward_types::MeshId,
    mode: Value,
    name: &str,
) -> Value {
    let (status, ticket) = request_json(
        app,
        "POST",
        &format!("/api/v1/meshes/{mesh}/join-tickets"),
        json!({"expires_in_seconds":300,
        "settings":{"name":name,"display_name":"小明的笔记本",
            "platform_hint":"android","labels":{"group":"finance"},"mode":mode}}),
        None,
        true,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{ticket}");
    assert!(
        OffsetDateTime::parse(
            ticket["expires_at"].as_str().unwrap(),
            &time::format_description::well_known::Rfc3339
        )
        .is_ok()
    );
    ticket
}
async fn exercise_controlled_join(store: &Store, app: &axum::Router, mesh: peerward_types::MeshId) {
    let ticket = new_invite(app, mesh, json!({"kind":"approval"}), "approved-device").await;
    let token = ticket["token"].as_str().unwrap();
    let path = format!("/api/v1/join/{token}/claim");
    let first = claim_document(token, 40);
    let second = claim_document(token, 44);
    let (a, b) = tokio::join!(
        request_json(app, "POST", &path, first.clone(), None, false),
        request_json(app, "POST", &path, second.clone(), None, false)
    );
    let (pending, accepted, rejected) = if a.0 == StatusCode::ACCEPTED {
        (a.1, first, second)
    } else {
        (b.1, second, first)
    };
    assert!(
        (a.0 == StatusCode::ACCEPTED && b.0 == StatusCode::CONFLICT)
            || (b.0 == StatusCode::ACCEPTED && a.0 == StatusCode::CONFLICT)
    );
    assert!(
        pending.get("credential").is_none()
            && pending.get("address").is_none()
            && pending.get("relays").is_none()
    );
    let count:(i64,i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM peers WHERE mesh_id=$1),(SELECT count(*) FROM peer_addresses WHERE mesh_id=$1),(SELECT count(*) FROM peer_credentials WHERE mesh_id=$1)")
        .bind(mesh.into_uuid()).fetch_one(store.pool()).await.unwrap();
    assert_eq!(count, (0, 0, 0));
    let stored: Value =
        sqlx::query_scalar("SELECT request_document FROM join_applications WHERE ticket_id=$1")
            .bind(Uuid::parse_str(ticket["id"].as_str().unwrap()).unwrap())
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert!(stored.get("token").is_none());
    let (status, replay) = request_json(app, "POST", &path, accepted.clone(), None, false).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(replay, pending, "polling cannot change deadline/version");
    let application = &pending["application"];
    let id = application["id"].as_str().unwrap();
    let endpoint = format!("/api/v1/meshes/{mesh}/join-applications/{id}/approve");
    let approval = json!({"identity_fingerprint":application["identity_fingerprint"]});
    let no_issuer = peerward_control::router(
        store.clone(),
        AuthConfig {
            oidc: None,
            development_bearer_token: Some("rotation-admin".into()),
            bootstrap_token: None,
        },
    );
    assert_eq!(
        request_json(
            &no_issuer,
            "POST",
            &endpoint,
            approval.clone(),
            Some(1),
            true
        )
        .await
        .0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        request_json(app, "POST", &endpoint, approval.clone(), Some(1), false)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        request_json(app, "POST", &endpoint, approval.clone(), Some(99), true)
            .await
            .0,
        StatusCode::CONFLICT
    );
    assert!(
        !request_json(
            app,
            "POST",
            &endpoint,
            json!({"identity_fingerprint":"0".repeat(64)}),
            Some(1),
            true
        )
        .await
        .0
        .is_success()
    );
    // The invitation can expire while its independently bounded request awaits review.
    sqlx::query(
        "UPDATE join_tickets SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1",
    )
    .bind(Uuid::parse_str(ticket["id"].as_str().unwrap()).unwrap())
    .execute(store.pool())
    .await
    .unwrap();
    let (a, b) = tokio::join!(
        request_json(app, "POST", &endpoint, approval.clone(), Some(1), true),
        request_json(app, "POST", &endpoint, approval.clone(), Some(1), true)
    );
    assert_eq!(a.0, StatusCode::OK, "{}", a.1);
    assert_eq!(a, b);
    assert_eq!(a.1["status"], "approved");
    assert_eq!(
        request_json(
            &no_issuer,
            "POST",
            &endpoint,
            approval.clone(),
            Some(1),
            true
        )
        .await,
        a,
        "committed approval replay does not depend on an available online issuer"
    );
    let (status, joined) = request_json(app, "POST", &path, accepted.clone(), None, false).await;
    assert_eq!(status, StatusCode::CREATED, "{joined}");
    assert!(joined["secondary_address"].is_string());
    assert_eq!(
        request_json(app, "POST", &path, accepted, None, false)
            .await
            .1,
        joined
    );
    assert_eq!(
        request_json(app, "POST", &path, rejected, None, false)
            .await
            .0,
        StatusCode::CONFLICT
    );
    let row: (String, Value) = sqlx::query_as("SELECT name,labels FROM peers WHERE id=$1")
        .bind(Uuid::parse_str(joined["peer_id"].as_str().unwrap()).unwrap())
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(row.0, "approved-device");
    assert_eq!(row.1["group"], "finance");
    assert_eq!(row.1["platform"], "linux");
    assert_device_information(app, mesh, &joined).await;
    let audits: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_log WHERE target_id=$1 AND action='join.application.approve'",
    )
    .bind(Uuid::parse_str(id).unwrap())
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(audits, 1);
    for (index, operation) in ["reject", "expire", "cancel"].into_iter().enumerate() {
        let ticket = new_invite(
            app,
            mesh,
            json!({"kind":"approval"}),
            &format!("{operation}-device"),
        )
        .await;
        let token = ticket["token"].as_str().unwrap();
        let path = format!("/api/v1/join/{token}/claim");
        let claim = claim_document(token, 60 + u8::try_from(index).unwrap() * 4);
        let (_, pending) = request_json(app, "POST", &path, claim.clone(), None, false).await;
        let id = pending["application"]["id"].as_str().unwrap();
        let filtered_path = format!(
            "/api/v1/meshes/{mesh}/join-applications?ticket={}&limit=1",
            ticket["id"].as_str().unwrap()
        );
        let (status, page) =
            request_json(app, "GET", &filtered_path, Value::Null, None, true).await;
        assert_eq!(status, StatusCode::OK, "{page}");
        assert_eq!(page["items"].as_array().unwrap().len(), 1);
        assert_eq!(
            page["items"][0]["id"], id,
            "filter must run before pagination across older history"
        );
        assert!(page["next_cursor"].is_null());
        assert_eq!(
            request_json(app, "GET", &filtered_path, Value::Null, None, false)
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );
        let (status, foreign) = request_json(
            app,
            "GET",
            &format!(
                "/api/v1/meshes/{}/join-applications?ticket={}&limit=1",
                Uuid::new_v4(),
                ticket["id"].as_str().unwrap()
            ),
            Value::Null,
            None,
            true,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            foreign["items"].as_array().unwrap().is_empty(),
            "ticket filter cannot cross the mesh boundary"
        );
        let detail = format!("/api/v1/meshes/{mesh}/join-applications/{id}");
        match operation {
            "reject" => {
                let endpoint = format!("{detail}/reject");
                let a = request_json(app, "POST", &endpoint, json!({}), Some(1), true).await;
                assert_eq!(a.0, StatusCode::OK, "{}", a.1);
                assert_eq!(
                    request_json(app, "POST", &endpoint, json!({}), Some(1), true).await,
                    a
                );
            }
            "expire" => {
                sqlx::query("UPDATE join_applications SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1").bind(Uuid::parse_str(id).unwrap()).execute(store.pool()).await.unwrap();
            }
            _ => {
                let endpoint = format!(
                    "/api/v1/meshes/{mesh}/join-tickets/{}",
                    ticket["id"].as_str().unwrap()
                );
                assert_eq!(
                    request_json(app, "DELETE", &endpoint, json!({}), Some(2), true)
                        .await
                        .0,
                    StatusCode::NO_CONTENT
                );
            }
        }
        assert_eq!(
            request_json(app, "POST", &path, claim, None, false).await.0,
            StatusCode::CONFLICT
        );
        assert_eq!(
            request_json(app, "POST", &path, claim_document(token, 80), None, false)
                .await
                .0,
            StatusCode::CONFLICT
        );
        let (status, metadata) = request_json(app, "GET", &detail, Value::Null, None, true).await;
        assert_eq!(status, StatusCode::OK);
        let (_, issues) = request_json(
            app,
            "GET",
            &format!("/api/v1/meshes/{mesh}/console/issues?status=all"),
            Value::Null,
            None,
            true,
        )
        .await;
        assert!(
            !issues["items"]
                .as_array()
                .unwrap()
                .iter()
                .any(|issue| issue["kind"] == "join_pending" && issue["resource_id"] == id)
        );
        let (_, overview) = request_json(
            app,
            "GET",
            &format!("/api/v1/meshes/{mesh}/console/overview"),
            Value::Null,
            None,
            true,
        )
        .await;
        assert_eq!(
            overview["pending_applications"], 0,
            "terminal or expired applications must not remain pending"
        );
        assert_eq!(
            metadata["status"],
            match operation {
                "reject" => "rejected",
                "expire" => "expired",
                _ => "cancelled",
            }
        );
    }
    let bearer = new_invite(app, mesh, json!({"kind":"bearer"}), "bearer-profile").await;
    let token = bearer["token"].as_str().unwrap();
    let (status, joined) = request_json(
        app,
        "POST",
        &format!("/api/v1/join/{token}/claim"),
        claim_document(token, 87),
        None,
        false,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_device_information(app, mesh, &joined).await;
    let identity = SigningKey::from_bytes(&[90; 32]);
    let fingerprint = hex::encode(Sha256::digest(identity.verifying_key().to_bytes()));
    let ticket = new_invite(
        app,
        mesh,
        json!({"kind":"prebound","identity_fingerprint":fingerprint}),
        "prebound-device",
    )
    .await;
    let token = ticket["token"].as_str().unwrap();
    let path = format!("/api/v1/join/{token}/claim");
    assert!(
        !request_json(app, "POST", &path, claim_document(token, 91), None, false)
            .await
            .0
            .is_success()
    );
    assert_eq!(
        request_json(app, "POST", &path, claim_document(token, 90), None, false)
            .await
            .0,
        StatusCode::CREATED
    );
    let (status, history) = request_json(
        app,
        "GET",
        &format!("/api/v1/meshes/{mesh}/join-tickets?limit=100"),
        Value::Null,
        None,
        true,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{history}");
    assert!(
        history["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["status"] == "approved")
    );
    assert!(
        history["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["status"] == "cancelled")
    );
    let (status, applications) = request_json(
        app,
        "GET",
        &format!("/api/v1/meshes/{mesh}/join-applications?limit=2"),
        Value::Null,
        None,
        true,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{applications}");
    assert_eq!(applications["items"].as_array().unwrap().len(), 2);
    assert!(applications["next_cursor"].is_string());
}

async fn assert_device_information(
    app: &axum::Router,
    mesh: peerward_types::MeshId,
    joined: &Value,
) {
    let path = format!(
        "/api/v1/meshes/{mesh}/peers/{}",
        joined["peer_id"].as_str().unwrap()
    );
    let (status, peer) = request_json(app, "GET", &path, Value::Null, None, true).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(peer["display_name"], "小明的笔记本");
    assert!(peer.get("purpose").is_none());
    assert_eq!(
        peer["labels"]["platform"], "linux",
        "platform hint cannot override device report"
    );
    assert!(
        peer["labels"].get("purpose").is_none(),
        "purpose cannot become a policy selector"
    );
    let (status, changed) = request_json(
        app,
        "PATCH",
        &path,
        json!({"location":"书房"}),
        peer["version"].as_u64(),
        true,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(changed["location"], "书房");
    assert_eq!(changed["labels"], peer["labels"]);
    assert_eq!(changed["name"], peer["name"]);
}
