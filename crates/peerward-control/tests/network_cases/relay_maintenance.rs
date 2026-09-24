use super::*;

async fn tick(store: &Store, id: Uuid) {
    sqlx::query("UPDATE maintenance_tasks SET next_attempt_at=clock_timestamp()-interval '1 second' WHERE id=$1")
        .bind(id).execute(store.pool()).await.unwrap();
    peerward_control::advance_maintenance_tasks(store)
        .await
        .unwrap();
}
async fn item(app: &Router, id: Uuid) -> Value {
    json_body(
        request(
            app,
            "GET",
            &format!("/api/v1/maintenance-tasks/{id}"),
            None,
            Value::Null,
        )
        .await,
    )
    .await
}
async fn published(store: &Store, mesh: Uuid) {
    // Database transaction tests only. The product gate uses actual signatures and hosts.
    sqlx::query("INSERT INTO signed_state_revisions(mesh_id,kind,revision,body)
        SELECT id,'relays',relay_revision,decode('01','hex') FROM meshes WHERE id=$1 ON CONFLICT DO NOTHING")
        .bind(mesh).execute(store.pool()).await.unwrap();
}
async fn ack(store: &Store, host: Uuid, state: &str) {
    sqlx::query("UPDATE relay_host_assignments SET state=$2,applied_revision=revision,observed_at=clock_timestamp() WHERE host_id=$1")
        .bind(host).bind(state).execute(store.pool()).await.unwrap();
}

pub async fn verify(store: &Store, app: &Router, mesh: Uuid) {
    let source = Uuid::new_v4();
    let replacement = Uuid::new_v4();
    for (id, default) in [(source, true), (replacement, false)] {
        sqlx::query("INSERT INTO relay_hosts(id,name,certificate_sha256,peer_endpoints,backbone_endpoints,is_default,last_seen)
            VALUES($1,$2,$3,ARRAY['tcp://127.0.0.1:27777'],ARRAY['tcp://127.0.0.1:27778'],$4,clock_timestamp())")
            .bind(id).bind(id.to_string()).bind(id.as_bytes().repeat(2)).bind(default).execute(store.pool()).await.unwrap();
    }
    let source_relay = Uuid::new_v4();
    let replacement_relay = Uuid::new_v4();
    let authority = Uuid::new_v4();
    sqlx::query("INSERT INTO mesh_authorities(id,mesh_id,serial,public_key,not_before,not_after,lifecycle,certificate)
        VALUES($1,$2,$3,$4,clock_timestamp()-interval '1 minute',clock_timestamp()+interval '1 day','active',$4)")
        .bind(authority).bind(mesh).bind(Uuid::new_v4()).bind(vec![77u8;32]).execute(store.pool()).await.unwrap();
    for (host, relay) in [(source, source_relay), (replacement, replacement_relay)] {
        sqlx::query("INSERT INTO relays(id,mesh_id,name,peer_endpoints,backbone_endpoints) VALUES($1,$2,$3,ARRAY['tcp://127.0.0.1:27777'],ARRAY['tcp://127.0.0.1:27778'])")
            .bind(relay).bind(mesh).bind(relay.to_string()).execute(store.pool()).await.unwrap();
        sqlx::query("INSERT INTO relay_host_assignments(host_id,mesh_id,relay_id,state,applied_revision,observed_at) VALUES($1,$2,$3,'ready',1,clock_timestamp())")
            .bind(host).bind(mesh).bind(relay).execute(store.pool()).await.unwrap();
        sqlx::query("INSERT INTO relay_credentials(id,mesh_id,relay_id,authority_id,serial,public_key,not_before,not_after,lifecycle,signature)
            VALUES($1,$2,$3,$4,$5,$6,clock_timestamp()-interval '1 minute',clock_timestamp()+interval '1 day','active',$7)")
            .bind(Uuid::new_v4()).bind(mesh).bind(relay).bind(authority).bind(Uuid::new_v4()).bind(vec![78u8;32]).bind(vec![79u8;64]).execute(store.pool()).await.unwrap();
        sqlx::query("INSERT INTO relay_runtime_leases(mesh_id,relay_id,instance_id,fencing_generation,lease_deadline) VALUES($1,$2,$3,1,clock_timestamp()+interval '1 hour')")
            .bind(mesh).bind(relay).bind(Uuid::new_v4()).execute(store.pool()).await.unwrap();
    }
    published(store, mesh).await;
    let path = "/api/v1/maintenance-tasks";
    let preview_path = format!("{path}/preview");
    let plan = json!({"operation":"relay_drain","host_id":source,"replacement_host_id":replacement,"grace_seconds":15});
    let preview = json_body(request(app, "POST", &preview_path, None, plan.clone()).await).await;
    assert_eq!(preview["blockers"], json!([]), "{preview}");
    let id = Uuid::new_v4();
    let body = json!({"id":id,"plan":plan,"preview_digest":preview["digest"]});
    sqlx::query("UPDATE relay_host_assignments SET observed_at=clock_timestamp()-interval '1 minute' WHERE host_id=$1")
        .bind(replacement).execute(store.pool()).await.unwrap();
    assert_eq!(
        request(app, "POST", path, None, body.clone())
            .await
            .status(),
        StatusCode::CONFLICT
    );
    ack(store, replacement, "ready").await;
    let (a, b) = tokio::join!(
        request(app, "POST", path, None, body.clone()),
        request(app, "POST", path, None, body.clone())
    );
    assert!([a.status(), b.status()].contains(&StatusCode::ACCEPTED));
    assert!([a.status(), b.status()].contains(&StatusCode::OK));
    let changed = json!({"id":id,"plan":body["plan"],"preview_digest":"0".repeat(64)});
    assert_eq!(
        request(app, "POST", path, None, changed).await.status(),
        StatusCode::CONFLICT
    );
    let current_default: Uuid = sqlx::query_scalar("SELECT id FROM relay_hosts WHERE is_default")
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(current_default, replacement);
    assert_eq!(
        request(
            app,
            "POST",
            &format!("/api/v1/meshes/{mesh}/relay-hosts"),
            None,
            json!({"host_id":source})
        )
        .await
        .status(),
        StatusCode::NOT_FOUND
    );
    tick(store, id).await;
    assert_eq!(item(app, id).await["stage"], "draining");
    tick(store, id).await;
    assert_eq!(item(app, id).await["status"], "waiting");
    // A stale applied revision cannot complete the operation, even beyond the grace period.
    sqlx::query("UPDATE maintenance_tasks SET grace_until=clock_timestamp()-interval '1 second' WHERE id=$1").bind(id).execute(store.pool()).await.unwrap();
    tick(store, id).await;
    assert_ne!(item(app, id).await["status"], "succeeded");
    ack(store, source, "draining").await;
    published(store, mesh).await;
    tick(store, id).await;
    assert_eq!(item(app, id).await["stage"], "suspending");
    ack(store, source, "suspended").await;
    published(store, mesh).await;
    tick(store, id).await;
    assert_eq!(
        item(app, id).await["error_code"],
        "runtime_lease_still_active"
    );
    sqlx::query("DELETE FROM relay_runtime_leases WHERE relay_id=$1")
        .bind(source_relay)
        .execute(store.pool())
        .await
        .unwrap();
    tick(store, id).await;
    assert_eq!(item(app, id).await["status"], "succeeded");
    assert_eq!(
        request(app, "POST", path, None, body).await.status(),
        StatusCode::OK
    );
    let plan = json!({"operation":"relay_resume","host_id":source,"replacement_host_id":null,"grace_seconds":15});
    let preview = json_body(request(app, "POST", &preview_path, None, plan.clone()).await).await;
    let resume = Uuid::new_v4();
    assert_eq!(
        request(
            app,
            "POST",
            path,
            None,
            json!({"id":resume,"plan":plan,"preview_digest":preview["digest"]})
        )
        .await
        .status(),
        StatusCode::ACCEPTED
    );
    tick(store, resume).await;
    assert_eq!(
        request(
            app,
            "POST",
            &format!("/api/v1/meshes/{mesh}/relay-hosts"),
            None,
            json!({"host_id":source})
        )
        .await
        .status(),
        StatusCode::NOT_FOUND,
        "restoring a host cannot silently expand its reviewed assignment scope"
    );
    sqlx::query(
        "UPDATE maintenance_tasks SET deadline=clock_timestamp()-interval '1 second' WHERE id=$1",
    )
    .bind(resume)
    .execute(store.pool())
    .await
    .unwrap();
    tick(store, resume).await;
    let failed = item(app, resume).await;
    assert_eq!(failed["status"], "failed");
    let retry = format!("{path}/{resume}/retry");
    assert_eq!(
        request(app, "POST", &retry, Some(1), Value::Null)
            .await
            .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        request(app, "POST", &retry, failed["version"].as_u64(), Value::Null)
            .await
            .status(),
        StatusCode::OK
    );
    // A current ack alone does not substitute for a running, signed Relay.
    ack(store, source, "ready").await;
    published(store, mesh).await;
    tick(store, resume).await;
    assert_eq!(item(app, resume).await["status"], "waiting");
    sqlx::query("INSERT INTO relay_runtime_leases(mesh_id,relay_id,instance_id,fencing_generation,lease_deadline) VALUES($1,$2,$3,2,clock_timestamp()+interval '1 hour')")
        .bind(mesh).bind(source_relay).bind(Uuid::new_v4()).execute(store.pool()).await.unwrap();
    sqlx::query("UPDATE relay_credentials SET lifecycle='revoked' WHERE relay_id=$1")
        .bind(source_relay)
        .execute(store.pool())
        .await
        .unwrap();
    published(store, mesh).await;
    tick(store, resume).await;
    assert_eq!(
        item(app, resume).await["status"],
        "waiting",
        "a ready runtime with a revoked credential cannot resume"
    );
    sqlx::query("INSERT INTO relay_credentials(id,mesh_id,relay_id,authority_id,serial,public_key,not_before,not_after,lifecycle,signature)
        VALUES($1,$2,$3,$4,$5,$6,clock_timestamp()-interval '1 minute',clock_timestamp()+interval '1 day','active',$7)")
        .bind(Uuid::new_v4()).bind(mesh).bind(source_relay).bind(authority).bind(Uuid::new_v4()).bind(vec![80u8;32]).bind(vec![81u8;64])
        .execute(store.pool()).await.unwrap();
    published(store, mesh).await;
    tick(store, resume).await;
    assert_eq!(item(app, resume).await["status"], "succeeded");
    let revoked: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM relay_credentials WHERE mesh_id=$1 AND lifecycle='revoked'",
    )
    .bind(mesh)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(
        revoked, 1,
        "a replacement credential does not reactivate the revoked serial"
    );
    let events: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_log WHERE target_id IN ($1,$2) AND action LIKE 'maintenance.%'",
    )
    .bind(id)
    .bind(resume)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert!(events >= 7);
}
