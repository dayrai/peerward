async fn admission_peer(
    app: &axum::Router,
    mesh: peerward_types::MeshId,
    kind: Value,
    seed: u8,
) -> Value {
    let (status,ticket)=request_json(app,"POST",&format!("/api/v1/meshes/{mesh}/join-tickets"),
        json!({"expires_in_seconds":300,"settings":{"name":format!("admission-{seed}"),"lifecycle":kind}}),None,true).await;
    assert_eq!(status, StatusCode::CREATED, "{ticket}");
    let token = ticket["token"].as_str().unwrap();
    let (status, joined) = request_json(
        app,
        "POST",
        &format!("/api/v1/join/{token}/claim"),
        claim_document(token, seed),
        None,
        false,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{joined}");
    joined
}

async fn exercise_device_admission(store: &Store, app: &axum::Router, issuer: &JoinIssuerConfig) {
    use peerward_credentials::{RotationRequestProof, SubjectCredential, sign_rotation_request};
    use peerward_types::{PeerId, RotationId};
    let mesh = issuer.mesh_id;
    let until = u64::try_from(OffsetDateTime::now_utc().unix_timestamp()).unwrap() + 600;
    let enrolled = admission_peer(
        app,
        mesh,
        json!({"kind":"expiring","valid_until":until}),
        80,
    )
    .await;
    let peer: PeerId = serde_json::from_value(enrolled["peer_id"].clone()).unwrap();
    let credential = SubjectCredential::decode(
        &URL_SAFE_NO_PAD
            .decode(enrolled["credential"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(credential.not_after, UnixTime(until));
    let (_, details) = request_json(
        app,
        "GET",
        &format!("/api/v1/meshes/{mesh}/peers/{peer}"),
        Value::Null,
        None,
        true,
    )
    .await;
    assert_eq!(
        details["admission"],
        json!({"kind":"expiring","valid_until":until})
    );
    let rotation = RotationId::new();
    let proof = RotationRequestProof {
        mesh_id: mesh,
        peer_id: peer,
        rotation_id: rotation,
        current_serial: credential.serial,
        identity_public_key: SigningKey::from_bytes(&[180; 32])
            .verifying_key()
            .to_bytes(),
        session_public_key: [181; 32],
        wireguard_public_key: [182; 32],
    };
    store
        .request_peer_rotation(
            rotation,
            mesh,
            peer,
            credential.serial,
            proof.identity_public_key,
            proof.session_public_key,
            proof.wireguard_public_key,
            sign_rotation_request(&[80; 32], &proof).unwrap(),
        )
        .await
        .unwrap();
    peerward_control::publish_enrollment_state(store, std::slice::from_ref(issuer))
        .await
        .unwrap();
    let replacement = store
        .issued_peer_rotation(mesh, peer, credential.serial)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        SubjectCredential::decode(&replacement.credential)
            .unwrap()
            .not_after,
        UnixTime(until)
    );
    assert!(sqlx::query("UPDATE peer_credentials SET not_after=$2+interval '1 second' WHERE mesh_id=$1 AND peer_id=$3")
        .bind(mesh.into_uuid()).bind(OffsetDateTime::from_unix_timestamp(i64::try_from(until).unwrap()).unwrap()).bind(peer.into_uuid()).execute(store.pool()).await.is_err());
    // Advance persisted cleanup fixtures, without claiming this changes signed bytes.
    sqlx::query("UPDATE peers SET admission_until=clock_timestamp()-interval '1 second' WHERE mesh_id=$1 AND id=$2")
        .bind(mesh.into_uuid()).bind(peer.into_uuid()).execute(store.pool()).await.unwrap();
    assert_eq!(store.expire_device_admissions(50).await.unwrap(), 1);
    assert_eq!(store.expire_device_admissions(50).await.unwrap(), 0);
    assert_retired(store, mesh, peer, "expired").await;
    let (_, details) = request_json(
        app,
        "GET",
        &format!("/api/v1/meshes/{mesh}/peers/{peer}"),
        Value::Null,
        None,
        true,
    )
    .await;
    let (status, error) = request_json(
        app,
        "PATCH",
        &format!("/api/v1/meshes/{mesh}/peers/{peer}"),
        json!({"administrative_state":"enabled"}),
        details["version"].as_u64(),
        true,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(error["error"]["code"], "device_admission_ended");
    exercise_ephemeral_admission(store, app, issuer).await;
}

async fn assert_retired(
    store: &Store,
    mesh: peerward_types::MeshId,
    peer: peerward_types::PeerId,
    reason: &str,
) {
    let row:(String,String,i64,i64,i64)=sqlx::query_as("SELECT p.administrative_state,p.admission_end_reason,
        (SELECT count(*) FROM peer_credentials c WHERE c.mesh_id=p.mesh_id AND c.peer_id=p.id AND c.lifecycle<>'revoked'),
        (SELECT count(*) FROM peer_addresses a WHERE a.mesh_id=p.mesh_id AND a.peer_id=p.id AND a.state='quarantine' AND a.quarantine_until>clock_timestamp()),
        (SELECT count(*) FROM peer_credential_rotation_requests r WHERE r.mesh_id=p.mesh_id AND r.peer_id=p.id AND r.status IN ('pending','issued'))
        FROM peers p WHERE p.mesh_id=$1 AND p.id=$2")
        .bind(mesh.into_uuid()).bind(peer.into_uuid()).fetch_one(store.pool()).await.unwrap();
    assert_eq!(row, ("disabled".into(), reason.into(), 0, 2, 0));
    let count:i64=sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE mesh_id=$1 AND target_id=$2 AND action='peer.admission.end'")
        .bind(mesh.into_uuid()).bind(peer.into_uuid()).fetch_one(store.pool()).await.unwrap();
    assert_eq!(count, 1);
}

async fn seed_offline_window(
    store: &Store,
    mesh: peerward_types::MeshId,
    peer: peerward_types::PeerId,
) {
    sqlx::query("UPDATE ephemeral_peer_observations SET offline_seconds=1799 WHERE mesh_id=$1 AND peer_id=$2")
        .bind(mesh.into_uuid()).bind(peer.into_uuid()).execute(store.pool()).await.unwrap();
    sqlx::query("UPDATE device_admission_observers SET observed_at=clock_timestamp()-interval '5 seconds' WHERE mesh_id=$1")
        .bind(mesh.into_uuid()).execute(store.pool()).await.unwrap();
}
async fn assert_offline_reset(
    store: &Store,
    mesh: peerward_types::MeshId,
    peer: peerward_types::PeerId,
) {
    let reset: bool = sqlx::query_scalar(
        "SELECT offline_seconds=0 FROM ephemeral_peer_observations WHERE mesh_id=$1 AND peer_id=$2",
    )
    .bind(mesh.into_uuid())
    .bind(peer.into_uuid())
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert!(reset);
}

async fn exercise_ephemeral_admission(
    store: &Store,
    app: &axum::Router,
    issuer: &JoinIssuerConfig,
) {
    use peerward_store::{PresenceLease, PresenceRole};
    use peerward_types::{AttachmentId, PeerId, RelayId};
    let mesh = issuer.mesh_id;
    let enrolled = admission_peer(app, mesh, json!({"kind":"ephemeral"}), 100).await;
    let peer: PeerId = serde_json::from_value(enrolled["peer_id"].clone()).unwrap();
    let mut observer = Uuid::new_v4();
    store
        .observe_ephemeral_peers(mesh, observer, None)
        .await
        .unwrap();
    seed_offline_window(store, mesh, peer).await;
    assert_eq!(
        store
            .observe_ephemeral_peers(mesh, observer, Some(std::time::Duration::from_secs(5)))
            .await
            .unwrap(),
        0,
        "no Relay observations cannot retire devices"
    );
    assert_offline_reset(store, mesh, peer).await;
    let relay = RelayId::new();
    sqlx::query("INSERT INTO relays(id,mesh_id,name,peer_endpoints,backbone_endpoints) VALUES($1,$2,'lifecycle-relay',ARRAY['tcp://127.0.0.1:1'],ARRAY['tcp://127.0.0.1:2'])")
        .bind(relay.into_uuid()).bind(mesh.into_uuid()).execute(store.pool()).await.unwrap();
    sqlx::query("INSERT INTO relay_credentials(id,mesh_id,relay_id,authority_id,serial,public_key,not_before,not_after,lifecycle,signature) VALUES($1,$2,$3,$4,$5,$6,clock_timestamp()-interval '1 minute',clock_timestamp()+interval '1 day','active',$7)")
        .bind(Uuid::new_v4()).bind(mesh.into_uuid()).bind(relay.into_uuid()).bind(issuer.authority_id).bind(Uuid::new_v4()).bind(vec![110u8;32]).bind(vec![111u8;64]).execute(store.pool()).await.unwrap();
    let runtime = Uuid::new_v4();
    store
        .acquire_relay_runtime(
            mesh,
            relay,
            runtime,
            OffsetDateTime::now_utc() + Duration::minutes(10),
        )
        .await
        .unwrap();
    store
        .observe_ephemeral_peers(mesh, observer, None)
        .await
        .unwrap();
    seed_offline_window(store, mesh, peer).await;
    // A failed publisher pass or a new Relay process interrupts continuous observation.
    assert_eq!(
        store
            .observe_ephemeral_peers(mesh, observer, None)
            .await
            .unwrap(),
        0
    );
    assert_offline_reset(store, mesh, peer).await;
    seed_offline_window(store, mesh, peer).await;
    store
        .acquire_relay_runtime(
            mesh,
            relay,
            Uuid::new_v4(),
            OffsetDateTime::now_utc() + Duration::minutes(10),
        )
        .await
        .unwrap();
    assert_eq!(
        store
            .observe_ephemeral_peers(mesh, observer, Some(std::time::Duration::from_secs(5)))
            .await
            .unwrap(),
        0
    );
    assert_offline_reset(store, mesh, peer).await;
    for interval in ["1 minute", "-1 minute"] {
        seed_offline_window(store, mesh, peer).await;
        sqlx::query("UPDATE device_admission_observers SET observed_at=clock_timestamp()-$2::interval WHERE mesh_id=$1")
            .bind(mesh.into_uuid()).bind(interval).execute(store.pool()).await.unwrap();
        assert_eq!(
            store
                .observe_ephemeral_peers(mesh, observer, Some(std::time::Duration::from_secs(5)))
                .await
                .unwrap(),
            0
        );
        assert_offline_reset(store, mesh, peer).await;
    }
    seed_offline_window(store, mesh, peer).await;
    let next_observer = Uuid::new_v4();
    assert_eq!(
        store
            .observe_ephemeral_peers(mesh, next_observer, Some(std::time::Duration::from_secs(5)))
            .await
            .unwrap(),
        0,
        "another publisher cannot accumulate the same interval"
    );
    sqlx::query("UPDATE device_admission_observers SET observed_at=clock_timestamp()-interval '16 seconds' WHERE mesh_id=$1")
        .bind(mesh.into_uuid()).execute(store.pool()).await.unwrap();
    observer = next_observer;
    store
        .observe_ephemeral_peers(mesh, observer, Some(std::time::Duration::from_secs(5)))
        .await
        .unwrap();
    assert_offline_reset(store, mesh, peer).await;
    seed_offline_window(store, mesh, peer).await;
    let lease = PresenceLease {
        mesh_id: mesh,
        peer_id: peer,
        relay_id: relay,
        attachment_id: AttachmentId::new(),
        role: PresenceRole::Primary,
        lease_deadline: OffsetDateTime::now_utc() + Duration::minutes(1),
    };
    let generation = store.acquire_presence(&lease).await.unwrap();
    assert_eq!(
        store
            .observe_ephemeral_peers(mesh, observer, Some(std::time::Duration::from_secs(5)))
            .await
            .unwrap(),
        0
    );
    assert_offline_reset(store, mesh, peer).await;
    store.release_presence(&lease, generation).await.unwrap();
    seed_offline_window(store, mesh, peer).await;
    sqlx::query("UPDATE relay_runtime_leases SET updated_at=clock_timestamp()-interval '1 minute' WHERE mesh_id=$1")
        .bind(mesh.into_uuid()).execute(store.pool()).await.unwrap();
    assert_eq!(
        store
            .observe_ephemeral_peers(mesh, observer, Some(std::time::Duration::from_secs(5)))
            .await
            .unwrap(),
        0
    );
    assert_offline_reset(store, mesh, peer).await;
    store
        .acquire_relay_runtime(
            mesh,
            relay,
            Uuid::new_v4(),
            OffsetDateTime::now_utc() + Duration::minutes(10),
        )
        .await
        .unwrap();
    store
        .observe_ephemeral_peers(mesh, observer, None)
        .await
        .unwrap();
    seed_offline_window(store, mesh, peer).await;
    assert_eq!(
        store
            .observe_ephemeral_peers(mesh, observer, Some(std::time::Duration::from_secs(5)))
            .await
            .unwrap(),
        1
    );
    assert_retired(store, mesh, peer, "ephemeral_offline").await;
    assert!(
        store.acquire_presence(&lease).await.is_err(),
        "retired identity cannot reconnect"
    );
    assert_eq!(
        store
            .observe_ephemeral_peers(mesh, observer, Some(std::time::Duration::from_secs(5)))
            .await
            .unwrap(),
        0
    );
}
