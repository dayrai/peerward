{
    let foreign_peer = PeerId::new();
    sqlx::query("INSERT INTO peers(id,mesh_id,name) VALUES($1,$2,'foreign')")
        .bind(foreign_peer.into_uuid())
        .bind(second_mesh.id.into_uuid())
        .execute(store.pool())
        .await
        .unwrap();
    let cross_mesh = sqlx::query("INSERT INTO services(id,mesh_id,peer_id,protocols,listen_port,alias) VALUES($1,$2,$3,ARRAY['tcp'],80,'cross')")
        .bind(Uuid::new_v4()).bind(first_mesh.id.into_uuid()).bind(foreign_peer.into_uuid())
        .execute(store.pool()).await;
    let error = cross_mesh.unwrap_err();
    assert_eq!(error.as_database_error().and_then(|error| error.code()).as_deref(), Some("23503"), "{error}");

    let shared_name = sqlx::query(
        "INSERT INTO services(id,mesh_id,peer_id,protocols,listen_port,alias)
         VALUES($1,$2,$3,ARRAY['tcp'],8080,'PEER-1')",
    )
    .bind(Uuid::new_v4())
    .bind(first_mesh.id.into_uuid())
    .bind(peers[1].into_uuid())
    .execute(store.pool())
    .await;
    let error = shared_name.unwrap_err();
    assert_eq!(error.as_database_error().and_then(|error| error.code()).as_deref(), Some("23505"), "{error}");

    let latest_cursor = high_water.cursor.unwrap();
    loop {
        let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM event_outbox")
            .fetch_one(store.pool())
            .await
            .unwrap();
        if remaining == 0 {
            break;
        }
        store
            .maintain(MaintenancePolicy {
                batch_size: 100,
                event_retention_seconds: 3_600,
                event_max_rows: 10_000,
                signed_state_versions: 2,
                terminal_retention_seconds: 3_600,
            })
            .await
            .unwrap();
    }
    let pruned_high_water = store.event_replay_start(None).await.unwrap();
    assert_eq!(pruned_high_water.after_sequence, high_water.after_sequence);
    assert_eq!(pruned_high_water.cursor, None);
    assert!(matches!(
        store.event_replay_start(Some(latest_cursor)).await,
        Err(StoreError::EventCursorExpired)
    ));
}
