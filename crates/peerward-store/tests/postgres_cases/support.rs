pub fn database_url() -> String {
    let value = std::env::var("PEERWARD_TEST_DATABASE_URL")
        .expect("PEERWARD_TEST_DATABASE_URL must identify an ephemeral PostgreSQL database");
    assert!(
        value
            .parse::<sqlx::postgres::PgConnectOptions>()
            .is_ok_and(|options| options.get_database() == Some("peerward_test")),
        "integration tests refuse a database not named peerward_test"
    );
    value
}

pub async fn assert_followup_migrations(store: &peerward_store::Store) {
    let versions = sqlx::query_scalar::<_, i32>(
        "SELECT version FROM peerward_schema_migrations ORDER BY version",
    )
    .fetch_all(store.pool())
    .await
    .unwrap();
    assert_eq!(versions, (1..=54).collect::<Vec<_>>());
    sqlx::query("INSERT INTO peerward_schema_migrations(version,checksum) VALUES(1000000,decode('01','hex'))")
        .execute(store.pool()).await.unwrap();
    assert!(matches!(
        store.migrate().await,
        Err(peerward_store::StoreError::NewerSchemaUnsupported)
    ));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM peerward_schema_migrations")
            .fetch_one(store.pool())
            .await
            .unwrap(),
        i64::try_from(versions.len() + 1).unwrap()
    );
    sqlx::query("DELETE FROM peerward_schema_migrations WHERE version=1000000 AND checksum=decode('01','hex')")
        .execute(store.pool()).await.unwrap();
    store.migrate().await.unwrap();
}

pub async fn assert_two_standbys_coexist(store: &peerward_store::Store, primary: &PresenceLease) {
    let legacy_relay = RelayId::new();
    sqlx::query(
        "INSERT INTO relays(id,mesh_id,name,peer_endpoints,backbone_endpoints)
         VALUES($1,$2,'legacy-standby',ARRAY['tcp://127.0.0.1:3'],ARRAY['tcp://127.0.0.1:4'])",
    )
    .bind(legacy_relay.into_uuid())
    .bind(primary.mesh_id.into_uuid())
    .execute(store.pool())
    .await
    .unwrap();
    for expected_generation in [1_i64, 2] {
        let generation: i64 = sqlx::query_scalar(
            "INSERT INTO relay_presence
             (mesh_id,peer_id,relay_id,attachment_id,role,fencing_generation,lease_deadline)
             VALUES($1,$2,$3,$4,'standby',1,$5)
             ON CONFLICT(mesh_id,peer_id,role) DO UPDATE SET
               relay_id=EXCLUDED.relay_id,attachment_id=EXCLUDED.attachment_id,
               fencing_generation=relay_presence.fencing_generation+1,
               lease_deadline=EXCLUDED.lease_deadline,updated_at=clock_timestamp()
             RETURNING fencing_generation",
        )
        .bind(primary.mesh_id.into_uuid())
        .bind(primary.peer_id.into_uuid())
        .bind(legacy_relay.into_uuid())
        .bind(AttachmentId::new().into_uuid())
        .bind(primary.lease_deadline)
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(generation, expected_generation);
    }
    assert!(
        store
            .acquire_presence(&PresenceLease {
                relay_id: legacy_relay,
                attachment_id: AttachmentId::new(),
                role: PresenceRole::Standby,
                ..primary.clone()
            })
            .await
            .unwrap()
            > 2
    );
    let visible: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM relay_presence_all
         WHERE mesh_id=$1 AND peer_id=$2 AND relay_id=$3 AND role='standby'",
    )
    .bind(primary.mesh_id.into_uuid())
    .bind(primary.peer_id.into_uuid())
    .bind(legacy_relay.into_uuid())
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(visible, 1);
    sqlx::query(
        "DELETE FROM relay_standby_presence_v1 WHERE mesh_id=$1 AND peer_id=$2 AND relay_id=$3",
    )
    .bind(primary.mesh_id.into_uuid())
    .bind(primary.peer_id.into_uuid())
    .bind(legacy_relay.into_uuid())
    .execute(store.pool())
    .await
    .unwrap();
    sqlx::query("DELETE FROM relay_presence WHERE mesh_id=$1 AND peer_id=$2 AND role='standby'")
        .bind(primary.mesh_id.into_uuid())
        .bind(primary.peer_id.into_uuid())
        .execute(store.pool())
        .await
        .unwrap();

    let mut previous: i64 = sqlx::query_scalar(
        "SELECT generation FROM peer_presence_generations WHERE mesh_id=$1 AND peer_id=$2",
    )
    .bind(primary.mesh_id.into_uuid())
    .bind(primary.peer_id.into_uuid())
    .fetch_one(store.pool())
    .await
    .unwrap();
    for (index, relay) in [RelayId::new(), RelayId::new()].into_iter().enumerate() {
        sqlx::query(
            "INSERT INTO relays(id,mesh_id,name,peer_endpoints,backbone_endpoints)
             VALUES($1,$2,$3,ARRAY['tcp://127.0.0.1:3'],ARRAY['tcp://127.0.0.1:4'])",
        )
        .bind(relay.into_uuid())
        .bind(primary.mesh_id.into_uuid())
        .bind(format!("standby-{index}"))
        .execute(store.pool())
        .await
        .unwrap();
        let generation = store
            .acquire_presence(&PresenceLease {
                relay_id: relay,
                attachment_id: AttachmentId::new(),
                role: PresenceRole::Standby,
                ..primary.clone()
            })
            .await
            .unwrap();
        assert!(generation > previous);
        previous = generation;
    }
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM relay_presence_all WHERE mesh_id=$1 AND peer_id=$2",
    )
    .bind(primary.mesh_id.into_uuid())
    .bind(primary.peer_id.into_uuid())
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(count, 3);
    sqlx::query("DELETE FROM relay_standby_presence_v1 WHERE mesh_id=$1 AND peer_id=$2")
        .bind(primary.mesh_id.into_uuid())
        .bind(primary.peer_id.into_uuid())
        .execute(store.pool())
        .await
        .unwrap();
}
use peerward_store::{DefaultPolicy, NewMesh, PresenceLease, PresenceRole};
use peerward_types::{AttachmentId, RelayId};

pub fn mesh_request(name: &str, suffix: &str) -> NewMesh {
    NewMesh {
        name: name.into(),
        address_cidr: "10.88.0.0/20".parse().unwrap(),
        gateway: "10.88.0.1".parse().unwrap(),
        dns_suffix: suffix.into(),
        mtu: 1380,
        reserved: vec!["10.88.0.2".parse().unwrap()],
        default_policy: DefaultPolicy::Deny,
        quarantine_seconds: 2,
        rotation_overlap_seconds: 60,
    }
}

pub async fn assert_wss_endpoints(store: &peerward_store::Store) {
    for endpoint in [
        "tcp://127.0.0.1:7777",
        "quic://relay.example:443",
        "quic://[2001:db8::1]:443",
        "quic://relay.example:443/peerward",
        "quic://relay.example:443?token=x",
        "quic://user@relay.example:443",
        "quic://relay.example",
        "quic://0.0.0.0:443",
        "quic://relay.example:0443",
        "tcp://relay.example:7777",
        "wss://relay.example:443/peerward",
        "wss://127.0.0.1:8443/peerward",
        "wss://[2001:db8::1]:443/peerward",
        "wss://relay.example/peerward",
        "wss://relay.example:443/Peerward",
        "wss://relay.example:443/peerward?token=x",
        "ws://relay.example:443/peerward",
        "tcp://0.0.0.0:7777",
        "wss://[::]:443/peerward",
        "tcp://224.0.0.1:7777",
        "wss://[ff02::1]:443/peerward",
        "tcp://127.1:7777",
        "wss://user@relay.example:443/peerward",
        "wss://relay.example:0443/peerward",
        "wss://relay.example:443/a/../peerward",
    ] {
        let expected = endpoint
            .parse::<peerward_types::NetworkEndpoint>()
            .is_ok_and(|parsed| parsed.as_str() == endpoint);
        let actual: bool = sqlx::query_scalar("SELECT public.peerward_valid_network_endpoint($1)")
            .bind(endpoint)
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(actual, expected, "SQL/Rust endpoint mismatch: {endpoint}");
    }
}

pub async fn assert_legacy_rejected(store: &peerward_store::Store) {
    use peerward_store::StoreError;
    use sha2::{Digest as _, Sha256};
    sqlx::raw_sql(
        "DROP SCHEMA public CASCADE; CREATE SCHEMA public;
         CREATE TABLE peerward_install_intent(
           singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
           product_major integer NOT NULL CHECK(product_major=1),
           wire_major integer NOT NULL CHECK(wire_major=2));
         INSERT INTO peerward_install_intent(singleton,product_major,wire_major)
         VALUES(true,1,2);
         CREATE TABLE peerward_schema_migrations(
           version integer PRIMARY KEY, checksum bytea NOT NULL,
           applied_at timestamptz NOT NULL DEFAULT clock_timestamp());",
    )
    .execute(store.pool())
    .await
    .unwrap();
    let first_migration = include_str!("../../migrations/0001_core.sql");
    sqlx::raw_sql(first_migration)
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query("INSERT INTO peerward_schema_migrations(version,checksum) VALUES(1,$1)")
        .bind(Sha256::digest(first_migration.as_bytes()).to_vec())
        .execute(store.pool())
        .await
        .unwrap();
    assert!(matches!(
        store.migrate().await,
        Err(StoreError::LegacySchemaUnsupported)
    ));
    let migration_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM peerward_schema_migrations")
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert_eq!(
        migration_count, 1,
        "incompatible installation must be rejected before writing migrations"
    );
    // Independently start a clean installation; never upgrade the old fixture.
    sqlx::raw_sql("DROP SCHEMA public CASCADE; CREATE SCHEMA public")
        .execute(store.pool())
        .await
        .unwrap();
}
