use std::{collections::HashSet, env};

use futures_util::{StreamExt, TryStreamExt, stream};
use peerward_store::{
    DefaultPolicy, JoinClaim, Lifecycle, NewAuthority, NewMesh, Store, StoreError,
};
use peerward_types::CredentialSerial;
use serde_json::{Value, json};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

const PEER_COUNT: u32 = 10_000;
const CONCURRENCY: usize = 128;

fn database_url() -> String {
    let value = env::var("PEERWARD_TEST_DATABASE_URL")
        .expect("PEERWARD_TEST_DATABASE_URL must identify an ephemeral PostgreSQL database");
    assert!(
        value
            .parse::<sqlx::postgres::PgConnectOptions>()
            .is_ok_and(|options| options.get_database() == Some("peerward_test")),
        "integration tests refuse a database not named peerward_test"
    );
    value
}

fn unique_bytes(index: u32, length: usize) -> Vec<u8> {
    let mut value = vec![u8::try_from(index % 251).unwrap(); length];
    value[..4].copy_from_slice(&index.to_be_bytes());
    value
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn ten_thousand_real_peers_are_allocated_concurrently() {
    let store = Store::connect(&database_url(), 64).await.unwrap();
    sqlx::raw_sql("DROP SCHEMA public CASCADE; CREATE SCHEMA public")
        .execute(store.pool())
        .await
        .unwrap();
    store.migrate().await.unwrap();

    let mesh = store
        .create_mesh(
            &NewMesh {
                name: "scale".into(),
                address_cidr: "10.96.0.0/17".parse().unwrap(),
                gateway: "10.96.0.1".parse().unwrap(),
                dns_suffix: "scale.mesh".into(),
                mtu: 1380,
                reserved: vec!["10.96.0.2".parse().unwrap()],
                default_policy: DefaultPolicy::Deny,
                quarantine_seconds: 60,
                rotation_overlap_seconds: 60,
            },
            "scale-test",
        )
        .await
        .unwrap();
    let now = OffsetDateTime::now_utc();
    let authority = NewAuthority {
        mesh_id: mesh.id,
        serial: CredentialSerial::new(),
        public_key: vec![7; 32],
        not_before: now - Duration::minutes(1),
        not_after: now + Duration::hours(1),
        replaces: None,
        overlap_deadline: None,
        certificate: vec![8; 64],
    };
    let authority_id = store
        .stage_authority(&authority, "scale-test")
        .await
        .unwrap();
    store
        .transition_authority(mesh.id, authority.serial, Lifecycle::Active, "scale-test")
        .await
        .unwrap();

    let claimed = stream::iter(0..PEER_COUNT)
        .map(|index| {
            let store = store.clone();
            async move {
                let token = format!("peerward-scale-ticket-{index:08}").into_bytes();
                store
                    .create_join_ticket(
                        mesh.id,
                        &token,
                        OffsetDateTime::now_utc() + Duration::minutes(30),
                        "scale-test",
                    )
                    .await?;
                store
                    .claim_join(&JoinClaim {
                        token,
                        name: format!("scale-peer-{index:08}"),
                        labels: json!({"scale":"10000"}),
                        claim_id: Uuid::new_v4(),
                        request_digest: unique_bytes(index, 32).try_into().unwrap(),
                        authority_id,
                        serial: CredentialSerial::new(),
                        identity_public_key: unique_bytes(index.saturating_add(1), 32),
                        public_key: unique_bytes(index, 32),
                        wireguard_public_key: unique_bytes(index.saturating_add(100_000), 32),
                        not_before: OffsetDateTime::now_utc() - Duration::minutes(1),
                        not_after: OffsetDateTime::now_utc() + Duration::hours(1),
                        signature: unique_bytes(index, 64),
                    })
                    .await
            }
        })
        .buffer_unordered(CONCURRENCY)
        .try_collect::<Vec<_>>()
        .await
        .unwrap_or_else(|error: StoreError| panic!("concurrent allocation failed: {error}"));

    assert_eq!(claimed.len(), usize::try_from(PEER_COUNT).unwrap());
    let addresses: HashSet<_> = claimed.iter().map(|peer| peer.address).collect();
    assert_eq!(addresses.len(), usize::try_from(PEER_COUNT).unwrap());
    assert!(!addresses.contains(&mesh.gateway));
    assert!(!addresses.contains(&"10.96.0.2".parse().unwrap()));

    let peer_count: i64 = sqlx::query_scalar("SELECT count(*) FROM peers WHERE mesh_id=$1")
        .bind(mesh.id.into_uuid())
        .fetch_one(store.pool())
        .await
        .unwrap();
    let consumed_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM join_tickets WHERE mesh_id=$1 AND consumed_at IS NOT NULL",
    )
    .bind(mesh.id.into_uuid())
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(peer_count, i64::from(PEER_COUNT));
    assert_eq!(consumed_count, i64::from(PEER_COUNT));

    sqlx::query("ANALYZE peers, peer_addresses, peer_credentials, audit_log")
        .execute(store.pool())
        .await
        .unwrap();
    let peer_cursor: (OffsetDateTime, Uuid) = sqlx::query_as(
        "SELECT created_at,id FROM peers WHERE mesh_id=$1 ORDER BY created_at,id OFFSET 5000 LIMIT 1",
    )
    .bind(mesh.id.into_uuid())
    .fetch_one(store.pool())
    .await
    .unwrap();
    let peer_plan: Value = sqlx::query_scalar(
        "EXPLAIN (FORMAT JSON) SELECT id FROM peers WHERE mesh_id=$1
         AND (created_at,id)>($2,$3) ORDER BY created_at,id LIMIT 50",
    )
    .bind(mesh.id.into_uuid())
    .bind(peer_cursor.0)
    .bind(peer_cursor.1)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert!(peer_plan.to_string().contains("peers_page_idx"));

    let address_plan: Value = sqlx::query_scalar(
        "EXPLAIN (FORMAT JSON) SELECT EXISTS(SELECT 1 FROM peer_addresses
         WHERE mesh_id=$1 AND address=$2::inet AND
           (state='active' OR (state='quarantine' AND quarantine_until>clock_timestamp())))",
    )
    .bind(mesh.id.into_uuid())
    .bind("10.96.1.1")
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert!(
        address_plan
            .to_string()
            .contains("peer_addresses_allocation_idx")
    );

    let expiry_plan: Value = sqlx::query_scalar(
        "EXPLAIN (FORMAT JSON) SELECT id FROM peer_credentials
         WHERE lifecycle IN ('active','overlap') AND
           (not_after<=clock_timestamp() OR
            (lifecycle='overlap' AND overlap_deadline<=clock_timestamp()))
         ORDER BY LEAST(not_after,COALESCE(overlap_deadline,'infinity')),id LIMIT 500",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert!(
        expiry_plan
            .to_string()
            .contains("peer_credentials_expiry_idx")
    );

    let audit_cursor: (OffsetDateTime, Uuid) = sqlx::query_as(
        "SELECT occurred_at,id FROM audit_log WHERE retained_mesh_id=$1
         ORDER BY occurred_at DESC,id DESC OFFSET 5000 LIMIT 1",
    )
    .bind(mesh.id.into_uuid())
    .fetch_one(store.pool())
    .await
    .unwrap();
    let audit_plan: Value = sqlx::query_scalar(
        "EXPLAIN (FORMAT JSON) SELECT id FROM audit_log WHERE retained_mesh_id=$1
         AND (occurred_at,id)<($2,$3) ORDER BY occurred_at DESC,id DESC LIMIT 50",
    )
    .bind(mesh.id.into_uuid())
    .bind(audit_cursor.0)
    .bind(audit_cursor.1)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert!(audit_plan.to_string().contains("audit_log_page_idx"));
}
