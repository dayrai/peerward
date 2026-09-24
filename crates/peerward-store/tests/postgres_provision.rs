use peerward_store::{
    DefaultPolicy, InitialAuthority, InitialInstallation, InitialRelay, NewMesh, Store, StoreError,
};
use peerward_types::{CredentialSerial, MeshId, RelayId};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

fn installation() -> InitialInstallation {
    let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
    InitialInstallation {
        mesh_id: MeshId::new(),
        mesh: NewMesh {
            name: "Keep my mesh".into(),
            address_cidr: "10.80.0.0/24".parse().unwrap(),
            gateway: "10.80.0.1".parse().unwrap(),
            dns_suffix: "keep.mesh".into(),
            mtu: 1420,
            reserved: vec!["10.80.0.2".parse().unwrap()],
            default_policy: DefaultPolicy::Allow,
            quarantine_seconds: 123,
            rotation_overlap_seconds: 456,
        },
        authority: InitialAuthority {
            id: Uuid::new_v4(),
            serial: CredentialSerial::new(),
            public_key: vec![1; 32],
            certificate: vec![2; 64],
            not_before: now,
            not_after: now + Duration::days(365),
        },
        relay: InitialRelay {
            id: RelayId::new(),
            name: "first-relay".into(),
            peer_endpoints: vec!["tcp://127.0.0.1:7777".parse().unwrap()],
            backbone_endpoints: vec!["tcp://127.0.0.1:7778".parse().unwrap()],
            credential_id: Uuid::new_v4(),
            credential_serial: CredentialSerial::new(),
            public_key: vec![3; 32],
            signature: vec![4; 64],
            not_before: now,
            not_after: now + Duration::days(30),
        },
    }
}

#[tokio::test]
async fn provision_completion_is_atomic_preserves_state_and_rejects_replacement() {
    let url =
        std::env::var("PEERWARD_TEST_DATABASE_URL").expect("ephemeral test database required");
    assert!(
        url.parse::<sqlx::postgres::PgConnectOptions>()
            .is_ok_and(|options| options.get_database() == Some("peerward_test"))
    );
    let store = Store::connect(&url, 8).await.unwrap();
    store.migrate().await.unwrap();
    let mut value = installation();
    assert!(matches!(
        store.complete_empty_mesh_installation(&value).await,
        Err(StoreError::NotFound)
    ));
    value.mesh_id = store.create_mesh(&value.mesh, "test").await.unwrap().id;
    sqlx::query("UPDATE meshes SET authority_revision=7,relay_revision=8,directory_revision=9,policy_revision=10,service_revision=11,revocation_revision=12,version=13 WHERE id=$1")
        .bind(value.mesh_id.into_uuid()).execute(store.pool()).await.unwrap();
    let before: serde_json::Value =
        sqlx::query_scalar("SELECT to_jsonb(m) FROM meshes m WHERE id=$1")
            .bind(value.mesh_id.into_uuid())
            .fetch_one(store.pool())
            .await
            .unwrap();
    let policy_before: serde_json::Value =
        sqlx::query_scalar("SELECT to_jsonb(p) FROM policies p WHERE mesh_id=$1")
            .bind(value.mesh_id.into_uuid())
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert!(matches!(
        store.initialize_installation(&value).await,
        Err(StoreError::Conflict)
    ));
    for field in 0..9 {
        let mut mismatch = value.clone();
        match field {
            0 => mismatch.mesh.name = "Changed".into(),
            1 => mismatch.mesh.address_cidr = "10.80.0.0/16".parse().unwrap(),
            2 => mismatch.mesh.gateway = "10.80.0.3".parse().unwrap(),
            3 => mismatch.mesh.dns_suffix = "changed.mesh".into(),
            4 => mismatch.mesh.mtu = 1380,
            5 => mismatch.mesh.default_policy = DefaultPolicy::Deny,
            6 => mismatch.mesh.quarantine_seconds += 1,
            7 => mismatch.mesh.rotation_overlap_seconds += 1,
            _ => mismatch.mesh.reserved.clear(),
        }
        assert!(
            matches!(
                store.complete_empty_mesh_installation(&mismatch).await,
                Err(StoreError::Conflict)
            ),
            "field {field}"
        );
    }
    assert!(
        store
            .complete_empty_mesh_installation(&value)
            .await
            .unwrap()
    );
    assert!(
        !store
            .complete_empty_mesh_installation(&value)
            .await
            .unwrap()
    );
    assert!(!store.initialize_installation(&value).await.unwrap());
    let after: serde_json::Value =
        sqlx::query_scalar("SELECT to_jsonb(m) FROM meshes m WHERE id=$1")
            .bind(value.mesh_id.into_uuid())
            .fetch_one(store.pool())
            .await
            .unwrap();
    let policy_after: serde_json::Value =
        sqlx::query_scalar("SELECT to_jsonb(p) FROM policies p WHERE mesh_id=$1")
            .bind(value.mesh_id.into_uuid())
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert_eq!(before, after);
    assert_eq!(policy_before, policy_after);
    let mut replacement = installation();
    replacement.mesh_id = value.mesh_id;
    assert!(matches!(
        store.complete_empty_mesh_installation(&replacement).await,
        Err(StoreError::Conflict)
    ));

    // All lifecycle states count, including deleted peers and relays and revoked authorities.
    for kind in ["peer", "relay", "authority"] {
        let mut occupied = installation();
        occupied.mesh_id = store.create_mesh(&occupied.mesh, "test").await.unwrap().id;
        match kind {
            "peer" => {
                sqlx::query("INSERT INTO peers(id,mesh_id,name,administrative_state) VALUES($1,$2,'old-peer','deleted')").bind(Uuid::new_v4()).bind(occupied.mesh_id.into_uuid()).execute(store.pool()).await.unwrap();
            }
            "relay" => {
                sqlx::query("INSERT INTO relays(id,mesh_id,name,peer_endpoints,backbone_endpoints,administrative_state) VALUES($1,$2,'old-relay',ARRAY['tcp://127.0.0.1:7777'],ARRAY['tcp://127.0.0.1:7778'],'deleted')").bind(Uuid::new_v4()).bind(occupied.mesh_id.into_uuid()).execute(store.pool()).await.unwrap();
            }
            _ => {
                sqlx::query("INSERT INTO mesh_authorities(id,mesh_id,serial,public_key,not_before,not_after,lifecycle,certificate) VALUES($1,$2,$3,$4,$5,$6,'revoked',$7)").bind(Uuid::new_v4()).bind(occupied.mesh_id.into_uuid()).bind(CredentialSerial::new().into_uuid()).bind(vec![5_u8;32]).bind(occupied.authority.not_before).bind(occupied.authority.not_after).bind(vec![6_u8;64]).execute(store.pool()).await.unwrap();
            }
        }
        assert!(
            matches!(
                store.complete_empty_mesh_installation(&occupied).await,
                Err(StoreError::Conflict)
            ),
            "{kind}"
        );
        let inserted: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mesh_authorities WHERE id=$1)")
                .bind(occupied.authority.id)
                .fetch_one(store.pool())
                .await
                .unwrap();
        assert!(!inserted);
    }
    // A late credential conflict must roll back the already inserted Authority and Relay.
    let mut collision = installation();
    collision.mesh_id = store.create_mesh(&collision.mesh, "test").await.unwrap().id;
    collision.relay.credential_id = value.relay.credential_id;
    assert!(
        store
            .complete_empty_mesh_installation(&collision)
            .await
            .is_err()
    );
    let left_partial_state: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM mesh_authorities WHERE mesh_id=$1)
         OR EXISTS(SELECT 1 FROM relays WHERE mesh_id=$1)",
    )
    .bind(collision.mesh_id.into_uuid())
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert!(!left_partial_state);

    // A concurrent Peer insert takes the Mesh FK lock first; completion must recheck
    // after waiting for that insertion to commit.
    let mut raced = installation();
    raced.mesh_id = store.create_mesh(&raced.mesh, "test").await.unwrap().id;
    let mut insertion = store.pool().begin().await.unwrap();
    sqlx::query("INSERT INTO peers(id,mesh_id,name) VALUES($1,$2,'concurrent-peer')")
        .bind(Uuid::new_v4())
        .bind(raced.mesh_id.into_uuid())
        .execute(&mut *insertion)
        .await
        .unwrap();
    let completion = store.complete_empty_mesh_installation(&raced);
    tokio::pin!(completion);
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), &mut completion)
            .await
            .is_err()
    );
    insertion.commit().await.unwrap();
    assert!(matches!(completion.await, Err(StoreError::Conflict)));

    let fresh = installation();
    assert!(store.initialize_installation(&fresh).await.unwrap());
    assert!(!store.initialize_installation(&fresh).await.unwrap());
}
