use peerward_store::{DefaultPolicy, NewMesh, PresenceLease, PresenceRole, Store, StoreError};
use peerward_types::{AttachmentId, PeerId, RelayId};
use time::{Duration, OffsetDateTime};

#[tokio::test]
async fn released_presence_keeps_its_fence_without_changing_peer_version() {
    let url = std::env::var("PEERWARD_TEST_DATABASE_URL").unwrap();
    assert!(
        url.parse::<sqlx::postgres::PgConnectOptions>()
            .is_ok_and(|options| options.get_database() == Some("peerward_test"))
    );
    let store = Store::connect(&url, 4).await.unwrap();
    store.migrate().await.unwrap();
    let mesh = store
        .create_mesh(
            &NewMesh {
                name: "presence-regression".into(),
                address_cidr: "10.88.0.0/24".parse().unwrap(),
                gateway: "10.88.0.1".parse().unwrap(),
                dns_suffix: "presence.mesh".into(),
                mtu: 1380,
                reserved: vec![],
                default_policy: DefaultPolicy::Deny,
                quarantine_seconds: 2,
                rotation_overlap_seconds: 60,
            },
            "test",
        )
        .await
        .unwrap();
    let peer = PeerId::new();
    let relay = RelayId::new();
    sqlx::query("INSERT INTO peers(id,mesh_id,name) VALUES($1,$2,'presence-peer')")
        .bind(peer.into_uuid())
        .bind(mesh.id.into_uuid())
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query("INSERT INTO relays(id,mesh_id,name,peer_endpoints,backbone_endpoints)
                 VALUES($1,$2,'presence-relay',ARRAY['tcp://127.0.0.1:1'],ARRAY['tcp://127.0.0.1:2'])")
        .bind(relay.into_uuid()).bind(mesh.id.into_uuid()).execute(store.pool()).await.unwrap();
    for role in [PresenceRole::Primary, PresenceRole::Standby] {
        let lease = PresenceLease {
            mesh_id: mesh.id,
            peer_id: peer,
            relay_id: relay,
            attachment_id: AttachmentId::new(),
            role,
            lease_deadline: OffsetDateTime::now_utc() + Duration::minutes(1),
        };
        let mut previous = 0;
        for _ in 0..3 {
            let current = store.acquire_presence(&lease).await.unwrap();
            assert!(current > previous);
            assert!(matches!(
                store.renew_presence(&lease, previous).await,
                Err(StoreError::Conflict)
            ));
            assert!(matches!(
                store.release_presence(&lease, previous).await,
                Err(StoreError::Conflict)
            ));
            store.renew_presence(&lease, current).await.unwrap();
            store.release_presence(&lease, current).await.unwrap();
            previous = current;
        }
    }
    let version: i64 = sqlx::query_scalar("SELECT version FROM peers WHERE id=$1")
        .bind(peer.into_uuid())
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(version, 1);
    assert!(matches!(
        store.active_presence(mesh.id, peer).await,
        Err(StoreError::NotFound)
    ));
}
