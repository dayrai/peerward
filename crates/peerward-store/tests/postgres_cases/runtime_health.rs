use peerward_store::{PeerRuntimeHealthRecord, Store};
use peerward_types::{MeshId, PeerId};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

pub async fn assert_observation_expiry(store: &Store, mesh: MeshId, peer: PeerId) {
    let now: OffsetDateTime = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(store.pool())
        .await
        .unwrap();
    let mut report = PeerRuntimeHealthRecord {
        sequence: 1,
        observed_at: now - Duration::seconds(60),
        direct_path_count: 0,
        relay_packets: 2,
        direct_packets: 0,
        degraded_reasons: vec!["dns_degraded".into()],
        signed_revision: 1,
    };
    assert!(
        store
            .commit_peer_runtime_health(Uuid::new_v4(), mesh, peer, &report)
            .await
            .unwrap()
    );
    let expiry =
        || {
            sqlx::query_scalar::<_, OffsetDateTime>(
        "SELECT expires_at FROM current_peer_runtime_health WHERE mesh_id=$1 AND peer_id=$2")
        .bind(mesh.into_uuid()).bind(peer.into_uuid())
        };
    assert_eq!(
        expiry().fetch_one(store.pool()).await.unwrap(),
        now + Duration::seconds(30)
    );
    assert!(
        !store
            .commit_peer_runtime_health(Uuid::new_v4(), mesh, peer, &report)
            .await
            .unwrap()
    );
    assert_eq!(
        expiry().fetch_one(store.pool()).await.unwrap(),
        now + Duration::seconds(30)
    );
    // Removing the current row must not give an old signed observation a new TTL.
    sqlx::query("DELETE FROM current_peer_runtime_health WHERE mesh_id=$1 AND peer_id=$2")
        .bind(mesh.into_uuid())
        .bind(peer.into_uuid())
        .execute(store.pool())
        .await
        .unwrap();
    assert!(
        store
            .commit_peer_runtime_health(Uuid::new_v4(), mesh, peer, &report)
            .await
            .unwrap()
    );
    assert_eq!(
        expiry().fetch_one(store.pool()).await.unwrap(),
        now + Duration::seconds(30)
    );
    report.sequence = 2;
    report.observed_at = now - Duration::seconds(91);
    assert!(
        !store
            .commit_peer_runtime_health(Uuid::new_v4(), mesh, peer, &report)
            .await
            .unwrap()
    );
    report.observed_at = now + Duration::seconds(120);
    assert!(
        !store
            .commit_peer_runtime_health(Uuid::new_v4(), mesh, peer, &report)
            .await
            .unwrap()
    );
    report.observed_at = now;
    assert!(
        store
            .commit_peer_runtime_health(Uuid::new_v4(), mesh, peer, &report)
            .await
            .unwrap()
    );
    assert_eq!(
        expiry().fetch_one(store.pool()).await.unwrap(),
        now + Duration::seconds(90)
    );
}
