use peerward_store::{Lifecycle, Store, StoreError};
use peerward_types::{CredentialSerial, MeshId, PeerId};
use uuid::Uuid;

pub async fn assert_authority_version_precondition(
    store: &Store,
    mesh_id: MeshId,
    authority_id: Uuid,
    serial: CredentialSerial,
) {
    assert!(matches!(
        store
            .transition_authority_if_version(
                mesh_id,
                authority_id,
                2,
                serial,
                Lifecycle::Active,
                "admin",
            )
            .await,
        Err(StoreError::Conflict)
    ));
    let state: (String, i64) =
        sqlx::query_as("SELECT lifecycle,version FROM mesh_authorities WHERE mesh_id=$1 AND id=$2")
            .bind(mesh_id.into_uuid())
            .bind(authority_id)
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert_eq!(state, ("staged".into(), 1));
    store
        .transition_authority_if_version(
            mesh_id,
            authority_id,
            1,
            serial,
            Lifecycle::Active,
            "admin",
        )
        .await
        .unwrap();
    let version: i64 =
        sqlx::query_scalar("SELECT version FROM mesh_authorities WHERE mesh_id=$1 AND id=$2")
            .bind(mesh_id.into_uuid())
            .bind(authority_id)
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert_eq!(version, 2);
}

pub async fn assert_overlap_expiry(
    store: &Store,
    mesh_id: MeshId,
    peer_id: PeerId,
    old_serial: CredentialSerial,
) {
    let before = store.mesh(mesh_id).await.unwrap();
    sqlx::query(
        "UPDATE peer_credentials SET overlap_deadline=clock_timestamp()-interval '1 second'
         WHERE mesh_id=$1 AND peer_id=$2 AND lifecycle='overlap'",
    )
    .bind(mesh_id.into_uuid())
    .bind(peer_id.into_uuid())
    .execute(store.pool())
    .await
    .unwrap();
    assert_eq!(store.expire_credentials(500).await.unwrap(), 1);
    assert_eq!(store.expire_credentials(500).await.unwrap(), 0);
    let lifecycle: String =
        sqlx::query_scalar("SELECT lifecycle FROM peer_credentials WHERE mesh_id=$1 AND serial=$2")
            .bind(mesh_id.into_uuid())
            .bind(old_serial.into_uuid())
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert_eq!(lifecycle, "revoked");
    let after = store.mesh(mesh_id).await.unwrap();
    assert_eq!(after.directory_revision, before.directory_revision + 1);
    assert_eq!(after.service_revision, before.service_revision + 1);
    assert_eq!(after.revocation_revision, before.revocation_revision + 1);

    let active_serial: Uuid = sqlx::query_scalar(
        "SELECT serial FROM peer_credentials WHERE mesh_id=$1 AND peer_id=$2
         AND lifecycle='active'",
    )
    .bind(mesh_id.into_uuid())
    .bind(peer_id.into_uuid())
    .fetch_one(store.pool())
    .await
    .unwrap();
    sqlx::query(
        "UPDATE peer_credentials SET not_after=clock_timestamp()-interval '1 microsecond'
         WHERE mesh_id=$1 AND serial=$2",
    )
    .bind(mesh_id.into_uuid())
    .bind(active_serial)
    .execute(store.pool())
    .await
    .unwrap();
    let before_not_after = store.mesh(mesh_id).await.unwrap();
    assert_eq!(store.expire_credentials(500).await.unwrap(), 1);
    assert_eq!(store.expire_credentials(500).await.unwrap(), 0);
    let active_lifecycle: String =
        sqlx::query_scalar("SELECT lifecycle FROM peer_credentials WHERE mesh_id=$1 AND serial=$2")
            .bind(mesh_id.into_uuid())
            .bind(active_serial)
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert_eq!(active_lifecycle, "revoked");
    let after_not_after = store.mesh(mesh_id).await.unwrap();
    assert_eq!(
        after_not_after.directory_revision,
        before_not_after.directory_revision + 1
    );
    assert_eq!(
        after_not_after.service_revision,
        before_not_after.service_revision + 1
    );
    assert_eq!(
        after_not_after.revocation_revision,
        before_not_after.revocation_revision + 1
    );
}

pub async fn released_address_history(store: &Store, mesh_id: MeshId, address: &str) -> Uuid {
    let row: (Uuid, String) = sqlx::query_as(
        "SELECT id,state FROM peer_addresses WHERE mesh_id=$1 AND address=$2::inet
         AND state<>'active'",
    )
    .bind(mesh_id.into_uuid())
    .bind(address)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(row.1, "released");
    row.0
}

pub async fn age_address_history(store: &Store, mesh_id: MeshId, address: &str) {
    sqlx::query(
        "UPDATE peer_addresses SET quarantine_until=clock_timestamp()-interval '2 hours'
         WHERE mesh_id=$1 AND address=$2::inet AND state='quarantine'",
    )
    .bind(mesh_id.into_uuid())
    .bind(address)
    .execute(store.pool())
    .await
    .unwrap();
}

pub async fn assert_address_history_removed(store: &Store, address_id: Uuid) {
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM peer_addresses WHERE id=$1)")
            .bind(address_id)
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert!(!exists);
}

pub async fn assert_both_families_quarantined(
    store: &peerward_store::Store,
    mesh: peerward_types::MeshId,
    peer: peerward_types::PeerId,
) {
    let count:i64=sqlx::query_scalar("SELECT count(*) FROM peer_addresses WHERE mesh_id=$1 AND peer_id=$2 AND state='quarantine'").bind(mesh.into_uuid()).bind(peer.into_uuid()).fetch_one(store.pool()).await.unwrap();
    assert_eq!(
        count, 2,
        "both address families share the quarantine lifecycle"
    );
}
