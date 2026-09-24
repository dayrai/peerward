use peerward_store::{MaintenancePolicy, Store};
use peerward_types::MeshId;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

pub async fn verify(store: &Store, mesh: MeshId) {
    let ticket = store
        .create_join_ticket(
            mesh,
            &[251; 32],
            OffsetDateTime::now_utc() + Duration::minutes(5),
            "history-test",
        )
        .await
        .unwrap();
    sqlx::query(
        "UPDATE join_tickets SET expires_at=clock_timestamp()-interval '60 days' WHERE id=$1",
    )
    .bind(ticket.id.into_uuid())
    .execute(store.pool())
    .await
    .unwrap();
    let recent = Uuid::new_v4();
    for index in 0..151 {
        sqlx::query("INSERT INTO configuration_applications(mesh_id,request_id,actor,request_digest,response,created_at) VALUES($1,$2,'test',$3,'{}',clock_timestamp()-make_interval(days=>$4))")
            .bind(mesh.into_uuid()).bind(if index==150 {recent} else {Uuid::new_v4()})
            .bind([7_u8;32].as_slice()).bind(if index==150 {1_i32} else {31})
            .execute(store.pool()).await.unwrap();
    }
    let policy = MaintenancePolicy {
        batch_size: 100,
        event_retention_seconds: 3600,
        event_max_rows: 10000,
        signed_state_versions: 2,
        terminal_retention_seconds: 3600,
    };
    for expected in [100_i64, 150, 150] {
        store.maintain(policy).await.unwrap();
        let archived:i64=sqlx::query_scalar("SELECT count(*) FROM configuration_applications WHERE mesh_id=$1 AND response IS NULL AND archived_at IS NOT NULL")
            .bind(mesh.into_uuid()).fetch_one(store.pool()).await.unwrap();
        assert_eq!(
            archived, expected,
            "response compaction is bounded and repeatable"
        );
        let count:i64=sqlx::query_scalar("SELECT count(*) FROM configuration_applications WHERE mesh_id=$1 AND actor='test' AND request_digest=$2")
            .bind(mesh.into_uuid()).bind([7_u8;32].as_slice()).fetch_one(store.pool()).await.unwrap();
        assert_eq!(count, 151, "all request identities survive compaction");
        let retained: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM join_tickets WHERE id=$1)")
                .bind(ticket.id.into_uuid())
                .fetch_one(store.pool())
                .await
                .unwrap();
        assert!(
            retained,
            "expired invitations remain visible in management history"
        );
        let recent_present:bool=sqlx::query_scalar("SELECT response IS NOT NULL AND archived_at IS NULL FROM configuration_applications WHERE mesh_id=$1 AND request_id=$2")
            .bind(mesh.into_uuid()).bind(recent).fetch_one(store.pool()).await.unwrap();
        assert!(recent_present);
    }
}
