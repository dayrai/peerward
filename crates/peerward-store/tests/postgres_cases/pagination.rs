use std::collections::HashSet;

use peerward_store::Store;
use peerward_types::MeshId;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

pub async fn assert_compound_pagination(store: &Store, mesh_id: MeshId) {
    let first_page: Vec<(Uuid, OffsetDateTime)> = sqlx::query_as(
        "SELECT id,created_at FROM peers WHERE mesh_id=$1 ORDER BY created_at,id LIMIT 500",
    )
    .bind(mesh_id.into_uuid())
    .fetch_all(store.pool())
    .await
    .unwrap();
    let (cursor_id, cursor_time) = *first_page.last().unwrap();
    let concurrent_id = Uuid::parse_str("00000000-0000-4000-8000-000000000001").unwrap();
    assert!(concurrent_id < cursor_id);
    sqlx::query(
        "INSERT INTO peers(id,mesh_id,name,created_at,updated_at)
         VALUES($1,$2,'page-concurrent',$3,$3)",
    )
    .bind(concurrent_id)
    .bind(mesh_id.into_uuid())
    .bind(cursor_time + Duration::microseconds(1))
    .execute(store.pool())
    .await
    .unwrap();
    let remaining_page_ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM peers WHERE mesh_id=$1 AND (created_at,id)>($2,$3)
         ORDER BY created_at,id",
    )
    .bind(mesh_id.into_uuid())
    .bind(cursor_time)
    .bind(cursor_id)
    .fetch_all(store.pool())
    .await
    .unwrap();
    assert!(remaining_page_ids.contains(&concurrent_id));
    let all_page_ids: HashSet<_> = first_page
        .iter()
        .map(|(id, _)| *id)
        .chain(remaining_page_ids)
        .collect();
    assert_eq!(all_page_ids.len(), 1_001);
}
