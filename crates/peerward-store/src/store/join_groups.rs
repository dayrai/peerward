// Caller holds the mesh lock, as collection CRUD does. Read current definitions
// rather than retaining a membership snapshot in an invitation.
async fn invitation_device_groups(
    tx: &mut Transaction<'_, Postgres>,
    mesh: Uuid,
    groups: &std::collections::BTreeSet<Uuid>,
) -> Result<Vec<(Uuid, peerward_management::CollectionDefinition)>, StoreError> {
    let ids: Vec<_> = groups.iter().copied().collect();
    let rows = sqlx::query("SELECT id,definition FROM network_collections WHERE mesh_id=$1 AND id=ANY($2) ORDER BY id FOR UPDATE")
        .bind(mesh).bind(&ids).fetch_all(&mut **tx).await?;
    if rows.len() != ids.len() {
        return Err(StoreError::Invalid(
            "invitation device group no longer exists in this mesh",
        ));
    }
    rows.into_iter()
        .map(|row| {
            let definition: peerward_management::CollectionDefinition =
                serde_json::from_value(row.try_get("definition")?)
                    .map_err(|_| StoreError::Invalid("device group definition"))?;
            if definition.kind != peerward_management::CollectionKind::Devices {
                return Err(StoreError::Invalid(
                    "invitation groups must contain devices",
                ));
            }
            Ok((row.try_get("id")?, definition))
        })
        .collect()
}

async fn enroll_device_groups(
    tx: &mut Transaction<'_, Postgres>,
    mesh: MeshId,
    peer: PeerId,
    ticket: Uuid,
    groups: &std::collections::BTreeSet<Uuid>,
    actor: &str,
) -> Result<(), StoreError> {
    for (id, mut definition) in invitation_device_groups(tx, mesh.into_uuid(), groups).await? {
        definition.members.insert(peer.into_uuid());
        definition
            .validate()
            .map_err(|_| StoreError::Invalid("invitation device group is full"))?;
        let document = serde_json::to_value(definition)
            .map_err(|_| StoreError::Invalid("device group definition"))?;
        let resolved: i64 = sqlx::query_scalar("SELECT count(*) FROM peers WHERE mesh_id=$1 AND administrative_state='enabled' AND ($2::jsonb->'members' @> jsonb_build_array(id) OR (COALESCE($2::jsonb->'labels','{}'::jsonb)<>'{}'::jsonb AND labels @> ($2::jsonb->'labels')))")
            .bind(mesh.into_uuid()).bind(&document).fetch_one(&mut **tx).await?;
        if resolved > 4096 {
            return Err(StoreError::Invalid("invitation device group is full"));
        }
        sqlx::query(
            "UPDATE network_collections SET definition=$2,updated_at=clock_timestamp() WHERE id=$1",
        )
        .bind(id)
        .bind(document)
        .execute(&mut **tx)
        .await?;
        mutation_records(
            tx,
            mesh,
            actor,
            "collection.enroll",
            "collection.updated",
            "collection",
            id,
            json!({"peer_id":peer,"ticket_id":ticket,"membership":"added"}),
        )
        .await?;
    }
    // The peer INSERT has already advanced management_revision in this same
    // transaction; the publisher observes membership and identity together.
    Ok(())
}
