async fn append_audit(
    transaction: &mut Transaction<'_, Postgres>,
    mesh_id: Option<MeshId>,
    actor: &str,
    action: &str,
    target_type: &str,
    target_id: Option<Uuid>,
    result: &str,
    metadata: Value,
) -> Result<(), StoreError> {
    if let Some(mesh) = mesh_id
        && result == "success"
    {
        observe_configuration_mutation(transaction, mesh, actor, action, target_type).await?;
    }
    append_audit_row(
        transaction,
        mesh_id,
        actor,
        action,
        target_type,
        target_id,
        result,
        metadata,
    )
    .await?;
    if let Some(mesh) = mesh_id
        && result == "success"
        && (matches!(
            target_type,
            "network_resource" | "gateway_binding" | "collection" | "auto_approval_rule"
        ) || (target_type == "peer" && action.starts_with("peer.")))
    {
        reconcile_auto_approvals(transaction, mesh).await?;
    }
    Ok(())
}

async fn append_audit_row(
    transaction: &mut Transaction<'_, Postgres>,
    mesh_id: Option<MeshId>,
    actor: &str,
    action: &str,
    target_type: &str,
    target_id: Option<Uuid>,
    result: &str,
    metadata: Value,
) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO audit_log
         (id,mesh_id,retained_mesh_id,actor,action,target_type,target_id,result,metadata)
         VALUES ($1,$2,$2,$3,$4,$5,$6,$7,$8)",
    )
    .bind(Uuid::new_v4())
    .bind(mesh_id.map(MeshId::into_uuid))
    .bind(actor)
    .bind(action)
    .bind(target_type)
    .bind(target_id)
    .bind(result)
    .bind(metadata)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}
