/// Audit and ownership fencing are in the mutation transaction, including bulk
/// operations. A failed ownership check rolls back all prior staged SQL writes.
async fn observe_configuration_mutation(
    tx: &mut Transaction<'_, Postgres>,
    mesh: MeshId,
    actor: &str,
    action: &str,
    target: &str,
) -> Result<(), StoreError> {
    let controlled = matches!(
        target,
        "network_resource"
            | "sharing"
            | "gateway_binding"
            | "collection"
            | "dns_profile"
            | "resource_policy"
            | "policy"
            | "auto_approval_rule"
            | "device_conditions"
    ) || (target == "mesh" && action == "mesh.update")
        || action == "configuration.apply";
    // Enrollment, device retirement, service readiness and live credentials are
    // not owned by a repository. They still invalidate a declaration preview.
    let dependency = (target == "peer" && action.starts_with("peer."))
        || target == "service"
        || matches!(target, "peer_credential" | "authority" | "revocation");
    if !controlled && !dependency {
        return Ok(());
    }
    let owner: Option<Uuid> = sqlx::query_scalar(
        "SELECT owner_machine_id FROM configuration_ownership WHERE mesh_id=$1 FOR UPDATE",
    )
    .bind(mesh.into_uuid())
    .fetch_one(&mut **tx)
    .await?;
    if controlled
        && match owner {
            Some(id) => actor != format!("machine:{id}"),
            None => actor.starts_with("machine:"),
        }
    {
        return Err(StoreError::ConfigurationOwned);
    }
    sqlx::query("UPDATE configuration_ownership SET updated_at=clock_timestamp() WHERE mesh_id=$1")
        .bind(mesh.into_uuid())
        .execute(&mut **tx)
        .await?;
    Ok(())
}
