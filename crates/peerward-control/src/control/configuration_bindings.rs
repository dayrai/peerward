async fn sync_configuration_bindings(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    mesh: Uuid,
    old: &peerward_api::ConfigurationDocument,
    new: &peerward_api::ConfigurationDocument,
) -> Result<(), ApiError> {
    use peerward_api::ConfigurationApproval;
    use peerward_management::{ApprovalSource, ForwardingMode, GatewayBinding};
    let ids: Vec<_> = new.bindings.iter().map(|x| x.id).collect();
    sqlx::query("DELETE FROM gateway_bindings WHERE mesh_id=$1 AND NOT(id=ANY($2))")
        .bind(mesh)
        .bind(&ids)
        .execute(&mut **tx)
        .await?;
    for entry in &new.bindings {
        let approved = matches!(
            entry.approval,
            ConfigurationApproval::Manual { approved: true }
        );
        let candidate = GatewayBinding {
            id: entry.id,
            resource_id: entry.resource_id,
            peer_id: entry.peer_id,
            version: 1,
            approved,
            priority: entry.priority,
            forwarding: entry.forwarding,
            return_route_confirmed: entry.return_route_confirmed,
            approval_source: ApprovalSource::Manual,
        };
        candidate.validate().map_err(management_error)?;
        let before = old.bindings.iter().find(|x| x.id == entry.id);
        let target_changed = old
            .resources
            .iter()
            .find(|r| r.id == entry.resource_id)
            .zip(new.resources.iter().find(|r| r.id == entry.resource_id))
            .is_some_and(|(a, b)| a.definition.target != b.definition.target);
        if before
            .is_some_and(|value| declaration_value(value).ok() == declaration_value(entry).ok())
            && !target_changed
        {
            continue;
        }
        let enabled:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM peers WHERE mesh_id=$1 AND id=$2 AND administrative_state='enabled' AND (admission_until IS NULL OR admission_until>clock_timestamp()))")
            .bind(mesh).bind(entry.peer_id.into_uuid()).fetch_one(&mut **tx).await?;
        if approved && !enabled {
            return Err(ApiError::conflict(
                "provider_unavailable",
                "cannot approve a disabled or expired provider",
            ));
        }
        let written=sqlx::query("INSERT INTO gateway_bindings(id,mesh_id,resource_id,peer_id,approved,priority,forwarding,return_route_confirmed,approval_source) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'{\"kind\":\"manual\"}'::jsonb)
            ON CONFLICT(id) DO UPDATE SET approved=EXCLUDED.approved,priority=EXCLUDED.priority,return_route_confirmed=EXCLUDED.return_route_confirmed,approval_source=EXCLUDED.approval_source,updated_at=clock_timestamp() WHERE gateway_bindings.mesh_id=EXCLUDED.mesh_id")
            .bind(entry.id).bind(mesh).bind(entry.resource_id).bind(entry.peer_id.into_uuid()).bind(approved).bind(i64::from(entry.priority))
            .bind(match entry.forwarding{ForwardingMode::Snat=>"snat",ForwardingMode::PreserveSource=>"preserve_source"}).bind(entry.return_route_confirmed).execute(&mut **tx).await?.rows_affected();
        if written != 1 {
            return Err(ApiError::conflict(
                "configuration_identity",
                "binding identity belongs to another Mesh",
            ));
        }
        match entry.approval {
            ConfigurationApproval::Automatic => {
                sqlx::query("INSERT INTO gateway_auto_eligibility(mesh_id,binding_id) VALUES($1,$2) ON CONFLICT DO NOTHING").bind(mesh).bind(entry.id).execute(&mut **tx).await?;
            }
            ConfigurationApproval::Manual { .. } => {
                sqlx::query(
                    "DELETE FROM gateway_auto_eligibility WHERE mesh_id=$1 AND binding_id=$2",
                )
                .bind(mesh)
                .bind(entry.id)
                .execute(&mut **tx)
                .await?;
            }
        }
        if approved {
            sqlx::query("DELETE FROM resource_withdrawals w USING network_resources r WHERE w.mesh_id=$1 AND r.mesh_id=w.mesh_id AND r.id=$2 AND w.target=r.definition->'target'")
                .bind(mesh).bind(entry.resource_id).execute(&mut **tx).await?;
        }
    }
    Ok(())
}
