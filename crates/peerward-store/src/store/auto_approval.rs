impl Store {
    /// Caller must hold the Mesh mutation lock. Effects remain in this transaction,
    /// allowing declaration previews to roll back the exact reconciliation path.
    pub async fn reconcile_configuration_approvals(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        mesh: MeshId,
    ) -> Result<(), StoreError> {
        reconcile_auto_approvals(tx, mesh).await
    }
}

async fn reconcile_auto_approvals(
    tx: &mut Transaction<'_, Postgres>,
    mesh: MeshId,
) -> Result<(), StoreError> {
    use peerward_management::{
        ApprovalSource, AutoApprovalDefinition, CollectionDefinition, CollectionKind,
        ResourceDefinition,
    };
    let rule_rows: Vec<(Uuid, i64, Value)> = sqlx::query_as(
        "SELECT id,version,definition FROM auto_approval_rules WHERE mesh_id=$1 ORDER BY id",
    )
    .bind(mesh.into_uuid())
    .fetch_all(&mut **tx)
    .await?;
    let bindings: Vec<sqlx::postgres::PgRow> = sqlx::query("SELECT b.id,b.peer_id,b.approved,b.approval_source,b.forwarding,r.definition FROM gateway_bindings b
        JOIN gateway_auto_eligibility e ON e.mesh_id=b.mesh_id AND e.binding_id=b.id
        JOIN network_resources r ON r.mesh_id=b.mesh_id AND r.id=b.resource_id
        WHERE b.mesh_id=$1 ORDER BY b.id FOR UPDATE OF b")
        .bind(mesh.into_uuid()).fetch_all(&mut **tx).await?;
    if bindings.is_empty() {
        return Ok(());
    }
    if rule_rows.len() > 64 || bindings.len() > 8192 {
        return Err(StoreError::Invalid("automatic approval bounds"));
    }
    let collection_rows: Vec<(Uuid, Value)> =
        sqlx::query_as("SELECT id,definition FROM network_collections WHERE mesh_id=$1")
            .bind(mesh.into_uuid())
            .fetch_all(&mut **tx)
            .await?;
    let mut collections = std::collections::BTreeMap::new();
    let peers: Vec<(Uuid,Value)> = sqlx::query_as("SELECT id,labels FROM peers WHERE mesh_id=$1 AND administrative_state='enabled' AND (admission_until IS NULL OR admission_until>clock_timestamp())")
        .bind(mesh.into_uuid()).fetch_all(&mut **tx).await?;
    let peers: Vec<(Uuid, std::collections::BTreeMap<String, String>)> = peers
        .into_iter()
        .map(|(id, labels)| {
            Ok((
                id,
                serde_json::from_value(labels)
                    .map_err(|_| StoreError::Invalid("stored peer labels"))?,
            ))
        })
        .collect::<Result<_, StoreError>>()?;
    for (id, value) in collection_rows {
        let definition: CollectionDefinition =
            serde_json::from_value(value).map_err(|_| StoreError::Invalid("stored collection"))?;
        if definition.kind == CollectionKind::Devices {
            collections.insert(
                id,
                definition
                    .resolve(id, peers.iter().map(|(id, labels)| (*id, labels)))
                    .members,
            );
        }
    }
    let mut rules = Vec::new();
    for (id, version, value) in rule_rows {
        let definition: AutoApprovalDefinition = serde_json::from_value(value)
            .map_err(|_| StoreError::Invalid("stored automatic approval rule"))?;
        definition
            .validate()
            .map_err(|_| StoreError::Invalid("stored automatic approval rule"))?;
        rules.push((
            id,
            u64::try_from(version).map_err(|_| StoreError::Invalid("rule version"))?,
            definition,
        ));
    }
    let mut changed = false;
    for binding in bindings {
        let id: Uuid = binding.try_get("id")?;
        let peer: Uuid = binding.try_get("peer_id")?;
        let approved: bool = binding.try_get("approved")?;
        let source: ApprovalSource = serde_json::from_value(binding.try_get("approval_source")?)
            .map_err(|_| StoreError::Invalid("approval source"))?;
        if approved && source == ApprovalSource::Manual {
            continue;
        }
        let resource: ResourceDefinition =
            serde_json::from_value(binding.try_get("definition")?)
                .map_err(|_| StoreError::Invalid("resource definition"))?;
        let automatic = rules
            .iter()
            .find(|(_, _, definition)| {
                binding
                    .try_get::<String, _>("forwarding")
                    .is_ok_and(|mode| mode == "snat")
                    && definition.covers(&resource.target)
                    && collections
                        .get(&definition.device_collection)
                        .is_some_and(|members| members.contains(&peer))
            })
            .map(|(rule_id, rule_version, _)| ApprovalSource::Automatic {
                rule_id: *rule_id,
                rule_version: *rule_version,
            });
        let next_approved = automatic.is_some();
        let next_source = automatic.unwrap_or_else(|| source.clone());
        if approved == next_approved && source == next_source {
            continue;
        }
        let next = serde_json::to_value(&next_source)
            .map_err(|_| StoreError::Invalid("approval source"))?;
        sqlx::query("UPDATE gateway_bindings SET approved=$3,approval_source=$4,updated_at=clock_timestamp() WHERE mesh_id=$1 AND id=$2")
            .bind(mesh.into_uuid()).bind(id).bind(next_approved).bind(&next).execute(&mut **tx).await?;
        if next_approved {
            sqlx::query("DELETE FROM resource_withdrawals w USING network_resources r,gateway_bindings b WHERE w.mesh_id=$1 AND r.mesh_id=w.mesh_id AND b.mesh_id=w.mesh_id AND b.id=$2 AND r.id=b.resource_id AND w.target=r.definition->'target'")
                .bind(mesh.into_uuid()).bind(id).execute(&mut **tx).await?;
        }
        let metadata = json!({"approved":next_approved,"approval_source":next});
        append_audit_row(
            tx,
            Some(mesh),
            "automatic",
            "auto_approval.changed",
            "gateway_binding",
            Some(id),
            "success",
            metadata.clone(),
        )
        .await?;
        append_event(
            tx,
            Some(mesh),
            "gateway_binding.approval_changed",
            "gateway_binding",
            Some(id),
            metadata,
        )
        .await?;
        changed = true;
    }
    if changed {
        sqlx::query("UPDATE meshes SET management_revision=management_revision+1 WHERE id=$1")
            .bind(mesh.into_uuid())
            .execute(&mut **tx)
            .await?;
    }
    Ok(())
}
