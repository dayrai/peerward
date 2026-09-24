async fn stage_configuration(
    store: &Store,
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    mesh: Uuid,
    old: &peerward_api::ConfigurationDocument,
    new: &peerward_api::ConfigurationDocument,
) -> Result<Vec<Uuid>, ApiError> {
    validate_declaration_references(tx, mesh, old, new).await?;
    validate_device_conditions(tx,mesh,&new.device_conditions).await?;
    if old.device_conditions != new.device_conditions {
        sqlx::query("UPDATE device_conditions SET definition=$2,updated_at=clock_timestamp() WHERE mesh_id=$1")
            .bind(mesh).bind(declaration_value(&new.device_conditions)?).execute(&mut **tx).await?;
    }
    // Delete targets before their bindings so the database captures former LAN
    // providers in withdrawal shadows, including cascaded binding deletions.
    let resource_ids: Vec<Uuid> = new.resources.iter().map(|x| x.id).collect();
    sqlx::query("DELETE FROM network_resources WHERE mesh_id=$1 AND NOT(id=ANY($2))")
        .bind(mesh)
        .bind(&resource_ids)
        .execute(&mut **tx)
        .await?;
    sync_configuration_values(
        tx,
        mesh,
        "network_resources",
        "definition",
        new.resources
            .iter()
            .map(|x| Ok((x.id, declaration_value(&x.definition)?)))
            .collect::<Result<Vec<_>, ApiError>>()?,
    )
    .await?;
    for resource in &new.resources {
        validate_network_target(tx, mesh, resource.id, &resource.definition).await?;
    }
    sync_configuration_values(
        tx,
        mesh,
        "network_collections",
        "definition",
        new.collections
            .iter()
            .map(|x| Ok((x.id, declaration_value(&x.definition)?)))
            .collect::<Result<Vec<_>, ApiError>>()?,
    )
    .await?;
    sync_configuration_values(
        tx,
        mesh,
        "auto_approval_rules",
        "definition",
        new.auto_approval_rules
            .iter()
            .map(|x| Ok((x.id, declaration_value(&x.definition)?)))
            .collect::<Result<Vec<_>, ApiError>>()?,
    )
    .await?;
    sync_configuration_bindings(tx, mesh, old, new).await?;
    store
        .reconcile_configuration_approvals(tx, mesh_id(mesh)?)
        .await?;
    resolve_network_collections(tx, mesh).await?;
    validate_dns_profiles(tx, mesh, &new.dns_profiles).await?;
    sync_configuration_values(
        tx,
        mesh,
        "dns_profiles",
        "profile",
        new.dns_profiles
            .iter()
            .map(|x| Ok((x.id, declaration_value(x)?)))
            .collect::<Result<Vec<_>, ApiError>>()?,
    )
    .await?;
    let failed_tests = validate_resource_policy_document(tx, mesh, &new.resource_policy).await?;
    if declaration_value(&old.peer_policy)? != declaration_value(&new.peer_policy)? {
        let current: i64 = sqlx::query_scalar("SELECT policy_revision FROM meshes WHERE id=$1")
            .bind(mesh)
            .fetch_one(&mut **tx)
            .await?;
        stage_peer_policy(
            tx,
            mesh,
            &PolicyPutRequest {
                revision: positive_revision(current.checked_add(1).ok_or_else(publisher_error)?)?,
                default_action: new.peer_policy.default_action.clone(),
                rules: new.peer_policy.rules.clone(),
            },
        )
        .await?;
    }
    if old.resource_policy != new.resource_policy {
        sync_configuration_values(
            tx,
            mesh,
            "resource_rules",
            "rule",
            new.resource_policy
                .rules
                .iter()
                .map(|x| Ok((x.id, declaration_value(x)?)))
                .collect::<Result<Vec<_>, ApiError>>()?,
        )
        .await?;
        let revision:i64=sqlx::query_scalar("UPDATE meshes SET resource_policy_revision=resource_policy_revision+1 WHERE id=$1 RETURNING resource_policy_revision").bind(mesh).fetch_one(&mut **tx).await?;
        sqlx::query(
            "INSERT INTO resource_policy_history(mesh_id,revision,document) VALUES($1,$2,$3)",
        )
        .bind(mesh)
        .bind(revision)
        .bind(declaration_value(&new.resource_policy)?)
        .execute(&mut **tx)
        .await?;
    }
    // Validate exactly the representation the publisher sends, including duplicate
    // exit providers and bounded effective grants, before any transaction commits.
    let effective = read_resource_configuration(tx, mesh_id(mesh)?).await?;
    effective.validate().map_err(management_error)?;
    Ok(failed_tests)
}

/// SQL identifiers are closed internal constants, never declaration input.
async fn sync_configuration_values(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    mesh: Uuid,
    table: &'static str,
    column: &'static str,
    values: Vec<(Uuid, Value)>,
) -> Result<(), ApiError> {
    if !matches!(
        (table, column),
        (
            "network_resources" | "network_collections" | "auto_approval_rules",
            "definition"
        ) | ("dns_profiles", "profile")
            | ("resource_rules", "rule")
    ) {
        return Err(publisher_error());
    }
    let ids: Vec<_> = values.iter().map(|x| x.0).collect();
    sqlx::query(&format!(
        "DELETE FROM {table} WHERE mesh_id=$1 AND NOT(id=ANY($2))"
    ))
    .bind(mesh)
    .bind(&ids)
    .execute(&mut **tx)
    .await?;
    for (id, value) in values {
        let known: Option<(Uuid, Value)> =
            sqlx::query_as(&format!("SELECT mesh_id,{column} FROM {table} WHERE id=$1"))
                .bind(id)
                .fetch_optional(&mut **tx)
                .await?;
        match known {
            Some((owner, _)) if owner != mesh => {
                return Err(ApiError::conflict(
                    "configuration_identity",
                    "identity belongs to a different Mesh",
                ));
            }
            Some((_, old)) if old == value => {}
            Some(_) => {
                sqlx::query(&format!("UPDATE {table} SET {column}=$3,updated_at=clock_timestamp() WHERE mesh_id=$1 AND id=$2")).bind(mesh).bind(id).bind(value).execute(&mut **tx).await?;
            }
            None => {
                sqlx::query(&format!(
                    "INSERT INTO {table}(id,mesh_id,{column}) VALUES($1,$2,$3)"
                ))
                .bind(id)
                .bind(mesh)
                .bind(value)
                .execute(&mut **tx)
                .await?;
            }
        }
    }
    Ok(())
}

async fn validate_declaration_references(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    mesh: Uuid,
    old: &peerward_api::ConfigurationDocument,
    new: &peerward_api::ConfigurationDocument,
) -> Result<(), ApiError> {
    use peerward_management::{CollectionKind, ResourceTarget};
    let peers: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM peers WHERE mesh_id=$1 AND administrative_state<>'deleted'",
    )
    .bind(mesh)
    .fetch_all(&mut **tx)
    .await?;
    let peers: BTreeSet<_> = peers.into_iter().collect();
    let resources: BTreeSet<_> = new.resources.iter().map(|x| x.id).collect();
    for collection in &new.collections {
        collection.definition.validate().map_err(management_error)?;
        if old
            .collections
            .iter()
            .any(|x| x.id == collection.id && x.definition.kind != collection.definition.kind)
        {
            return Err(ApiError::conflict(
                "collection_kind",
                "collection kind is immutable",
            ));
        }
        let known = match collection.definition.kind {
            CollectionKind::Devices => &peers,
            CollectionKind::Resources => &resources,
        };
        if !collection.definition.members.is_subset(known) {
            return Err(ApiError::invalid(
                "collection_member",
                "unknown or cross-Mesh collection member",
            ));
        }
    }
    for rule in &new.auto_approval_rules {
        rule.definition.validate().map_err(management_error)?;
        if !new.collections.iter().any(|c|c.id==rule.definition.device_collection&&c.definition.kind==CollectionKind::Devices)
            || !new.resources.iter().any(|r|matches!(r.definition.target,ResourceTarget::Subnet{site_id,..} if site_id==rule.definition.site_id)) {
            return Err(ApiError::invalid("auto_approval_reference","automatic approval needs a declared device collection and site"));
        }
    }
    for rule in &new.peer_policy.rules {
        validate_policy_rule(rule)?;
        if rule
            .source
            .peer_ids
            .iter()
            .chain(&rule.destination.peer_ids)
            .any(|id| !peers.contains(&id.into_uuid()))
        {
            return Err(ApiError::invalid(
                "policy_reference",
                "peer policy references a device outside this Mesh",
            ));
        }
    }
    for binding in &new.bindings {
        if !resources.contains(&binding.resource_id)
            || !peers.contains(&binding.peer_id.into_uuid())
        {
            return Err(ApiError::invalid(
                "binding_reference",
                "provider or target is absent from this Mesh declaration",
            ));
        }
        if let Some(previous) = old.bindings.iter().find(|x| x.id == binding.id)
            && (previous.peer_id != binding.peer_id
                || previous.resource_id != binding.resource_id
                || previous.forwarding != binding.forwarding)
        {
            return Err(ApiError::conflict(
                "binding_identity",
                "create a new binding identity when changing target, provider or forwarding mode",
            ));
        }
    }
    Ok(())
}
