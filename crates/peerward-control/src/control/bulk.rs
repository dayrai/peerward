const MAX_BULK_ITEMS: usize = 100;

async fn preview_bulk(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    Path(mesh): Path<Uuid>,
    ApiJson(body): ApiJson<BulkRequest>,
) -> Result<Json<BulkPreviewResponse>, ApiError> {
    authorize(&context, &HeaderMap::new(), Capability::ResourceWrite, false)?;
    mesh_id(mesh)?;
    validate_bulk_request(&body)?;
    let ids = body.items.iter().map(|item| item.id).collect::<Vec<_>>();
    let (table, state_expression, _) = bulk_family_config(body.family);
    let visible = if body.family == BulkResourceFamily::Peer {
        " AND administrative_state<>'deleted'"
    } else {
        ""
    };
    let statement = format!(
        "SELECT id,version,{state_expression} AS current_state FROM {table} \
         WHERE mesh_id=$1 AND id=ANY($2){visible}"
    );
    let rows = sqlx::query(&statement)
        .bind(mesh)
        .bind(&ids)
        .fetch_all(state.store.pool())
        .await?;
    let actual = rows
        .into_iter()
        .map(|row| {
            Ok((
                row.try_get::<Uuid, _>("id")?,
                (
                    row.try_get::<i64, _>("version")?,
                    row.try_get::<String, _>("current_state")?,
                ),
            ))
        })
        .collect::<Result<BTreeMap<_, _>, sqlx::Error>>()?;
    let mut items = Vec::with_capacity(body.items.len());
    for requested in &body.items {
        let (version, current_state, ready, error_code) = match actual.get(&requested.id) {
            None => (requested.version, "missing".into(), false, Some("not_found".into())),
            Some((version, state)) if u64::try_from(*version).ok() != Some(requested.version) => (
                u64::try_from(*version).unwrap_or_default(),
                state.clone(),
                false,
                Some("revision_conflict".into()),
            ),
            Some((version, state)) if !bulk_state_ready(body.family, state) => (
                u64::try_from(*version).unwrap_or_default(),
                state.clone(),
                false,
                Some("invalid_resource_state".into()),
            ),
            Some((version, state)) => (
                u64::try_from(*version).unwrap_or_default(),
                state.clone(),
                true,
                None,
            ),
        };
        items.push(BulkPreviewItem {
            id: requested.id,
            version,
            current_state,
            ready,
            error_code,
        });
    }
    Ok(Json(BulkPreviewResponse {
        family: body.family,
        valid: items.iter().all(|item| item.ready),
        items,
    }))
}

async fn commit_bulk(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(mesh): Path<Uuid>,
    ApiJson(body): ApiJson<BulkRequest>,
) -> Result<Json<BulkCommitResponse>, ApiError> {
    authorize(&context, &headers, Capability::ResourceWrite, true)?;
    let mesh_id = mesh_id(mesh)?;
    validate_bulk_request(&body)?;
    let mut sorted = body.items.clone();
    sorted.sort_by_key(|item| item.id);
    let mut transaction = state.store.begin_mutation().await?;
    let (_, state_expression, versioned_family) = bulk_family_config(body.family);
    let (table, _, _) = bulk_family_config(body.family);
    for item in &sorted {
        let expected = i64::try_from(item.version)
            .map_err(|_| ApiError::invalid("invalid_version", "resource version is too large"))?;
        lock_resource_version(
            &mut transaction,
            versioned_family,
            Some(mesh),
            item.id,
            expected,
        )
        .await?;
        let statement = format!(
            "SELECT {state_expression} AS current_state FROM {table} WHERE mesh_id=$1 AND id=$2"
        );
        let state_name: String = sqlx::query_scalar(&statement)
            .bind(mesh)
            .bind(item.id)
            .fetch_one(&mut *transaction)
            .await?;
        if !bulk_state_ready(body.family, &state_name) {
            return Err(ApiError::conflict(
                "invalid_resource_state",
                "one or more resources cannot be changed in their current state",
            ));
        }
    }
    let ids = sorted.iter().map(|item| item.id).collect::<Vec<_>>();
    apply_bulk_mutation(&mut transaction, body.family, mesh, &ids).await?;
    state
        .store
        .commit_mutation(
            transaction,
            &MutationRecord {
                mesh_id: Some(mesh_id),
                actor: context.actor.clone(),
                action: format!("{}.bulk_disable", bulk_family_name(body.family)),
                event_type: format!("{}.bulk_disabled", bulk_family_name(body.family)),
                resource_type: bulk_family_name(body.family).into(),
                resource_id: None,
                result: "success".into(),
                metadata: json!({"resource_ids": ids, "count": ids.len()}),
                correlation: CORRELATION_CONTEXT.try_with(|context| *context).ok(),
            },
        )
        .await?;
    let statement = format!("SELECT id,version FROM {table} WHERE mesh_id=$1 AND id=ANY($2)");
    let rows = sqlx::query(&statement)
        .bind(mesh)
        .bind(&ids)
        .fetch_all(state.store.pool())
        .await?;
    let versions = rows
        .into_iter()
        .map(|row| {
            let id: Uuid = row.try_get("id")?;
            let version: i64 = row.try_get("version")?;
            let version = u64::try_from(version)
                .map_err(|_| sqlx::Error::ColumnDecode {
                    index: "version".into(),
                    source: "negative resource version".into(),
                })?;
            Ok((id, version))
        })
        .collect::<Result<BTreeMap<_, _>, sqlx::Error>>()?;
    Ok(Json(BulkCommitResponse {
        family: body.family,
        committed: ids.len(),
        versions,
    }))
}

fn validate_bulk_request(body: &BulkRequest) -> Result<(), ApiError> {
    if body.items.is_empty() || body.items.len() > MAX_BULK_ITEMS {
        return Err(ApiError::invalid(
            "invalid_bulk_size",
            "bulk requests must contain between 1 and 100 resources",
        ));
    }
    let unique = body.items.iter().map(|item| item.id).collect::<HashSet<_>>();
    if unique.len() != body.items.len() || body.items.iter().any(|item| item.version == 0) {
        return Err(ApiError::invalid(
            "invalid_bulk_items",
            "bulk resource IDs must be unique and versions must be positive",
        ));
    }
    Ok(())
}

fn bulk_family_config(
    family: BulkResourceFamily,
) -> (&'static str, &'static str, VersionedFamily) {
    match family {
        BulkResourceFamily::Peer => ("peers", "administrative_state", VersionedFamily::Peer),
        BulkResourceFamily::Relay => ("relays", "administrative_state", VersionedFamily::Relay),
        BulkResourceFamily::JoinTicket => (
            "join_tickets",
            "CASE WHEN consumed_at IS NOT NULL THEN 'consumed' WHEN cancelled_at IS NOT NULL THEN 'cancelled' ELSE 'active' END",
            VersionedFamily::JoinTicket,
        ),
        BulkResourceFamily::Service => ("services", "state", VersionedFamily::Service),
    }
}

fn bulk_state_ready(family: BulkResourceFamily, state: &str) -> bool {
    match family {
        BulkResourceFamily::JoinTicket => state == "active",
        _ => state == "enabled",
    }
}

fn bulk_family_name(family: BulkResourceFamily) -> &'static str {
    match family {
        BulkResourceFamily::Peer => "peer",
        BulkResourceFamily::Relay => "relay",
        BulkResourceFamily::JoinTicket => "join_ticket",
        BulkResourceFamily::Service => "service",
    }
}

async fn apply_bulk_mutation(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    family: BulkResourceFamily,
    mesh: Uuid,
    ids: &[Uuid],
) -> Result<(), ApiError> {
    match family {
        BulkResourceFamily::Peer => bulk_disable_peers(transaction, mesh, ids).await?,
        BulkResourceFamily::Relay => bulk_disable_relays(transaction, mesh, ids).await?,
        BulkResourceFamily::JoinTicket => {
            sqlx::query("UPDATE join_tickets SET cancelled_at=clock_timestamp() WHERE mesh_id=$1 AND id=ANY($2) AND consumed_at IS NULL AND cancelled_at IS NULL")
                .bind(mesh).bind(ids).execute(&mut **transaction).await?;
        }
        BulkResourceFamily::Service => {
            sqlx::query("UPDATE services SET state='disabled',updated_at=clock_timestamp() WHERE mesh_id=$1 AND id=ANY($2) AND state='enabled'")
                .bind(mesh).bind(ids).execute(&mut **transaction).await?;
            sqlx::query("UPDATE meshes SET service_revision=service_revision+1,directory_revision=directory_revision+1,updated_at=clock_timestamp() WHERE id=$1")
                .bind(mesh).execute(&mut **transaction).await?;
        }
    }
    Ok(())
}

async fn bulk_disable_peers(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>, mesh: Uuid, ids: &[Uuid],
) -> Result<(), ApiError> {
    sqlx::query("UPDATE peers SET administrative_state='disabled',updated_at=clock_timestamp() WHERE mesh_id=$1 AND id=ANY($2) AND administrative_state='enabled'")
        .bind(mesh).bind(ids).execute(&mut **transaction).await?;
    sqlx::query("UPDATE peer_credentials SET lifecycle='revoked' WHERE mesh_id=$1 AND peer_id=ANY($2) AND lifecycle<>'revoked'")
        .bind(mesh).bind(ids).execute(&mut **transaction).await?;
    sqlx::query("UPDATE services SET state='disabled',updated_at=clock_timestamp() WHERE mesh_id=$1 AND peer_id=ANY($2) AND state='enabled'")
        .bind(mesh).bind(ids).execute(&mut **transaction).await?;
    sqlx::query("DELETE FROM relay_presence WHERE mesh_id=$1 AND peer_id=ANY($2)")
        .bind(mesh).bind(ids).execute(&mut **transaction).await?;
    sqlx::query("DELETE FROM relay_standby_presence_v1 WHERE mesh_id=$1 AND peer_id=ANY($2)")
        .bind(mesh).bind(ids).execute(&mut **transaction).await?;
    sqlx::query("UPDATE peer_addresses a SET state='quarantine',released_at=clock_timestamp(),quarantine_until=clock_timestamp()+make_interval(secs=>m.quarantine_seconds::double precision) FROM meshes m WHERE a.mesh_id=$1 AND a.peer_id=ANY($2) AND a.state='active' AND m.id=a.mesh_id")
        .bind(mesh).bind(ids).execute(&mut **transaction).await?;
    sqlx::query("UPDATE meshes SET directory_revision=directory_revision+1,service_revision=service_revision+1,revocation_revision=revocation_revision+1,updated_at=clock_timestamp() WHERE id=$1")
        .bind(mesh).execute(&mut **transaction).await?;
    Ok(())
}

async fn bulk_disable_relays(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>, mesh: Uuid, ids: &[Uuid],
) -> Result<(), ApiError> {
    sqlx::query("UPDATE relays SET administrative_state='disabled',updated_at=clock_timestamp() WHERE mesh_id=$1 AND id=ANY($2) AND administrative_state='enabled'")
        .bind(mesh).bind(ids).execute(&mut **transaction).await?;
    sqlx::query("UPDATE relay_credentials SET lifecycle='revoked' WHERE mesh_id=$1 AND relay_id=ANY($2) AND lifecycle<>'revoked'")
        .bind(mesh).bind(ids).execute(&mut **transaction).await?;
    sqlx::query("DELETE FROM relay_presence WHERE mesh_id=$1 AND relay_id=ANY($2)")
        .bind(mesh).bind(ids).execute(&mut **transaction).await?;
    sqlx::query("DELETE FROM relay_standby_presence_v1 WHERE mesh_id=$1 AND relay_id=ANY($2)")
        .bind(mesh).bind(ids).execute(&mut **transaction).await?;
    sqlx::query("UPDATE meshes SET relay_revision=relay_revision+1,directory_revision=directory_revision+1,revocation_revision=revocation_revision+1,updated_at=clock_timestamp() WHERE id=$1")
        .bind(mesh).execute(&mut **transaction).await?;
    Ok(())
}
