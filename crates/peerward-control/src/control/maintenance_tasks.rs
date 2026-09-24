use peerward_api::{MaintenanceOperation, MaintenancePlanRequest, MaintenanceTaskCreateRequest};

fn maintenance_record(actor: &str, id: Uuid, action: &str, metadata: Value) -> MutationRecord {
    MutationRecord {
        mesh_id: None,
        actor: actor.into(),
        action: action.into(),
        event_type: action.into(),
        resource_type: "maintenance_task".into(),
        resource_id: Some(id),
        result: "success".into(),
        metadata,
        correlation: None,
    }
}

async fn maintenance_preview(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
    ApiJson(plan): ApiJson<MaintenancePlanRequest>,
) -> Result<Json<Value>, ApiError> {
    authorize(&context, &headers, Capability::TrustManage, true)?;
    let mut tx = state.store.begin_mutation().await?;
    let result = maintenance_plan(&mut tx, &plan).await?;
    tx.rollback().await?;
    Ok(Json(result))
}

async fn maintenance_plan(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    plan: &MaintenancePlanRequest,
) -> Result<Value, ApiError> {
    if plan.host_id.get_version_num() != 4
        || !(15..=900).contains(&plan.grace_seconds)
        || plan
            .replacement_host_id
            .is_some_and(|id| id == plan.host_id || id.get_version_num() != 4)
        || (plan.operation == MaintenanceOperation::RelayDrain
            && plan.replacement_host_id.is_none())
        || (plan.operation == MaintenanceOperation::RelayResume
            && plan.replacement_host_id.is_some())
    {
        return Err(ApiError::invalid(
            "invalid_maintenance_plan",
            "select a host, a distinct replacement for draining, and a grace period of 15 to 900 seconds",
        ));
    }
    let hosts = sqlx::query(
        "SELECT id,name,enabled,maintenance_state,revision,is_default,
        COALESCE(last_seen>clock_timestamp()-interval '30 seconds',false) AS online
        FROM relay_hosts WHERE id=$1 OR id=$2 ORDER BY id FOR UPDATE",
    )
    .bind(plan.host_id)
    .bind(plan.replacement_host_id)
    .fetch_all(&mut **tx)
    .await?;
    let host = hosts
        .iter()
        .find(|row| row.get::<Uuid, _>("id") == plan.host_id)
        .ok_or_else(ApiError::not_found)?;
    let mut blockers = Vec::<&str>::new();
    if !host.try_get::<bool, _>("enabled")? || !host.try_get::<bool, _>("online")? {
        blockers.push("host_unavailable");
    }
    let expected_state = if plan.operation == MaintenanceOperation::RelayDrain {
        "active"
    } else {
        "suspended"
    };
    if host.try_get::<String, _>("maintenance_state")? != expected_state {
        blockers.push("host_state_changed");
    }
    let replacement = hosts
        .iter()
        .find(|row| Some(row.get::<Uuid, _>("id")) == plan.replacement_host_id);
    if plan.operation == MaintenanceOperation::RelayDrain
        && !replacement.is_some_and(|row| {
            row.get::<bool, _>("enabled")
                && row.get::<bool, _>("online")
                && row.get::<String, _>("maintenance_state") == "active"
        })
    {
        blockers.push("replacement_unavailable");
    }
    let rows = sqlx::query("SELECT a.mesh_id,m.name,m.lifecycle,a.revision,a.desired,
        b.revision AS replacement_revision FROM relay_host_assignments a JOIN meshes m ON m.id=a.mesh_id
        LEFT JOIN relay_host_assignments b ON b.mesh_id=a.mesh_id AND b.host_id=$2
        WHERE a.host_id=$1 AND a.desired<>'removed' ORDER BY a.mesh_id LIMIT 257")
        .bind(plan.host_id).bind(plan.replacement_host_id).fetch_all(&mut **tx).await?;
    if rows.len() > 256 {
        return Err(ApiError::invalid(
            "maintenance_capacity",
            "maintain at most 256 Mesh assignments per host",
        ));
    }
    let mut affected = Vec::new();
    for row in rows {
        let mesh: Uuid = row.try_get("mesh_id")?;
        if row.try_get::<String, _>("lifecycle")? != "active" {
            blockers.push("mesh_lifecycle_in_progress");
        }
        if plan.operation == MaintenanceOperation::RelayDrain
            && !maintenance_replacement_ready(
                tx,
                plan.replacement_host_id.unwrap_or_default(),
                mesh,
            )
            .await?
        {
            blockers.push("replacement_not_ready_for_every_mesh");
        }
        affected.push(json!({"mesh_id":mesh,"name":row.try_get::<String,_>("name")?,
            "source_revision":row.try_get::<i64,_>("revision")?,"source_desired":row.try_get::<String,_>("desired")?,
            "replacement_revision":row.try_get::<Option<i64>,_>("replacement_revision")?}));
    }
    blockers.sort_unstable();
    blockers.dedup();
    let definition = json!({"plan":plan,"host_version":host.try_get::<i64,_>("revision")?,
        "replacement_version":replacement.map(|r|r.get::<i64,_>("revision")),"affected":affected});
    let digest = hex::encode(Sha256::digest(
        serde_json::to_vec(&definition).map_err(|_| dynamic_invalid())?,
    ));
    Ok(
        json!({"digest":digest,"definition":definition,"host_name":host.try_get::<String,_>("name")?,
        "replacement_name":replacement.map(|r|r.get::<String,_>("name")),"blockers":blockers,
        "will_change_default_host":host.try_get::<bool,_>("is_default")? && plan.operation==MaintenanceOperation::RelayDrain,
        "existing_connections_may_reconnect":true,"application_state":"requires_host_acknowledgement"}),
    )
}

async fn maintenance_replacement_ready(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    host: Uuid,
    mesh: Uuid,
) -> Result<bool, ApiError> {
    Ok(sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM relay_host_assignments a
        JOIN relay_hosts h ON h.id=a.host_id AND h.enabled AND h.maintenance_state='active'
            AND h.last_seen>clock_timestamp()-interval '30 seconds'
        JOIN relays r ON r.id=a.relay_id AND r.mesh_id=a.mesh_id AND r.administrative_state='enabled'
        JOIN relay_runtime_leases l ON l.mesh_id=a.mesh_id AND l.relay_id=a.relay_id AND l.lease_deadline>clock_timestamp()
        JOIN relay_credentials c ON c.mesh_id=a.mesh_id AND c.relay_id=a.relay_id AND c.lifecycle='active'
            AND c.not_before<=clock_timestamp() AND c.not_after>clock_timestamp()+interval '60 seconds'
        JOIN mesh_authorities ca ON ca.id=c.authority_id AND ca.mesh_id=a.mesh_id
            AND ca.lifecycle IN ('active','overlap') AND ca.not_after>clock_timestamp()+interval '60 seconds'
            AND (ca.lifecycle='active' OR ca.overlap_deadline>clock_timestamp()+interval '60 seconds')
        JOIN meshes m ON m.id=a.mesh_id AND m.lifecycle='active'
        WHERE a.host_id=$1 AND a.mesh_id=$2 AND a.desired='active' AND a.state='ready'
            AND a.applied_revision=a.revision AND a.observed_at>clock_timestamp()-interval '30 seconds'
            AND EXISTS(SELECT 1 FROM signed_state_revisions s WHERE s.mesh_id=m.id AND s.kind='relays' AND s.revision=m.relay_revision))")
        .bind(host).bind(mesh).fetch_one(&mut **tx).await?)
}

async fn create_maintenance_task(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<MaintenanceTaskCreateRequest>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    authorize(&context, &headers, Capability::TrustManage, true)?;
    if body.id.get_version_num() != 4 || body.preview_digest.len() != 64 {
        return Err(dynamic_invalid());
    }
    let request = serde_json::to_value(&body).map_err(|_| dynamic_invalid())?;
    let mut tx = state.store.begin_mutation().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(format!("maintenance/{}", body.id))
        .execute(&mut *tx)
        .await?;
    if let Some(row) =
        sqlx::query("SELECT to_jsonb(t) AS item FROM maintenance_tasks t WHERE id=$1")
            .bind(body.id)
            .fetch_optional(&mut *tx)
            .await?
    {
        let value: Value = row.try_get("item")?;
        if value["request"] != request || value["actor"] != context.actor {
            return Err(ApiError::conflict(
                "idempotency_conflict",
                "task ID belongs to a different request",
            ));
        }
        return Ok((StatusCode::OK, Json(value)));
    }
    let preview = maintenance_plan(&mut tx, &body.plan).await?;
    if preview["digest"] != body.preview_digest {
        return Err(ApiError::conflict(
            "preview_changed",
            "host assignments changed; preview again",
        ));
    }
    if preview["blockers"]
        .as_array()
        .is_none_or(|items| !items.is_empty())
    {
        return Err(ApiError::conflict(
            "maintenance_not_ready",
            "resolve the preview blockers before starting maintenance",
        ));
    }
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM maintenance_tasks WHERE host_id=$1 AND status<>'succeeded'",
    )
    .bind(body.plan.host_id)
    .fetch_one(&mut *tx)
    .await?;
    if count != 0 {
        return Err(ApiError::conflict(
            "maintenance_in_progress",
            "retry the existing unfinished task",
        ));
    }
    if body.plan.operation == MaintenanceOperation::RelayDrain {
        sqlx::query("UPDATE relay_hosts SET maintenance_state='draining',revision=revision+1,is_default=false WHERE id=$1")
            .bind(body.plan.host_id).execute(&mut *tx).await?;
        if preview["will_change_default_host"] == true {
            sqlx::query("UPDATE relay_hosts SET is_default=true,revision=revision+1 WHERE id=$1")
                .bind(body.plan.replacement_host_id)
                .execute(&mut *tx)
                .await?;
        }
    }
    let value: Value = sqlx::query_scalar(
        "INSERT INTO maintenance_tasks(id,host_id,operation,request,actor)
        VALUES($1,$2,$3,$4,$5) RETURNING to_jsonb(maintenance_tasks)",
    )
    .bind(body.id)
    .bind(body.plan.host_id)
    .bind(body.plan.operation.as_str())
    .bind(request)
    .bind(&context.actor)
    .fetch_one(&mut *tx)
    .await?;
    state
        .store
        .commit_mutation(
            tx,
            &maintenance_record(&context.actor, body.id, "maintenance.created", preview),
        )
        .await?;
    Ok((StatusCode::ACCEPTED, Json(value)))
}

async fn list_maintenance_tasks(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
) -> Result<Json<ApiPage<Value>>, ApiError> {
    authorize(&context, &HeaderMap::new(), Capability::TrustManage, false)?;
    let cursor = query.cursor()?;
    let limit = query.limit()?;
    let mut rows = sqlx::query("SELECT id,created_at,to_jsonb(t) AS item FROM maintenance_tasks t
        WHERE ($1::timestamptz IS NULL OR (created_at,id)<($1,$2)) ORDER BY created_at DESC,id DESC LIMIT $3")
        .bind(cursor.map(|c|c.timestamp)).bind(cursor.map(|c|c.id)).bind(i64::from(limit)+1).fetch_all(state.store.pool()).await?;
    let more = rows.len() > usize::from(limit);
    rows.truncate(usize::from(limit));
    let next_cursor = if more {
        rows.last()
            .map(|row| {
                Ok::<_, ApiError>(encode_page_cursor(ApiPageCursor {
                    timestamp: row.try_get("created_at")?,
                    id: row.try_get("id")?,
                }))
            })
            .transpose()?
    } else {
        None
    };
    Ok(Json(ApiPage {
        items: rows
            .iter()
            .map(|r| r.try_get("item"))
            .collect::<Result<Vec<_>, _>>()?,
        next_cursor,
    }))
}
async fn get_maintenance_task(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    authorize(&context, &HeaderMap::new(), Capability::TrustManage, false)?;
    Ok(Json(
        sqlx::query_scalar("SELECT to_jsonb(t) FROM maintenance_tasks t WHERE id=$1")
            .bind(id)
            .fetch_optional(state.store.pool())
            .await?
            .ok_or_else(ApiError::not_found)?,
    ))
}
async fn retry_maintenance_task(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    authorize(&context, &headers, Capability::TrustManage, true)?;
    let version = require_if_match(&headers)?;
    let mut tx = state.store.begin_mutation().await?;
    let value:Value=sqlx::query_scalar("UPDATE maintenance_tasks SET status='waiting',version=version+1,attempt=attempt+1,error_code=NULL,
        deadline=clock_timestamp()+interval '30 minutes',next_attempt_at=clock_timestamp(),updated_at=clock_timestamp()
        WHERE id=$1 AND version=$2 AND status='failed' RETURNING to_jsonb(maintenance_tasks)")
        .bind(id).bind(version).fetch_optional(&mut *tx).await?
        .ok_or_else(||ApiError::conflict("task_changed","reload the task; only failed tasks can be retried"))?;
    state
        .store
        .commit_mutation(
            tx,
            &maintenance_record(&context.actor, id, "maintenance.retried", json!({"id":id})),
        )
        .await?;
    Ok(Json(value))
}
