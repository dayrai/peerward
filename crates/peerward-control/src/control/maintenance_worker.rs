async fn run_maintenance_tasks(store: Store) {
    let mut interval = tokio::time::interval(Duration::from_secs(2));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        if let Err(error) = advance_maintenance_tasks(&store).await {
            tracing::warn!(%error,"Maintenance task step deferred");
        }
    }
}

/// Performs bounded database-atomic steps. Relay hosts acknowledge the exact
/// assignment revision over mTLS; no shell or external operation runs here.
pub async fn advance_maintenance_tasks(store: &Store) -> Result<usize, ApiError> {
    let mut advanced = 0;
    for _ in 0..8 {
        let mut tx = store.begin_mutation().await?;
        let Some(task)=sqlx::query("SELECT *,deadline<=clock_timestamp() AS expired,
            COALESCE(grace_until<=clock_timestamp(),false) AS grace_elapsed
            FROM maintenance_tasks WHERE status IN ('queued','waiting') AND next_attempt_at<=clock_timestamp()
            ORDER BY next_attempt_at,id FOR UPDATE SKIP LOCKED LIMIT 1").fetch_optional(&mut *tx).await? else { break; };
        let id: Uuid = task.try_get("id")?;
        let request: MaintenanceTaskCreateRequest =
            serde_json::from_value(task.try_get("request")?).map_err(|_| dynamic_invalid())?;
        let host = request.plan.host_id;
        sqlx::query("SELECT id FROM relay_hosts WHERE id=$1 OR id=$2 ORDER BY id FOR UPDATE")
            .bind(host)
            .bind(request.plan.replacement_host_id)
            .fetch_all(&mut *tx)
            .await?;
        let (stage, status, error) = if task.try_get::<bool, _>("expired")? {
            (
                task.try_get::<String, _>("stage")?,
                "failed",
                Some("maintenance_timeout"),
            )
        } else {
            let rows=sqlx::query("SELECT a.mesh_id,a.relay_id,a.desired,a.state,a.revision,a.applied_revision,
                COALESCE(a.observed_at>clock_timestamp()-interval '30 seconds',false) AS fresh
                FROM relay_host_assignments a JOIN meshes m ON m.id=a.mesh_id
                WHERE a.host_id=$1 AND a.desired<>'removed' AND m.lifecycle='active' ORDER BY a.mesh_id")
                .bind(host).fetch_all(&mut *tx).await?;
            // Serialize publication and Mesh lifecycle transitions before changing routes.
            for row in &rows {
                sqlx::query("SELECT id FROM meshes WHERE id=$1 FOR UPDATE")
                    .bind(row.try_get::<Uuid, _>("mesh_id")?)
                    .fetch_optional(&mut *tx)
                    .await?;
            }
            if request.plan.operation == MaintenanceOperation::RelayDrain {
                advance_relay_drain(&mut tx, &request.plan, &task, &rows).await?
            } else {
                advance_relay_resume(&mut tx, &request.plan, &task, &rows).await?
            }
        };
        let changed = task.try_get::<String, _>("stage")? != stage
            || task.try_get::<String, _>("status")? != status
            || task.try_get::<Option<String>, _>("error_code")?.as_deref() != error;
        sqlx::query(
            "UPDATE maintenance_tasks SET stage=$2,status=$3,error_code=$4,version=version+$5,
            updated_at=CASE WHEN $5=1 THEN clock_timestamp() ELSE updated_at END,
            next_attempt_at=clock_timestamp()+interval '2 seconds' WHERE id=$1",
        )
        .bind(id)
        .bind(&stage)
        .bind(status)
        .bind(error)
        .bind(i64::from(changed))
        .execute(&mut *tx)
        .await?;
        if changed {
            store
                .commit_mutation(
                    tx,
                    &maintenance_record(
                        "control:maintenance",
                        id,
                        "maintenance.progress",
                        json!({"id":id,"stage":stage,"status":status,"reason":error}),
                    ),
                )
                .await?;
        } else {
            tx.commit().await?;
        }
        advanced += 1;
    }
    Ok(advanced)
}

type MaintenanceStep = (String, &'static str, Option<&'static str>);
fn maintenance_wait(stage: &str, reason: Option<&'static str>) -> MaintenanceStep {
    (stage.into(), "waiting", reason)
}

async fn advance_relay_drain(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    plan: &MaintenancePlanRequest,
    task: &sqlx::postgres::PgRow,
    rows: &[sqlx::postgres::PgRow],
) -> Result<MaintenanceStep, ApiError> {
    for row in rows {
        if !maintenance_replacement_ready(
            tx,
            plan.replacement_host_id.ok_or_else(dynamic_invalid)?,
            row.try_get("mesh_id")?,
        )
        .await?
        {
            return Ok(maintenance_wait(
                &task.try_get::<String, _>("stage")?,
                Some("replacement_unavailable"),
            ));
        }
    }
    if task
        .try_get::<Option<OffsetDateTime>, _>("grace_until")?
        .is_none()
    {
        change_host_assignments(tx, plan.host_id, "draining").await?;
        sqlx::query("UPDATE maintenance_tasks SET grace_until=clock_timestamp()+make_interval(secs=>$2) WHERE id=$1")
            .bind(task.try_get::<Uuid,_>("id")?).bind(f64::from(plan.grace_seconds)).execute(&mut **tx).await?;
        return Ok(maintenance_wait("draining", None));
    }
    let suspended = rows
        .iter()
        .all(|r| r.get::<String, _>("desired") == "suspended");
    let expected = if suspended { "suspended" } else { "draining" };
    let applied = rows.iter().all(|r| {
        r.get::<String, _>("state") == expected
            && r.get::<bool, _>("fresh")
            && r.get::<i64, _>("applied_revision") == r.get::<i64, _>("revision")
    });
    if !applied {
        return Ok(maintenance_wait(
            expected,
            Some("awaiting_host_acknowledgement"),
        ));
    }
    if !suspended {
        if !task.try_get::<bool, _>("grace_elapsed")? {
            return Ok(maintenance_wait("draining", None));
        }
        change_host_assignments(tx, plan.host_id, "suspended").await?;
        return Ok(maintenance_wait("suspending", None));
    }
    let live: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM relay_runtime_leases l
        JOIN relay_host_assignments a ON a.mesh_id=l.mesh_id AND a.relay_id=l.relay_id
        WHERE a.host_id=$1 AND a.desired='suspended' AND l.lease_deadline>clock_timestamp())",
    )
    .bind(plan.host_id)
    .fetch_one(&mut **tx)
    .await?;
    if live {
        return Ok(maintenance_wait(
            "suspending",
            Some("runtime_lease_still_active"),
        ));
    }
    sqlx::query(
        "UPDATE relay_hosts SET maintenance_state='suspended',revision=revision+1 WHERE id=$1",
    )
    .bind(plan.host_id)
    .execute(&mut **tx)
    .await?;
    Ok(("suspended".into(), "succeeded", None))
}

async fn advance_relay_resume(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    plan: &MaintenancePlanRequest,
    task: &sqlx::postgres::PgRow,
    rows: &[sqlx::postgres::PgRow],
) -> Result<MaintenanceStep, ApiError> {
    if task.try_get::<String, _>("stage")? == "queued" {
        sqlx::query(
            "UPDATE relay_hosts SET maintenance_state='active',revision=revision+1 WHERE id=$1",
        )
        .bind(plan.host_id)
        .execute(&mut **tx)
        .await?;
        change_host_assignments(tx, plan.host_id, "active").await?;
        return Ok(maintenance_wait("restoring", None));
    }
    for row in rows {
        if !maintenance_replacement_ready(tx, plan.host_id, row.try_get("mesh_id")?).await? {
            return Ok(maintenance_wait("restoring", Some("awaiting_ready_host")));
        }
    }
    Ok(("ready".into(), "succeeded", None))
}

async fn change_host_assignments(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    host: Uuid,
    desired: &str,
) -> Result<(), ApiError> {
    let meshes:Vec<Uuid>=sqlx::query_scalar("UPDATE relay_host_assignments SET desired=$2,revision=revision+1,state='pending',
        observed_at=NULL,active_sessions=NULL,error_code=NULL,updated_at=clock_timestamp()
        WHERE host_id=$1 AND desired<>'removed' AND desired<>$2
        AND EXISTS(SELECT 1 FROM meshes m WHERE m.id=mesh_id AND m.lifecycle='active') RETURNING mesh_id")
        .bind(host).bind(desired).fetch_all(&mut **tx).await?;
    for mesh in meshes {
        sqlx::query("UPDATE meshes SET relay_revision=relay_revision+1 WHERE id=$1")
            .bind(mesh)
            .execute(&mut **tx)
            .await?;
    }
    sqlx::query("UPDATE relay_hosts SET revision=revision+1 WHERE id=$1")
        .bind(host)
        .execute(&mut **tx)
        .await?;
    Ok(())
}
