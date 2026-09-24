fn validate_deployment_report(report: &DeploymentTaskReport) -> Result<(), ApiError> {
    if report.task_id.get_version_num() != 4
        || report.local_version == 0
        || report.local_version > i64::MAX as u64
        || report.stage.is_empty()
        || report.stage.len() > 64
        || !report
            .stage
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b == b'_')
        || report.error_code.as_ref().is_some_and(|s| {
            s.len() > 128 || s.is_empty() || !s.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
        })
        || report.artifact.as_ref().is_some_and(|a| {
            !deployment_digest(&a.sha256)
                || a.bytes == 0
                || a.bytes > 128 * 1024 * 1024 * 1024
                || a.files == 0
                || a.files > 100_000
        })
        || (report.status == DeploymentTaskStatus::Succeeded
            && (report.artifact.is_none() || report.error_code.is_some()))
    {
        return Err(deployment_invalid());
    }
    Ok(())
}
fn validate_deployment_preview(preview: &DeploymentPreview) -> Result<(), ApiError> {
    if !deployment_digest(&preview.digest)
        || preview.services_to_pause.is_empty()
        || preview.services_to_pause.len() > 258
        || preview
            .services_to_pause
            .iter()
            .any(|s| !peerward_management::name_valid(s))
        || preview.online_files == 0
        || preview.online_files > 100_000
        || preview.meshes > 10000
        || (preview.relay_hosts == 0 && preview.upgrade.is_none())
        || preview.relay_hosts > 256
    {
        return Err(deployment_invalid());
    }
    if let Some(upgrade) = &preview.upgrade {
        validate_native_upgrade_preview(upgrade)?;
    }
    Ok(())
}

async fn deployment_exchange(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    ApiJson(body): ApiJson<DeploymentExchange>,
) -> Result<Json<Value>, ApiError> {
    if !matches!(context.source,AuthSource::DeploymentRunner(runner) if runner==id) {
        return Err(ApiError::forbidden(
            "runner_exchange_only",
            "use this installation's restricted runner credential",
        ));
    }
    if body.sequence == 0
        || body.sequence > i64::MAX as u64
        || !deployment_digest(&body.profile_digest)
        || body.reports.len() > 16
    {
        return Err(deployment_invalid());
    }
    if let Some(preview) = &body.preview {
        validate_deployment_preview(preview)?;
    }
    let mut report_ids = std::collections::HashSet::new();
    for report in &body.reports {
        validate_deployment_report(report)?;
        if !report_ids.insert(report.task_id) {
            return Err(deployment_invalid());
        }
    }
    let bytes = serde_json::to_vec(&body).map_err(|_| deployment_invalid())?;
    let hashed = Sha256::digest(&bytes).to_vec();
    let sequence = i64::try_from(body.sequence).map_err(|_| deployment_invalid())?;
    let mut tx = state.store.begin_mutation().await?;
    let runner=sqlx::query("SELECT * FROM deployment_runners WHERE id=$1 AND revoked_at IS NULL AND expires_at>clock_timestamp() FOR UPDATE")
        .bind(id).fetch_optional(&mut *tx).await?.ok_or_else(ApiError::not_found)?;
    if runner.try_get::<String, _>("profile_digest")? != body.profile_digest {
        return Err(ApiError::conflict(
            "runner_profile_changed",
            "register the changed local installation profile explicitly",
        ));
    }
    let previous: i64 = runner.try_get("exchange_sequence")?;
    if sequence <= previous {
        if sequence == previous
            && runner
                .try_get::<Option<Vec<u8>>, _>("exchange_digest")?
                .as_ref()
                == Some(&hashed)
        {
            return Ok(Json(runner.try_get("exchange_response")?));
        }
        return Err(ApiError::conflict(
            "runner_sequence_replayed",
            "keep the durable exchange sequence and retry the exact original request",
        ));
    }
    let mut changes = Vec::new();
    for report in &body.reports {
        let row=sqlx::query("SELECT status,local_version,report,operation,preview FROM deployment_tasks WHERE id=$1 AND runner_id=$2 FOR UPDATE")
            .bind(report.task_id).bind(id).fetch_optional(&mut *tx).await?.ok_or_else(ApiError::not_found)?;
        validate_native_upgrade_report(
            &row.try_get::<String, _>("operation")?,
            &row.try_get::<Value, _>("preview")?,
            report,
        )?;
        let incoming = serde_json::to_value(report).map_err(|_| deployment_invalid())?;
        let version = i64::try_from(report.local_version).map_err(|_| deployment_invalid())?;
        let old_version: i64 = row.try_get("local_version")?;
        let status: String = row.try_get("status")?;
        if version <= old_version {
            if version == old_version
                && row.try_get::<Option<Value>, _>("report")?.as_ref() == Some(&incoming)
            {
                continue;
            }
            return Err(ApiError::conflict(
                "task_report_replayed",
                "task observations cannot roll back or change an existing local version",
            ));
        }
        if !matches!(status.as_str(), "running" | "recovery_required") {
            return Err(ApiError::conflict(
                "task_terminal",
                "only an assigned unfinished task accepts new observations",
            ));
        }
        sqlx::query("UPDATE deployment_tasks SET status=$3,stage=$4,report=$5,local_version=$6,reported_at=clock_timestamp(),updated_at=clock_timestamp(),version=version+1 WHERE id=$1 AND runner_id=$2")
            .bind(report.task_id).bind(id).bind(report.status.as_str()).bind(&report.stage).bind(incoming).bind(version).execute(&mut *tx).await?;
        changes.push(json!({"id":report.task_id,"status":report.status.as_str(),"local_version":report.local_version}));
    }
    // Running operations are never automatically reassigned after heartbeat loss.
    // The same runner receives the same task and must consult its durable local journal.
    let mut task:Option<Value>=sqlx::query_scalar("SELECT to_jsonb(t) FROM deployment_tasks t WHERE runner_id=$1 AND status IN ('running','recovery_required') ORDER BY created_at,id LIMIT 1")
        .bind(id).fetch_optional(&mut *tx).await?;
    if task.is_none() {
        let queued=sqlx::query("SELECT id,request,preview,created_at>clock_timestamp()-interval '15 minutes' AS fresh FROM deployment_tasks WHERE runner_id=$1 AND status='queued' ORDER BY created_at,id LIMIT 1 FOR UPDATE")
            .bind(id).fetch_optional(&mut *tx).await?;
        if let Some(row) = queued {
            let task_id: Uuid = row.try_get("id")?;
            let request: Value = row.try_get("request")?;
            let approved: Value = row.try_get("preview")?;
            if row.try_get::<bool, _>("fresh")?
                && body.preview.as_ref().is_some_and(|p| {
                    request["preview_digest"] == p.digest
                        && serde_json::to_value(p).ok().as_ref() == Some(&approved)
                })
            {
                task=Some(sqlx::query_scalar("UPDATE deployment_tasks SET status='running',stage='assigned',version=version+1,updated_at=clock_timestamp() WHERE id=$1 RETURNING to_jsonb(deployment_tasks)")
                    .bind(task_id).fetch_one(&mut *tx).await?);
                changes.push(json!({"id":task_id,"status":"running"}));
            } else {
                let reason = if row.try_get::<bool, _>("fresh")? {
                    "preview_changed"
                } else {
                    "queue_expired"
                };
                sqlx::query("UPDATE deployment_tasks SET status='failed',stage=$2,version=version+1,updated_at=clock_timestamp() WHERE id=$1")
                    .bind(task_id).bind(reason).execute(&mut *tx).await?;
                changes.push(json!({"id":task_id,"status":"failed","reason":reason}));
            }
        }
    }
    let response = json!({"sequence":body.sequence,"task":task});
    sqlx::query("UPDATE deployment_runners SET exchange_sequence=$2,exchange_digest=$3,exchange_response=$4,last_seen=clock_timestamp(),preview=$5,
        preview_at=CASE WHEN $5::jsonb IS NULL THEN NULL ELSE clock_timestamp() END WHERE id=$1")
        .bind(id).bind(sequence).bind(hashed).bind(&response).bind(body.preview.as_ref().map(serde_json::to_value).transpose().map_err(|_|deployment_invalid())?).execute(&mut *tx).await?;
    if changes.is_empty() {
        tx.commit().await?;
    } else {
        state
            .store
            .commit_mutation(
                tx,
                &deployment_record(
                    &context.actor,
                    id,
                    "deployment.observed",
                    json!({"tasks":changes}),
                ),
            )
            .await?;
    }
    Ok(Json(response))
}
