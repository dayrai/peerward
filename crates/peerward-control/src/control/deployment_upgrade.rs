fn deployment_version(value: &str) -> Result<semver::Version, ApiError> {
    if value.len() > 128 {
        return Err(deployment_invalid());
    }
    let version = semver::Version::parse(value).map_err(|_| deployment_invalid())?;
    if version.to_string() != value {
        return Err(deployment_invalid());
    }
    Ok(version)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeRecoveryRequest {
    request_id: Uuid,
}

async fn recover_deployment_task(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    ApiJson(body): ApiJson<NativeRecoveryRequest>,
) -> Result<Json<Value>, ApiError> {
    authorize(&context, &headers, Capability::TrustManage, true)?;
    if body.request_id.get_version_num() != 4 {
        return Err(deployment_invalid());
    }
    let version = require_if_match(&headers)?;
    let mut tx = state.store.begin_mutation().await?;
    let runner_id: Uuid = sqlx::query_scalar("SELECT runner_id FROM deployment_tasks WHERE id=$1")
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(ApiError::not_found)?;
    let connected:Option<bool>=sqlx::query_scalar("SELECT revoked_at IS NULL AND expires_at>clock_timestamp() AND last_seen>clock_timestamp()-interval '30 seconds' FROM deployment_runners WHERE id=$1 FOR UPDATE")
        .bind(runner_id).fetch_one(&mut *tx).await?;
    if let Some(old) = sqlx::query(
        "SELECT task_id,expected_version,actor FROM deployment_task_recoveries WHERE request_id=$1",
    )
    .bind(body.request_id)
    .fetch_optional(&mut *tx)
    .await?
    {
        if old.get::<Uuid, _>("task_id") != id
            || old.get::<i64, _>("expected_version") != version
            || old.get::<String, _>("actor") != context.actor
        {
            return Err(ApiError::conflict(
                "recovery_request_reused",
                "recovery request belongs to a different task or version",
            ));
        }
        return Ok(Json(
            sqlx::query_scalar("SELECT to_jsonb(t) FROM deployment_tasks t WHERE id=$1")
                .bind(id)
                .fetch_one(&mut *tx)
                .await?,
        ));
    }
    if connected != Some(true) {
        return Err(ApiError::conflict(
            "runner_unobserved",
            "wait for a fresh observation from the same registered runner",
        ));
    }
    let task:Value=sqlx::query_scalar("UPDATE deployment_tasks SET status='running',stage='recovery_requested',recovery_generation=recovery_generation+1,version=version+1,updated_at=clock_timestamp() WHERE id=$1 AND version=$2 AND operation='native_upgrade' AND status='recovery_required' RETURNING to_jsonb(deployment_tasks)")
        .bind(id).bind(version).fetch_optional(&mut *tx).await?.ok_or_else(||ApiError::conflict("task_changed","reload the recovery-required native task before retrying"))?;
    sqlx::query("INSERT INTO deployment_task_recoveries(request_id,task_id,expected_version,actor,recovery_generation) VALUES($1,$2,$3,$4,$5)")
        .bind(body.request_id).bind(id).bind(version).bind(&context.actor).bind(task["recovery_generation"].as_i64().ok_or_else(deployment_invalid)?)
        .execute(&mut *tx).await?;
    state
        .store
        .commit_mutation(
            tx,
            &deployment_record(
                &context.actor,
                id,
                "deployment.upgrade_recovery_requested",
                json!({"request_id":body.request_id,"generation":task["recovery_generation"]}),
            ),
        )
        .await?;
    Ok(Json(task))
}
fn validate_native_upgrade_preview(
    value: &peerward_api::NativeUpgradePreview,
) -> Result<(), ApiError> {
    let current = deployment_version(&value.current_version)?;
    let target = deployment_version(&value.version)?;
    let floor = deployment_version(&value.rollback_floor)?;
    if target.cmp_precedence(&current).is_lt()
        || target.cmp_precedence(&floor).is_lt()
        || value.current_version == value.version
        || !deployment_digest(&value.manifest_sha256)
        || !deployment_digest(&value.artifact_sha256)
        || value.artifact_bytes == 0
        || value.artifact_bytes > 256 * 1024 * 1024
    {
        return Err(deployment_invalid());
    }
    Ok(())
}

fn validate_native_upgrade_report(
    operation: &str,
    preview: &Value,
    report: &DeploymentTaskReport,
) -> Result<(), ApiError> {
    use peerward_api::NativeUpgradeState;
    if operation == "installation_backup" {
        return if report.upgrade.is_none() {
            Ok(())
        } else {
            Err(deployment_invalid())
        };
    }
    let expected: peerward_api::NativeUpgradePreview =
        serde_json::from_value(preview["upgrade"].clone()).map_err(|_| deployment_invalid())?;
    let Some(result) = &report.upgrade else {
        return if report.status == DeploymentTaskStatus::Succeeded {
            Err(deployment_invalid())
        } else {
            Ok(())
        };
    };
    deployment_version(&result.version)?;
    if result.role != expected.role
        || result.manifest_sha256 != expected.manifest_sha256
        || !deployment_digest(&result.current_sha256)
    {
        return Err(deployment_invalid());
    }
    let consistent = match result.state {
        NativeUpgradeState::Succeeded => {
            report.status == DeploymentTaskStatus::Succeeded
                && result.runtime_checked
                && result.version == expected.version
                && result.current_sha256 == expected.artifact_sha256
                && report.artifact.as_ref().is_some_and(|a| {
                    a.sha256 == expected.artifact_sha256
                        && a.bytes == expected.artifact_bytes
                        && a.files == 1
                })
        }
        NativeUpgradeState::RolledBack => {
            report.status == DeploymentTaskStatus::Failed
                && result.runtime_checked
                && result.role != peerward_api::NativeUpgradeRole::Control
                && result.version == expected.current_version
                && report
                    .artifact
                    .as_ref()
                    .is_some_and(|a| a.sha256 == result.current_sha256 && a.files == 1)
        }
        NativeUpgradeState::RecoveryRequired => {
            report.status == DeploymentTaskStatus::RecoveryRequired && !result.runtime_checked
        }
    };
    if !consistent {
        return Err(deployment_invalid());
    }
    Ok(())
}
