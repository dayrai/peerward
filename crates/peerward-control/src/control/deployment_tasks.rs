use peerward_api::{
    DeploymentExchange, DeploymentPreview, DeploymentRunnerCreate, DeploymentTaskCreate,
    DeploymentTaskReport, DeploymentTaskStatus,
};

fn deployment_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn deployment_invalid() -> ApiError {
    ApiError::invalid(
        "invalid_deployment_operation",
        "use the fixed operation, current preview and bounded public fields",
    )
}
fn deployment_record(actor: &str, id: Uuid, action: &str, metadata: Value) -> MutationRecord {
    MutationRecord {
        mesh_id: None,
        actor: actor.into(),
        action: action.into(),
        event_type: action.into(),
        resource_type: "deployment_task".into(),
        resource_id: Some(id),
        result: "success".into(),
        metadata,
        correlation: None,
    }
}

async fn authenticate_deployment_runner(
    state: &AppState,
    token: &str,
    method: &axum::http::Method,
    path: &str,
) -> Result<AuthContext, ApiError> {
    let reject = || {
        ApiError::unauthorized(
            "invalid_deployment_runner",
            "runner credential is invalid, expired, revoked or outside its exchange scope",
        )
    };
    if token.len() != 54 || *method != axum::http::Method::POST {
        return Err(reject());
    }
    let hashed = secret_digest(token.as_bytes());
    let id:Uuid=sqlx::query_scalar("SELECT id FROM deployment_runners WHERE token_digest=$1 AND revoked_at IS NULL AND expires_at>clock_timestamp()")
        .bind(hashed.as_slice()).fetch_optional(state.store.pool()).await?.ok_or_else(reject)?;
    if path != format!("/api/v1/deployment-runners/{id}/exchange") {
        return Err(reject());
    }
    Ok(AuthContext {
        actor: format!("runner:{id}"),
        role: Role::Operator,
        source: AuthSource::DeploymentRunner(id),
    })
}

async fn create_deployment_runner(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<DeploymentRunnerCreate>,
) -> Result<(StatusCode, HeaderMap, Json<Value>), ApiError> {
    authorize(&context, &headers, Capability::TrustManage, true)?;
    if body.id.get_version_num() != 4
        || !peerward_management::name_valid(&body.name)
        || !deployment_digest(&body.profile_digest)
        || !(300..=7_776_000).contains(&body.ttl_seconds)
    {
        return Err(deployment_invalid());
    }
    let mut tx = state.store.begin_mutation().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(5057,43)")
        .execute(&mut *tx)
        .await?;
    let count:i64=sqlx::query_scalar("SELECT count(*) FROM deployment_runners WHERE revoked_at IS NULL AND expires_at>clock_timestamp()")
        .fetch_one(&mut *tx).await?;
    if count >= 64 {
        return Err(ApiError::conflict(
            "runner_capacity",
            "revoke unused deployment runners first",
        ));
    }
    let mut bytes = Zeroizing::new([0u8; 33]);
    OsRng.fill_bytes(bytes.as_mut());
    let token = Zeroizing::new(format!(
        "pw_runner_{}",
        URL_SAFE_NO_PAD.encode(bytes.as_ref())
    ));
    let hashed = secret_digest(token.as_bytes());
    let row:Value=sqlx::query_scalar("INSERT INTO deployment_runners(id,name,profile_digest,token_digest,expires_at)
        VALUES($1,$2,$3,$4,clock_timestamp()+$5*interval '1 second') RETURNING to_jsonb(deployment_runners)-'token_digest'-'exchange_digest'-'exchange_response'")
        .bind(body.id).bind(&body.name).bind(&body.profile_digest).bind(hashed.as_slice()).bind(i64::from(body.ttl_seconds))
        .fetch_one(&mut *tx).await?;
    state
        .store
        .commit_mutation(
            tx,
            &deployment_record(
                &context.actor,
                body.id,
                "deployment.runner_created",
                json!({"name":body.name}),
            ),
        )
        .await?;
    let mut response = HeaderMap::new();
    response.insert("cache-control", HeaderValue::from_static("no-store"));
    Ok((
        StatusCode::CREATED,
        response,
        Json(json!({"runner":row,"token":token.as_str()})),
    ))
}

async fn deployment_page(
    state: &AppState,
    query: ListQuery,
    runners: bool,
) -> Result<Json<ApiPage<Value>>, ApiError> {
    let cursor = query.cursor()?;
    let limit = query.limit()?;
    let selection = if runners {
        "SELECT id,created_at,(to_jsonb(t)-'token_digest'-'exchange_digest'-'exchange_response') || jsonb_build_object('connected',COALESCE(revoked_at IS NULL AND expires_at>clock_timestamp() AND last_seen>clock_timestamp()-interval '30 seconds',false),'ready',COALESCE(revoked_at IS NULL AND expires_at>clock_timestamp() AND last_seen>clock_timestamp()-interval '30 seconds' AND preview_at>clock_timestamp()-interval '30 seconds',false)) AS item FROM deployment_runners t"
    } else {
        "SELECT id,created_at,to_jsonb(t) AS item FROM deployment_tasks t"
    };
    let sql = format!(
        "{selection} WHERE ($1::timestamptz IS NULL OR (created_at,id)<($1,$2)) ORDER BY created_at DESC,id DESC LIMIT $3"
    );
    let mut rows = sqlx::query(&sql)
        .bind(cursor.map(|c| c.timestamp))
        .bind(cursor.map(|c| c.id))
        .bind(i64::from(limit) + 1)
        .fetch_all(state.store.pool())
        .await?;
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
            .map(|row| row.try_get("item"))
            .collect::<Result<Vec<_>, _>>()?,
        next_cursor,
    }))
}
async fn list_deployment_runners(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
) -> Result<Json<ApiPage<Value>>, ApiError> {
    authorize(&context, &HeaderMap::new(), Capability::TrustManage, false)?;
    deployment_page(&state, query, true).await
}
async fn list_deployment_tasks(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
) -> Result<Json<ApiPage<Value>>, ApiError> {
    authorize(&context, &HeaderMap::new(), Capability::TrustManage, false)?;
    deployment_page(&state, query, false).await
}
async fn revoke_deployment_runner(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    authorize(&context, &headers, Capability::TrustManage, true)?;
    let version = require_if_match(&headers)?;
    let mut tx = state.store.begin_mutation().await?;
    let value:Value=sqlx::query_scalar("UPDATE deployment_runners SET revoked_at=clock_timestamp(),version=version+1,preview=NULL,preview_at=NULL
        WHERE id=$1 AND version=$2 AND revoked_at IS NULL RETURNING to_jsonb(deployment_runners)-'token_digest'-'exchange_digest'-'exchange_response'")
        .bind(id).bind(version).fetch_optional(&mut *tx).await?.ok_or_else(||ApiError::conflict("runner_changed","reload the current runner version"))?;
    sqlx::query("UPDATE deployment_tasks SET status='cancelled',stage='runner_revoked',version=version+1,updated_at=clock_timestamp() WHERE runner_id=$1 AND status='queued'")
        .bind(id).execute(&mut *tx).await?;
    state
        .store
        .commit_mutation(
            tx,
            &deployment_record(
                &context.actor,
                id,
                "deployment.runner_revoked",
                json!({"running_tasks":"local recovery still required"}),
            ),
        )
        .await?;
    Ok(Json(value))
}

async fn create_deployment_task(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<DeploymentTaskCreate>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    authorize(&context, &headers, Capability::TrustManage, true)?;
    if body.id.get_version_num() != 4
        || body.runner_id.get_version_num() != 4
        || !deployment_digest(&body.preview_digest)
    {
        return Err(deployment_invalid());
    }
    let request = serde_json::to_value(&body).map_err(|_| deployment_invalid())?;
    let mut tx = state.store.begin_mutation().await?;
    let runner=sqlx::query("SELECT *,revoked_at IS NULL AND expires_at>clock_timestamp() AND last_seen>clock_timestamp()-interval '30 seconds' AND preview_at>clock_timestamp()-interval '30 seconds' AS ready
        FROM deployment_runners WHERE id=$1 FOR UPDATE").bind(body.runner_id).fetch_optional(&mut *tx).await?.ok_or_else(ApiError::not_found)?;
    if let Some(row) =
        sqlx::query("SELECT actor,request,to_jsonb(t) AS item FROM deployment_tasks t WHERE id=$1")
            .bind(body.id)
            .fetch_optional(&mut *tx)
            .await?
    {
        if row.get::<String, _>("actor") != context.actor
            || row.get::<Value, _>("request") != request
        {
            return Err(ApiError::conflict(
                "task_id_reused",
                "task ID is bound to a different request",
            ));
        }
        return Ok((StatusCode::OK, Json(row.try_get("item")?)));
    }
    let preview: Option<Value> = runner.try_get("preview")?;
    if runner.try_get::<Option<bool>, _>("ready")? != Some(true)
        || preview
            .as_ref()
            .is_none_or(|p| p["digest"] != body.preview_digest)
    {
        return Err(ApiError::conflict(
            "deployment_preview_stale",
            "wait for the local runner, review its current preview and submit again",
        ));
    }
    let is_upgrade = preview.as_ref().is_some_and(|p| !p["upgrade"].is_null());
    if is_upgrade != (body.operation == peerward_api::DeploymentOperation::NativeUpgrade) {
        return Err(ApiError::conflict(
            "deployment_operation_changed",
            "select the operation advertised in the current preview",
        ));
    }
    let active:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM deployment_tasks WHERE runner_id=$1 AND status IN ('queued','running','recovery_required'))")
        .bind(body.runner_id).fetch_one(&mut *tx).await?;
    if active {
        return Err(ApiError::conflict(
            "deployment_task_in_progress",
            "complete or recover the existing task first",
        ));
    }
    let value:Value=sqlx::query_scalar("INSERT INTO deployment_tasks(id,runner_id,request,actor,preview,profile_digest,operation) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING to_jsonb(deployment_tasks)")
        .bind(body.id).bind(body.runner_id).bind(request).bind(&context.actor).bind(&preview).bind(runner.try_get::<String,_>("profile_digest")?).bind(body.operation.as_str())
        .fetch_one(&mut *tx).await?;
    state
        .store
        .commit_mutation(
            tx,
            &deployment_record(
                &context.actor,
                body.id,
                if is_upgrade {
                    "deployment.upgrade_queued"
                } else {
                    "deployment.backup_queued"
                },
                json!({"runner_id":body.runner_id,"preview":preview}),
            ),
        )
        .await?;
    Ok((StatusCode::ACCEPTED, Json(value)))
}
async fn get_deployment_task(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    authorize(&context, &HeaderMap::new(), Capability::TrustManage, false)?;
    Ok(Json(
        sqlx::query_scalar("SELECT to_jsonb(t) FROM deployment_tasks t WHERE id=$1")
            .bind(id)
            .fetch_optional(state.store.pool())
            .await?
            .ok_or_else(ApiError::not_found)?,
    ))
}
async fn cancel_deployment_task(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    authorize(&context, &headers, Capability::TrustManage, true)?;
    let version = require_if_match(&headers)?;
    let mut tx = state.store.begin_mutation().await?;
    let value:Value=sqlx::query_scalar("UPDATE deployment_tasks SET status='cancelled',stage='cancelled',version=version+1,updated_at=clock_timestamp()
        WHERE id=$1 AND version=$2 AND status='queued' RETURNING to_jsonb(deployment_tasks)")
        .bind(id).bind(version).fetch_optional(&mut *tx).await?.ok_or_else(||ApiError::conflict("task_started","only a queued task can be cancelled; running operations require local recovery"))?;
    state
        .store
        .commit_mutation(
            tx,
            &deployment_record(
                &context.actor,
                id,
                "deployment.task_cancelled",
                json!({"operation":value["operation"]}),
            ),
        )
        .await?;
    Ok(Json(value))
}
