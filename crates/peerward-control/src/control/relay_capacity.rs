use peerward_api::{RelayCapacityReport, RelayObservationChallenge};

async fn relay_capacity_challenge(
    Extension(RelayHostIdentity(host)): Extension<RelayHostIdentity>,
    State(state): State<AppState>,
) -> Result<Json<RelayObservationChallenge>, ApiError> {
    let nonce = sqlx::query_scalar("INSERT INTO relay_host_capacity(host_id,nonce)
        SELECT id,$2 FROM relay_hosts WHERE id=$1 AND enabled
        ON CONFLICT(host_id) DO UPDATE SET
          nonce=CASE WHEN relay_host_capacity.nonce_created_at<clock_timestamp()-interval '30 seconds' OR relay_host_capacity.nonce=relay_host_capacity.last_nonce THEN $2 ELSE relay_host_capacity.nonce END,
          nonce_created_at=CASE WHEN relay_host_capacity.nonce_created_at<clock_timestamp()-interval '30 seconds' OR relay_host_capacity.nonce=relay_host_capacity.last_nonce THEN clock_timestamp() ELSE relay_host_capacity.nonce_created_at END
        RETURNING nonce")
        .bind(host).bind(Uuid::new_v4()).fetch_optional(state.store.pool()).await.map_err(|error| {
            tracing::warn!(?error,"Relay observation challenge database failure");ApiError::from(error)
        })?
        .ok_or_else(ApiError::not_found)?;
    Ok(Json(RelayObservationChallenge { nonce }))
}

fn capacity_counters(report: &RelayCapacityReport) -> [u64; 8] {
    [
        report.uptime_millis,
        report.received_bytes,
        report.accepted_bytes,
        report.no_route_total,
        report.queue_full_total,
        report.invalid_forwarded_frames_total,
        report.audit_queued_total,
        report.audit_dropped_total,
    ]
}

async fn relay_capacity_report(
    Extension(RelayHostIdentity(host)): Extension<RelayHostIdentity>,
    State(state): State<AppState>,
    Json(request): Json<RelayCapacityReport>,
) -> Result<StatusCode, ApiError> {
    if request.nonce.get_version_num() != 4
        || request.process_id.get_version_num() != 4
        || request.session_limit == 0
        || request.session_limit > 1_000_000
        || request.authenticated_peer_sessions > request.session_limit
        || request.mesh_contexts > 65_536
    {
        return Err(dynamic_invalid());
    }
    let body = serde_json::to_value(&request).map_err(|_| dynamic_invalid())?;
    let mut tx = state.store.begin_mutation().await?;
    // Recheck enabled after TLS connection establishment, including keep-alive.
    let row=sqlx::query("SELECT c.*,c.nonce_created_at>clock_timestamp()-interval '30 seconds' AS nonce_fresh FROM relay_host_capacity c
        JOIN relay_hosts h ON h.id=c.host_id WHERE c.host_id=$1 AND h.enabled FOR UPDATE OF c")
        .bind(host).fetch_optional(&mut *tx).await?.ok_or_else(ApiError::not_found)?;
    let previous: Option<Value> = row.try_get("report")?;
    if row.try_get::<Option<Uuid>, _>("last_nonce")? == Some(request.nonce) {
        return if previous.as_ref() == Some(&body) {
            Ok(StatusCode::NO_CONTENT)
        } else {
            Err(ApiError::conflict(
                "observation_replay",
                "Observation nonce already used",
            ))
        };
    }
    if row.try_get::<Uuid, _>("nonce")? != request.nonce
        || !row.try_get::<bool, _>("nonce_fresh")?
    {
        return Err(ApiError::conflict(
            "observation_expired",
            "Fetch a new observation challenge",
        ));
    }
    let previous =
        previous.and_then(|value| serde_json::from_value::<RelayCapacityReport>(value).ok());
    let same_process = previous
        .as_ref()
        .is_some_and(|old| old.process_id == request.process_id);
    if let Some(old) = previous.as_ref().filter(|_| same_process)
        && capacity_counters(old)
            .iter()
            .zip(capacity_counters(&request))
            .any(|(before, after)| after < *before)
    {
        return Err(ApiError::conflict(
            "observation_regressed",
            "Process counters must not decrease",
        ));
    }
    sqlx::query(
        "UPDATE relay_host_capacity SET previous_report=CASE WHEN $4 THEN report ELSE NULL END,
        report=$2,last_nonce=$3,observed_at=clock_timestamp() WHERE host_id=$1",
    )
    .bind(host)
    .bind(body)
    .bind(request.nonce)
    .bind(same_process)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn get_relay_capacity(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(host): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    authorize(&auth, &HeaderMap::new(), Capability::TrustManage, false)?;
    let row = sqlx::query(
        "SELECT h.id,h.name,h.enabled,c.report,c.previous_report,c.observed_at,
        COALESCE(h.enabled AND c.observed_at>clock_timestamp()-interval '30 seconds',false) AS fresh
        FROM relay_hosts h LEFT JOIN relay_host_capacity c ON c.host_id=h.id WHERE h.id=$1",
    )
    .bind(host)
    .fetch_optional(state.store.pool())
    .await?
    .ok_or_else(ApiError::not_found)?;
    let report: Option<Value> = row.try_get("report")?;
    let previous: Option<Value> = row.try_get("previous_report")?;
    let fresh: bool = row.try_get("fresh")?;
    let mut deltas = Value::Null;
    if let (Some(current), Some(old)) = (&report, &previous) {
        let elapsed = current["uptime_millis"]
            .as_u64()
            .unwrap_or(0)
            .saturating_sub(old["uptime_millis"].as_u64().unwrap_or(0));
        if elapsed > 0 {
            let difference = |key: &str| {
                current[key]
                    .as_u64()
                    .unwrap_or(0)
                    .saturating_sub(old[key].as_u64().unwrap_or(0))
            };
            deltas = json!({"interval_millis":elapsed,"received_bytes":difference("received_bytes"),"accepted_bytes":difference("accepted_bytes"),
                "queue_full":difference("queue_full_total"),"audit_dropped":difference("audit_dropped_total"),"invalid_frames":difference("invalid_forwarded_frames_total")});
        }
    }
    let mut report = report;
    if let Some(Value::Object(fields)) = &mut report {
        fields.remove("nonce");
    }
    Ok(Json(
        json!({"host_id":host,"name":row.try_get::<String,_>("name")?,"fresh":fresh,
        "observed_at":row.try_get::<Option<OffsetDateTime>,_>("observed_at")?.map(OffsetDateTime::unix_timestamp),
        "measurement":"activated_framed_carrier","report":report,"last_interval":deltas}),
    ))
}
