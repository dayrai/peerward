fn credential_status(credential: Option<&peerward_api::CredentialBrief>) -> String {
    let Some(deadline) = credential
        .and_then(|item| item.not_after.as_deref())
        .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok())
    else {
        return "missing".into();
    };
    let remaining = deadline - OffsetDateTime::now_utc();
    if remaining <= TimeDuration::ZERO {
        "expired"
    } else if remaining <= TimeDuration::days(7) {
        "warning_7d"
    } else if remaining <= TimeDuration::days(30) {
        "warning_30d"
    } else {
        "healthy"
    }
    .into()
}

async fn create_service(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(mesh): Path<Uuid>,
    ApiJson(body): ApiJson<ServiceCreateRequest>,
) -> Result<(StatusCode, HeaderMap, Json<ServiceResource>), ApiError> {
    authorize(&context, &headers, Capability::ResourceWrite, true)?;
    if !peerward_api::valid_labels(&body.labels) {
        return Err(ApiError::invalid(
            "invalid_labels",
            "service labels are invalid",
        ));
    }
    let mesh_id = mesh_id(mesh)?;
    let peer = body.peer_id.into_uuid();
    if !valid_service_protocols(&body.protocols)
        || body.listen_port == 0
        || body
            .alias
            .as_deref()
            .is_some_and(|alias| !valid_dns_label(alias))
    {
        return Err(ApiError::invalid(
            "invalid_service",
            "invalid service protocols, listen port, or alias",
        ));
    }
    let protocols = body
        .protocols
        .iter()
        .map(|protocol| match protocol {
            peerward_types::ServiceProtocol::Tcp => "tcp",
            peerward_types::ServiceProtocol::Udp => "udp",
        })
        .collect::<Vec<_>>();
    let service_id = ServiceId::new();
    let mut transaction = state.store.begin_mutation().await?;
    sqlx::query("SELECT id FROM meshes WHERE id=$1 AND lifecycle='active' FOR UPDATE")
        .bind(mesh)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or_else(ApiError::not_found)?;
    sqlx::query("SELECT id FROM peers WHERE mesh_id=$1 AND id=$2 AND administrative_state<>'deleted' FOR SHARE")
        .bind(mesh).bind(peer).fetch_optional(&mut *transaction).await?
        .ok_or_else(ApiError::not_found)?;
    sqlx::query("INSERT INTO services(id,mesh_id,peer_id,protocols,listen_port,alias,labels) VALUES($1,$2,$3,$4,$5,$6,$7)")
        .bind(service_id.into_uuid()).bind(mesh).bind(peer).bind(protocols)
        .bind(i32::from(body.listen_port)).bind(&body.alias)
        .bind(serde_json::to_value(&body.labels).map_err(|_| ApiError::invalid("invalid_labels", "service labels are invalid"))?)
        .execute(&mut *transaction).await?;
    sqlx::query("UPDATE meshes SET service_revision=service_revision+1, directory_revision=directory_revision+1, updated_at=clock_timestamp() WHERE id=$1")
        .bind(mesh).execute(&mut *transaction).await?;
    state
        .store
        .commit_mutation(
            transaction,
            &mutation(
                &context,
                Some(mesh_id),
                "service.create",
                "service.created",
                "service",
                Some(service_id.into_uuid()),
            ),
        )
        .await?;
    let resource = load_service(&state.store, mesh, service_id.into_uuid()).await?;
    Ok((
        StatusCode::CREATED,
        etag_headers(resource.version)?,
        Json(resource),
    ))
}

fn valid_service_protocols(protocols: &[peerward_types::ServiceProtocol]) -> bool {
    matches!(
        protocols,
        [peerward_types::ServiceProtocol::Tcp | peerward_types::ServiceProtocol::Udp]
            | [
                peerward_types::ServiceProtocol::Tcp,
                peerward_types::ServiceProtocol::Udp
            ]
    )
}

fn valid_dns_label(alias: &str) -> bool {
    !alias.is_empty()
        && alias.len() <= 63
        && alias.is_ascii()
        && alias
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        && alias
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && alias
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
}

async fn delete_service(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((mesh, service)): Path<(Uuid, Uuid)>,
) -> Result<(HeaderMap, StatusCode), ApiError> {
    authorize(&context, &headers, Capability::ResourceWrite, true)?;
    let expected = require_if_match(&headers)?;
    let mesh_id = mesh_id(mesh)?;
    ServiceId::from_uuid(service).map_err(|_| ApiError::invalid_id())?;
    let mut transaction = state.store.begin_mutation().await?;
    lock_resource_version(
        &mut transaction,
        VersionedFamily::Service,
        Some(mesh),
        service,
        expected,
    )
    .await?;
    let changed = sqlx::query(
        "UPDATE services SET state='disabled', updated_at=clock_timestamp()
         WHERE mesh_id=$1 AND id=$2 AND state='enabled'",
    )
    .bind(mesh)
    .bind(service)
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    if changed != 1 {
        return Err(ApiError::not_found());
    }
    sqlx::query("UPDATE meshes SET service_revision=service_revision+1, directory_revision=directory_revision+1, updated_at=clock_timestamp() WHERE id=$1")
        .bind(mesh).execute(&mut *transaction).await?;
    state
        .store
        .commit_mutation(
            transaction,
            &mutation(
                &context,
                Some(mesh_id),
                "service.disable",
                "service.disabled",
                "service",
                Some(service),
            ),
        )
        .await?;
    let version: i64 =
        sqlx::query_scalar("SELECT version FROM services WHERE mesh_id=$1 AND id=$2")
            .bind(mesh)
            .bind(service)
            .fetch_one(state.store.pool())
            .await?;
    Ok((
        etag_headers(u64::try_from(version).map_err(|_| {
            ApiError::internal("service_projection", "Service version is invalid")
        })?)?,
        StatusCode::NO_CONTENT,
    ))
}

async fn list_audit(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    Path(mesh): Path<Uuid>,
    Query(query): Query<ListQuery>,
) -> Result<Json<ApiPage<AuditResource>>, ApiError> {
    authorize(
        &context,
        &HeaderMap::new(),
        Capability::StatusAuditRead,
        false,
    )?;
    mesh_id(mesh)?;
    let limit = query.limit()?;
    let cursor = query.cursor()?;
    let rows = sqlx::query(
        "SELECT jsonb_build_object('id',id,'actor',actor,'action',action,
        'target_type',target_type,'target_id',target_id,'timestamp',occurred_at,'result',result,
        'metadata',metadata) AS item,id,occurred_at AS cursor_time FROM audit_log WHERE retained_mesh_id=$1
        AND ($2::timestamptz IS NULL OR (occurred_at,id)<($2,$3))
        ORDER BY occurred_at DESC,id DESC LIMIT $4",
    )
    .bind(mesh)
    .bind(cursor.map(|cursor| cursor.timestamp))
    .bind(cursor.map(|cursor| cursor.id))
    .bind(i64::from(limit) + 1)
    .fetch_all(state.store.pool())
    .await?;
    rows_to_page(rows, limit)
}

async fn list_global_audit(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
) -> Result<Json<ApiPage<AuditResource>>, ApiError> {
    authorize(
        &context,
        &HeaderMap::new(),
        Capability::StatusAuditRead,
        false,
    )?;
    let limit = query.limit()?;
    let cursor = query.cursor()?;
    let rows = sqlx::query(
        "SELECT jsonb_build_object('id',id,'actor',actor,'action',action,
        'target_type',target_type,'target_id',target_id,'timestamp',occurred_at,'result',result,
        'metadata',metadata) AS item,id,occurred_at AS cursor_time FROM audit_log
        WHERE ($1::timestamptz IS NULL OR (occurred_at,id)<($1,$2))
        ORDER BY occurred_at DESC,id DESC LIMIT $3",
    )
    .bind(cursor.map(|cursor| cursor.timestamp))
    .bind(cursor.map(|cursor| cursor.id))
    .bind(i64::from(limit) + 1)
    .fetch_all(state.store.pool())
    .await?;
    rows_to_page(rows, limit)
}

async fn events(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Sse<impl futures_util::Stream<Item = Result<Event, Infallible>>>, ApiError> {
    authorize(&context, &headers, Capability::StatusAuditRead, false)?;
    let supplied = headers.get("last-event-id");
    let cursor = supplied
        .map(|value| {
            value
                .to_str()
                .ok()
                .and_then(|value| value.parse().ok())
                .and_then(|uuid| EventId::from_uuid(uuid).ok())
                .ok_or_else(|| {
                    ApiError::invalid("invalid_event_cursor", "event cursor must be a UUIDv4")
                })
        })
        .transpose()?;
    let start = match state.store.event_replay_start(cursor).await {
        Err(StoreError::EventCursorExpired) => {
            state
                .metrics
                .sse_cursor_resets
                .fetch_add(1, Ordering::Relaxed);
            return Err(ApiError::from(StoreError::EventCursorExpired));
        }
        result => result?,
    };
    let permit = Arc::clone(&state.sse_connections)
        .try_acquire_owned()
        .map_err(|_| {
            state
                .metrics
                .sse_capacity_rejections
                .fetch_add(1, Ordering::Relaxed);
            ApiError::new(
                StatusCode::TOO_MANY_REQUESTS,
                "sse_capacity",
                "event stream capacity reached",
            )
        })?;
    let store = state.store;
    let mut signal = state.event_signal.clone();
    let fresh = supplied.is_none();
    let audit_only = !context_allows(&context, Capability::ResourceRead);
    let output = stream! {
        let _permit = permit;
        let mut sequence = start.after_sequence;
        if fresh {
            let mut ready = Event::default().event("peerward.ready");
            if let Some(cursor) = start.cursor {
                ready = ready.id(cursor.to_string());
            }
            ready = ready.json_data(json!({"cursor":start.cursor.map(|cursor| cursor.to_string())}))
                .unwrap_or_else(|_| Event::default().event("error").data("serialization failed"));
            yield Ok(ready);
        }
        loop {
            match store.events_after_global_sequence(sequence, 500).await {
                Ok(events) if events.is_empty() => {
                    tokio::select! {
                        changed = signal.changed() => {
                            if changed.is_err() {
                                tokio::time::sleep(Duration::from_secs(5)).await;
                            }
                        }
                        () = tokio::time::sleep(Duration::from_secs(5)) => {}
                    }
                },
                Ok(events) => for event in events {
                    sequence = event.sequence;
                    yield Ok(if audit_only { audit_event_to_sse(&event) } else { event_to_sse(&event) });
                },
                Err(_) => {
                    yield Ok(Event::default().event("error").data("event replay unavailable"));
                    break;
                }
            }
        }
    };
    Ok(Sse::new(output).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keepalive"),
    ))
}
