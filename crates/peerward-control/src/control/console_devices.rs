async fn console_devices(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    Path(mesh): Path<Uuid>,
    Query(query): Query<ConsoleQuery>,
) -> Result<Json<peerward_api::ConsoleDevicePage>, ApiError> {
    authorize(&context, &HeaderMap::new(), Capability::ResourceRead, false)?;
    mesh_id(mesh)?;
    let checked_at = u64::try_from(OffsetDateTime::now_utc().unix_timestamp()).ok();
    let limit = query.bounded_limit()?;
    let cursor = query
        .cursor
        .as_deref()
        .map(|s| Uuid::parse_str(s).map_err(|_| ApiError::invalid_id()))
        .transpose()?;
    let rows=sqlx::query("WITH devices AS (
        SELECT p.id,peerward_peer_api_json(p)||jsonb_build_object('version',p.version) AS item FROM peers p
        WHERE p.mesh_id=$1 AND p.administrative_state<>'deleted'
        AND strpos(lower(p.name||' '||p.display_name||' '||p.location||' '||p.labels::text||' '||COALESCE(peerward_peer_api_json(p)->>'mesh_addresses','')),lower($2))>0
        AND ($3::text IS NULL OR p.labels->>'platform'=$3)
        AND ($7::uuid IS NULL OR EXISTS(SELECT 1 FROM relay_presence_all presence WHERE presence.mesh_id=p.mesh_id AND presence.peer_id=p.id AND presence.relay_id=$7 AND presence.lease_deadline>clock_timestamp()))
    ), filtered AS (
        SELECT * FROM devices WHERE $4::text IS NULL
        OR ($4='online' AND (item->>'online')::boolean)
        OR ($4='offline' AND NOT (item->>'online')::boolean)
        OR ($4='disabled' AND item->>'administrative_state'='disabled')
    )
    SELECT page.item,page.id,totals.total FROM (SELECT count(*) AS total FROM filtered) totals
    LEFT JOIN LATERAL (SELECT item,id FROM filtered WHERE $5::uuid IS NULL OR id>$5
        ORDER BY id LIMIT $6) page ON true ORDER BY page.id")
        .bind(mesh).bind(query.q.unwrap_or_default()).bind(query.platform).bind(query.status)
        .bind(cursor).bind(i64::from(limit)+1).bind(query.relay_id).fetch_all(state.store.pool()).await?;
    let has_more = rows.len() > usize::from(limit);
    let total = rows
        .first()
        .map(|r| r.try_get::<i64, _>("total"))
        .transpose()?
        .unwrap_or(0)
        .cast_unsigned();
    let mut items = Vec::new();
    for row in rows.into_iter().take(usize::from(limit)) {
        if let Some(value) = row.try_get::<Option<Value>, _>("item")? {
            items.push(
                serde_json::from_value::<PeerResource>(value).map_err(|_| publisher_error())?,
            );
        }
    }
    let next_cursor = has_more.then(|| items.last().unwrap().id.to_string());
    let ids = items
        .iter()
        .map(|peer| peer.id.into_uuid())
        .collect::<Vec<_>>();
    let facts = sqlx::query("SELECT p.id,h.observed_at AS runtime_observed_at,h.degraded_reasons,
        (SELECT max(updated_at) FROM relay_presence_all r WHERE r.mesh_id=p.mesh_id AND r.peer_id=p.id) AS last_connected_at,
        (SELECT count(*) FROM services s WHERE s.mesh_id=p.mesh_id AND s.peer_id=p.id AND s.state='enabled' AND NOT s.console_paused) AS provided_services,
        (SELECT count(DISTINCT b.resource_id) FROM gateway_bindings b JOIN network_resources n ON n.mesh_id=b.mesh_id AND n.id=b.resource_id WHERE b.mesh_id=p.mesh_id AND b.peer_id=p.id AND b.approved AND NOT n.console_paused) AS forwarded_resources
        FROM peers p LEFT JOIN current_peer_runtime_health h ON h.mesh_id=p.mesh_id
          AND h.peer_id=p.id AND h.expires_at>clock_timestamp() AND h.observed_at<=clock_timestamp()
        WHERE p.mesh_id=$1 AND p.id=ANY($2)")
        .bind(mesh).bind(&ids).fetch_all(state.store.pool()).await?;
    let mut summaries = std::collections::BTreeMap::new();
    for row in facts {
        let timestamp: Option<time::OffsetDateTime> = row.try_get("last_connected_at")?;
        let id: Uuid = row.try_get("id")?;
        let runtime_observed_at = row.try_get::<Option<OffsetDateTime>, _>("runtime_observed_at")?
            .and_then(|value| u64::try_from(value.unix_timestamp()).ok());
        let reasons = row.try_get::<Option<Vec<String>>, _>("degraded_reasons")?.unwrap_or_default();
        let online = items.iter().any(|peer| peer.id.into_uuid() == id && peer.online);
        summaries.insert(
            id.to_string(),
            peerward_api::ConsoleDeviceSummary {
                last_connected_at: timestamp
                    .map(|value| value.format(&time::format_description::well_known::Rfc3339))
                    .transpose()
                    .map_err(|_| publisher_error())?,
                provided_services: row.try_get::<i64, _>("provided_services")?.cast_unsigned(),
                forwarded_resources: row
                    .try_get::<i64, _>("forwarded_resources")?
                    .cast_unsigned(),
                runtime_observed_at,
                diagnostics: console_runtime_diagnostics(online, checked_at, runtime_observed_at, reasons),
            },
        );
    }
    Ok(Json(peerward_api::ConsoleDevicePage {
        items,
        next_cursor,
        total,
        summaries,
    }))
}

fn console_runtime_diagnostics(
    online: bool,
    checked_at: Option<u64>,
    reported_at: Option<u64>,
    reasons: Vec<String>,
) -> Vec<peerward_types::RuntimeDiagnostic> {
    use peerward_types::{DiagnosticCode, RuntimeDiagnostic};
    if !online {
        // A previously healthy report cannot establish current connectivity.
        return vec![RuntimeDiagnostic::new(DiagnosticCode::DeviceOffline, checked_at)];
    }
    if reported_at.is_none() {
        return vec![RuntimeDiagnostic::new(DiagnosticCode::ObservationUnavailable, None)];
    }
    reasons.into_iter().map(|reason| {
        let code = serde_json::from_value::<DiagnosticCode>(Value::String(reason))
            .unwrap_or(DiagnosticCode::Unknown);
        RuntimeDiagnostic::new(code, reported_at)
    }).collect()
}

async fn export_console_devices(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    Path(mesh): Path<Uuid>,
    Query(query): Query<ConsoleQuery>,
) -> Result<Response, ApiError> {
    authorize(&context, &HeaderMap::new(), Capability::ResourceRead, false)?;
    query.bounded_limit()?;
    let rows:Vec<Value>=sqlx::query_scalar("WITH devices AS (SELECT peerward_peer_api_json(p) AS item FROM peers p WHERE p.mesh_id=$1 AND p.administrative_state<>'deleted'
        AND strpos(lower(p.name||' '||p.display_name||' '||p.location||' '||p.labels::text||' '||COALESCE(peerward_peer_api_json(p)->>'mesh_addresses','')),lower($2))>0 AND ($3::text IS NULL OR p.labels->>'platform'=$3)
        AND ($5::uuid IS NULL OR EXISTS(SELECT 1 FROM relay_presence_all presence WHERE presence.mesh_id=p.mesh_id AND presence.peer_id=p.id AND presence.relay_id=$5 AND presence.lease_deadline>clock_timestamp())))
        SELECT item FROM devices WHERE $4::text IS NULL OR ($4='online' AND (item->>'online')::boolean) OR ($4='offline' AND NOT(item->>'online')::boolean) OR ($4='disabled' AND item->>'administrative_state'='disabled') ORDER BY item->>'id' LIMIT 10001")
        .bind(mesh).bind(query.q.unwrap_or_default()).bind(query.platform).bind(query.status).bind(query.relay_id).fetch_all(state.store.pool()).await?;
    if rows.len() > 10000 {
        return Err(ApiError::invalid(
            "export_limit",
            "narrow filters to at most 10000 devices per export",
        ));
    }
    let mut csv =
        String::from("\u{feff}id,name,display_name,location,platform,state,online,addresses\r\n");
    for row in rows {
        let addresses = row["mesh_addresses"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .unwrap_or_default();
        let fields = [
            row["id"].as_str().unwrap_or_default(),
            row["name"].as_str().unwrap_or_default(),
            row["display_name"].as_str().unwrap_or_default(),
            row["location"].as_str().unwrap_or_default(),
            row["labels"]["platform"].as_str().unwrap_or_default(),
            row["administrative_state"].as_str().unwrap_or_default(),
            if row["online"] == true {
                "true"
            } else {
                "false"
            },
            &addresses,
        ];
        csv.push_str(
            &fields
                .into_iter()
                .map(console_csv_field)
                .collect::<Vec<_>>()
                .join(","),
        );
        csv.push_str("\r\n");
    }
    Ok((
        [
            (header::CONTENT_TYPE, "text/csv; charset=utf-8"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=peerward-devices.csv",
            ),
            (header::CACHE_CONTROL, "no-store"),
        ],
        csv,
    )
        .into_response())
}
fn console_csv_field(value: &str) -> String {
    let prefix = if value.trim_start().starts_with(['=', '+', '-', '@']) {
        "'"
    } else {
        ""
    };
    format!("\"{prefix}{}\"", value.replace('"', "\"\""))
}

async fn console_device_activity(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    Path((mesh, peer)): Path<(Uuid, Uuid)>,
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
    let rows=sqlx::query("SELECT jsonb_build_object('id',id,'actor',actor,'action',action,'target_type',target_type,'target_id',target_id,'timestamp',occurred_at,'result',result,'metadata',metadata) AS item,id,occurred_at AS cursor_time FROM audit_log WHERE retained_mesh_id=$1 AND ((target_type='peer' AND target_id=$2) OR metadata->>'peer_id'=$2::text) AND ($3::timestamptz IS NULL OR (occurred_at,id)<($3,$4)) ORDER BY occurred_at DESC,id DESC LIMIT $5")
        .bind(mesh).bind(peer).bind(cursor.map(|c|c.timestamp)).bind(cursor.map(|c|c.id)).bind(i64::from(limit)+1).fetch_all(state.store.pool()).await?;
    rows_to_page(rows, limit)
}
