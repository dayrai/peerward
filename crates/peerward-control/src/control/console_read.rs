use peerward_api::{
    ConsoleEvidence, ConsoleIssue, ConsoleIssuePage, ConsoleNoticeUpdate, ConsoleOverview,
    ConsoleSearchItem, ConsoleSharingResource,
};

// A bounded page is returned independently of aggregate counters.
const CONSOLE_ISSUES_FACTS_SQL: &str = "
WITH facts AS (
 SELECT p.id,p.version,COALESCE((SELECT generation FROM peer_presence_generations g WHERE g.mesh_id=p.mesh_id AND g.peer_id=p.id),0) AS presence_generation,COALESCE(NULLIF(p.display_name,''),p.name) AS name,p.updated_at,
        peerward_peer_api_json(p) AS data
 FROM peers p WHERE p.mesh_id=$1 AND p.administrative_state='enabled'
), issues AS (
 SELECT id,'device_offline' AS kind,'warning' AS severity,name,clock_timestamp() AS updated_at,
        presence_generation::text||':offline' AS fingerprint,'/peers' AS route FROM facts
 WHERE NOT COALESCE((data->>'online')::boolean,false)
 UNION ALL
 SELECT f.id,'credential_expiring',
        CASE WHEN c.not_after<=clock_timestamp() THEN 'critical' ELSE 'warning' END,
        f.name,clock_timestamp(),c.serial::text||CASE WHEN c.not_after<=clock_timestamp() THEN ':expired' WHEN c.not_after<=clock_timestamp()+interval '7 days' THEN ':7d' ELSE ':30d' END,'/peers'
 FROM facts f JOIN peer_credentials c ON c.peer_id=f.id AND c.mesh_id=$1
 WHERE c.lifecycle='active' AND c.not_after<=clock_timestamp()+interval '30 days'
 UNION ALL
 SELECT id,'join_pending','info',COALESCE(request_document->>'name',id::text),created_at,version::text,'/join-tickets'
 FROM join_applications WHERE mesh_id=$1 AND status='pending' AND expires_at>clock_timestamp()
 UNION ALL
 SELECT r.id,'gateway_path_missing','warning',r.definition->>'name',clock_timestamp(),r.version::text||':no_path:'||COALESCE((
   SELECT md5(string_agg(b.id::text||':'||b.version::text||':'||COALESCE(g.generation::text,'0')||':'||COALESCE(a.evidence_generation::text,'none'),',' ORDER BY b.id))
   FROM gateway_bindings b LEFT JOIN peer_presence_generations g ON g.mesh_id=b.mesh_id AND g.peer_id=b.peer_id
   LEFT JOIN route_advertisements a ON a.mesh_id=b.mesh_id AND a.binding_id=b.id
   WHERE b.mesh_id=r.mesh_id AND b.resource_id=r.id),'none'),'/services'
 FROM network_resources r WHERE r.mesh_id=$1 AND NOT r.console_paused AND NOT EXISTS (
   SELECT 1 FROM gateway_bindings b JOIN peers p ON p.mesh_id=b.mesh_id AND p.id=b.peer_id
   JOIN route_advertisements a ON a.mesh_id=b.mesh_id AND a.binding_id=b.id
   WHERE b.mesh_id=r.mesh_id AND b.resource_id=r.id AND b.approved AND p.administrative_state='enabled'
     AND (peerward_peer_api_json(p)->>'online')::boolean AND a.binding_version=b.version
     AND a.published AND a.forwarding_ready AND a.valid_until>clock_timestamp())
 UNION ALL
 SELECT r.id,'target_probe_failed','warning',r.definition->>'name',max(h.observed_at),
   r.version::text||':'||md5(string_agg(b.id::text||':'||b.version::text||':'||h.result||':'||h.evidence_generation::text,',' ORDER BY b.id)),'/services'
 FROM network_resources r JOIN gateway_bindings b ON b.mesh_id=r.mesh_id AND b.resource_id=r.id
 JOIN target_health_observations h ON h.mesh_id=b.mesh_id AND h.binding_id=b.id
 JOIN peers p ON p.mesh_id=b.mesh_id AND p.id=b.peer_id
 JOIN peer_credentials c ON c.mesh_id=b.mesh_id AND c.peer_id=b.peer_id AND c.serial=h.credential_serial
 JOIN mesh_authorities a ON a.mesh_id=c.mesh_id AND a.id=c.authority_id
 WHERE r.mesh_id=$1 AND NOT r.console_paused AND b.approved AND p.administrative_state='enabled'
   AND h.binding_version=b.version AND h.resource_version=r.version AND h.valid_until>clock_timestamp()
   AND h.observed_at<=clock_timestamp() AND h.result<>'reachable'
   AND c.lifecycle IN ('active','overlap') AND (c.lifecycle='active' OR c.overlap_deadline>clock_timestamp())
   AND c.not_before<=clock_timestamp() AND c.not_after>clock_timestamp()
   AND a.lifecycle IN ('active','overlap') AND (a.lifecycle='active' OR a.overlap_deadline>clock_timestamp())
   AND a.not_before<=clock_timestamp() AND a.not_after>clock_timestamp()
 GROUP BY r.id,r.version,r.definition
 UNION ALL
 SELECT p.id,'configuration_rejected_'||c.category,'warning',COALESCE(NULLIF(p.display_name,''),p.name),c.received_at,
 c.configuration_version::text||':'||encode(c.configuration_digest,'hex'),'/peers'
 FROM configuration_receipts c JOIN peers p ON p.mesh_id=c.mesh_id AND p.id=c.peer_id
 WHERE c.mesh_id=$1 AND c.result='rejected' AND p.administrative_state='enabled'
)";

const CONSOLE_ISSUES_PAGE_SQL: &str = "
, notices AS (
 SELECT i.*,COALESCE(s.known,false) AS known,COALESCE(s.is_read,false) AS is_read
 FROM issues i LEFT JOIN console_notice_state s ON s.mesh_id=$1 AND s.actor=$2
  AND s.notice_id=i.kind||':'||i.id::text AND s.fingerprint=i.fingerprint
), filtered AS (
 SELECT * FROM notices WHERE CASE $5::text
  WHEN 'open' THEN NOT known WHEN 'known' THEN known
  WHEN 'unread' THEN NOT is_read WHEN 'read' THEN is_read ELSE true END
)
SELECT totals.*,page.* FROM (
 SELECT (SELECT count(*) FROM filtered) AS total,
        (SELECT count(*) FROM notices) AS all_count,
        (SELECT count(*) FROM notices WHERE NOT known) AS open_count,
        (SELECT count(*) FROM notices WHERE NOT is_read) AS unread_count
) totals LEFT JOIN LATERAL (
 SELECT * FROM filtered WHERE ($3::text IS NULL OR kind||':'||id::text>$3)
 ORDER BY kind||':'||id::text LIMIT $4
) page ON true";

async fn console_issue_page(
    state: &AppState,
    mesh: Uuid,
    actor: &str,
    cursor: Option<&str>,
    limit: u16,
    status: &str,
) -> Result<ConsoleIssuePage, ApiError> {
    if !matches!(status, "all" | "open" | "known" | "read" | "unread") {
        return Err(ApiError::invalid("invalid_query", "invalid issue status"));
    }
    let rows = sqlx::query(&format!(
        "{CONSOLE_ISSUES_FACTS_SQL}{CONSOLE_ISSUES_PAGE_SQL}"
    ))
    .bind(mesh)
    .bind(actor)
    .bind(cursor)
    .bind(i64::from(limit) + 1)
    .bind(status)
    .fetch_all(state.store.pool())
    .await?;
    let count = |key| -> Result<u64, ApiError> {
        Ok(rows
            .first()
            .map(|r| r.try_get::<i64, _>(key))
            .transpose()?
            .unwrap_or(0)
            .cast_unsigned())
    };
    let total = count("total")?;
    let all_count = count("all_count")?;
    let open_count = count("open_count")?;
    let unread_count = count("unread_count")?;
    let has_more = rows.len() > usize::from(limit);
    let mut items = Vec::new();
    for row in rows.into_iter().take(usize::from(limit)) {
        let Some(id) = row.try_get::<Option<Uuid>, _>("id")? else {
            continue;
        };
        let kind: String = row.try_get("kind")?;
        let route: String = row.try_get("route")?;
        let observed: OffsetDateTime = row.try_get("updated_at")?;
        items.push(ConsoleIssue {
            id: format!("{kind}:{id}"),
            fingerprint: row.try_get("fingerprint")?,
            mesh_id: mesh,
            kind,
            severity: row.try_get("severity")?,
            name: row.try_get("name")?,
            resource_id: id,
            href: format!("{route}?mesh={mesh}&resource={id}"),
            observed_at: Some(observed.format(&Rfc3339).map_err(|_| publisher_error())?),
            known: row.try_get("known")?,
            read: row.try_get("is_read")?,
        });
    }
    let next_cursor = has_more.then(|| items.last().unwrap().id.clone());
    Ok(ConsoleIssuePage {
        checked_at: OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .map_err(|_| publisher_error())?,
        items,
        next_cursor,
        total,
        all_count,
        open_count,
        unread_count,
    })
}

async fn console_overview(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    Path(mesh): Path<Uuid>,
) -> Result<Json<ConsoleOverview>, ApiError> {
    authorize(&context, &HeaderMap::new(), Capability::ResourceRead, false)?;
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM meshes WHERE id=$1 AND lifecycle<>'deleted')",
    )
    .bind(mesh)
    .fetch_one(state.store.pool())
    .await?;
    if !exists {
        return Err(ApiError::not_found());
    }
    let row=sqlx::query("SELECT
        (SELECT count(*) FROM peers WHERE mesh_id=$1 AND administrative_state<>'deleted') AS devices,
        (SELECT count(*) FROM peers p WHERE mesh_id=$1 AND administrative_state='enabled' AND (peerward_peer_api_json(p)->>'online')::boolean) AS online,
        (SELECT count(*) FROM services WHERE mesh_id=$1) AS services,
        (SELECT count(*) FROM network_resources WHERE mesh_id=$1 AND definition->'target'->>'kind'='subnet') AS networks,
        (SELECT count(*) FROM network_resources WHERE mesh_id=$1 AND definition->'target'->>'kind'='internet') AS exits,
        (SELECT count(*) FROM peers p WHERE p.mesh_id=$1 AND p.administrative_state='enabled' AND EXISTS(SELECT 1 FROM peer_credentials c WHERE c.mesh_id=p.mesh_id AND c.peer_id=p.id AND c.lifecycle='active' AND c.not_after<=clock_timestamp()+interval '30 days')) AS credentials,
        (SELECT count(*) FROM join_applications WHERE mesh_id=$1 AND status='pending' AND expires_at>clock_timestamp()) AS pending")
        .bind(mesh).fetch_one(state.store.pool()).await?;
    let issues = console_issue_page(&state, mesh, &context.actor, None, 3, "open").await?;
    Ok(Json(ConsoleOverview {
        observed_at: current_unix_seconds(),
        devices: row.try_get::<i64, _>("devices")?.cast_unsigned(),
        online_devices: row.try_get::<i64, _>("online")?.cast_unsigned(),
        services: row.try_get::<i64, _>("services")?.cast_unsigned(),
        networks: row.try_get::<i64, _>("networks")?.cast_unsigned(),
        exits: row.try_get::<i64, _>("exits")?.cast_unsigned(),
        credential_warnings: row.try_get::<i64, _>("credentials")?.cast_unsigned(),
        pending_applications: row.try_get::<i64, _>("pending")?.cast_unsigned(),
        issues: issues.items,
        issue_count: issues.all_count,
        open_issue_count: issues.open_count,
        unread_notice_count: issues.unread_count,
    }))
}

#[derive(Deserialize)]
struct ConsoleQuery {
    resource: Option<Uuid>,
    relay_id: Option<Uuid>,
    provider: Option<Uuid>,
    cursor: Option<String>,
    limit: Option<u16>,
    q: Option<String>,
    mesh: Option<Uuid>,
    kind: Option<String>,
    status: Option<String>,
    platform: Option<String>,
}
impl ConsoleQuery {
    fn bounded_limit(&self) -> Result<u16, ApiError> {
        let value = self.limit.unwrap_or(50);
        if !(1..=100).contains(&value)
            || self.cursor.as_ref().is_some_and(|s| s.len() > 160)
            || self.q.as_ref().is_some_and(|s| s.len() > 128)
        {
            return Err(ApiError::invalid(
                "invalid_query",
                "query exceeds its bounds",
            ));
        }
        Ok(value)
    }
}

async fn console_issues(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    Path(mesh): Path<Uuid>,
    Query(query): Query<ConsoleQuery>,
) -> Result<Json<ConsoleIssuePage>, ApiError> {
    authorize(&context, &HeaderMap::new(), Capability::ResourceRead, false)?;
    let page = console_issue_page(
        &state,
        mesh,
        &context.actor,
        query.cursor.as_deref(),
        query.bounded_limit()?,
        query.status.as_deref().unwrap_or("all"),
    )
    .await?;
    Ok(Json(page))
}

async fn console_notice_update(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(mesh): Path<Uuid>,
    ApiJson(body): ApiJson<ConsoleNoticeUpdate>,
) -> Result<StatusCode, ApiError> {
    authorize(&context, &headers, Capability::ResourceRead, true)?;
    if body.id.is_empty()
        || body.id.len() > 160
        || body.fingerprint.is_empty()
        || body.fingerprint.len() > 160
        || body
            .id
            .chars()
            .chain(body.fingerprint.chars())
            .any(char::is_control)
    {
        return Err(ApiError::invalid(
            "invalid_notice",
            "invalid notice identity",
        ));
    }
    let mut tx = state.store.begin_mutation().await?;
    let facts = CONSOLE_ISSUES_FACTS_SQL;
    let valid:bool=sqlx::query_scalar(&format!("{facts} SELECT EXISTS(SELECT 1 FROM issues WHERE kind||':'||id::text=$2 AND fingerprint=$3)"))
        .bind(mesh).bind(&body.id).bind(&body.fingerprint).fetch_one(&mut *tx).await?;
    if !valid {
        return Err(ApiError::conflict(
            "notice_changed",
            "issue changed; refresh its current evidence",
        ));
    }
    sqlx::query("INSERT INTO console_notice_state(mesh_id,actor,notice_id,fingerprint,known,is_read)
        VALUES($1,$2,$3,$4,COALESCE($5,false),COALESCE($6,false))
        ON CONFLICT(mesh_id,actor,notice_id) DO UPDATE SET fingerprint=EXCLUDED.fingerprint,
        known=COALESCE($5,CASE WHEN console_notice_state.fingerprint=$4 THEN console_notice_state.known ELSE false END),
        is_read=COALESCE($6,CASE WHEN console_notice_state.fingerprint=$4 THEN console_notice_state.is_read ELSE false END),
        updated_at=clock_timestamp()")
        .bind(mesh).bind(&context.actor).bind(&body.id).bind(&body.fingerprint).bind(body.known).bind(body.read)
        .execute(&mut *tx).await?;
    state
        .store
        .commit_mutation(
            tx,
            &mutation(
                &context,
                Some(mesh_id(mesh)?),
                "console.notice.update",
                "console.notice.updated",
                "console_notice",
                None,
            ),
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn console_search(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    Query(query): Query<ConsoleQuery>,
) -> Result<Json<ApiPage<ConsoleSearchItem>>, ApiError> {
    authorize(&context, &HeaderMap::new(), Capability::ResourceRead, false)?;
    let limit = query.bounded_limit()?;
    let q = query.q.as_deref().unwrap_or("").trim();
    if q.is_empty() && !matches!(query.kind.as_deref(), Some("mesh" | "group")) {
        return Ok(Json(ApiPage {
            items: vec![],
            next_cursor: None,
        }));
    }
    let rows=sqlx::query("WITH items AS (
        SELECT id,mesh_id,'device' AS kind,COALESCE(NULLIF(display_name,''),name) AS name,'/peers' AS route FROM peers WHERE administrative_state<>'deleted'
        UNION ALL SELECT id,mesh_id,'service',COALESCE(NULLIF(display_name,''),alias,listen_port::text),'/services' FROM services
        UNION ALL SELECT id,mesh_id,definition->'target'->>'kind',definition->>'name','/services' FROM network_resources
        UNION ALL SELECT id,id,'mesh',name,'/meshes' FROM meshes WHERE lifecycle<>'deleted'
        UNION ALL SELECT id,mesh_id,'group',definition->>'name','/policy' FROM network_collections WHERE definition->>'kind'='devices')
        SELECT i.*,m.name AS mesh_name FROM items i JOIN meshes m ON m.id=i.mesh_id
        WHERE ($1::uuid IS NULL OR i.mesh_id=$1) AND (strpos(lower(i.name),lower($2))>0 OR (i.kind='device' AND EXISTS(SELECT 1 FROM peers p WHERE p.mesh_id=i.mesh_id AND p.id=i.id AND strpos(lower(p.name),lower($2))>0)))
        AND ($3::text IS NULL OR i.kind||':'||i.id::text>$3) AND ($5::text IS NULL OR i.kind=$5)
        ORDER BY i.kind||':'||i.id::text LIMIT $4")
        .bind(query.mesh).bind(q).bind(query.cursor).bind(i64::from(limit)+1).bind(query.kind).fetch_all(state.store.pool()).await?;
    let has_more = rows.len() > usize::from(limit);
    let mut items = Vec::new();
    for row in rows.into_iter().take(usize::from(limit)) {
        let id: Uuid = row.try_get("id")?;
        let mesh_id: Uuid = row.try_get("mesh_id")?;
        let route: String = row.try_get("route")?;
        let kind: String = row.try_get("kind")?;
        let href = if kind == "group" {
            format!("{route}?mesh={mesh_id}&source=group:{id}")
        } else {
            format!("{route}?mesh={mesh_id}&resource={id}")
        };
        items.push(ConsoleSearchItem {
            id,
            mesh_id,
            mesh_name: row.try_get("mesh_name")?,
            kind,
            name: row.try_get("name")?,
            href,
        });
    }
    let next_cursor = has_more.then(|| {
        let last = items.last().unwrap();
        format!("{}:{}", last.kind, last.id)
    });
    Ok(Json(ApiPage { items, next_cursor }))
}

fn console_evidence(state: &str, reason: &str) -> ConsoleEvidence {
    ConsoleEvidence {
        state: state.into(),
        reason: reason.into(),
        observed_at: None,
        diagnostic: None,
    }
}

async fn console_sharing(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    Path(mesh): Path<Uuid>,
    Query(query): Query<ConsoleQuery>,
) -> Result<Json<ApiPage<ConsoleSharingResource>>, ApiError> {
    authorize(&context, &HeaderMap::new(), Capability::ResourceRead, false)?;
    let limit = query.bounded_limit()?;
    let rows=sqlx::query("WITH items AS (
        SELECT id,'service' AS kind,COALESCE(NULLIF(display_name,''),alias,listen_port::text) AS name FROM services WHERE mesh_id=$1 AND ($7::uuid IS NULL OR peer_id=$7)
        UNION ALL SELECT id,CASE WHEN definition->'target'->>'kind'='internet' THEN 'internet' ELSE 'lan' END,definition->>'name' FROM network_resources r WHERE mesh_id=$1 AND ($7::uuid IS NULL OR EXISTS(SELECT 1 FROM gateway_bindings b WHERE b.mesh_id=r.mesh_id AND b.resource_id=r.id AND b.peer_id=$7)))
        SELECT * FROM items WHERE ($2::text IS NULL OR kind||':'||id::text>$2)
        AND ($3::text IS NULL OR kind=$3) AND strpos(lower(name),lower($4))>0 AND ($6::uuid IS NULL OR id=$6) ORDER BY kind||':'||id::text LIMIT $5")
        .bind(mesh).bind(query.cursor).bind(query.kind).bind(query.q.unwrap_or_default())
        .bind(i64::from(limit)+1).bind(query.resource).bind(query.provider).fetch_all(state.store.pool()).await?;
    let has_more = rows.len() > usize::from(limit);
    let mut items = Vec::new();
    for row in rows.into_iter().take(usize::from(limit)) {
        let id: Uuid = row.try_get("id")?;
        let kind: String = row.try_get("kind")?;
        let mut view = ConsoleSharingResource {
            id,
            version: 0,
            kind: kind.clone(),
            name: row.try_get("name")?,
            provider: String::new(),
            target: String::new(),
            configuration: console_evidence("ready", "saved"),
            authorization: console_evidence("unknown", "select_source"),
            path: console_evidence("unknown", "no_current_path"),
            reachability: console_evidence("unknown", "not_probed"),
            service: None,
            network: None,
        };
        if kind == "service" {
            let service = load_service(&state.store, mesh, id).await?;
            let peer = load_peer(&state.store, mesh, service.peer_id.into_uuid()).await?;
            view.version = service.version;
            view.provider = if peer.display_name.is_empty() {
                peer.name
            } else {
                peer.display_name
            };
            view.target = format!(
                "{} · {}",
                service
                    .protocols
                    .iter()
                    .map(|p| format!("{p:?}"))
                    .collect::<Vec<_>>()
                    .join("/"),
                service.listen_port
            );
            view.path = console_evidence(
                if peer.online { "ready" } else { "blocked" },
                if peer.online {
                    "provider_online"
                } else {
                    "provider_offline"
                },
            );
            view.path.observed_at = Some(OffsetDateTime::now_utc().format(&Rfc3339).map_err(|_| publisher_error())?);
            if service.state != "enabled" {
                view.configuration = console_evidence("paused", "service_disabled");
            }
            let paused: bool = sqlx::query_scalar(
                "SELECT console_paused FROM services WHERE mesh_id=$1 AND id=$2",
            )
            .bind(mesh)
            .bind(id)
            .fetch_one(state.store.pool())
            .await?;
            if paused {
                view.configuration = console_evidence("paused", "resource_paused");
                view.path = console_evidence("paused", "resource_paused");
            }
            view.service = Some(service);
        } else {
            let resource = load_network_resource(&state.store, mesh, id).await?;
            view.version = resource.version;
            view.target = match resource.definition.target {
                peerward_management::ResourceTarget::Subnet { prefix, .. } => prefix.to_string(),
                peerward_management::ResourceTarget::Internet { ipv4, ipv6 } => {
                    match (ipv4, ipv6) {
                        (true, true) => "IPv4 + IPv6".into(),
                        (true, false) => "IPv4".into(),
                        _ => "IPv6".into(),
                    }
                }
            };
            let bindings=sqlx::query("SELECT COALESCE(NULLIF(p.display_name,''),p.name) AS name,
                b.approved AND COALESCE((peerward_peer_api_json(p)->>'online')::boolean,false)
                AND a.published AND a.forwarding_ready AND a.binding_version=b.version AND a.valid_until>clock_timestamp() AND NOT EXISTS(SELECT 1 FROM network_resources r WHERE r.id=b.resource_id AND r.mesh_id=b.mesh_id AND r.console_paused) AS ready
                FROM gateway_bindings b JOIN peers p ON p.id=b.peer_id AND p.mesh_id=b.mesh_id
                LEFT JOIN route_advertisements a ON a.mesh_id=b.mesh_id AND a.binding_id=b.id
                WHERE b.mesh_id=$1 AND b.resource_id=$2 ORDER BY b.priority,b.id")
                .bind(mesh).bind(id).fetch_all(state.store.pool()).await?;
            view.provider = bindings
                .iter()
                .map(|r| r.try_get::<String, _>("name"))
                .collect::<Result<Vec<_>, _>>()?
                .join(", ");
            let ready = bindings
                .iter()
                .any(|r| r.try_get::<Option<bool>, _>("ready").ok().flatten() == Some(true));
            view.path = console_evidence(
                if ready { "ready" } else { "unknown" },
                if ready {
                    "gateway_advertised"
                } else {
                    "no_current_path"
                },
            );
            let Json(health) = get_target_health(
                Extension(context.clone()),
                State(state.clone()),
                Path((mesh, id)),
            )
            .await?;
            if let Some(observations) = health["bindings"].as_array() {
                if let Some(observation) = observations.iter().find(|o| o["status"] == "reachable")
                {
                    view.reachability = console_evidence("ready", "gateway_tcp_connect");
                    view.reachability.observed_at =
                        observation["observed_at"].as_str().map(str::to_owned);
                } else if let Some(observation) = observations.iter().find(|o| {
                    matches!(
                        o["status"].as_str(),
                        Some("refused" | "timeout" | "unavailable")
                    )
                }) {
                    view.reachability = console_evidence("blocked", "gateway_probe_failed");
                    view.reachability.observed_at =
                        observation["observed_at"].as_str().map(str::to_owned);
                }
            }
            let paused: bool = sqlx::query_scalar(
                "SELECT console_paused FROM network_resources WHERE mesh_id=$1 AND id=$2",
            )
            .bind(mesh)
            .bind(id)
            .fetch_one(state.store.pool())
            .await?;
            if paused {
                view.configuration = console_evidence("paused", "resource_paused");
                view.path = console_evidence("paused", "resource_paused");
            }
            view.network = Some(resource);
        }
        for evidence in [&mut view.path, &mut view.reachability] {
            let code = match evidence.reason.as_str() {
                "provider_offline" => Some(peerward_types::DiagnosticCode::DeviceOffline),
                "gateway_probe_failed" => Some(peerward_types::DiagnosticCode::TargetUnreachable),
                "no_current_path" | "not_probed" => Some(peerward_types::DiagnosticCode::ObservationUnavailable),
                _ => None,
            };
            evidence.diagnostic = code.map(|code| peerward_types::RuntimeDiagnostic::new(code,
                evidence.observed_at.as_deref()
                    .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok())
                    .and_then(|value| u64::try_from(value.unix_timestamp()).ok())));
        }
        items.push(view);
    }
    let next_cursor = has_more.then(|| {
        let last = items.last().unwrap();
        format!("{}:{}", last.kind, last.id)
    });
    Ok(Json(ApiPage { items, next_cursor }))
}
