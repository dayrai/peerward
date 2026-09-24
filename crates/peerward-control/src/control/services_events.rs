async fn list_services(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    Path(mesh): Path<Uuid>,
    Query(query): Query<ListQuery>,
) -> Result<Json<ApiPage<ServiceResource>>, ApiError> {
    authorize(&context, &HeaderMap::new(), Capability::ResourceRead, false)?;
    mesh_id(mesh)?;
    json_page(
        &state.store,
        "SELECT jsonb_build_object('id',id,'version',version,'peer_id',peer_id,'protocols',protocols,'listen_port',listen_port,
         'alias',alias,'labels',labels,'state',state) AS item,id,created_at AS cursor_time FROM services
         WHERE mesh_id=$1 AND ($2::timestamptz IS NULL OR (created_at,id)>($2,$3))
         ORDER BY created_at,id LIMIT $4",
        mesh,
        query.cursor()?,
        query.limit()?,
    )
    .await
}

async fn get_service(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    Path((mesh, service)): Path<(Uuid, Uuid)>,
) -> Result<(HeaderMap, Json<ServiceResource>), ApiError> {
    authorize(&context, &HeaderMap::new(), Capability::ResourceRead, false)?;
    mesh_id(mesh)?;
    ServiceId::from_uuid(service).map_err(|_| ApiError::invalid_id())?;
    let resource = load_service(&state.store, mesh, service).await?;
    Ok((etag_headers(resource.version)?, Json(resource)))
}

async fn load_service(store: &Store, mesh: Uuid, service: Uuid) -> Result<ServiceResource, ApiError> {
    let value: Option<Value> = sqlx::query_scalar(
        "SELECT jsonb_build_object('id',id,'version',version,'peer_id',peer_id,
        'protocols',protocols,'listen_port',listen_port,'alias',alias,'labels',labels,'state',state)
        FROM services WHERE mesh_id=$1 AND id=$2",
    )
    .bind(mesh)
    .bind(service)
    .fetch_optional(store.pool())
    .await?;
    serde_json::from_value(value.ok_or_else(ApiError::not_found)?)
        .map_err(|_| ApiError::internal("service_projection", "Service projection is invalid"))
}

async fn get_topology(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    Path(mesh): Path<Uuid>,
) -> Result<Json<TopologyResource>, ApiError> {
    authorize(&context, &HeaderMap::new(), Capability::ResourceRead, false)?;
    mesh_id(mesh)?;
    let projected_rows: i64 = sqlx::query_scalar(
        "SELECT (SELECT count(*) FROM peers WHERE mesh_id=$1 AND administrative_state<>'deleted')
          +(SELECT count(*) FROM relays WHERE mesh_id=$1)
          +(SELECT count(*) FROM relay_presence_all WHERE mesh_id=$1
            AND peer_id IN (SELECT id FROM peers WHERE mesh_id=$1 AND administrative_state<>'deleted')
            AND lease_deadline>clock_timestamp())",
    )
    .bind(mesh)
    .fetch_one(state.store.pool())
    .await?;
    if projected_rows > 2_000 {
        return Err(ApiError::conflict(
            "topology_pagination_required",
            "topology exceeds the compatibility response limit; use summary, nodes, and edges",
        ));
    }
    let peer_values = sqlx::query_scalar::<_, Value>(
        "SELECT peerward_peer_api_json(peer)||jsonb_build_object('version',peer.version) FROM peers peer WHERE peer.mesh_id=$1 AND peer.administrative_state<>'deleted' ORDER BY peer.name,peer.id",
    )
    .bind(mesh)
    .fetch_all(state.store.pool())
    .await?;
    let relay_values = sqlx::query_scalar::<_, Value>(
        "SELECT peerward_relay_api_json(relay)||jsonb_build_object('version',relay.version) FROM relays relay WHERE relay.mesh_id=$1 ORDER BY relay.name,relay.id",
    )
    .bind(mesh)
    .fetch_all(state.store.pool())
    .await?;
    let peers = peer_values
        .into_iter()
        .map(serde_json::from_value::<PeerResource>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ApiError::internal("topology_projection", "Peer topology projection is invalid"))?;
    let relays = relay_values
        .into_iter()
        .map(serde_json::from_value::<RelayResource>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ApiError::internal("topology_projection", "Relay topology projection is invalid"))?;
    let health_rows = sqlx::query(
        "SELECT peer_id,direct_path_count,relay_packets,direct_packets,degraded_reasons,
         signed_revision,observed_at FROM current_peer_runtime_health
         WHERE mesh_id=$1 AND expires_at>clock_timestamp() AND observed_at<=clock_timestamp()",
    )
    .bind(mesh)
    .fetch_all(state.store.pool())
    .await?;
    let runtime_health = health_rows
        .into_iter()
        .map(|row| {
            let peer_id: Uuid = row.try_get("peer_id")?;
            let relay_packets: i64 = row.try_get("relay_packets")?;
            let direct_packets: i64 = row.try_get("direct_packets")?;
            let total = u128::try_from(relay_packets)
                .unwrap_or_default()
                .saturating_add(u128::try_from(direct_packets).unwrap_or_default());
            let share = u16::try_from(
                u128::try_from(relay_packets)
                    .unwrap_or_default()
                    .saturating_mul(10_000)
                    .checked_div(total)
                    .unwrap_or_default(),
            )
            .unwrap_or(10_000);
            let observed_at: OffsetDateTime = row.try_get("observed_at")?;
            Ok((
                peer_id,
                RuntimeHealthSummary {
                    direct_path_count: u32::try_from(row.try_get::<i32, _>("direct_path_count")?)
                        .unwrap_or_default(),
                    relay_packet_share_bps: share,
                    degraded_reasons: row.try_get("degraded_reasons")?,
                    signed_revision: u64::try_from(row.try_get::<i64, _>("signed_revision")?)
                        .unwrap_or_default(),
                    observed_at: observed_at
                        .format(&Rfc3339)
                        .map_err(|error| sqlx::Error::Decode(Box::new(error)))?,
                },
            ))
        })
        .collect::<Result<BTreeMap<_, _>, sqlx::Error>>()?;
    let presence = peers
        .iter()
        .flat_map(|peer| peer.presence.iter().map(move |edge| TopologyPresenceEdge {
            peer_id: peer.id,
            relay_id: edge.relay_id,
            role: edge.role.clone(),
        }))
        .collect();
    Ok(Json(TopologyResource {
        peers: peers.into_iter().map(|peer| {
            let runtime_health = runtime_health.get(&peer.id.into_uuid()).cloned();
            TopologyPeerNode {
                id: peer.id,
                name: peer.name,
                online: peer.online,
                administrative_state: peer.administrative_state,
                credential_status: credential_status(peer.credentials.active.as_ref()),
                runtime_health,
            }
        }).collect(),
        relays: relays.into_iter().map(|relay| TopologyRelayNode {
            id: relay.id,
            name: relay.name,
            online: relay.online,
            administrative_state: relay.administrative_state,
            presence_count: relay.presence_count,
            region: relay.region,
            routing_weight: relay.routing_weight,
            credential_status: credential_status(relay.credentials.active.as_ref()),
        }).collect(),
        presence,
    }))
}

#[derive(Deserialize)]
struct TopologyNodesQuery {
    kind: Option<String>,
    relay_id: Option<Uuid>,
    region: Option<String>,
    cursor: Option<String>,
    limit: Option<u16>,
}

#[derive(Deserialize)]
struct TopologyEdgesQuery {
    kind: String,
    cursor: Option<String>,
    limit: Option<u16>,
}

async fn get_topology_summary(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    Path(mesh): Path<Uuid>,
) -> Result<Json<TopologySummary>, ApiError> {
    authorize(&context, &HeaderMap::new(), Capability::ResourceRead, false)?;
    mesh_id(mesh)?;
    let counts = sqlx::query(
        "SELECT
          (SELECT count(*) FROM peers WHERE mesh_id=$1 AND administrative_state<>'deleted') AS peer_count,
          (SELECT count(*) FROM peers peer WHERE peer.mesh_id=$1 AND peer.administrative_state<>'deleted'
            AND peer.administrative_state='enabled' AND EXISTS(
              SELECT 1 FROM relay_presence_all presence JOIN relays relay
                ON relay.mesh_id=presence.mesh_id AND relay.id=presence.relay_id
              JOIN relay_runtime_leases runtime ON runtime.mesh_id=relay.mesh_id
                AND runtime.relay_id=relay.id AND runtime.lease_deadline>clock_timestamp()
              WHERE presence.mesh_id=peer.mesh_id AND presence.peer_id=peer.id
                AND presence.lease_deadline>clock_timestamp()
                AND relay.administrative_state='enabled')) AS online_peer_count,
          (SELECT count(*) FROM relays WHERE mesh_id=$1) AS relay_count,
          (SELECT count(*) FROM relays relay WHERE relay.mesh_id=$1
            AND relay.administrative_state='enabled' AND EXISTS(
              SELECT 1 FROM relay_runtime_leases runtime WHERE runtime.mesh_id=relay.mesh_id
                AND runtime.relay_id=relay.id AND runtime.lease_deadline>clock_timestamp()))
            AS online_relay_count,
          (SELECT count(*) FROM relay_presence_all WHERE mesh_id=$1
            AND peer_id IN (SELECT id FROM peers WHERE mesh_id=$1 AND administrative_state<>'deleted')
            AND lease_deadline>clock_timestamp()) AS presence_count",
    )
    .bind(mesh)
    .fetch_one(state.store.pool())
    .await?;
    let region_rows = sqlx::query(
        "SELECT relay.region,count(*) AS relay_count,
          count(*) FILTER (WHERE relay.administrative_state='enabled' AND EXISTS(
            SELECT 1 FROM relay_runtime_leases runtime WHERE runtime.mesh_id=relay.mesh_id
              AND runtime.relay_id=relay.id AND runtime.lease_deadline>clock_timestamp()))
            AS online_relay_count,
          (SELECT count(*) FROM relay_presence_all presence JOIN relays owner
            ON owner.mesh_id=presence.mesh_id AND owner.id=presence.relay_id
            WHERE presence.mesh_id=$1 AND owner.region=relay.region
              AND presence.peer_id IN (SELECT id FROM peers WHERE mesh_id=$1 AND administrative_state<>'deleted')
              AND presence.lease_deadline>clock_timestamp()) AS presence_count
         FROM relays relay WHERE relay.mesh_id=$1 GROUP BY relay.region ORDER BY relay.region",
    )
    .bind(mesh)
    .fetch_all(state.store.pool())
    .await?;
    let regions = region_rows
        .into_iter()
        .map(|row| {
            Ok(TopologyRegionSummary {
                region: row.try_get("region")?,
                relay_count: count_u64(&row, "relay_count")?,
                online_relay_count: count_u64(&row, "online_relay_count")?,
                presence_count: count_u64(&row, "presence_count")?,
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    let topology = sqlx::query(
        "SELECT revision,body FROM signed_state_revisions WHERE mesh_id=$1
         AND kind='relay_topology' ORDER BY revision DESC LIMIT 1",
    )
    .bind(mesh)
    .fetch_optional(state.store.pool())
    .await?;
    let (backbone_revision, backbone_mode, backbone_edge_count) = if let Some(row) = topology {
        let signed = decode_relay_topology(&row.try_get::<Vec<u8>, _>("body")?)
            .map_err(|_| ApiError::internal("topology_projection", "signed topology is invalid"))?;
        (
            Some(signed.topology.revision),
            Some(match signed.topology.mode {
                peerward_directory::RelayTopologyMode::FullMesh => "full_mesh".into(),
                peerward_directory::RelayTopologyMode::Sparse => "sparse".into(),
            }),
            u64::try_from(signed.topology.edges.len()).unwrap_or(u64::MAX),
        )
    } else {
        (None, None, 0)
    };
    Ok(Json(TopologySummary {
        peer_count: count_u64(&counts, "peer_count")?,
        online_peer_count: count_u64(&counts, "online_peer_count")?,
        relay_count: count_u64(&counts, "relay_count")?,
        online_relay_count: count_u64(&counts, "online_relay_count")?,
        presence_count: count_u64(&counts, "presence_count")?,
        regions,
        backbone_revision,
        backbone_mode,
        backbone_edge_count,
    }))
}

async fn get_topology_nodes(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    Path(mesh): Path<Uuid>,
    Query(query): Query<TopologyNodesQuery>,
) -> Result<Json<ApiPage<TopologyNodeItem>>, ApiError> {
    authorize(&context, &HeaderMap::new(), Capability::ResourceRead, false)?;
    mesh_id(mesh)?;
    let kind = match query.kind.as_deref() {
        None => None,
        Some("peer") => Some(0_i16),
        Some("relay") => Some(1_i16),
        Some(_) => return Err(ApiError::invalid("invalid_kind", "kind must be peer or relay")),
    };
    if let Some(relay) = query.relay_id {
        RelayId::from_uuid(relay).map_err(|_| ApiError::invalid_id())?;
    }
    if let Some(region) = &query.region {
        validate_relay_region(region)?;
    }
    let limit = topology_limit(query.limit)?;
    let cursor = query
        .cursor
        .as_deref()
        .map(decode_topology_node_cursor)
        .transpose()?;
    let rows = sqlx::query(
        "SELECT * FROM (
           SELECT 0::smallint AS kind_order,peer.id,peer.name,peer.administrative_state,
             EXISTS(SELECT 1 FROM relay_presence_all presence JOIN relays relay
               ON relay.mesh_id=presence.mesh_id AND relay.id=presence.relay_id
               JOIN relay_runtime_leases runtime ON runtime.mesh_id=relay.mesh_id
                 AND runtime.relay_id=relay.id AND runtime.lease_deadline>clock_timestamp()
               WHERE presence.mesh_id=peer.mesh_id AND presence.peer_id=peer.id
                 AND presence.lease_deadline>clock_timestamp()
                 AND relay.administrative_state='enabled') AS online,
             CASE WHEN credential.not_after IS NULL THEN 'missing'
               WHEN credential.not_after<=clock_timestamp() THEN 'expired'
               WHEN credential.not_after<=clock_timestamp()+interval '7 days' THEN 'warning_7d'
               WHEN credential.not_after<=clock_timestamp()+interval '30 days' THEN 'warning_30d'
               ELSE 'healthy' END AS credential_status,
             NULL::text AS region,NULL::integer AS routing_weight,NULL::bigint AS presence_count
           FROM peers peer LEFT JOIN LATERAL (
             SELECT not_after FROM peer_credentials WHERE mesh_id=peer.mesh_id
               AND peer_id=peer.id AND lifecycle='active' LIMIT 1) credential ON true
           WHERE peer.mesh_id=$1 AND peer.administrative_state<>'deleted'
             AND ($3::uuid IS NULL OR EXISTS(SELECT 1 FROM relay_presence_all presence
               WHERE presence.mesh_id=peer.mesh_id AND presence.peer_id=peer.id
                 AND presence.relay_id=$3 AND presence.lease_deadline>clock_timestamp()))
             AND ($4::text IS NULL OR EXISTS(SELECT 1 FROM relay_presence_all presence JOIN relays relay
               ON relay.mesh_id=presence.mesh_id AND relay.id=presence.relay_id
               WHERE presence.mesh_id=peer.mesh_id AND presence.peer_id=peer.id
                 AND presence.lease_deadline>clock_timestamp() AND relay.region=$4))
           UNION ALL
           SELECT 1::smallint,relay.id,relay.name,relay.administrative_state,
             relay.administrative_state='enabled' AND EXISTS(SELECT 1 FROM relay_runtime_leases runtime
               WHERE runtime.mesh_id=relay.mesh_id AND runtime.relay_id=relay.id
                 AND runtime.lease_deadline>clock_timestamp()),
             CASE WHEN credential.not_after IS NULL THEN 'missing'
               WHEN credential.not_after<=clock_timestamp() THEN 'expired'
               WHEN credential.not_after<=clock_timestamp()+interval '7 days' THEN 'warning_7d'
               WHEN credential.not_after<=clock_timestamp()+interval '30 days' THEN 'warning_30d'
               ELSE 'healthy' END,
             relay.region,relay.routing_weight,
             (SELECT count(*) FROM relay_presence_all presence WHERE presence.mesh_id=relay.mesh_id
               AND presence.relay_id=relay.id AND presence.lease_deadline>clock_timestamp()
               AND presence.peer_id IN (SELECT id FROM peers WHERE mesh_id=$1 AND administrative_state<>'deleted'))
           FROM relays relay LEFT JOIN LATERAL (
             SELECT not_after FROM relay_credentials WHERE mesh_id=relay.mesh_id
               AND relay_id=relay.id AND lifecycle='active' LIMIT 1) credential ON true
           WHERE relay.mesh_id=$1 AND ($3::uuid IS NULL OR relay.id=$3)
             AND ($4::text IS NULL OR relay.region=$4)
         ) node WHERE ($2::smallint IS NULL OR kind_order=$2)
           AND ($5::smallint IS NULL OR (kind_order,id)>($5,$6))
         ORDER BY kind_order,id LIMIT $7",
    )
    .bind(mesh)
    .bind(kind)
    .bind(query.relay_id)
    .bind(query.region)
    .bind(cursor.map(|value| value.0))
    .bind(cursor.map_or(Uuid::nil(), |value| value.1))
    .bind(i64::from(limit) + 1)
    .fetch_all(state.store.pool())
    .await?;
    let has_more = rows.len() > usize::from(limit);
    let mut items = Vec::new();
    let mut last = None;
    for row in rows.into_iter().take(usize::from(limit)) {
        let kind_order: i16 = row.try_get("kind_order")?;
        let id: Uuid = row.try_get("id")?;
        last = Some((kind_order, id));
        let administrative_state = match row.try_get::<String, _>("administrative_state")?.as_str() {
            "enabled" => AdministrativeState::Enabled,
            "disabled" | "deleted" => AdministrativeState::Disabled,
            _ => return Err(ApiError::internal("topology_projection", "node state is invalid")),
        };
        items.push(TopologyNodeItem {
            kind: if kind_order == 0 { "peer" } else { "relay" }.into(),
            id,
            name: row.try_get("name")?,
            online: row.try_get("online")?,
            administrative_state,
            credential_status: row.try_get("credential_status")?,
            region: row.try_get("region")?,
            routing_weight: row
                .try_get::<Option<i32>, _>("routing_weight")?
                .map(u16::try_from)
                .transpose()
                .map_err(|_| ApiError::internal("topology_projection", "routing weight is invalid"))?,
            presence_count: row
                .try_get::<Option<i64>, _>("presence_count")?
                .map(u64::try_from)
                .transpose()
                .map_err(|_| ApiError::internal("topology_projection", "presence count is invalid"))?,
        });
    }
    Ok(Json(ApiPage {
        items,
        next_cursor: if has_more {
            last.map(encode_topology_node_cursor)
        } else {
            None
        },
    }))
}

async fn get_topology_edges(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    Path(mesh): Path<Uuid>,
    Query(query): Query<TopologyEdgesQuery>,
) -> Result<Json<ApiPage<TopologyEdgeItem>>, ApiError> {
    authorize(&context, &HeaderMap::new(), Capability::ResourceRead, false)?;
    mesh_id(mesh)?;
    let limit = topology_limit(query.limit)?;
    match query.kind.as_str() {
        "presence" => topology_presence_edges(&state.store, mesh, &query, limit).await,
        "backbone" => topology_backbone_edges(&state.store, mesh, &query, limit).await,
        _ => Err(ApiError::invalid(
            "invalid_kind",
            "kind must be presence or backbone",
        )),
    }
}

async fn topology_presence_edges(
    store: &Store,
    mesh: Uuid,
    query: &TopologyEdgesQuery,
    limit: u16,
) -> Result<Json<ApiPage<TopologyEdgeItem>>, ApiError> {
    let cursor = query
        .cursor
        .as_deref()
        .map(|value| decode_topology_edge_cursor(value, 0))
        .transpose()?;
    let rows = sqlx::query(
        "SELECT peer_id,relay_id,role FROM relay_presence_all WHERE mesh_id=$1
            AND peer_id IN (SELECT id FROM peers WHERE mesh_id=$1 AND administrative_state<>'deleted')
         AND lease_deadline>clock_timestamp()
         AND ($2::uuid IS NULL OR (peer_id,relay_id,role)>($2,$3,$4))
         ORDER BY peer_id,relay_id,role LIMIT $5",
    )
    .bind(mesh)
    .bind(cursor.map(|value| value.0))
    .bind(cursor.map_or(Uuid::nil(), |value| value.1))
    .bind(cursor.map_or(String::new(), |value| if value.2 == 0 { "primary".into() } else { "standby".into() }))
    .bind(i64::from(limit) + 1)
    .fetch_all(store.pool())
    .await?;
    let has_more = rows.len() > usize::from(limit);
    let mut items = Vec::new();
    let mut last = None;
    for row in rows.into_iter().take(usize::from(limit)) {
        let source_id: Uuid = row.try_get("peer_id")?;
        let target_id: Uuid = row.try_get("relay_id")?;
        let role: String = row.try_get("role")?;
        let role_tag = u8::from(role == "standby");
        last = Some((source_id, target_id, role_tag));
        items.push(TopologyEdgeItem {
            kind: "presence".into(),
            source_id,
            target_id,
            role: Some(role),
            revision: None,
        });
    }
    Ok(Json(ApiPage {
        items,
        next_cursor: if has_more {
            last.map(|value| encode_topology_edge_cursor(0, value))
        } else {
            None
        },
    }))
}

async fn topology_backbone_edges(
    store: &Store,
    mesh: Uuid,
    query: &TopologyEdgesQuery,
    limit: u16,
) -> Result<Json<ApiPage<TopologyEdgeItem>>, ApiError> {
    let cursor = query
        .cursor
        .as_deref()
        .map(|value| decode_topology_edge_cursor(value, 1))
        .transpose()?;
    let row = sqlx::query(
        "SELECT body FROM signed_state_revisions WHERE mesh_id=$1 AND kind='relay_topology'
         ORDER BY revision DESC LIMIT 1",
    )
    .bind(mesh)
    .fetch_optional(store.pool())
    .await?;
    let Some(row) = row else {
        return Ok(Json(ApiPage {
            items: Vec::new(),
            next_cursor: None,
        }));
    };
    let topology = decode_relay_topology(&row.try_get::<Vec<u8>, _>("body")?)
        .map_err(|_| ApiError::internal("topology_projection", "signed topology is invalid"))?
        .topology;
    let mut edges = topology
        .edges
        .into_iter()
        .filter(|edge| cursor.is_none_or(|value| (edge.left.into_uuid(), edge.right.into_uuid()) > (value.0, value.1)))
        .take(usize::from(limit) + 1)
        .collect::<Vec<_>>();
    let has_more = edges.len() > usize::from(limit);
    edges.truncate(usize::from(limit));
    let last = edges.last().map(|edge| (edge.left.into_uuid(), edge.right.into_uuid(), 0));
    Ok(Json(ApiPage {
        items: edges
            .into_iter()
            .map(|edge| TopologyEdgeItem {
                kind: "backbone".into(),
                source_id: edge.left.into_uuid(),
                target_id: edge.right.into_uuid(),
                role: None,
                revision: Some(topology.revision),
            })
            .collect(),
        next_cursor: if has_more {
            last.map(|value| encode_topology_edge_cursor(1, value))
        } else {
            None
        },
    }))
}

fn topology_limit(limit: Option<u16>) -> Result<u16, ApiError> {
    let limit = limit.unwrap_or(100);
    if (1..=200).contains(&limit) {
        Ok(limit)
    } else {
        Err(ApiError::invalid(
            "invalid_limit",
            "limit must be between 1 and 200",
        ))
    }
}

fn count_u64(row: &sqlx::postgres::PgRow, column: &str) -> Result<u64, ApiError> {
    u64::try_from(row.try_get::<i64, _>(column)?)
        .map_err(|_| ApiError::internal("topology_projection", "aggregate count is invalid"))
}

fn encode_topology_node_cursor((kind, id): (i16, Uuid)) -> String {
    let mut bytes = [0_u8; 18];
    bytes[0] = 1;
    bytes[1] = u8::try_from(kind).unwrap_or_default();
    bytes[2..].copy_from_slice(id.as_bytes());
    URL_SAFE_NO_PAD.encode(bytes)
}

fn decode_topology_node_cursor(value: &str) -> Result<(i16, Uuid), ApiError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| ApiError::invalid("invalid_cursor", "cursor is invalid"))?;
    if bytes.len() != 18 || bytes[0] != 1 || bytes[1] > 1 {
        return Err(ApiError::invalid("invalid_cursor", "cursor is invalid"));
    }
    Ok((i16::from(bytes[1]), Uuid::from_slice(&bytes[2..]).map_err(|_| ApiError::invalid("invalid_cursor", "cursor is invalid"))?))
}

fn encode_topology_edge_cursor(kind: u8, (left, right, role): (Uuid, Uuid, u8)) -> String {
    let mut bytes = [0_u8; 35];
    bytes[0] = 1;
    bytes[1] = kind;
    bytes[2..18].copy_from_slice(left.as_bytes());
    bytes[18..34].copy_from_slice(right.as_bytes());
    bytes[34] = role;
    URL_SAFE_NO_PAD.encode(bytes)
}

fn decode_topology_edge_cursor(value: &str, expected_kind: u8) -> Result<(Uuid, Uuid, u8), ApiError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| ApiError::invalid("invalid_cursor", "cursor is invalid"))?;
    if bytes.len() != 35 || bytes[0] != 1 || bytes[1] != expected_kind || bytes[34] > 1 {
        return Err(ApiError::invalid("invalid_cursor", "cursor is invalid"));
    }
    Ok((
        Uuid::from_slice(&bytes[2..18]).map_err(|_| ApiError::invalid("invalid_cursor", "cursor is invalid"))?,
        Uuid::from_slice(&bytes[18..34]).map_err(|_| ApiError::invalid("invalid_cursor", "cursor is invalid"))?,
        bytes[34],
    ))
}

include!("services_audit_events.rs");
