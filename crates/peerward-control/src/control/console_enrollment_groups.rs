async fn console_enrollment_groups(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    Path(mesh): Path<Uuid>,
) -> Result<Json<Vec<peerward_api::ConsoleEnrollmentGroup>>, ApiError> {
    use peerward_api::{ConsoleEnrollmentGrant, ConsoleEnrollmentGroup};
    authorize(&context, &HeaderMap::new(), Capability::ResourceRead, false)?;
    let mut tx = state.store.begin_mutation().await?;
    lock_configuration(&mut tx, mesh).await?;
    let rows: Vec<(Uuid, String)> = sqlx::query_as("SELECT id,definition->>'name' FROM network_collections WHERE mesh_id=$1 AND definition->>'kind'='devices' ORDER BY definition->>'name',id")
        .bind(mesh).fetch_all(&mut *tx).await?;
    let mut groups: Vec<_> = rows
        .into_iter()
        .map(|(id, name)| ConsoleEnrollmentGroup {
            id,
            name,
            grants: vec![],
        })
        .collect();
    let services = sqlx::query("SELECT COALESCE(NULLIF(s.display_name,''),NULLIF(s.alias,''),s.id::text) AS name,s.listen_port,s.protocols,s.console_paused,g.source,g.source_collections FROM console_service_grants g JOIN services s ON s.mesh_id=g.mesh_id AND s.id=g.service_id WHERE g.mesh_id=$1 AND g.enabled AND s.state='enabled' ORDER BY s.id,g.id")
        .bind(mesh).fetch_all(&mut *tx).await?;
    for row in services {
        let selected: Vec<Uuid> = row.try_get("source_collections")?;
        let source: peerward_management::DeviceSelector =
            serde_json::from_value(row.try_get("source")?).map_err(|_| publisher_error())?;
        let conditional = row.try_get::<bool, _>("console_paused")?
            || !source.peers.is_empty()
            || !source.labels.is_empty()
            || !source.cidrs.is_empty();
        let port =
            u16::try_from(row.try_get::<i32, _>("listen_port")?).map_err(|_| publisher_error())?;
        let protocols: Vec<String> = row.try_get("protocols")?;
        for group in groups
            .iter_mut()
            .filter(|group| selected.contains(&group.id))
        {
            for transport in &protocols {
                group.grants.push(ConsoleEnrollmentGrant {
                    name: row.try_get("name")?,
                    protocol: if transport.eq_ignore_ascii_case("udp") {
                        17
                    } else {
                        6
                    },
                    destination_ports: vec![(port, port)],
                    conditional,
                });
            }
        }
    }
    let configuration = read_resource_configuration(&mut tx, mesh_id(mesh)?).await?;
    let now = u64::try_from(time::OffsetDateTime::now_utc().unix_timestamp()).unwrap_or_default();
    for rule in configuration.rules.iter().filter(|rule| {
        rule.enabled
            && rule.action == peerward_management::ResourceAction::Allow
            && rule.not_after.is_none_or(|until| now < until)
    }) {
        let conditional = !rule.source.peers.is_empty()
            || !rule.source.labels.is_empty()
            || !rule.source.cidrs.is_empty()
            || !rule.providers.is_empty()
            || rule.not_after.is_some();
        for resource in configuration.resources.iter().filter(|resource| {
            rule.resources.contains(&resource.id)
                || peerward_management::collection_contains(
                    &configuration.collections,
                    &rule.resource_collections,
                    peerward_management::CollectionKind::Resources,
                    resource.id,
                )
        }) {
            for group in groups
                .iter_mut()
                .filter(|group| rule.source_collections.contains(&group.id))
            {
                group.grants.push(ConsoleEnrollmentGrant {
                    name: resource.definition.name.clone(),
                    protocol: rule.protocol,
                    destination_ports: rule.destination_ports.clone(),
                    conditional,
                });
            }
        }
    }
    for group in &mut groups {
        group.grants.sort_by(|a, b| {
            (&a.name, a.protocol, &a.destination_ports, a.conditional).cmp(&(
                &b.name,
                b.protocol,
                &b.destination_ports,
                b.conditional,
            ))
        });
        group.grants.dedup();
    }
    tx.rollback().await?;
    Ok(Json(groups))
}
