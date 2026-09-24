async fn console_matrix(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    Path(mesh): Path<Uuid>,
    ApiJson(query): ApiJson<peerward_api::ConsoleMatrixQuery>,
) -> Result<Json<peerward_api::ConsoleMatrix>, ApiError> {
    use peerward_api::ConsoleMatrixTarget as Target;
    authorize(&context, &HeaderMap::new(), Capability::ResourceRead, false)?;
    if query.targets.len() > 20 {
        return Err(ApiError::invalid(
            "matrix_bounds",
            "at most 20 targets per evaluation",
        ));
    }
    let mut tx = state.store.begin_mutation().await?;
    lock_configuration(&mut tx, mesh).await?;
    let (selector, groups, _) = console_grant_source(&mut tx, mesh, &query.source).await?;
    let configuration = read_resource_configuration(&mut tx, mesh_id(mesh)?).await?;
    let source_ids: Vec<Uuid> = if groups.is_empty() {
        selector.peers.iter().map(|p| p.into_uuid()).collect()
    } else {
        configuration
            .collections
            .iter()
            .filter(|c| groups.contains(&c.id))
            .flat_map(|c| c.members.iter().copied())
            .collect()
    };
    let raw = load_current_policy_from(&mut *tx, mesh).await?;
    let policy = canonical_policy(&effective_console_policy(&mut tx, mesh, &raw).await?)?;
    let now = current_unix_seconds();
    let mut cells = vec![];
    for target in query.targets {
        let (id, family) = match &target {
            Target::Service { id, address, .. } => {
                (*id, address.map(|a| if a.is_ipv4() { 4 } else { 6 }))
            }
            Target::Network { id, address, .. } => {
                (*id, address.map(|a| if a.is_ipv4() { 4 } else { 6 }))
            }
        };
        let mut cell = peerward_api::ConsoleMatrixCell {
            id,
            outcome: "unknown".into(),
            sources: source_ids.len() as u64,
            allowed_sources: 0,
            unknown_sources: 0,
            matched_rules: vec![],
            reasons: vec!["policy_simulation_is_not_connectivity_evidence".into()],
        };
        let mut ids = source_ids.clone();
        let endpoint = match &target {
            Target::Service {
                id,
                address,
                protocol,
            } => {
                let row:Option<(Uuid,i32,Vec<String>,bool,String)>=sqlx::query_as("SELECT peer_id,listen_port,protocols,console_paused,state::text FROM services WHERE mesh_id=$1 AND id=$2")
                    .bind(mesh).bind(id).fetch_optional(&mut *tx).await?;
                let row = row.ok_or_else(ApiError::not_found)?;
                if protocol.is_some_and(|p| {
                    !matches!(p, 6 | 17)
                        || !row
                            .2
                            .iter()
                            .any(|name| (p == 6 && name == "tcp") || (p == 17 && name == "udp"))
                }) {
                    return Err(ApiError::invalid(
                        "service_protocol",
                        "select a configured service transport",
                    ));
                }
                if let Some(address) = address {
                    let owned: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM peer_addresses WHERE mesh_id=$1 AND peer_id=$2 AND address=$3::inet AND state='active')")
                        .bind(mesh).bind(row.0).bind(address.to_string()).fetch_one(&mut *tx).await?;
                    if !owned {
                        return Err(ApiError::invalid(
                            "service_address",
                            "select an active address of the publishing device",
                        ));
                    }
                }
                ids.push(row.0);
                Some(row)
            }
            Target::Network {
                id,
                address,
                provider,
                protocol,
                port,
            } => {
                let resource = configuration
                    .resources
                    .iter()
                    .find(|r| r.id == *id)
                    .ok_or_else(ApiError::not_found)?;
                if let (Some(address), Some(_), Some(protocol)) = (address, provider, protocol) {
                    if !resource.definition.target.contains(*address) {
                        return Err(ApiError::invalid(
                            "target_address",
                            "address is outside the resource",
                        ));
                    }
                    validate_packet_predicate(*protocol, *port)?;
                } else {
                    cell.outcome = "conditions".into();
                    cell.reasons
                        .push("specify_address_protocol_port_and_gateway".into());
                    cells.push(cell);
                    continue;
                }
                None
            }
        };
        let descriptors = console_descriptors(&mut tx, mesh, &ids, family).await?;
        let service_v4 = if endpoint.is_some() {
            console_descriptors(&mut tx, mesh, &ids, Some(4)).await?
        } else {
            BTreeMap::new()
        };
        let service_v6 = if endpoint.is_some() {
            console_descriptors(&mut tx, mesh, &ids, Some(6)).await?
        } else {
            BTreeMap::new()
        };
        let mut partial = false;
        for source in &source_ids {
            let Some(source) = descriptors.get(source) else {
                cell.unknown_sources += 1;
                continue;
            };
            let (allowed, matched, reasons, mixed) =
                if let Some((provider, port, protocols, paused, state)) = &endpoint {
                    let Some(destination) = descriptors.get(provider) else {
                        cell.unknown_sources += 1;
                        continue;
                    };
                    let admitted = configuration.admission.permits(source.id, now)
                        && configuration.admission.permits(destination.id, now);
                    // A service matrix cell covers every configured transport and
                    // shared address family, so CIDR conditions cannot make one
                    // IPv4 sample stand in for a different IPv6 decision.
                    let mut decisions = Vec::new();
                    for family in [&service_v4, &service_v6] {
                        if let (Some(source), Some(destination)) =
                            (family.get(&source.id.into_uuid()), family.get(provider))
                        {
                            if let Target::Service {
                                address: Some(address),
                                ..
                            } = &target
                                && destination.address != *address
                            {
                                continue;
                            }
                            for protocol in protocols {
                                let number = if protocol == "tcp" { 6 } else { 17 };
                                if let Target::Service {
                                    protocol: Some(selected),
                                    ..
                                } = &target
                                    && *selected != number
                                {
                                    continue;
                                }
                                decisions.push(policy.decide_initiation(
                                    source,
                                    destination,
                                    if protocol == "tcp" {
                                        IpProtocol::TCP
                                    } else {
                                        IpProtocol::UDP
                                    },
                                    u16::try_from(*port).ok(),
                                ));
                            }
                        }
                    }
                    if decisions.is_empty() {
                        cell.unknown_sources += 1;
                        continue;
                    }
                    let allowed = decisions
                        .iter()
                        .filter(|d| d.action == PolicyAction::Allow)
                        .count();
                    let reasons = if *paused {
                        vec!["resource_paused".into()]
                    } else if !admitted {
                        vec!["device_conditions_restricted".into()]
                    } else if state != "enabled" {
                        vec!["service_disabled".into()]
                    } else {
                        vec![]
                    };
                    (
                        admitted && !*paused && state == "enabled" && allowed == decisions.len(),
                        decisions
                            .iter()
                            .filter_map(|d| d.rule_id.map(RuleId::into_uuid))
                            .collect::<Vec<_>>(),
                        reasons,
                        admitted
                            && !*paused
                            && state == "enabled"
                            && allowed > 0
                            && allowed < decisions.len(),
                    )
                } else if let Target::Network {
                    id,
                    address: Some(address),
                    provider: Some(provider),
                    protocol: Some(protocol),
                    port,
                } = &target
                {
                    let (allowed, matched, reasons) = console_resource_decision(
                        &configuration,
                        &configuration.rules,
                        source,
                        *id,
                        *address,
                        *provider,
                        *protocol,
                        *port,
                        now,
                    );
                    (allowed, matched.into_iter().collect(), reasons, false)
                } else {
                    unreachable!()
                };
            if allowed {
                cell.allowed_sources += 1;
            }
            partial |= mixed;
            cell.matched_rules.extend(matched);
            cell.reasons.extend(reasons);
        }
        cell.outcome = if source_ids.is_empty() {
            cell.reasons.push("empty_source".into());
            "unknown"
        } else if cell.unknown_sources > 0 {
            "unknown"
        } else if partial || (cell.allowed_sources > 0 && cell.allowed_sources < cell.sources) {
            "partial"
        } else if cell.allowed_sources == cell.sources {
            "allowed"
        } else {
            "denied"
        }
        .into();
        cell.matched_rules.sort();
        cell.matched_rules.dedup();
        cell.reasons.sort();
        cell.reasons.dedup();
        cells.push(cell);
    }
    tx.rollback().await?;
    Ok(Json(peerward_api::ConsoleMatrix {
        observed_at: now,
        cells,
    }))
}

async fn console_descriptors(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    mesh: Uuid,
    ids: &[Uuid],
    family: Option<i32>,
) -> Result<BTreeMap<Uuid, PeerDescriptor>, ApiError> {
    let rows:Vec<(Uuid,Option<String>,Value)>=sqlx::query_as("SELECT p.id,a.address,p.labels FROM peers p JOIN meshes m ON m.id=p.mesh_id
        LEFT JOIN LATERAL (SELECT host(address) AS address FROM peer_addresses WHERE mesh_id=p.mesh_id AND peer_id=p.id AND state='active' AND ($3::integer IS NULL OR family(address)=$3)
        ORDER BY (family(address)<>family(m.address_cidr)),address LIMIT 1) a ON true WHERE p.mesh_id=$1 AND p.id=ANY($2) AND p.administrative_state='enabled'")
        .bind(mesh).bind(ids).bind(family).fetch_all(&mut **tx).await?;
    let mut result = BTreeMap::new();
    for (id, address, labels) in rows {
        if let Some(address) = address {
            result.insert(
                id,
                PeerDescriptor {
                    id: peer_id(id)?,
                    address: address.parse().map_err(|_| publisher_error())?,
                    labels: serde_json::from_value(labels).map_err(|_| publisher_error())?,
                },
            );
        }
    }
    Ok(result)
}

#[allow(clippy::too_many_arguments)]
fn console_resource_decision(
    configuration: &peerward_management::ResourceConfiguration,
    rules: &[peerward_management::ResourceRule],
    source: &PeerDescriptor,
    resource_id: Uuid,
    address: std::net::IpAddr,
    provider: PeerId,
    protocol: u8,
    port: Option<u16>,
    now: u64,
) -> (bool, Option<Uuid>, Vec<String>) {
    let exit = configuration
        .resources
        .iter()
        .find(|r| r.id == resource_id)
        .filter(|r| {
            matches!(
                r.definition.target,
                peerward_management::ResourceTarget::Internet { .. }
            )
        })
        .map(|r| r.id);
    let aliases =
        peerward_management::packet_resource_aliases(&configuration.resources, address, exit);
    let approved = configuration
        .bindings
        .iter()
        .any(|b| aliases.contains(&b.resource_id) && b.peer_id == provider && b.approved);
    let (action, matched, _) = peerward_management::decide_resource_aliases(
        rules,
        &configuration.collections,
        &aliases,
        &configuration.bindings,
        &peerward_management::ResourceAccess {
            source_peer: source.id,
            source_address: source.address,
            source_labels: &source.labels,
            resource: resource_id,
            provider,
            protocol,
            destination_port: port,
            now,
        },
    );
    let shadowed = configuration.withdrawals.iter().any(|w| {
        matches!(w.target, peerward_management::ResourceTarget::Subnet { .. })
            && w.target.contains(address)
            && configuration
                .resources
                .iter()
                .filter(|r| aliases.contains(&r.id))
                .all(|r| w.target.specificity() >= r.definition.target.specificity())
    });
    let admitted = configuration.admission.permits(source.id, now)
        && configuration.admission.permits(provider, now);
    let mut reasons = vec![];
    if !approved {
        reasons.push("provider_not_approved".into());
    }
    if shadowed {
        reasons.push("resource_path_withdrawn".into());
    }
    if !aliases.contains(&resource_id) {
        reasons.push("more_specific_resource_selected".into());
    }
    if aliases.len() > 1 {
        reasons.push("equal_prefix_aliases_share_policy_order".into());
    }
    if !admitted {
        reasons.push("device_conditions_restricted".into());
    }
    (
        admitted && approved && !shadowed && action == peerward_management::ResourceAction::Allow,
        matched,
        reasons,
    )
}
