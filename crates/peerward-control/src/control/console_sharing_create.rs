/// Each request identity derives its binding/grant identities as well as its resource.
/// The preview stages the exact write transaction and rolls it back.
fn console_child_id(parent: Uuid, label: &[u8]) -> Uuid {
    let mut hash = Sha256::new();
    hash.update(b"peerward/console-sharing/v1\0");
    hash.update(parent.as_bytes());
    hash.update(label);
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&hash.finalize()[..16]);
    bytes[6] = (bytes[6] & 15) | 64;
    bytes[8] = (bytes[8] & 63) | 128;
    Uuid::from_bytes(bytes)
}

async fn console_grant_source(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    mesh: Uuid,
    source: &peerward_api::ConsoleGrantSource,
) -> Result<
    (
        peerward_management::DeviceSelector,
        std::collections::BTreeSet<Uuid>,
        u64,
    ),
    ApiError,
> {
    use peerward_api::ConsoleGrantSource;
    let mut selector = peerward_management::DeviceSelector::default();
    let mut groups = std::collections::BTreeSet::new();
    let count = match source {
        ConsoleGrantSource::None => 0,
        ConsoleGrantSource::Peer { id } => {
            sqlx::query("SELECT id FROM peers WHERE mesh_id=$1 AND id=$2 AND administrative_state='enabled' FOR SHARE")
                .bind(mesh).bind(id.into_uuid()).fetch_optional(&mut **tx).await?.ok_or_else(ApiError::not_found)?;
            selector.peers.insert(*id);
            1
        }
        ConsoleGrantSource::Collection { id } => {
            let collections = resolve_network_collections(tx, mesh).await?;
            let group = collections
                .iter()
                .find(|c| c.id == *id && c.kind == peerward_management::CollectionKind::Devices)
                .ok_or_else(ApiError::not_found)?;
            groups.insert(*id);
            group.members.len() as u64
        }
    };
    Ok((selector, groups, count))
}

async fn stage_console_sharing(
    store: &Store,
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    mesh: Uuid,
    version: u64,
    draft: &peerward_api::ConsoleSharingDraft,
) -> Result<peerward_api::ConsoleSharingPreview, ApiError> {
    use peerward_api::{ConsoleGrantSource, ConsoleSharingTarget as Target};
    if draft.request_id.get_version_num() != 4 {
        return Err(ApiError::invalid_id());
    }
    validate_peer_description(&draft.name)?;
    validate_console_reason(&draft.reason)?;
    if draft.name.trim().is_empty() {
        return Err(ApiError::invalid(
            "name_required",
            "a display name is required",
        ));
    }
    sqlx::query("SELECT id FROM peers WHERE mesh_id=$1 AND id=$2 AND administrative_state='enabled' FOR SHARE")
        .bind(mesh).bind(draft.provider.into_uuid()).fetch_optional(&mut **tx).await?.ok_or_else(ApiError::not_found)?;
    let (source, groups, affected) = console_grant_source(tx, mesh, &draft.source).await?;
    let mut overlaps = vec![];
    let mut warnings = vec![
        "submitted_is_not_applied".to_owned(),
        "policy_simulation_is_not_connectivity_evidence".to_owned(),
    ];
    if matches!(draft.source, ConsoleGrantSource::Collection { .. }) && affected == 0 {
        warnings.push("empty_collection_grants_nobody".into());
    }
    if !matches!(draft.source, ConsoleGrantSource::None) {
        warnings.push("existing_rule_order_and_denies_preserved".into());
    }
    match &draft.target {
        Target::Service {
            protocols,
            port,
            alias,
        } => {
            if *port == 0
                || !valid_service_protocols(protocols)
                || alias.as_deref().is_some_and(|a| !valid_dns_label(a))
            {
                return Err(ApiError::invalid(
                    "invalid_service",
                    "invalid service endpoint or DNS label",
                ));
            }
            let transports = protocols
                .iter()
                .map(|p| match p {
                    peerward_types::ServiceProtocol::Tcp => "tcp",
                    peerward_types::ServiceProtocol::Udp => "udp",
                })
                .collect::<Vec<_>>();
            overlaps=sqlx::query_scalar("SELECT COALESCE(NULLIF(display_name,''),alias,id::text) FROM services WHERE mesh_id=$1 AND peer_id=$2 AND listen_port=$3 AND protocols && $4::text[] AND state='enabled' ORDER BY id")
                .bind(mesh).bind(draft.provider.into_uuid()).bind(i32::from(*port)).bind(&transports).fetch_all(&mut **tx).await?;
            sqlx::query("INSERT INTO services(id,mesh_id,peer_id,protocols,listen_port,alias,labels,display_name) VALUES($1,$2,$3,$4,$5,$6,'{}'::jsonb,$7)")
                .bind(draft.request_id).bind(mesh).bind(draft.provider.into_uuid()).bind(transports).bind(i32::from(*port)).bind(alias).bind(&draft.name).execute(&mut **tx).await?;
            if !matches!(draft.source, ConsoleGrantSource::None) {
                sqlx::query("INSERT INTO console_service_grants(mesh_id,id,service_id,source,source_collections) VALUES($1,$2,$3,$4,$5)")
                    .bind(mesh).bind(console_child_id(draft.request_id,b"grant")).bind(draft.request_id).bind(declaration_value(&source)?)
                    .bind(groups.iter().copied().collect::<Vec<_>>()).execute(&mut **tx).await?;
            }
            let mut policy = load_current_policy_from(&mut **tx, mesh).await?;
            policy.revision = policy.revision.checked_add(1).ok_or_else(publisher_error)?;
            stage_peer_policy(tx, mesh, &policy).await?;
            sqlx::query("UPDATE meshes SET service_revision=service_revision+1,directory_revision=directory_revision+1 WHERE id=$1").bind(mesh).execute(&mut **tx).await?;
        }
        Target::Network {
            definition,
            dns_name,
            dns_address,
        } => {
            definition.validate().map_err(management_error)?;
            if definition.name != draft.name {
                return Err(ApiError::invalid(
                    "resource_name",
                    "resource and display names must agree",
                ));
            }
            let old = read_configuration_document(tx, mesh).await?;
            let mut new = old.clone();
            for resource in &old.resources {
                let overlaps_target = match (&definition.target, &resource.definition.target) {
                    (
                        peerward_management::ResourceTarget::Subnet { prefix: a, .. },
                        peerward_management::ResourceTarget::Subnet { prefix: b, .. },
                    ) => a.contains(&b.network()) || b.contains(&a.network()),
                    (
                        peerward_management::ResourceTarget::Internet { ipv4: a, ipv6: b },
                        peerward_management::ResourceTarget::Internet { ipv4: c, ipv6: d },
                    ) => (*a && *c) || (*b && *d),
                    _ => false,
                };
                if overlaps_target {
                    overlaps.push(resource.definition.name.clone());
                }
            }
            new.resources
                .push(peerward_api::NetworkResourceCreateRequest {
                    id: draft.request_id,
                    definition: definition.clone(),
                });
            new.bindings.push(peerward_api::ConfigurationBinding {
                id: console_child_id(draft.request_id, b"binding"),
                resource_id: draft.request_id,
                peer_id: draft.provider,
                priority: 100,
                forwarding: peerward_management::ForwardingMode::Snat,
                return_route_confirmed: false,
                approval: peerward_api::ConfigurationApproval::Manual { approved: true },
            });
            if !matches!(draft.source, ConsoleGrantSource::None) {
                if draft.protocol != 0 {
                    validate_packet_predicate(draft.protocol, draft.port)?;
                } else if draft.port.is_some() {
                    return Err(ApiError::invalid(
                        "invalid_port",
                        "all protocols cannot specify a port",
                    ));
                }
                new.resource_policy
                    .rules
                    .push(peerward_management::ResourceRule {
                        id: console_child_id(draft.request_id, b"grant"),
                        priority: 1000,
                        enabled: true,
                        action: peerward_management::ResourceAction::Allow,
                        source,
                        source_collections: groups,
                        resources: [draft.request_id].into(),
                        resource_collections: std::collections::BTreeSet::new(),
                        providers: std::collections::BTreeSet::new(),
                        protocol: draft.protocol,
                        destination_ports: draft.port.map(|p| vec![(p, p)]).unwrap_or_default(),
                        not_after: None,
                    });
            }
            match (dns_name, dns_address) {
                (Some(name), Some(address)) => {
                    if !definition.target.contains(*address)
                        || !peerward_management::valid_dns_name(name)
                    {
                        return Err(ApiError::invalid(
                            "invalid_dns",
                            "DNS address must belong to this resource",
                        ));
                    }
                    let profile = new
                        .dns_profiles
                        .iter_mut()
                        .find(|p| p.id == mesh)
                        .ok_or_else(publisher_error)?;
                    if profile.records.contains_key(name) {
                        return Err(ApiError::conflict(
                            "dns_exists",
                            "DNS name already configured",
                        ));
                    }
                    profile.records.insert(
                        name.clone(),
                        vec![match address {
                            std::net::IpAddr::V4(a) => peerward_management::DnsRecord::A(*a),
                            std::net::IpAddr::V6(a) => peerward_management::DnsRecord::AAAA(*a),
                        }],
                    );
                }
                (None, None) => {}
                _ => {
                    return Err(ApiError::invalid(
                        "invalid_dns",
                        "provide both DNS name and address",
                    ));
                }
            }
            normalize_configuration(&mut new, mesh)?;
            let failed = stage_configuration(store, tx, mesh, &old, &new).await?;
            if !failed.is_empty() {
                return Err(ApiError::conflict(
                    "policy_tests_failed",
                    "saved assertions failed; review advanced policy tests",
                ));
            }
            warnings.push("gateway_requires_current_forwarding_advertisement".into());
        }
    }
    if !overlaps.is_empty() {
        warnings.push("overlapping_targets_share_packet_policy".into());
    }
    let digest = declaration_digest(&(version, draft, affected, &overlaps, &warnings))?;
    Ok(peerward_api::ConsoleSharingPreview {
        version,
        digest,
        resource_id: draft.request_id,
        affected_sources: affected,
        overlapping_resources: overlaps,
        warnings,
        applied: false,
    })
}

async fn preview_console_sharing(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(mesh): Path<Uuid>,
    ApiJson(draft): ApiJson<peerward_api::ConsoleSharingDraft>,
) -> Result<Json<peerward_api::ConsoleSharingPreview>, ApiError> {
    authorize(&context, &headers, Capability::ResourceWrite, true)?;
    let mut tx = state.store.begin_mutation().await?;
    let version = lock_configuration(&mut tx, mesh).await?;
    assert_configuration_owner(&mut tx, mesh, &context.actor).await?;
    let result = stage_console_sharing(&state.store, &mut tx, mesh, version, &draft).await?;
    tx.rollback().await?;
    Ok(Json(result))
}

async fn apply_console_sharing(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(mesh): Path<Uuid>,
    ApiJson(body): ApiJson<peerward_api::ConsoleSharingApply>,
) -> Result<Json<peerward_api::ConsoleSharingPreview>, ApiError> {
    authorize(&context, &headers, Capability::ResourceWrite, true)?;
    let expected = require_if_match(&headers)?;
    let digest = declaration_digest(&(expected, &body))?;
    let mut tx = state.store.begin_mutation().await?;
    let version = lock_configuration(&mut tx, mesh).await?;
    assert_configuration_owner(&mut tx, mesh, &context.actor).await?;
    let prior:Option<(String,String,Value)>=sqlx::query_as("SELECT actor,digest,response FROM console_sharing_requests WHERE mesh_id=$1 AND request_id=$2")
        .bind(mesh).bind(body.draft.request_id).fetch_optional(&mut *tx).await?;
    if let Some((actor, known, response)) = prior {
        if actor != context.actor || digest != known {
            return Err(ApiError::conflict(
                "request_reused",
                "request identity is bound to different content or authority",
            ));
        }
        tx.rollback().await?;
        return Ok(Json(
            serde_json::from_value(response).map_err(|_| publisher_error())?,
        ));
    }
    check_configuration_version(version, expected)?;
    let mut preview =
        stage_console_sharing(&state.store, &mut tx, mesh, version, &body.draft).await?;
    if preview.digest != body.preview_digest {
        return Err(ApiError::conflict(
            "preview_changed",
            "dependencies changed; review again",
        ));
    }
    bump_management(&mut tx, mesh).await?;
    preview.applied = true;
    sqlx::query("INSERT INTO console_sharing_requests(mesh_id,request_id,actor,digest,response) VALUES($1,$2,$3,$4,$5)")
        .bind(mesh).bind(body.draft.request_id).bind(&context.actor).bind(digest).bind(declaration_value(&preview)?).execute(&mut *tx).await?;
    let mut record = mutation(
        &context,
        Some(mesh_id(mesh)?),
        "sharing.create",
        "sharing.created",
        "sharing",
        Some(preview.resource_id),
    );
    record.metadata = json!({"reason":body.draft.reason,"affected_sources":preview.affected_sources,"overlapping_resources":preview.overlapping_resources,"warnings":preview.warnings});
    state.store.commit_mutation(tx, &record).await?;
    Ok(Json(preview))
}
