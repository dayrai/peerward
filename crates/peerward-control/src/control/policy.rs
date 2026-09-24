async fn get_policy(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    Path(mesh): Path<Uuid>,
) -> Result<Json<PolicyPutRequest>, ApiError> {
    authorize(&context, &HeaderMap::new(), Capability::ResourceRead, false)?;
    mesh_id(mesh)?;
    let policy: Option<Value> = sqlx::query_scalar(
        "SELECT jsonb_build_object('revision',revision,'default_action',default_action,
          'rules',COALESCE((SELECT jsonb_agg(jsonb_build_object('id',r.id,'priority',r.priority,
          'action',r.action,'enabled',r.enabled,'log',r.audit_log,
          'source',jsonb_build_object(
            'peer_ids',COALESCE((SELECT jsonb_agg(p.peer_id ORDER BY p.peer_id)
              FROM policy_rule_peers p WHERE p.mesh_id=r.mesh_id AND p.policy_revision=r.policy_revision
              AND p.rule_id=r.id AND p.direction='source'),'[]'::jsonb),
            'labels',r.source_labels,'cidrs',to_jsonb(r.source_cidrs)),
          'destination',jsonb_build_object(
            'peer_ids',COALESCE((SELECT jsonb_agg(p.peer_id ORDER BY p.peer_id)
              FROM policy_rule_peers p WHERE p.mesh_id=r.mesh_id AND p.policy_revision=r.policy_revision
              AND p.rule_id=r.id AND p.direction='destination'),'[]'::jsonb),
            'labels',r.destination_labels,'cidrs',to_jsonb(r.destination_cidrs)),
          'protocol',r.protocol,
          'destination_ports',COALESCE((SELECT jsonb_agg(jsonb_build_object(
            'first',lower(span),'last',upper(span)-1) ORDER BY lower(span),upper(span))
            FROM unnest(r.destination_port_ranges) span),'[]'::jsonb))
          ORDER BY r.priority,CASE r.action WHEN 'deny' THEN 0 ELSE 1 END,r.id) FROM policy_rules r
          WHERE r.mesh_id=p.mesh_id AND r.policy_revision=p.revision),'[]'::jsonb))
         FROM policies p WHERE mesh_id=$1 AND current",
    )
    .bind(mesh)
    .fetch_optional(state.store.pool())
    .await?;
    let policy = serde_json::from_value(policy.ok_or_else(ApiError::not_found)?)
        .map_err(|_| ApiError::internal("policy_projection", "Policy projection is invalid"))?;
    Ok(Json(policy))
}

async fn simulate_policy(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    Path(mesh): Path<Uuid>,
    ApiJson(body): ApiJson<PolicySimulationRequest>,
) -> Result<Json<PolicySimulationResponse>, ApiError> {
    authorize(&context, &HeaderMap::new(), Capability::ResourceRead, false)?;
    if body.draft_policy.is_some() {
        authorize(
            &context,
            &HeaderMap::new(),
            Capability::ResourceWrite,
            false,
        )?;
    }
    mesh_id(mesh)?;
    let policy_request = match body.draft_policy {
        Some(policy) => policy,
        None => load_current_policy(&state.store, mesh).await?,
    };
    if !policy_request.within_limits() {
        return Err(ApiError::invalid(
            "policy_too_large",
            "policy exceeds a collection limit",
        ));
    }
    let effective = console_policy_for_simulation(&state.store, mesh, &policy_request).await?;
    let policy = canonical_policy(&effective)?;
    let canonical = encode_policy_document(&policy)
        .map_err(|_| ApiError::invalid("invalid_policy", "policy is not canonical"))?;
    let source_id = body.source_peer_id.into_uuid();
    let service_id = body.target_service_id.into_uuid();
    let service: (Uuid, i32, Vec<String>) = sqlx::query_as(
        "SELECT peer_id,listen_port,protocols FROM services WHERE mesh_id=$1 AND id=$2 AND state='enabled'",
    )
    .bind(mesh)
    .bind(service_id)
    .fetch_optional(state.store.pool())
    .await?
    .ok_or_else(ApiError::not_found)?;
    let requested_protocol = match body.protocol {
        peerward_types::ServiceProtocol::Tcp => ("tcp", IpProtocol::TCP),
        peerward_types::ServiceProtocol::Udp => ("udp", IpProtocol::UDP),
    };
    if !service
        .2
        .iter()
        .any(|protocol| protocol == requested_protocol.0)
    {
        return Err(ApiError::invalid(
            "service_protocol_unavailable",
            "target Service does not publish the requested protocol",
        ));
    }
    let source = load_policy_peer(&state.store, mesh, source_id).await?;
    let destination = load_policy_peer(&state.store, mesh, service.0).await?;
    let decision = policy.decide_initiation(
        &source,
        &destination,
        requested_protocol.1,
        u16::try_from(service.1).ok(),
    );
    let default_action_used = decision.rule_id.is_none();
    let mut warnings = Vec::new();
    if source.id == destination.id {
        warnings.push("source_and_destination_peer_are_equal".into());
    }
    let admitted =
        simulation_device_admitted(&state.store, mesh, &[source.id, destination.id]).await?;
    if !admitted {
        warnings.push("device_conditions_restricted".into());
    }
    Ok(Json(PolicySimulationResponse {
        allowed: admitted && decision.action == PolicyAction::Allow,
        action: if admitted && decision.action == PolicyAction::Allow {
            "allow"
        } else {
            "deny"
        }
        .into(),
        matched_rule_id: decision.rule_id.map(RuleId::into_uuid),
        default_action_used,
        policy_revision: policy_request.revision,
        canonical_sha256: hex::encode(Sha256::digest(canonical)),
        warnings,
    }))
}

async fn load_policy_peer(
    store: &Store,
    mesh: Uuid,
    peer: Uuid,
) -> Result<PeerDescriptor, ApiError> {
    load_policy_peer_family(store, mesh, peer, None).await
}

async fn load_policy_peer_family(
    store: &Store,
    mesh: Uuid,
    peer: Uuid,
    family: Option<i32>,
) -> Result<PeerDescriptor, ApiError> {
    let row: (Option<String>, Value, String) = sqlx::query_as(
        "SELECT host(address.address),peer.labels,peer.administrative_state::text FROM peers peer JOIN meshes m ON m.id=peer.mesh_id LEFT JOIN peer_addresses address
         ON address.mesh_id=peer.mesh_id AND address.peer_id=peer.id AND address.state='active' AND ($3::integer IS NULL OR family(address.address)=$3)
         WHERE peer.mesh_id=$1 AND peer.id=$2 ORDER BY (family(address.address)<>family(m.address_cidr)),address.address LIMIT 1",
    )
    .bind(mesh)
    .bind(peer)
    .bind(family)
    .fetch_optional(store.pool())
    .await?
    .ok_or_else(ApiError::not_found)?;
    if row.2 != "enabled" {
        return Err(ApiError::conflict(
            "peer_disabled",
            "choose an enabled device for simulation",
        ));
    }
    let address = row.0.ok_or_else(|| {
        ApiError::conflict(
            if family.is_some() {"peer_address_family_unavailable"} else {"peer_not_enrolled"},
            "device has no active address in the requested family; complete enrollment or choose a supported target",
        )
    })?;
    Ok(PeerDescriptor {
        id: peer_id(peer)?,
        address: address
            .parse()
            .map_err(|_| ApiError::internal("peer_address", "Peer address is invalid"))?,
        labels: serde_json::from_value(row.1)
            .map_err(|_| ApiError::internal("peer_labels", "Peer labels are invalid"))?,
    })
}

async fn load_current_policy(store: &Store, mesh: Uuid) -> Result<PolicyPutRequest, ApiError> {
    load_current_policy_from(store.pool(), mesh).await
}

async fn load_current_policy_from<'e, E>(
    executor: E,
    mesh: Uuid,
) -> Result<PolicyPutRequest, ApiError>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    let policy: Option<Value> = sqlx::query_scalar(
        "SELECT jsonb_build_object('revision',revision,'default_action',default_action,
          'rules',COALESCE((SELECT jsonb_agg(jsonb_build_object('id',r.id,'priority',r.priority,
          'action',r.action,'enabled',r.enabled,'log',r.audit_log,
          'source',jsonb_build_object('peer_ids',COALESCE((SELECT jsonb_agg(p.peer_id ORDER BY p.peer_id) FROM policy_rule_peers p WHERE p.mesh_id=r.mesh_id AND p.policy_revision=r.policy_revision AND p.rule_id=r.id AND p.direction='source'),'[]'::jsonb),'labels',r.source_labels,'cidrs',to_jsonb(r.source_cidrs)),
          'destination',jsonb_build_object('peer_ids',COALESCE((SELECT jsonb_agg(p.peer_id ORDER BY p.peer_id) FROM policy_rule_peers p WHERE p.mesh_id=r.mesh_id AND p.policy_revision=r.policy_revision AND p.rule_id=r.id AND p.direction='destination'),'[]'::jsonb),'labels',r.destination_labels,'cidrs',to_jsonb(r.destination_cidrs)),
          'protocol',r.protocol,'destination_ports',COALESCE((SELECT jsonb_agg(jsonb_build_object('first',lower(span),'last',upper(span)-1) ORDER BY lower(span),upper(span)) FROM unnest(r.destination_port_ranges) span),'[]'::jsonb)) ORDER BY r.priority,CASE r.action WHEN 'deny' THEN 0 ELSE 1 END,r.id) FROM policy_rules r WHERE r.mesh_id=p.mesh_id AND r.policy_revision=p.revision),'[]'::jsonb)) FROM policies p WHERE mesh_id=$1 AND current",
    )
    .bind(mesh)
    .fetch_optional(executor)
    .await?;
    serde_json::from_value(policy.ok_or_else(ApiError::not_found)?)
        .map_err(|_| ApiError::internal("policy_projection", "Policy projection is invalid"))
}

async fn validate_policy(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    Path(mesh): Path<Uuid>,
    ApiJson(mut body): ApiJson<PolicyPutRequest>,
) -> Result<Json<PolicyValidationResponse>, ApiError> {
    state
        .metrics
        .policy_validations
        .fetch_add(1, Ordering::Relaxed);
    authorize(
        &context,
        &HeaderMap::new(),
        Capability::ResourceWrite,
        false,
    )?;
    mesh_id(mesh)?;
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM meshes WHERE id=$1)")
        .bind(mesh)
        .fetch_one(state.store.pool())
        .await?;
    if !exists {
        return Err(ApiError::not_found());
    }

    let mut field_errors = BTreeMap::new();
    if !body.within_limits() {
        field_errors.insert(
            "document".to_owned(),
            "policy exceeds a collection limit".to_owned(),
        );
    }
    if !matches!(body.default_action.as_str(), "allow" | "deny") {
        field_errors.insert(
            "default_action".to_owned(),
            "must be allow or deny".to_owned(),
        );
    }
    let mut rule_ids = std::collections::BTreeSet::new();
    for (index, rule) in body.rules.iter().enumerate() {
        if !rule_ids.insert(rule.id) {
            field_errors.insert(
                format!("rules.{index}.id"),
                "rule identifier is duplicated".to_owned(),
            );
        }
        if validate_policy_rule(rule).is_err() {
            field_errors.insert(
                format!("rules.{index}"),
                "rule fields are not canonical or internally consistent".to_owned(),
            );
        }
    }

    let mut warnings = Vec::new();
    if body.default_action == "allow" {
        warnings.push("default_allow_permits_unmatched_initiations".to_owned());
    }
    if body.rules.iter().all(|rule| !rule.enabled) {
        warnings.push("no_enabled_rules".to_owned());
    }
    if !field_errors.is_empty() {
        state
            .metrics
            .policy_validation_failures
            .fetch_add(1, Ordering::Relaxed);
        return Ok(Json(PolicyValidationResponse {
            valid: false,
            normalized: None,
            canonical_sha256: None,
            field_errors,
            warnings,
        }));
    }

    normalize_policy_request(&mut body);
    let Ok(canonical) = canonical_policy_document(&body) else {
        state
            .metrics
            .policy_validation_failures
            .fetch_add(1, Ordering::Relaxed);
        field_errors.insert(
            "document".to_owned(),
            "cannot be represented by the canonical policy compiler".to_owned(),
        );
        return Ok(Json(PolicyValidationResponse {
            valid: false,
            normalized: None,
            canonical_sha256: None,
            field_errors,
            warnings,
        }));
    };
    Ok(Json(PolicyValidationResponse {
        valid: true,
        normalized: Some(body),
        canonical_sha256: Some(hex::encode(Sha256::digest(canonical))),
        field_errors,
        warnings,
    }))
}

fn normalize_policy_request(body: &mut PolicyPutRequest) {
    for rule in &mut body.rules {
        for selector in [&mut rule.source, &mut rule.destination] {
            selector.peer_ids.sort_unstable();
            selector.cidrs.sort_unstable_by_key(ToString::to_string);
        }
        rule.destination_ports
            .sort_unstable_by_key(|span| (span.first, span.last));
    }
    body.rules.sort_unstable_by(|left, right| {
        left.priority
            .cmp(&right.priority)
            .then_with(|| match (left.action.as_str(), right.action.as_str()) {
                ("deny", "allow") => std::cmp::Ordering::Less,
                ("allow", "deny") => std::cmp::Ordering::Greater,
                _ => std::cmp::Ordering::Equal,
            })
            .then_with(|| left.id.as_bytes().cmp(right.id.as_bytes()))
    });
}

async fn put_policy(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(mesh): Path<Uuid>,
    ApiJson(body): ApiJson<PolicyPutRequest>,
) -> Result<Json<PolicyPutRequest>, ApiError> {
    authorize(&context, &headers, Capability::ResourceWrite, true)?;
    let mut transaction = state.store.begin_mutation().await?;
    stage_peer_policy(&mut transaction, mesh, &body).await?;
    state
        .store
        .commit_mutation(
            transaction,
            &mutation(
                &context,
                Some(mesh_id(mesh)?),
                "policy.replace",
                "policy.replaced",
                "policy",
                None,
            ),
        )
        .await?;
    get_policy(Extension(context), State(state), Path(mesh)).await
}

async fn stage_peer_policy(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    mesh: Uuid,
    body: &PolicyPutRequest,
) -> Result<(), ApiError> {
    if !body.within_limits() {
        return Err(ApiError::invalid(
            "policy_too_large",
            "policy exceeds a collection limit",
        ));
    }
    mesh_id(mesh)?;
    let revision = i64::try_from(body.revision)
        .map_err(|_| ApiError::invalid("invalid_revision", "revision too large"))?;
    let effective = effective_console_policy(transaction, mesh, body).await?;
    let document = canonical_policy_document(&effective)?;
    let current: i64 =
        sqlx::query_scalar("SELECT policy_revision FROM meshes WHERE id=$1 FOR UPDATE")
            .bind(mesh)
            .fetch_optional(&mut **transaction)
            .await?
            .ok_or_else(ApiError::not_found)?;
    if revision <= current {
        return Err(ApiError::conflict(
            "revision_rollback",
            "policy revision must increase",
        ));
    }
    sqlx::query("UPDATE policies SET current=false WHERE mesh_id=$1 AND current")
        .bind(mesh)
        .execute(&mut **transaction)
        .await?;
    sqlx::query(
        "INSERT INTO policies(mesh_id,revision,default_action,document,current)
         VALUES($1,$2,$3,$4,true)",
    )
    .bind(mesh)
    .bind(revision)
    .bind(&body.default_action)
    .bind(document)
    .execute(&mut **transaction)
    .await?;
    for rule in &body.rules {
        validate_policy_rule(rule)?;
        sqlx::query(
            "INSERT INTO policy_rules(id,mesh_id,policy_revision,priority,action,
            enabled,audit_log,source_labels,source_cidrs,destination_labels,destination_cidrs,
            protocol,destination_port_ranges)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8,
              ARRAY(SELECT value::cidr FROM unnest($9::text[]) value),$10,
              ARRAY(SELECT value::cidr FROM unnest($11::text[]) value),$12,
              ARRAY(SELECT int8range((span->>'first')::bigint,
                (span->>'last')::bigint + 1, '[)') FROM jsonb_array_elements($13) span))",
        )
        .bind(rule.id)
        .bind(mesh)
        .bind(revision)
        .bind(i32::try_from(rule.priority).unwrap_or(i32::MAX))
        .bind(&rule.action)
        .bind(rule.enabled)
        .bind(rule.log)
        .bind(
            serde_json::to_value(&rule.source.labels)
                .map_err(|_| ApiError::invalid("invalid_labels", "source labels are invalid"))?,
        )
        .bind(
            rule.source
                .cidrs
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
        )
        .bind(
            serde_json::to_value(&rule.destination.labels).map_err(|_| {
                ApiError::invalid("invalid_labels", "destination labels are invalid")
            })?,
        )
        .bind(
            rule.destination
                .cidrs
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
        )
        .bind(policy_protocol_name(rule.protocol))
        .bind(
            serde_json::to_value(&rule.destination_ports).map_err(|_| {
                ApiError::invalid("invalid_policy_ports", "invalid policy port ranges")
            })?,
        )
        .execute(&mut **transaction)
        .await?;
        for (direction, peers) in [
            ("source", &rule.source.peer_ids),
            ("destination", &rule.destination.peer_ids),
        ] {
            for peer_id in peers {
                sqlx::query(
                    "INSERT INTO policy_rule_peers(mesh_id,policy_revision,rule_id,direction,peer_id)
                     VALUES($1,$2,$3,$4,$5)",
                )
                .bind(mesh)
                .bind(revision)
                .bind(rule.id)
                .bind(direction)
                .bind(peer_id.into_uuid())
                .execute(&mut **transaction)
                .await?;
            }
        }
    }
    sqlx::query(
        "UPDATE meshes SET policy_revision=$1,directory_revision=directory_revision+1 WHERE id=$2",
    )
    .bind(revision)
    .bind(mesh)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

fn canonical_policy(body: &PolicyPutRequest) -> Result<Policy, ApiError> {
    let default = match body.default_action.as_str() {
        "allow" => PolicyAction::Allow,
        "deny" => PolicyAction::Deny,
        _ => {
            return Err(ApiError::invalid(
                "invalid_policy",
                "invalid default action",
            ));
        }
    };
    let rules = body
        .rules
        .iter()
        .map(|rule| {
            validate_policy_rule(rule)?;
            let id = RuleId::from_uuid(rule.id).map_err(|_| ApiError::invalid_id())?;
            let source = Selector::new(
                rule.source.peer_ids.iter().copied(),
                rule.source.labels.clone(),
                rule.source.cidrs.clone(),
            );
            let destination = Selector::new(
                rule.destination.peer_ids.iter().copied(),
                rule.destination.labels.clone(),
                rule.destination.cidrs.clone(),
            );
            let ports = rule
                .destination_ports
                .iter()
                .map(|span| {
                    PortRange::new(span.first, span.last).map_err(|_| {
                        ApiError::invalid("invalid_policy_ports", "invalid port range")
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(CanonicalRule {
                id,
                priority: rule.priority,
                enabled: rule.enabled,
                log: rule.log,
                action: match rule.action.as_str() {
                    "allow" => PolicyAction::Allow,
                    "deny" => PolicyAction::Deny,
                    _ => return Err(ApiError::invalid("invalid_policy", "invalid action")),
                },
                source,
                destination,
                protocol: rule.protocol,
                destination_ports: ports,
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    Ok(Policy::new(body.revision, default, rules))
}

fn canonical_policy_document(body: &PolicyPutRequest) -> Result<Vec<u8>, ApiError> {
    encode_policy_document(&canonical_policy(body)?)
        .map_err(|_| ApiError::invalid("invalid_policy", "policy is not canonical"))
}

fn policy_protocol_name(protocol: peerward_types::PolicyProtocol) -> &'static str {
    match protocol {
        peerward_types::PolicyProtocol::Any => "any",
        peerward_types::PolicyProtocol::Tcp => "tcp",
        peerward_types::PolicyProtocol::Udp => "udp",
        peerward_types::PolicyProtocol::Icmp => "icmp",
    }
}
