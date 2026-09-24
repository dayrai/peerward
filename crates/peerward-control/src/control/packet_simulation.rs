async fn simulate_policy_extended(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    Path(mesh): Path<Uuid>,
    ApiJson(body): ApiJson<peerward_api::PolicySimulationInput>,
) -> Result<Json<PolicySimulationResponse>, ApiError> {
    match body {
        peerward_api::PolicySimulationInput::Service(body) => {
            simulate_policy(Extension(context), State(state), Path(mesh), ApiJson(body)).await
        }
        peerward_api::PolicySimulationInput::Packet(body) => {
            authorize(&context, &HeaderMap::new(), Capability::ResourceRead, false)?;
            if body.draft_policy.is_some() || body.draft_resource_rules.is_some() {
                authorize(
                    &context,
                    &HeaderMap::new(),
                    Capability::ResourceWrite,
                    false,
                )?;
            }
            simulate_packet(&state.store, mesh, body).await.map(Json)
        }
    }
}

fn validate_packet_predicate(protocol: u8, port: Option<u16>) -> Result<(), ApiError> {
    if ![1, 6, 17, 58].contains(&protocol)
        || port == Some(0)
        || ([6, 17].contains(&protocol) != port.is_some())
    {
        return Err(ApiError::invalid(
            "invalid_service",
            "TCP/UDP require a destination port; ICMP must not specify one",
        ));
    }
    Ok(())
}

async fn simulate_packet(
    store: &Store,
    mesh: Uuid,
    body: peerward_api::PacketSimulationRequest,
) -> Result<PolicySimulationResponse, ApiError> {
    validate_packet_predicate(body.protocol, body.destination_port)?;
    let family = match &body.target {
        peerward_api::PacketSimulationTarget::Resource { address, .. } => {
            Some(if address.is_ipv4() { 4 } else { 6 })
        }
        peerward_api::PacketSimulationTarget::Peer { .. } => match body.protocol {
            1 => Some(4),
            58 => Some(6),
            _ => None,
        },
    };
    let source =
        load_policy_peer_family(store, mesh, body.source_peer_id.into_uuid(), family).await?;
    match body.target {
        peerward_api::PacketSimulationTarget::Peer {
            peer_id: destination,
        } => {
            if body.draft_resource_rules.is_some() {
                return Err(ApiError::invalid(
                    "invalid_target",
                    "resource rules require a resource target",
                ));
            }
            let document = match body.draft_policy {
                Some(draft) => draft,
                None => load_current_policy(store, mesh).await?,
            };
            if !document.within_limits() {
                return Err(ApiError::invalid(
                    "policy_too_large",
                    "policy exceeds limits",
                ));
            }
            let effective = console_policy_for_simulation(store, mesh, &document).await?;
            let policy = canonical_policy(&effective)?;
            let destination =
                load_policy_peer_family(store, mesh, destination.into_uuid(), family).await?;
            let decision = policy.decide_initiation(
                &source,
                &destination,
                IpProtocol::new(body.protocol),
                body.destination_port,
            );
            let admitted =
                simulation_device_admitted(store, mesh, &[source.id, destination.id]).await?;
            let mut warnings = vec!["policy_simulation_is_not_connectivity_evidence".into()];
            if !admitted {
                warnings.push("device_conditions_restricted".into());
            }
            Ok(PolicySimulationResponse {
                allowed: admitted && decision.action == PolicyAction::Allow,
                action: if admitted && decision.action == PolicyAction::Allow {
                    "allow"
                } else {
                    "deny"
                }
                .into(),
                matched_rule_id: decision.rule_id.map(RuleId::into_uuid),
                default_action_used: decision.rule_id.is_none(),
                policy_revision: document.revision,
                canonical_sha256: hex::encode(Sha256::digest(
                    encode_policy_document(&policy).map_err(|_| publisher_error())?,
                )),
                warnings,
            })
        }
        peerward_api::PacketSimulationTarget::Resource {
            resource_id,
            address,
            provider_peer_id,
        } => {
            if body.draft_policy.is_some() {
                return Err(ApiError::invalid(
                    "invalid_target",
                    "Peer policy does not grant resource access",
                ));
            }
            let resource = load_network_resource(store, mesh, resource_id).await?;
            if !resource.definition.target.contains(address) {
                return Err(ApiError::invalid(
                    "target_address",
                    "address is outside the resource",
                ));
            }
            let document = load_resource_policy(store, mesh, None).await?;
            let rules = body.draft_resource_rules.unwrap_or(document.document.rules);
            if rules.len() > 4096 {
                return Err(ApiError::invalid(
                    "policy_too_large",
                    "policy exceeds limits",
                ));
            }
            let mut transaction = store.begin_mutation().await?;
            let configuration =
                read_resource_configuration(&mut transaction, mesh_id(mesh)?).await?;
            let collections = &configuration.collections;
            transaction.rollback().await?;
            for rule in &rules {
                rule.validate().map_err(management_error)?;
                validate_rule_collections(rule, collections)?;
            }
            let (allowed, matched, mut warnings) = console_resource_decision(
                &configuration,
                &rules,
                &source,
                resource_id,
                address,
                provider_peer_id,
                body.protocol,
                body.destination_port,
                current_unix_seconds(),
            );
            warnings.push("policy_simulation_is_not_connectivity_evidence".into());
            Ok(PolicySimulationResponse {
                allowed,
                action: if allowed { "allow" } else { "deny" }.into(),
                matched_rule_id: matched,
                default_action_used: matched.is_none(),
                policy_revision: document.version,
                canonical_sha256: hex::encode(
                    peerward_management::content_digest(&rules).map_err(management_error)?,
                ),
                warnings,
            })
        }
    }
}

async fn simulation_device_admitted(
    store: &Store,
    mesh: Uuid,
    peers: &[PeerId],
) -> Result<bool, ApiError> {
    let mut tx = store.begin_mutation().await?;
    let admission = read_device_admission(&mut tx, mesh).await?;
    tx.rollback().await?;
    Ok(peers
        .iter()
        .all(|peer| admission.permits(*peer, current_unix_seconds())))
}
