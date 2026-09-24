/// Derive runtime-only rules without rewriting the administrator's ordered policy.
async fn effective_console_policy(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    mesh: Uuid,
    body: &PolicyPutRequest,
) -> Result<PolicyPutRequest, ApiError> {
    let mut effective = body.clone();
    let services:Vec<(Uuid,Uuid,i32,Vec<String>,bool)>=sqlx::query_as(
        "SELECT id,peer_id,listen_port,protocols,console_paused FROM services WHERE mesh_id=$1 AND state='enabled' ORDER BY id")
        .bind(mesh).fetch_all(&mut **tx).await?;
    let grants:Vec<(Uuid,Uuid,Value,Vec<Uuid>,i64)>=sqlx::query_as(
        "SELECT id,service_id,source,source_collections,priority FROM console_service_grants WHERE mesh_id=$1 AND enabled ORDER BY id")
        .bind(mesh).fetch_all(&mut **tx).await?;
    let collections = if grants.iter().any(|g| !g.3.is_empty()) {
        resolve_network_collections(tx, mesh).await?
    } else {
        vec![]
    };
    for (service, peer, port, protocols, paused) in services {
        for transport in protocols {
            let protocol = if transport == "tcp" {
                peerward_types::PolicyProtocol::Tcp
            } else {
                peerward_types::PolicyProtocol::Udp
            };
            if paused {
                effective.rules.push(console_service_rule(
                    service,
                    peer,
                    port,
                    protocol,
                    0,
                    "deny",
                    peerward_api::PolicySelectorRequest::default(),
                    b"pause",
                )?);
            }
            for (id, target, source, groups, priority) in grants.iter().filter(|g| g.1 == service) {
                let _ = target;
                let source: peerward_management::DeviceSelector =
                    serde_json::from_value(source.clone()).map_err(|_| publisher_error())?;
                let mut peers = source.peers.iter().copied().collect::<Vec<_>>();
                if !groups.is_empty() {
                    let members: std::collections::BTreeSet<Uuid> = collections
                        .iter()
                        .filter(|c| {
                            c.kind == peerward_management::CollectionKind::Devices
                                && groups.contains(&c.id)
                        })
                        .flat_map(|c| c.members.iter().copied())
                        .collect();
                    if members.is_empty() {
                        continue;
                    }
                    peers = members
                        .into_iter()
                        .filter_map(|p| PeerId::from_uuid(p).ok())
                        .filter(|p| source.peers.is_empty() || source.peers.contains(p))
                        .collect();
                    if peers.is_empty() {
                        continue;
                    }
                }
                let selector = peerward_api::PolicySelectorRequest {
                    peer_ids: peers,
                    labels: source.labels,
                    cidrs: source.cidrs,
                };
                effective.rules.push(console_service_rule(
                    *id,
                    peer,
                    port,
                    protocol,
                    u32::try_from(*priority).map_err(|_| publisher_error())?,
                    "allow",
                    selector,
                    b"grant",
                )?);
            }
        }
    }
    if !effective.within_limits() {
        return Err(ApiError::invalid(
            "policy_too_large",
            "effective service policy exceeds its bounds",
        ));
    }
    normalize_policy_request(&mut effective);
    Ok(effective)
}

fn console_service_rule(
    id: Uuid,
    peer: Uuid,
    port: i32,
    protocol: peerward_types::PolicyProtocol,
    priority: u32,
    action: &str,
    source: peerward_api::PolicySelectorRequest,
    domain: &[u8],
) -> Result<PolicyRuleRequest, ApiError> {
    let mut digest = Sha256::new();
    digest.update(b"peerward/console-service-rule/v1\0");
    digest.update(domain);
    digest.update(id.as_bytes());
    digest.update(format!("{protocol:?}").as_bytes());
    let mut bytes: [u8; 16] = digest.finalize()[..16]
        .try_into()
        .map_err(|_| publisher_error())?;
    bytes[6] = (bytes[6] & 15) | 64;
    bytes[8] = (bytes[8] & 63) | 128;
    Ok(PolicyRuleRequest {
        id: Uuid::from_bytes(bytes),
        priority,
        action: action.into(),
        enabled: true,
        log: false,
        source,
        destination: peerward_api::PolicySelectorRequest {
            peer_ids: vec![peer_id(peer)?],
            ..Default::default()
        },
        protocol,
        destination_ports: vec![peerward_api::PolicyPortSpan {
            first: u16::try_from(port).map_err(|_| publisher_error())?,
            last: u16::try_from(port).map_err(|_| publisher_error())?,
        }],
    })
}

/// Recompile collection-based grants before taking the publication snapshot.
async fn refresh_console_service_policy(store: &Store, mesh: Uuid) -> Result<(), ApiError> {
    let mut tx = store.begin_mutation().await?;
    let eligible: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM meshes WHERE id=$1 AND lifecycle='active')",
    )
    .bind(mesh)
    .fetch_one(&mut *tx)
    .await?;
    if !eligible {
        tx.rollback().await?;
        return Ok(());
    }
    sqlx::query("SELECT id FROM meshes WHERE id=$1 FOR UPDATE")
        .bind(mesh)
        .fetch_one(&mut *tx)
        .await?;
    let mut raw = load_current_policy_from(&mut *tx, mesh).await?;
    let effective = effective_console_policy(&mut tx, mesh, &raw).await?;
    let stored: Vec<u8> =
        sqlx::query_scalar("SELECT document FROM policies WHERE mesh_id=$1 AND current")
            .bind(mesh)
            .fetch_one(&mut *tx)
            .await?;
    if canonical_policy_document(&effective)? == stored {
        tx.rollback().await?;
    } else {
        raw.revision = raw.revision.checked_add(1).ok_or_else(publisher_error)?;
        stage_peer_policy(&mut tx, mesh, &raw).await?;
        let context = AuthContext {
            actor: "console-policy-publisher".into(),
            role: Role::Admin,
            source: AuthSource::Bearer,
        };
        store
            .commit_mutation(
                tx,
                &mutation(
                    &context,
                    Some(mesh_id(mesh)?),
                    "service.grants_recompile",
                    "policy.updated",
                    "service",
                    None,
                ),
            )
            .await?;
    }
    Ok(())
}

async fn console_policy_for_simulation(
    store: &Store,
    mesh: Uuid,
    raw: &PolicyPutRequest,
) -> Result<PolicyPutRequest, ApiError> {
    let mut tx = store.begin_mutation().await?;
    let result = effective_console_policy(&mut tx, mesh, raw).await?;
    tx.rollback().await?;
    Ok(result)
}
