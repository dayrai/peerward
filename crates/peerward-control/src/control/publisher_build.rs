async fn publish_mesh_state(
    store: &Store,
    mesh_id: MeshId,
    issuer: &JoinIssuer,
) -> Result<usize, ApiError> {
    issue_pending_peer_rotations(store, mesh_id, issuer).await?;
    refresh_console_service_policy(store, mesh_id.into_uuid()).await?;
    let mut transaction = store.pool().begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *transaction)
        .await?;
    let lock_key = format!("peerward.publisher.{mesh_id}");
    let elected: bool =
        sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(hashtextextended($1,0))")
            .bind(lock_key)
            .fetch_one(&mut *transaction)
            .await?;
    if !elected {
        transaction.commit().await?;
        return Ok(0);
    }
    let revisions = sqlx::query(
        "SELECT m.authority_revision,m.directory_revision,m.relay_revision,m.policy_revision,
                m.service_revision,m.revocation_revision FROM meshes m JOIN mesh_authorities a
          ON a.mesh_id=m.id AND a.id=$2 AND a.lifecycle='active'
          AND a.not_before<=clock_timestamp() AND a.not_after>clock_timestamp()
          WHERE m.id=$1 AND m.lifecycle IN ('creating','active')",
    )
    .bind(mesh_id.into_uuid())
    .bind(issuer.authority_id)
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or_else(ApiError::not_found)?;
    let authority_revision = revision(&revisions, "authority_revision")?;
    let directory_revision = revision(&revisions, "directory_revision")?;
    let relay_revision = revision(&revisions, "relay_revision")?;
    let policy_revision = revision(&revisions, "policy_revision")?;
    let service_revision = revision(&revisions, "service_revision")?;
    let revocation_revision = revision(&revisions, "revocation_revision")?;

    let latest = sqlx::query(
        "SELECT DISTINCT ON (kind) kind,revision FROM signed_state_revisions
         WHERE mesh_id=$1 ORDER BY kind,revision DESC",
    )
    .bind(mesh_id.into_uuid())
    .fetch_all(&mut *transaction)
    .await?;
    let latest = latest
        .into_iter()
        .map(|row| {
            let kind = row.try_get::<String, _>("kind")?;
            let revision =
                u64::try_from(row.try_get::<i64, _>("revision")?).map_err(|_| publisher_error())?;
            Ok((kind, revision))
        })
        .collect::<Result<HashMap<_, _>, ApiError>>()?;
    let changed = |kind: &str, revision: u64| latest.get(kind) != Some(&revision);
    let authorities_changed = changed("authorities", authority_revision);
    let peers_changed = changed("peers", directory_revision);
    let relays_changed = changed("relays", relay_revision);
    let policy_changed = changed("policy", policy_revision);
    let services_changed = changed("services", service_revision);
    let revocations_changed = changed("revocations", revocation_revision);
    let previous_topology = sqlx::query(
        "SELECT revision,body,published_at FROM signed_state_revisions
         WHERE mesh_id=$1 AND kind='relay_topology' ORDER BY revision DESC LIMIT 1",
    )
    .bind(mesh_id.into_uuid())
    .fetch_optional(&mut *transaction)
    .await?;
    let topology_rows = sqlx::query(
        "SELECT r.id,r.region,r.routing_weight,runtime.wire_capabilities,
                runtime.neighbor_health
         FROM relays r
         JOIN relay_runtime_leases runtime ON runtime.mesh_id=r.mesh_id
           AND runtime.relay_id=r.id AND runtime.lease_deadline>clock_timestamp()
         JOIN relay_credentials c ON c.mesh_id=r.mesh_id AND c.relay_id=r.id
           AND c.lifecycle='active' AND c.not_before<=clock_timestamp()
           AND c.not_after>clock_timestamp()
         JOIN mesh_authorities authority ON authority.mesh_id=c.mesh_id
           AND authority.id=c.authority_id AND authority.lifecycle IN ('active','overlap')
           AND (authority.lifecycle='active' OR authority.overlap_deadline>clock_timestamp())
         WHERE r.mesh_id=$1 AND r.administrative_state='enabled'
         AND NOT EXISTS(SELECT 1 FROM relay_host_assignments a WHERE a.mesh_id=r.mesh_id AND a.relay_id=r.id AND a.desired='suspended') ORDER BY r.id",
    )
    .bind(mesh_id.into_uuid())
    .fetch_all(&mut *transaction)
    .await?;
    let mut topology_nodes = Vec::with_capacity(topology_rows.len());
    let mut health_samples = BTreeMap::<(RelayId, RelayId), Vec<(u32, u16)>>::new();
    for row in topology_rows {
        let relay_id = RelayId::from_uuid(row.try_get("id")?).map_err(|_| publisher_error())?;
        let health =
            serde_json::from_value::<Vec<RelayNeighborHealth>>(row.try_get("neighbor_health")?)
                .map_err(|_| publisher_error())?;
        for sample in health {
            let key = if relay_id < sample.relay_id {
                (relay_id, sample.relay_id)
            } else {
                (sample.relay_id, relay_id)
            };
            health_samples
                .entry(key)
                .or_default()
                .push((sample.rtt_millis, sample.loss_permyriad));
        }
        topology_nodes.push(RelayTopologyNodeV1 {
            relay_id,
            region: row.try_get("region")?,
            routing_weight: u16::try_from(row.try_get::<i32, _>("routing_weight")?)
                .map_err(|_| publisher_error())?,
            capabilities: u64::try_from(row.try_get::<i64, _>("wire_capabilities")?)
                .map_err(|_| publisher_error())?,
        });
    }
    let edge_health = health_samples
        .into_iter()
        .map(|(edge, samples)| {
            let count = u64::try_from(samples.len()).map_err(|_| publisher_error())?;
            let rtt = samples.iter().map(|(rtt, _)| u64::from(*rtt)).sum::<u64>() / count;
            let loss = samples
                .iter()
                .map(|(_, loss)| u64::from(*loss))
                .sum::<u64>()
                / count;
            Ok((
                edge,
                (
                    u32::try_from(rtt).map_err(|_| publisher_error())?,
                    u16::try_from(loss).map_err(|_| publisher_error())?,
                ),
            ))
        })
        .collect::<Result<BTreeMap<_, _>, ApiError>>()?;
    let next_topology_revision = previous_topology
        .as_ref()
        .map(|row| u64::try_from(row.try_get::<i64, _>("revision")?).map_err(|_| publisher_error()))
        .transpose()?
        .unwrap_or(0)
        .saturating_add(1);
    let mut topology_candidate = RelayTopologyV1::build(
        mesh_id,
        next_topology_revision,
        topology_nodes,
        8,
        SPARSE_BACKBONE_V1_CAPABILITY,
    )
    .map_err(|_| publisher_error())?;
    topology_candidate
        .apply_link_health(&edge_health)
        .map_err(|_| publisher_error())?;
    let topology_changed = if let Some(row) = &previous_topology {
        let previous = decode_relay_topology(&row.try_get::<Vec<u8>, _>("body")?)
            .map_err(|_| publisher_error())?;
        let published_at: OffsetDateTime = row.try_get("published_at")?;
        relay_topology_publication_due(
            &previous.topology,
            &topology_candidate,
            published_at,
            OffsetDateTime::now_utc(),
        )
    } else {
        true
    };
    if !authorities_changed
        && !peers_changed
        && !relays_changed
        && !policy_changed
        && !services_changed
        && !revocations_changed
        && !topology_changed
    {
        transaction.commit().await?;
        return Ok(0);
    }
    let parent_rows = sqlx::query(
        "SELECT request_id,trace_id,span_id,trace_flags FROM event_outbox
         WHERE mesh_id=$1 AND request_id IS NOT NULL
           AND committed_at>COALESCE((SELECT max(published_at) FROM signed_state_revisions
             WHERE mesh_id=$1),'-infinity'::timestamptz)
         ORDER BY sequence LIMIT 32",
    )
    .bind(mesh_id.into_uuid())
    .fetch_all(&mut *transaction)
    .await?;
    let parent_contexts = parent_rows
        .into_iter()
        .map(publisher_correlation)
        .collect::<Result<Vec<_>, _>>()?;
    let publication_request_id = Uuid::new_v4();
    let publication_span = tracing::info_span!(
        "state.publish",
        request_id = %publication_request_id,
        trace_id = tracing::field::Empty,
        span_id = tracing::field::Empty,
        parent_context_count = parent_contexts.len(),
    );
    if let Some(parent) = parent_contexts.first().copied() {
        let _ = publication_span.set_parent(open_telemetry_parent(parent));
    }
    for parent in &parent_contexts {
        let parent = open_telemetry_parent(*parent);
        publication_span.add_link(parent.span().span_context().clone());
    }
    let fallback_context = if let Some(parent) = parent_contexts.first().copied() {
        CorrelationContext {
            request_id: publication_request_id,
            flags: 0,
            ..parent.child()
        }
    } else {
        let root = CorrelationContext::root(false);
        CorrelationContext {
            request_id: publication_request_id,
            ..root
        }
    };
    let publication_context = correlation_from_span(&publication_span, publication_request_id)
        .unwrap_or(fallback_context);
    publication_span.record("trace_id", hex::encode(publication_context.trace_id));
    publication_span.record("span_id", hex::encode(publication_context.span_id));
    tracing::info!(
        parent: &publication_span,
        parent_context_count = parent_contexts.len(),
        request_id = %publication_context.request_id,
        "Building signed state publication"
    );

    let authority_rows = if authorities_changed {
        sqlx::query(
            "SELECT id,serial,certificate,lifecycle FROM mesh_authorities WHERE mesh_id=$1
             AND (lifecycle='active' OR (lifecycle='overlap' AND overlap_deadline>clock_timestamp()))
             AND not_before<=clock_timestamp() AND not_after>clock_timestamp()
             ORDER BY CASE lifecycle WHEN 'active' THEN 0 ELSE 1 END,serial",
        )
        .bind(mesh_id.into_uuid())
        .fetch_all(&mut *transaction)
        .await?
    } else {
        Vec::new()
    };
    let mut active_authority = None;
    let mut overlap_authorities = Vec::new();
    for row in authority_rows {
        let certificate = AuthorityCertificate::decode(&row.try_get::<Vec<u8>, _>("certificate")?)
            .map_err(|_| publisher_error())?;
        if row.try_get::<String, _>("lifecycle")? == "active" {
            if row.try_get::<Uuid, _>("id")? != issuer.authority_id
                || active_authority.replace(certificate).is_some()
            {
                return Err(publisher_error());
            }
        } else {
            overlap_authorities.push(certificate);
        }
    }
    let active_authority = if authorities_changed {
        Some(active_authority.ok_or_else(publisher_error)?)
    } else {
        None
    };
    overlap_authorities.sort_by_key(|certificate| certificate.serial);
    let revoked_authorities = if authorities_changed {
        sqlx::query_scalar::<_, Uuid>(
            "SELECT serial FROM mesh_authorities WHERE mesh_id=$1 AND lifecycle='revoked'
             ORDER BY serial",
        )
        .bind(mesh_id.into_uuid())
        .fetch_all(&mut *transaction)
        .await?
        .into_iter()
        .map(credential_serial)
        .collect::<Result<Vec<_>, _>>()?
    } else {
        Vec::new()
    };

    let peer_rows = if peers_changed {
        sqlx::query(
        "SELECT p.id,p.name,host(a.address) AS address,host(a.secondary_address) AS secondary_address,p.labels,c.identity_public_key,c.public_key,
           c.serial,c.not_after,
           COALESCE((SELECT jsonb_agg(jsonb_build_object(
               'serial',accepted.serial,
               'identity_public_key',encode(accepted.identity_public_key,'hex'),
               'noise_public_key',encode(accepted.public_key,'hex'),
               'wireguard_public_key',encode(accepted.wireguard_public_key,'hex'),
               'not_before',floor(extract(epoch FROM accepted.not_before))::bigint,
               'not_after',floor(extract(epoch FROM accepted.not_after))::bigint,
               'overlap_until',CASE WHEN accepted.lifecycle='overlap'
                 THEN floor(extract(epoch FROM LEAST(accepted.overlap_deadline,aa.overlap_deadline,accepted.not_after)))::bigint END,
               'signature',encode(accepted.signature,'hex')) ORDER BY accepted.serial)
             FROM peer_credentials accepted
             JOIN mesh_authorities aa ON aa.mesh_id=accepted.mesh_id
               AND aa.id=accepted.authority_id AND aa.lifecycle IN ('active','overlap')
               AND aa.not_before<=clock_timestamp() AND aa.not_after>clock_timestamp()
               AND (aa.lifecycle='active' OR aa.overlap_deadline>clock_timestamp())
             WHERE accepted.mesh_id=p.mesh_id AND accepted.peer_id=p.id
               AND accepted.wireguard_public_key IS NOT NULL
               AND accepted.lifecycle IN ('active','overlap')
               AND (accepted.lifecycle='active' OR accepted.overlap_deadline>clock_timestamp())
               AND accepted.not_before<=clock_timestamp() AND accepted.not_after>clock_timestamp()),'[]'::jsonb) AS accepted_bindings
         FROM peers p
         JOIN LATERAL (SELECT address, (SELECT second.address FROM peer_addresses second WHERE second.mesh_id=p.mesh_id AND second.peer_id=p.id AND second.state='active' AND family(second.address)<>family(first.address)) AS secondary_address FROM peer_addresses first JOIN meshes m ON m.id=first.mesh_id WHERE first.mesh_id=p.mesh_id AND first.peer_id=p.id AND first.state='active' AND family(first.address)=family(m.address_cidr)) a ON true
         JOIN peer_credentials c ON c.mesh_id=p.mesh_id AND c.peer_id=p.id
              AND c.wireguard_public_key IS NOT NULL
              AND c.lifecycle='active' AND c.not_before<=clock_timestamp()
              AND c.not_after>clock_timestamp()
         JOIN mesh_authorities ma ON ma.mesh_id=c.mesh_id AND ma.id=c.authority_id
              AND ma.lifecycle IN ('active','overlap')
              AND (ma.lifecycle='active' OR ma.overlap_deadline>clock_timestamp())
         WHERE p.mesh_id=$1 AND p.administrative_state='enabled' ORDER BY p.id",
    )
    .bind(mesh_id.into_uuid())
    .fetch_all(&mut *transaction)
    .await?
    } else {
        Vec::new()
    };
    let peers = peer_rows
        .into_iter()
        .map(|row| publisher_peer(row, mesh_id, issuer))
        .collect::<Result<Vec<_>, _>>()?;

    let relay_rows = if relays_changed {
        sqlx::query(
            "SELECT r.id,r.peer_endpoints,r.backbone_endpoints,c.public_key,c.serial
         FROM relays r JOIN relay_credentials c
           ON c.mesh_id=r.mesh_id AND c.relay_id=r.id AND c.lifecycle='active'
          AND c.not_before<=clock_timestamp() AND c.not_after>clock_timestamp()
         JOIN mesh_authorities ma ON ma.mesh_id=c.mesh_id AND ma.id=c.authority_id
          AND ma.lifecycle IN ('active','overlap')
          AND (ma.lifecycle='active' OR ma.overlap_deadline>clock_timestamp())
         WHERE r.mesh_id=$1 AND r.administrative_state='enabled'
         AND NOT EXISTS(SELECT 1 FROM relay_host_assignments a WHERE a.mesh_id=r.mesh_id AND a.relay_id=r.id AND a.desired='suspended') ORDER BY r.id",
        )
        .bind(mesh_id.into_uuid())
        .fetch_all(&mut *transaction)
        .await?
    } else {
        Vec::new()
    };
    let relays = relay_rows
        .into_iter()
        .map(publisher_relay)
        .collect::<Result<Vec<_>, _>>()?;

    let policy_document: Vec<u8> = if policy_changed {
        sqlx::query_scalar(
            "SELECT document FROM policies WHERE mesh_id=$1 AND revision=$2 AND current",
        )
        .bind(mesh_id.into_uuid())
        .bind(i64::try_from(policy_revision).map_err(|_| publisher_error())?)
        .fetch_one(&mut *transaction)
        .await?
    } else {
        Vec::new()
    };

    let service_rows = if services_changed {
        sqlx::query(
        "SELECT s.id,s.peer_id,s.protocols,s.listen_port,s.alias,host(a.address) AS address,c.serial
         FROM services s
         JOIN peers p ON p.mesh_id=s.mesh_id AND p.id=s.peer_id
              AND p.administrative_state='enabled'
         JOIN peer_addresses a ON a.mesh_id=s.mesh_id AND a.peer_id=s.peer_id AND a.state='active' AND family(a.address)=(SELECT family(address_cidr) FROM meshes WHERE id=s.mesh_id)
         JOIN peer_credentials c ON c.mesh_id=s.mesh_id AND c.peer_id=s.peer_id
              AND c.wireguard_public_key IS NOT NULL
              AND c.lifecycle='active' AND c.not_before<=clock_timestamp()
              AND c.not_after>clock_timestamp()
         JOIN mesh_authorities ma ON ma.mesh_id=c.mesh_id AND ma.id=c.authority_id
              AND ma.lifecycle IN ('active','overlap')
              AND (ma.lifecycle='active' OR ma.overlap_deadline>clock_timestamp())
         WHERE s.mesh_id=$1 AND s.state='enabled' AND NOT s.console_paused ORDER BY s.id",
    )
    .bind(mesh_id.into_uuid())
    .fetch_all(&mut *transaction)
    .await?
    } else {
        Vec::new()
    };
    let services = service_rows
        .into_iter()
        .map(publisher_service)
        .collect::<Result<Vec<_>, _>>()?;

    let revoked_rows = if revocations_changed {
        sqlx::query(
            "SELECT serial FROM mesh_authorities WHERE mesh_id=$1 AND lifecycle='revoked'
         UNION SELECT serial FROM peer_credentials WHERE mesh_id=$1 AND lifecycle='revoked'
         UNION SELECT serial FROM relay_credentials WHERE mesh_id=$1 AND lifecycle='revoked'
         UNION SELECT c.serial FROM peer_credentials c JOIN mesh_authorities a
           ON a.mesh_id=c.mesh_id AND a.id=c.authority_id
           WHERE c.mesh_id=$1 AND a.lifecycle='revoked'
         UNION SELECT c.serial FROM relay_credentials c JOIN mesh_authorities a
           ON a.mesh_id=c.mesh_id AND a.id=c.authority_id
           WHERE c.mesh_id=$1 AND a.lifecycle='revoked'
         ORDER BY serial",
        )
        .bind(mesh_id.into_uuid())
        .fetch_all(&mut *transaction)
        .await?
    } else {
        Vec::new()
    };
    let revoked = revoked_rows
        .into_iter()
        .map(|row| credential_serial(row.try_get("serial")?))
        .collect::<Result<Vec<_>, ApiError>>()?;
    let mut states = Vec::new();
    if authorities_changed {
        let authorities = issuer
            .authority
            .sign_authority_bundle(
                mesh_id,
                authority_revision,
                active_authority.ok_or_else(publisher_error)?,
                overlap_authorities,
                revoked_authorities,
            )
            .map_err(|_| publisher_error())?;
        states.push((
            SignedStateKind::Authorities,
            authority_revision,
            authorities.encode().map_err(|_| publisher_error())?,
        ));
    }
    if peers_changed {
        let peers = issuer
            .directory
            .sign_peers(mesh_id, directory_revision, peers)
            .map_err(|_| publisher_error())?;
        states.push((
            SignedStateKind::Peers,
            directory_revision,
            encode_peer_directory(&peers).map_err(|_| publisher_error())?,
        ));
    }
    if relays_changed {
        let relays = issuer
            .directory
            .sign_relays(mesh_id, relay_revision, relays)
            .map_err(|_| publisher_error())?;
        states.push((
            SignedStateKind::Relays,
            relay_revision,
            encode_relay_directory(&relays).map_err(|_| publisher_error())?,
        ));
    }
    if topology_changed {
        let topology = issuer
            .directory
            .sign_relay_topology(topology_candidate)
            .map_err(|_| publisher_error())?;
        states.push((
            SignedStateKind::RelayTopology,
            topology.topology.revision,
            encode_relay_topology(&topology).map_err(|_| publisher_error())?,
        ));
    }
    if policy_changed {
        let policy = issuer
            .directory
            .sign_policy(mesh_id, policy_revision, policy_document);
        states.push((
            SignedStateKind::Policy,
            policy_revision,
            encode_policy(&policy).map_err(|_| publisher_error())?,
        ));
    }
    if services_changed {
        let services = issuer
            .services
            .sign(RemoteServiceSnapshot {
                mesh_id,
                revision: service_revision,
                services,
            })
            .map_err(|_| publisher_error())?;
        states.push((
            SignedStateKind::Services,
            service_revision,
            serde_json::to_vec(&services).map_err(|_| publisher_error())?,
        ));
    }
    if revocations_changed {
        let revocations = issuer
            .directory
            .sign_revocations(mesh_id, revocation_revision, revoked)
            .map_err(|_| publisher_error())?;
        states.push((
            SignedStateKind::Revocations,
            revocation_revision,
            encode_revocations(&revocations).map_err(|_| publisher_error())?,
        ));
    }
    let published = store
        .publish_signed_states_with_context(mesh_id, &states, Some(publication_context))
        .await
        .map_err(ApiError::from)?;
    transaction.commit().await?;
    Ok(published)
}

include!("publisher_rows.rs");
