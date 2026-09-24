async fn publish_configuration(
    store: &Store,
    mesh: MeshId,
    issuer: &JoinIssuer,
) -> Result<usize, ApiError> {
    use peerward_management::{
        AuthorizationLease, ComponentReference, ConfigurationDelivery, ConfigurationManifest,
        ConfigurationPart as Part, content_digest,
    };
    let mut tx = store.begin_mutation().await?;
    // Hold authoritative revisions stable through lease commit. A stale publication cannot renew.
    let row=sqlx::query("SELECT authority_revision,directory_revision,policy_revision,revocation_revision,management_revision,lease_seconds
        FROM meshes WHERE id=$1 AND lifecycle IN ('creating','active') FOR UPDATE")
        .bind(mesh.into_uuid()).fetch_optional(&mut *tx).await?.ok_or_else(ApiError::not_found)?;
    let current_authority: Option<Uuid>=sqlx::query_scalar("SELECT id FROM mesh_authorities WHERE mesh_id=$1 AND lifecycle='active' AND not_before<=clock_timestamp() AND not_after>clock_timestamp()")
        .bind(mesh.into_uuid()).fetch_optional(&mut *tx).await?;
    if current_authority != Some(issuer.authority_id) {
        return Err(publisher_error());
    }
    let mut parts = BTreeMap::new();
    for (part, kind, column) in [
        (Part::Authorities, "authorities", "authority_revision"),
        (Part::Peers, "peers", "directory_revision"),
        (Part::Policy, "policy", "policy_revision"),
        (Part::Revocations, "revocations", "revocation_revision"),
    ] {
        let version: i64 = row.try_get(column)?;
        let bytes: Vec<u8> = sqlx::query_scalar(
            "SELECT body FROM signed_state_revisions WHERE mesh_id=$1 AND kind=$2 AND revision=$3",
        )
        .bind(mesh.into_uuid())
        .bind(kind)
        .bind(version)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(publisher_error)?;
        parts.insert(
            part,
            ComponentReference {
                // Existing signed directories legitimately begin at revision zero
                // before the first device joins. Completeness is proved by the digest.
                version: u64::try_from(version).map_err(|_| publisher_error())?,
                digest: Sha256::digest(&bytes).into(),
            },
        );
    }
    let resources = read_resource_configuration(&mut tx, mesh).await?;
    let dns: Vec<peerward_management::DnsProfile> = configuration_rows(
        &mut tx,
        mesh,
        "SELECT profile FROM dns_profiles WHERE mesh_id=$1 ORDER BY id",
    )
    .await?;
    let management = positive_revision(row.try_get("management_revision")?)?;
    parts.insert(
        Part::Resources,
        ComponentReference {
            version: management,
            digest: content_digest(&resources).map_err(management_error)?,
        },
    );
    parts.insert(
        Part::Dns,
        ComponentReference {
            version: management,
            digest: content_digest(&dns).map_err(management_error)?,
        },
    );
    let previous:Option<Vec<u8>>=sqlx::query_scalar("SELECT body FROM signed_state_revisions WHERE mesh_id=$1 AND kind='configuration' ORDER BY revision DESC LIMIT 1")
        .bind(mesh.into_uuid()).fetch_optional(&mut *tx).await?;
    let previous = previous
        .map(|bytes| serde_json::from_slice::<ConfigurationDelivery>(&bytes))
        .transpose()
        .map_err(|_| publisher_error())?;
    // Time-dependent evidence may expire without a database mutation. Never reuse
    // a component version for changed bytes; fence its new signed admission view.
    if previous.as_ref().is_some_and(|old| {
        old.resources != resources
            && old
                .manifest
                .manifest
                .parts
                .get(&Part::Resources)
                .is_some_and(|reference| reference.version == management)
    }) {
        let next:i64=sqlx::query_scalar("UPDATE meshes SET management_revision=management_revision+1 WHERE id=$1 RETURNING management_revision")
            .bind(mesh.into_uuid()).fetch_one(&mut *tx).await?;
        for part in [Part::Resources, Part::Dns] {
            parts.get_mut(&part).ok_or_else(publisher_error)?.version = positive_revision(next)?;
        }
    }
    let now = current_unix_seconds();
    let ttl =
        u64::try_from(row.try_get::<i32, _>("lease_seconds")?).map_err(|_| publisher_error())?;
    let changed = previous
        .as_ref()
        .is_none_or(|previous| previous.manifest.manifest.parts != parts);
    // A device that lost its monotonic lease on restart/suspend reports a signed
    // Core rejection. Coalesce requests for this exact lease into one new lease;
    // stale receipts cannot cause repeated publication or change the intent.
    let refresh = if let Some(previous) = &previous {
        sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM configuration_receipts WHERE mesh_id=$1
             AND category='core' AND result='rejected' AND reason=$2 AND lease_sequence=$3)",
        )
        .bind(mesh.into_uuid())
        .bind(peerward_management::FRESH_AUTHORIZATION_REQUIRED)
        .bind(i64::try_from(previous.lease.lease.sequence).map_err(|_| publisher_error())?)
        .fetch_one(&mut *tx)
        .await?
    } else {
        false
    };
    if !changed
        && !refresh
        && previous.as_ref().is_some_and(|previous| {
            now < previous.lease.lease.renew_at()
                && previous.lease.lease.valid_until - previous.lease.lease.issued_at == ttl
        })
    {
        tx.rollback().await?;
        return Ok(0);
    }
    let version = match &previous {
        Some(previous) if changed => previous
            .manifest
            .manifest
            .version
            .checked_add(1)
            .ok_or_else(publisher_error)?,
        Some(previous) => previous.manifest.manifest.version,
        None => 1,
    };
    let manifest = ConfigurationManifest {
        mesh_id: mesh,
        version,
        parts,
    };
    let sequence = previous
        .as_ref()
        .map_or(Some(1), |previous| {
            previous.lease.lease.sequence.checked_add(1)
        })
        .ok_or_else(publisher_error)?;
    let lease = AuthorizationLease {
        mesh_id: mesh,
        configuration_digest: content_digest(&manifest).map_err(management_error)?,
        sequence,
        issued_at: now,
        valid_until: now.checked_add(ttl).ok_or_else(publisher_error)?,
    };
    let delivery = ConfigurationDelivery {
        manifest: issuer
            .directory
            .sign_manifest(manifest)
            .map_err(management_error)?,
        lease: issuer
            .directory
            .sign_lease(lease)
            .map_err(management_error)?,
        resources,
        dns,
    };
    delivery.validate_payload().map_err(management_error)?;
    let bytes = serde_json::to_vec(&delivery).map_err(|_| publisher_error())?;
    if bytes.len() > peerward_types::MAX_SIGNED_STATE_BYTES {
        return Err(publisher_error());
    }
    sqlx::query("INSERT INTO signed_state_revisions(mesh_id,kind,revision,body) VALUES($1,'configuration',$2,$3)")
        .bind(mesh.into_uuid()).bind(i64::try_from(sequence).map_err(|_| publisher_error())?).bind(bytes).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mesh_authorization_bounds(mesh_id,valid_until) VALUES($1,to_timestamp($2::double precision)) ON CONFLICT(mesh_id) DO UPDATE SET valid_until=GREATEST(mesh_authorization_bounds.valid_until,EXCLUDED.valid_until)")
        .bind(mesh.into_uuid()).bind(i64::try_from(delivery.lease.lease.valid_until).map_err(|_|publisher_error())?).execute(&mut *tx).await?;
    let actor = AuthContext {
        actor: "configuration-publisher".into(),
        role: Role::Admin,
        source: AuthSource::Bearer,
    };
    store
        .commit_mutation(
            tx,
            &mutation(
                &actor,
                Some(mesh),
                "configuration.lease",
                "state.published",
                "signed_state",
                None,
            ),
        )
        .await?;
    Ok(1)
}

async fn configuration_rows<T: DeserializeOwned>(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    mesh: MeshId,
    query: &str,
) -> Result<Vec<T>, ApiError> {
    sqlx::query_scalar::<_, Value>(query)
        .bind(mesh.into_uuid())
        .fetch_all(&mut **tx)
        .await?
        .into_iter()
        .map(|value| serde_json::from_value(value).map_err(|_| publisher_error()))
        .collect()
}

async fn read_resource_configuration(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    mesh: MeshId,
) -> Result<peerward_management::ResourceConfiguration, ApiError> {
    use peerward_management::ResourceConfiguration;
    let collections = resolve_network_collections(tx, mesh.into_uuid()).await?;
    Ok(ResourceConfiguration {
        admission: read_device_admission(tx, mesh.into_uuid()).await?,
        collections,
        withdrawals: configuration_rows(tx,mesh,"SELECT jsonb_build_object('target',target,'providers',providers) FROM resource_withdrawals WHERE mesh_id=$1 UNION SELECT jsonb_build_object('target',r.definition->'target','providers',COALESCE((SELECT jsonb_agg(b.peer_id) FROM gateway_bindings b WHERE b.mesh_id=r.mesh_id AND b.resource_id=r.id),'[]'::jsonb)) FROM network_resources r WHERE r.mesh_id=$1 AND r.console_paused").await?,
        capture_exclusions: configuration_rows(tx,mesh,"SELECT jsonb_build_object('target',target,'providers',providers) FROM provider_capture_exclusions WHERE mesh_id=$1 ORDER BY target::text").await?,
        resources: configuration_rows(tx,mesh,"SELECT jsonb_build_object('id',id,'mesh_id',mesh_id,'version',version,'definition',definition) FROM network_resources WHERE mesh_id=$1 ORDER BY id").await?,
        bindings: configuration_rows(tx,mesh,"SELECT (to_jsonb(b)-'mesh_id'-'created_at'-'updated_at') || jsonb_build_object('approved',b.approved AND NOT r.console_paused) FROM gateway_bindings b JOIN peers p ON p.mesh_id=b.mesh_id AND p.id=b.peer_id JOIN network_resources r ON r.mesh_id=b.mesh_id AND r.id=b.resource_id WHERE b.mesh_id=$1 AND p.administrative_state='enabled' ORDER BY b.id").await?,
        advertisements: configuration_rows(tx,mesh,"SELECT jsonb_build_object('binding_version',a.binding_version,'binding_id',a.binding_id,'peer_id',a.peer_id,'sequence',a.sequence,'published',a.published,'forwarding_ready',a.forwarding_ready,'valid_until',floor(extract(epoch FROM a.valid_until))::bigint)
            FROM route_advertisements a JOIN gateway_bindings b ON b.mesh_id=a.mesh_id AND b.id=a.binding_id JOIN peers p ON p.mesh_id=b.mesh_id AND p.id=b.peer_id WHERE a.mesh_id=$1 AND p.administrative_state='enabled' ORDER BY a.binding_id").await?,
        rules: configuration_rows(tx,mesh,"SELECT rule FROM resource_rules WHERE mesh_id=$1 ORDER BY id").await?,
    })
}
