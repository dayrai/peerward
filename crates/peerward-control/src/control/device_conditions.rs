async fn read_device_conditions(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    mesh: Uuid,
) -> Result<(u64, peerward_management::DeviceConditions), ApiError> {
    let (version, definition): (i64, Value) =
        sqlx::query_as("SELECT version,definition FROM device_conditions WHERE mesh_id=$1")
            .bind(mesh)
            .fetch_optional(&mut **tx)
            .await?
            .ok_or_else(ApiError::not_found)?;
    Ok((
        positive_revision(version)?,
        serde_json::from_value(definition).map_err(|_| publisher_error())?,
    ))
}

async fn validate_device_conditions(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    mesh: Uuid,
    definition: &peerward_management::DeviceConditions,
) -> Result<(), ApiError> {
    definition.validate().map_err(management_error)?;
    let peers: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM peers WHERE mesh_id=$1 AND administrative_state<>'deleted'",
    )
    .bind(mesh)
    .fetch_all(&mut **tx)
    .await?;
    if definition
        .scope
        .peers
        .iter()
        .any(|p| !peers.contains(&p.into_uuid()))
    {
        return Err(ApiError::invalid(
            "condition_scope",
            "select devices in this Mesh",
        ));
    }
    Ok(())
}

async fn read_device_admission(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    mesh: Uuid,
) -> Result<peerward_management::AdmissionConfiguration, ApiError> {
    use peerward_management::{AdmissionConfiguration, AdmissionDecision, DeviceEvidence};
    let (_, definition) = read_device_conditions(tx, mesh).await?;
    if !definition.enabled {
        return Ok(AdmissionConfiguration::default());
    }
    let rows = sqlx::query("SELECT p.id,p.labels,
        ARRAY(SELECT host(address) FROM peer_addresses WHERE mesh_id=p.mesh_id AND peer_id=p.id AND state='active') AS addresses,
        e.evidence,COALESCE(floor(extract(epoch FROM e.valid_until))::bigint,0) AS evidence_until,
        CASE WHEN e.observed_at<=clock_timestamp() AND p.administrative_state='enabled'
            AND c.lifecycle IN ('active','overlap') AND a.lifecycle IN ('active','overlap')
            AND c.not_before<=clock_timestamp() AND a.not_before<=clock_timestamp()
            THEN floor(extract(epoch FROM LEAST(c.not_after,a.not_after,
                CASE WHEN c.lifecycle='overlap' THEN c.overlap_deadline ELSE c.not_after END,
                CASE WHEN a.lifecycle='overlap' THEN a.overlap_deadline ELSE a.not_after END)))::bigint ELSE 0 END AS credential_until
        FROM peers p LEFT JOIN device_evidence e ON e.mesh_id=p.mesh_id AND e.peer_id=p.id
        LEFT JOIN peer_credentials c ON c.mesh_id=p.mesh_id AND c.peer_id=p.id AND c.serial=e.credential_serial
        LEFT JOIN mesh_authorities a ON a.mesh_id=c.mesh_id AND a.id=c.authority_id
        WHERE p.mesh_id=$1 AND p.administrative_state<>'deleted' ORDER BY p.id LIMIT 4097")
        .bind(mesh).fetch_all(&mut **tx).await?;
    if rows.len() > 4096 {
        return Err(ApiError::invalid(
            "condition_capacity",
            "at most 4096 devices in an admission directory",
        ));
    }
    let mut admission = AdmissionConfiguration {
        enabled: true,
        peers: BTreeMap::new(),
    };
    for row in rows {
        let id = peer_id(row.try_get("id")?)?;
        let addresses: Vec<String> = row.try_get("addresses")?;
        let labels =
            serde_json::from_value(row.try_get("labels")?).map_err(|_| publisher_error())?;
        // A matching address in either family selects the entire device, never just one tunnel IP.
        let selected = addresses.iter().any(|address| {
            address
                .parse()
                .is_ok_and(|address| definition.scope.matches(id, address, &labels))
        }) || (addresses.is_empty()
            && definition.scope.cidrs.is_empty()
            && definition.scope.matches(
                id,
                "0.0.0.0".parse().map_err(|_| publisher_error())?,
                &labels,
            ));
        let decision = if selected {
            let evidence: Option<DeviceEvidence> = row
                .try_get::<Option<Value>, _>("evidence")?
                .map(serde_json::from_value)
                .transpose()
                .map_err(|_| publisher_error())?;
            definition.evaluate(
                evidence.as_ref(),
                u64::try_from(row.try_get::<i64, _>("evidence_until")?).unwrap_or(0),
                u64::try_from(row.try_get::<i64, _>("credential_until")?).unwrap_or(0),
                current_unix_seconds(),
            )
        } else {
            AdmissionDecision::unrestricted()
        };
        admission.peers.insert(id, decision);
    }
    Ok(admission)
}

async fn get_device_conditions(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    Path(mesh): Path<Uuid>,
) -> Result<(HeaderMap, Json<Value>), ApiError> {
    authorize(&context, &HeaderMap::new(), Capability::ResourceRead, false)?;
    let mut tx = state.store.begin_mutation().await?;
    let (version, definition) = read_device_conditions(&mut tx, mesh).await?;
    let admission = read_device_admission(&mut tx, mesh).await?;
    let restricted = admission
        .peers
        .values()
        .filter(|d| !d.permits(current_unix_seconds()))
        .count();
    tx.rollback().await?;
    Ok((
        etag_headers(version)?,
        Json(
            json!({"version":version,"definition":definition,"restricted_devices":restricted,"evidence_source":"device_signed_self_report","credential_source":"control_verified","evidence_lifetime_seconds":900}),
        ),
    ))
}

async fn put_device_conditions(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(mesh): Path<Uuid>,
    ApiJson(definition): ApiJson<peerward_management::DeviceConditions>,
) -> Result<(HeaderMap, Json<Value>), ApiError> {
    authorize(&context, &headers, Capability::ResourceWrite, true)?;
    let expected = require_if_match(&headers)?;
    let mut tx = state.store.begin_mutation().await?;
    sqlx::query("SELECT id FROM meshes WHERE id=$1 AND lifecycle='active' FOR UPDATE")
        .bind(mesh)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(ApiError::not_found)?;
    validate_device_conditions(&mut tx, mesh, &definition).await?;
    let written=sqlx::query("UPDATE device_conditions SET definition=$3,updated_at=clock_timestamp() WHERE mesh_id=$1 AND version=$2")
        .bind(mesh).bind(expected).bind(declaration_value(&definition)?).execute(&mut *tx).await?;
    if written.rows_affected() != 1 {
        return Err(ApiError::conflict(
            "version_conflict",
            "device conditions changed; reload and review before saving",
        ));
    }
    // An admission restriction must not be blocked by positive connectivity assertions.
    bump_management(&mut tx, mesh).await?;
    state
        .store
        .commit_mutation(
            tx,
            &mutation(
                &context,
                Some(mesh_id(mesh)?),
                "device_conditions.save",
                "device_conditions.changed",
                "device_conditions",
                Some(mesh),
            ),
        )
        .await?;
    get_device_conditions(Extension(context), State(state), Path(mesh)).await
}

async fn get_peer_device_condition(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    Path((mesh, peer)): Path<(Uuid, Uuid)>,
) -> Result<Json<Value>, ApiError> {
    authorize(&context, &HeaderMap::new(), Capability::ResourceRead, false)?;
    let mut tx = state.store.begin_mutation().await?;
    let name: String = sqlx::query_scalar("SELECT name FROM peers WHERE mesh_id=$1 AND id=$2")
        .bind(mesh)
        .bind(peer)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(ApiError::not_found)?;
    let admission = read_device_admission(&mut tx, mesh).await?;
    let decision = admission
        .peers
        .get(&peer_id(peer)?)
        .cloned()
        .unwrap_or_else(peerward_management::AdmissionDecision::unrestricted);
    let evidence:Option<Value>=sqlx::query_scalar("SELECT jsonb_build_object('statement',evidence,'observed_at',observed_at,'valid_until',valid_until,'credential_serial',credential_serial,'source','device_signed_self_report') FROM device_evidence WHERE mesh_id=$1 AND peer_id=$2").bind(mesh).bind(peer).fetch_optional(&mut *tx).await?;
    tx.rollback().await?;
    Ok(Json(
        json!({"peer_id":peer,"name":name,"conditions_enabled":admission.enabled,"decision":decision,"evidence":evidence,"credential_source":"control_verified","client_application":"check_configuration_receipts"}),
    ))
}
