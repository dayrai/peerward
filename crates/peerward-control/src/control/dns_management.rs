async fn list_dns_profiles(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    Path(mesh): Path<Uuid>,
    Query(query): Query<ListQuery>,
) -> Result<Json<ApiPage<peerward_api::DnsProfileResponse>>, ApiError> {
    authorize(&context, &HeaderMap::new(), Capability::ResourceRead, false)?;
    mesh_id(mesh)?;
    json_page(&state.store,"SELECT jsonb_build_object('version',version,'profile',profile) AS item,id,created_at AS cursor_time
        FROM dns_profiles WHERE mesh_id=$1 AND ($2::timestamptz IS NULL OR (created_at,id)>($2,$3)) ORDER BY created_at,id LIMIT $4",
        mesh,query.cursor()?,query.limit()?).await
}

async fn load_dns_profile(
    store: &Store,
    mesh: Uuid,
    id: Uuid,
) -> Result<peerward_api::DnsProfileResponse, ApiError> {
    let (version, profile): (i64, Value) =
        sqlx::query_as("SELECT version,profile FROM dns_profiles WHERE mesh_id=$1 AND id=$2")
            .bind(mesh)
            .bind(id)
            .fetch_optional(store.pool())
            .await?
            .ok_or_else(ApiError::not_found)?;
    Ok(peerward_api::DnsProfileResponse {
        version: positive_revision(version)?,
        profile: serde_json::from_value(profile).map_err(|_| publisher_error())?,
    })
}

async fn get_dns_profile(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    Path((mesh, id)): Path<(Uuid, Uuid)>,
) -> Result<(HeaderMap, Json<peerward_api::DnsProfileResponse>), ApiError> {
    authorize(&context, &HeaderMap::new(), Capability::ResourceRead, false)?;
    mesh_id(mesh)?;
    let response = load_dns_profile(&state.store, mesh, id).await?;
    Ok((etag_headers(response.version)?, Json(response)))
}

async fn validate_dns_profiles(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    mesh: Uuid,
    profiles: &[peerward_management::DnsProfile],
) -> Result<(), ApiError> {
    if profiles.len() > 64 {
        return Err(ApiError::invalid(
            "dns_limit",
            "at most 64 DNS profiles are supported",
        ));
    }
    let suffix: String = sqlx::query_scalar("SELECT dns_suffix FROM meshes WHERE id=$1")
        .bind(mesh)
        .fetch_one(&mut **tx)
        .await?;
    let reserved: Vec<String> = sqlx::query_scalar(
        "SELECT normalized_name FROM mesh_names WHERE mesh_id=$1 AND owner_kind<>'dns'",
    )
    .bind(mesh)
    .fetch_all(&mut **tx)
    .await?;
    for profile in profiles {
        if reserved.iter().any(|name| {
            profile.records.contains_key(&format!("{name}.{suffix}"))
                || profile
                    .routes
                    .iter()
                    .any(|route| route.suffix == format!("{name}.{suffix}"))
        }) {
            return Err(ApiError::conflict(
                "dns_reserved_name",
                "DNS records and namespace delegations cannot replace existing Peer names or Service aliases; choose another name",
            ));
        }
    }
    let peers:Vec<(Uuid,String,Value)>=sqlx::query_as("SELECT p.id,host(a.address),p.labels FROM peers p JOIN peer_addresses a
        ON p.mesh_id=a.mesh_id AND p.id=a.peer_id WHERE p.mesh_id=$1 AND p.administrative_state='enabled' AND a.state='active'")
        .bind(mesh).fetch_all(&mut **tx).await?;
    for profile in profiles {
        profile.validate().map_err(management_error)?;
        if profile.id == mesh && profile.scope != peerward_management::DeviceSelector::default() {
            return Err(ApiError::invalid(
                "default_dns_scope",
                "the default DNS profile must apply to the entire Mesh",
            ));
        }
        for peer in &profile.scope.peers {
            let exists: bool =
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM peers WHERE mesh_id=$1 AND id=$2)")
                    .bind(mesh)
                    .bind(peer.into_uuid())
                    .fetch_one(&mut **tx)
                    .await?;
            if !exists {
                return Err(ApiError::invalid(
                    "dns_peer_missing",
                    "DNS scope references a device outside this Mesh",
                ));
            }
        }
    }
    // Evaluate every currently addressable device. Future label changes are checked again by
    // the executing client; an ambiguous private namespace fails closed, never public fallback.
    for (peer, address, labels) in peers {
        peerward_management::EffectiveDns::for_peer(
            profiles,
            peer_id(peer)?,
            address.parse().map_err(|_| publisher_error())?,
            &serde_json::from_value(labels).map_err(|_| publisher_error())?,
        )
        .map_err(management_error)?;
    }
    Ok(())
}

async fn save_dns_profile(
    context: AuthContext,
    state: AppState,
    headers: HeaderMap,
    mesh: Uuid,
    id: Uuid,
    profile: peerward_management::DnsProfile,
    create: bool,
) -> Result<
    (
        StatusCode,
        HeaderMap,
        Json<peerward_api::DnsProfileResponse>,
    ),
    ApiError,
> {
    authorize(&context, &headers, Capability::ResourceWrite, true)?;
    let mesh_id = mesh_id(mesh)?;
    if profile.id != id {
        return Err(ApiError::invalid(
            "dns_identity",
            "profile ID must match the path",
        ));
    }
    let expected = if create {
        None
    } else {
        Some(require_if_match(&headers)?)
    };
    let mut tx = state.store.begin_mutation().await?;
    sqlx::query("SELECT id FROM meshes WHERE id=$1 AND lifecycle='active' FOR UPDATE")
        .bind(mesh)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(ApiError::not_found)?;
    let rows: Vec<(i64, Value)> =
        sqlx::query_as("SELECT version,profile FROM dns_profiles WHERE mesh_id=$1 ORDER BY id")
            .bind(mesh)
            .fetch_all(&mut *tx)
            .await?;
    let mut profiles = Vec::new();
    let mut previous = None;
    for (version, value) in rows {
        let known: peerward_management::DnsProfile =
            serde_json::from_value(value).map_err(|_| publisher_error())?;
        if known.id == id {
            previous = Some((version, known));
        } else {
            profiles.push(known);
        }
    }
    if let Some((_, previous)) = &previous
        && create
    {
        if previous != &profile {
            return Err(ApiError::conflict(
                "request_reused",
                "DNS profile identity already has different content",
            ));
        }
        tx.rollback().await?;
        let response = load_dns_profile(&state.store, mesh, id).await?;
        return Ok((
            StatusCode::OK,
            etag_headers(response.version)?,
            Json(response),
        ));
    }
    if !create && previous.as_ref().map(|item| item.0) != expected {
        return Err(ApiError::conflict(
            "version_conflict",
            "DNS profile changed; reload before saving",
        ));
    }
    profiles.push(profile.clone());
    validate_dns_profiles(&mut tx, mesh, &profiles).await?;
    let written=sqlx::query("INSERT INTO dns_profiles(id,mesh_id,profile) VALUES($1,$2,$3)
        ON CONFLICT(id) DO UPDATE SET profile=excluded.profile,updated_at=clock_timestamp() WHERE dns_profiles.mesh_id=excluded.mesh_id")
        .bind(id).bind(mesh).bind(serde_json::to_value(profile).map_err(|_|publisher_error())?).execute(&mut *tx).await?;
    if written.rows_affected() != 1 {
        return Err(ApiError::conflict(
            "request_reused",
            "DNS profile identity is already in use",
        ));
    }
    bump_management(&mut tx, mesh).await?;
    state
        .store
        .commit_mutation(
            tx,
            &mutation(
                &context,
                Some(mesh_id),
                "dns_profile.save",
                "dns_profile.changed",
                "dns_profile",
                Some(id),
            ),
        )
        .await?;
    let response = load_dns_profile(&state.store, mesh, id).await?;
    Ok((
        if create {
            StatusCode::CREATED
        } else {
            StatusCode::OK
        },
        etag_headers(response.version)?,
        Json(response),
    ))
}

async fn create_dns_profile(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(mesh): Path<Uuid>,
    ApiJson(profile): ApiJson<peerward_management::DnsProfile>,
) -> Result<
    (
        StatusCode,
        HeaderMap,
        Json<peerward_api::DnsProfileResponse>,
    ),
    ApiError,
> {
    save_dns_profile(context, state, headers, mesh, profile.id, profile, true).await
}
async fn replace_dns_profile(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((mesh, id)): Path<(Uuid, Uuid)>,
    ApiJson(profile): ApiJson<peerward_management::DnsProfile>,
) -> Result<
    (
        StatusCode,
        HeaderMap,
        Json<peerward_api::DnsProfileResponse>,
    ),
    ApiError,
> {
    save_dns_profile(context, state, headers, mesh, id, profile, false).await
}
async fn delete_dns_profile(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((mesh, id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, ApiError> {
    authorize(&context, &headers, Capability::ResourceWrite, true)?;
    let expected = require_if_match(&headers)?;
    if mesh == id {
        return Err(ApiError::invalid(
            "default_dns_required",
            "clear the default profile instead of deleting it",
        ));
    }
    let mut tx = state.store.begin_mutation().await?;
    sqlx::query("SELECT id FROM meshes WHERE id=$1 AND lifecycle='active' FOR UPDATE")
        .bind(mesh)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(ApiError::not_found)?;
    let removed = sqlx::query("DELETE FROM dns_profiles WHERE mesh_id=$1 AND id=$2 AND version=$3")
        .bind(mesh)
        .bind(id)
        .bind(expected)
        .execute(&mut *tx)
        .await?;
    if removed.rows_affected() != 1 {
        return Err(ApiError::conflict(
            "version_conflict",
            "DNS profile changed",
        ));
    }
    bump_management(&mut tx, mesh).await?;
    state
        .store
        .commit_mutation(
            tx,
            &mutation(
                &context,
                Some(mesh_id(mesh)?),
                "dns_profile.delete",
                "dns_profile.deleted",
                "dns_profile",
                Some(id),
            ),
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn preview_dns(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    Path(mesh): Path<Uuid>,
    ApiJson(body): ApiJson<peerward_api::DnsPreviewRequest>,
) -> Result<Json<peerward_management::EffectiveDns>, ApiError> {
    authorize(&context, &HeaderMap::new(), Capability::ResourceRead, false)?;
    mesh_id(mesh)?;
    let profiles = if let Some(draft) = body.draft_profiles {
        authorize(
            &context,
            &HeaderMap::new(),
            Capability::ResourceWrite,
            false,
        )?;
        if draft.len() > 64 {
            return Err(ApiError::invalid(
                "dns_limit",
                "at most 64 DNS profiles are supported",
            ));
        }
        draft
    } else {
        let values: Vec<Value> =
            sqlx::query_scalar("SELECT profile FROM dns_profiles WHERE mesh_id=$1 ORDER BY id")
                .bind(mesh)
                .fetch_all(state.store.pool())
                .await?;
        values
            .into_iter()
            .map(serde_json::from_value)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| publisher_error())?
    };
    let peer = load_policy_peer(&state.store, mesh, body.peer_id.into_uuid()).await?;
    Ok(Json(
        peerward_management::EffectiveDns::for_peer(&profiles, peer.id, peer.address, &peer.labels)
            .map_err(management_error)?,
    ))
}
