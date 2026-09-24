const TICKET_PROJECTION:&str="SELECT t.id,t.mesh_id,t.created_at,jsonb_build_object(
    'id',t.id,'version',t.version,'expires_at',t.expires_at,'created_at',t.created_at,
    'consumed',t.consumed_at IS NOT NULL,'settings',t.settings,'claimed_peer_id',t.claimed_peer_id,
    'status',CASE WHEN t.consumed_at IS NOT NULL THEN 'approved' WHEN t.cancelled_at IS NOT NULL THEN 'cancelled'
        WHEN a.status IS NOT NULL THEN CASE WHEN a.status='pending' AND a.expires_at<=clock_timestamp() THEN 'expired' ELSE a.status END
        WHEN t.expires_at<=clock_timestamp() THEN 'expired' ELSE 'unused' END) AS item
    FROM join_tickets t LEFT JOIN join_applications a ON a.ticket_id=t.id";

async fn list_tickets(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    Path(mesh): Path<Uuid>,
    Query(query): Query<ListQuery>,
) -> Result<Json<ApiPage<JoinTicketResource>>, ApiError> {
    authorize(&context, &HeaderMap::new(), Capability::ResourceRead, false)?;
    mesh_id(mesh)?;
    json_page(
        &state.store,
        &format!(
            "SELECT item,id,created_at AS cursor_time FROM ({TICKET_PROJECTION}) t WHERE mesh_id=$1
        AND ($2::timestamptz IS NULL OR (created_at,id)>($2,$3)) ORDER BY created_at,id LIMIT $4"
        ),
        mesh,
        query.cursor()?,
        query.limit()?,
    )
    .await
}

async fn create_ticket(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(mesh): Path<Uuid>,
    ApiJson(body): ApiJson<JoinTicketCreateRequest>,
) -> Result<(StatusCode, HeaderMap, Json<JoinTicketCreateResponse>), ApiError> {
    authorize(&context, &headers, Capability::ResourceWrite, true)?;
    if !(60..=7 * 24 * 60 * 60).contains(&body.expires_in_seconds) {
        return Err(ApiError::invalid(
            "invalid_expiry",
            "Join Ticket expiry must be between 60 seconds and 7 days",
        ));
    }
    body.settings.validate().map_err(management_error)?;
    if body
        .settings
        .lifecycle
        .deadline()
        .is_some_and(|until| until <= current_unix_seconds().saturating_add(60))
    {
        return Err(ApiError::invalid(
            "device_deadline_too_soon",
            "Device access must extend at least 60 seconds beyond enrollment; choose a later deadline",
        ));
    }
    let mesh_id = mesh_id(mesh)?;
    let active: Uuid = sqlx::query_scalar(
        "SELECT id FROM mesh_authorities WHERE mesh_id=$1 AND lifecycle='active'
         AND not_before<=clock_timestamp() AND not_after>clock_timestamp()",
    )
    .bind(mesh)
    .fetch_optional(state.store.pool())
    .await?
    .ok_or_else(|| {
        ApiError::unavailable(
            "active_authority_unavailable",
            "Mesh has no currently active Authority",
        )
    })?;
    let issuer = state
        .join_issuers
        .get(&mesh_id)
        .and_then(|issuers| {
            issuers
                .iter()
                .find(|issuer| issuer.authority_id == active)
                .cloned()
        })
        .ok_or_else(|| {
            ApiError::unavailable(
                "active_authority_key_unavailable",
                "active Authority trust material is unavailable",
            )
        })?;
    let mut token = [0_u8; 32];
    OsRng.fill_bytes(&mut token);
    let expiry = OffsetDateTime::now_utc()
        + TimeDuration::seconds(
            i64::try_from(body.expires_in_seconds)
                .map_err(|_| ApiError::invalid("invalid_expiry", "expiry is too large"))?,
        );
    let ticket = state
        .store
        .create_configured_join_ticket(mesh_id, &token, expiry, &context.actor, &body.settings)
        .await?;
    let expires_at_unix = u64::try_from(ticket.expires_at.unix_timestamp())
        .map_err(|_| ApiError::invalid("invalid_expiry", "Join Ticket expiry is invalid"))?;
    let token = URL_SAFE_NO_PAD.encode(token);
    let claim_url = state.public_url.as_ref().map(|origin| {
        format!("{}api/v1/join/{token}/claim", origin.as_str())
    });
    let response = JoinTicketCreateResponse {
        version: ticket.version,
        id: ticket.id.into_uuid(),
        mesh_id: ticket.mesh_id,
        expires_at: ticket.expires_at.format(&Rfc3339).map_err(|_| publisher_error())?,
        expires_at_unix,
        token,
        claim_url,
        root_fingerprint: hex::encode(Sha256::digest(issuer.root_public_key)),
    };
    Ok((
        StatusCode::CREATED,
        etag_headers(response.version)?,
        Json(response),
    ))
}

async fn get_ticket(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    Path((mesh, ticket)): Path<(Uuid, Uuid)>,
) -> Result<(HeaderMap, Json<JoinTicketResource>), ApiError> {
    authorize(&context, &HeaderMap::new(), Capability::ResourceRead, false)?;
    mesh_id(mesh)?;
    TicketId::from_uuid(ticket).map_err(|_| ApiError::invalid_id())?;
    let value: Option<Value> = sqlx::query_scalar(&format!(
        "SELECT item FROM ({TICKET_PROJECTION}) t WHERE mesh_id=$1 AND id=$2"
    ))
    .bind(mesh)
    .bind(ticket)
    .fetch_optional(state.store.pool())
    .await?;
    let resource: JoinTicketResource =
        serde_json::from_value(value.ok_or_else(ApiError::not_found)?).map_err(|_| {
            ApiError::internal("ticket_projection", "Join Ticket projection is invalid")
        })?;
    Ok((etag_headers(resource.version)?, Json(resource)))
}

async fn delete_ticket(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((mesh, ticket)): Path<(Uuid, Uuid)>,
) -> Result<(HeaderMap, StatusCode), ApiError> {
    authorize(&context, &headers, Capability::ResourceWrite, true)?;
    let expected = require_if_match(&headers)?;
    let mesh_id = mesh_id(mesh)?;
    TicketId::from_uuid(ticket).map_err(|_| ApiError::invalid_id())?;
    let mut transaction = state.store.begin_mutation().await?;
    sqlx::query("SELECT id FROM meshes WHERE id=$1 FOR UPDATE")
        .bind(mesh)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or_else(ApiError::not_found)?;
    lock_resource_version(
        &mut transaction,
        VersionedFamily::JoinTicket,
        Some(mesh),
        ticket,
        expected,
    )
    .await?;
    let changed = sqlx::query(
        "UPDATE join_tickets SET cancelled_at=clock_timestamp()
         WHERE mesh_id=$1 AND id=$2 AND consumed_at IS NULL AND cancelled_at IS NULL",
    )
    .bind(mesh_id.into_uuid())
    .bind(ticket)
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    if changed != 1 {
        return Err(ApiError::not_found());
    }
    state
        .store
        .commit_mutation(
            transaction,
            &mutation(
                &context,
                Some(mesh_id),
                "join_ticket.delete",
                "join_ticket.deleted",
                "join_ticket",
                Some(ticket),
            ),
        )
        .await?;
    let version: i64 =
        sqlx::query_scalar("SELECT version FROM join_tickets WHERE mesh_id=$1 AND id=$2")
            .bind(mesh)
            .bind(ticket)
            .fetch_one(state.store.pool())
            .await?;
    Ok((
        etag_headers(u64::try_from(version).map_err(|_| {
            ApiError::internal("ticket_projection", "Join Ticket version is invalid")
        })?)?,
        StatusCode::NO_CONTENT,
    ))
}

async fn claim_join(
    State(state): State<AppState>,
    Path(token): Path<String>,
    ApiJson(body): ApiJson<JoinClaimRequest>,
) -> Result<Response, ApiError> {
    state.metrics.join_claims.fetch_add(1, Ordering::Relaxed);
    let token = URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|_| ApiError::invalid("invalid_token", "invalid join token"))?;
    let identity_public_key = URL_SAFE_NO_PAD
        .decode(&body.identity_public_key)
        .map_err(|_| ApiError::invalid("invalid_identity_key", "invalid Ed25519 identity key"))?;
    let identity_key: [u8; 32] = identity_public_key
        .as_slice()
        .try_into()
        .map_err(|_| ApiError::invalid("invalid_identity_key", "identity key must be 32 bytes"))?;
    let session_public_key = URL_SAFE_NO_PAD
        .decode(&body.session_public_key)
        .map_err(|_| ApiError::invalid("invalid_session_key", "invalid X25519 session key"))?;
    let session_key: [u8; 32] = session_public_key
        .as_slice()
        .try_into()
        .map_err(|_| ApiError::invalid("invalid_session_key", "session key must be 32 bytes"))?;
    let wireguard_public_key = URL_SAFE_NO_PAD
        .decode(&body.wireguard_public_key)
        .map_err(|_| ApiError::invalid("invalid_wireguard_key", "invalid WireGuard public key"))?;
    let wireguard_key: [u8; 32] = wireguard_public_key.as_slice().try_into().map_err(|_| {
        ApiError::invalid("invalid_wireguard_key", "WireGuard key must be 32 bytes")
    })?;
    let nonce = URL_SAFE_NO_PAD
        .decode(&body.nonce)
        .map_err(|_| ApiError::invalid("invalid_nonce", "invalid enrollment nonce"))?;
    let signature: [u8; 64] = URL_SAFE_NO_PAD
        .decode(&body.signature)
        .map_err(|_| ApiError::invalid("invalid_claim_signature", "invalid claim signature"))?
        .try_into()
        .map_err(|_| {
            ApiError::invalid(
                "invalid_claim_signature",
                "claim signature must be 64 bytes",
            )
        })?;
    if body.supported_wire_major != peerward_wire::PROTOCOL_MAJOR {
        return Err(ApiError::invalid(
            "unsupported_wire_major",
            "unsupported Wire major; update the client and join again",
        ));
    }
    let ticket_digest = secret_digest(&token);
    let proof = JoinClaimProof {
        schema_version: body.schema_version,
        claim_id: body.claim_id,
        ticket_digest,
        identity_public_key: identity_key,
        session_public_key: session_key,
        wireguard_public_key: wireguard_key,
        client_version: &body.client_version,
        supported_wire_major: body.supported_wire_major,
        nonce: &nonce,
        device_name: &body.device_name,
        device_model: &body.device_model,
        platform: &body.platform,
        platform_version: &body.platform_version,
    };
    verify_join_claim(&proof, &signature).map_err(|_| {
        ApiError::invalid(
            "invalid_claim_signature",
            "the new identity did not authenticate this Join claim",
        )
    })?;
    let request_digest = Sha256::digest(join_claim_transcript(&proof).map_err(|_| {
        ApiError::invalid(
            "invalid_join_claim",
            "Join claim fields are outside their bounds",
        )
    })?)
    .into();
    let signed_request = serde_json::to_value(&body).map_err(|_| publisher_error())?;
    let name = enrollment_peer_name(&body.device_name, &nonce);
    let labels = json!({
        "device_model": body.device_model,
        "platform": body.platform,
        "platform_version": body.platform_version,
    });
    let claim = PublicJoinClaim {
        token,
        claim_id: body.claim_id,
        request_digest,
        name,
        labels,
        identity_public_key,
        public_noise_key: session_public_key,
        wireguard_public_key,
    };
    if let Some(response_document) = state.store.replay_public_join(&claim).await? {
        state.metrics.join_replays.fetch_add(1, Ordering::Relaxed);
        state
            .metrics
            .join_completions
            .fetch_add(1, Ordering::Relaxed);
        return Ok((
            StatusCode::CREATED,
            [(header::CONTENT_TYPE, "application/json")],
            response_document,
        )
            .into_response());
    }
    if let Some(application) = state
        .store
        .submit_join_application(&claim, &signed_request)
        .await?
    {
        use peerward_management::JoinApplicationStatus;
        match application.status {
            JoinApplicationStatus::Pending => {
                return Ok((
                    StatusCode::ACCEPTED,
                    [(header::RETRY_AFTER, "5")],
                    Json(peerward_management::PendingJoinResponse {
                        application,
                        retry_after_seconds: 5,
                    }),
                )
                    .into_response());
            }
            JoinApplicationStatus::Approved => {
                let document = state
                    .store
                    .replay_public_join(&claim)
                    .await?
                    .ok_or_else(|| {
                        ApiError::conflict("application_changed", "retry the same signed claim")
                    })?;
                return Ok((
                    StatusCode::CREATED,
                    [(header::CONTENT_TYPE, "application/json")],
                    document,
                )
                    .into_response());
            }
            JoinApplicationStatus::Rejected => {
                return Err(ApiError::conflict(
                    "application_rejected",
                    "the admission request was rejected; obtain a new invitation",
                ));
            }
            JoinApplicationStatus::Cancelled => {
                return Err(ApiError::conflict(
                    "application_cancelled",
                    "the invitation was cancelled; obtain a new invitation",
                ));
            }
            JoinApplicationStatus::Expired => {
                return Err(ApiError::conflict(
                    "application_expired",
                    "the approval deadline passed; obtain a new invitation",
                ));
            }
        }
    }
    let selected_mesh: Uuid =
        sqlx::query_scalar("SELECT mesh_id FROM join_tickets WHERE token_digest=$1")
            .bind(secret_digest(&claim.token).as_slice())
            .fetch_optional(state.store.pool())
            .await?
            .ok_or_else(ApiError::not_found)?;
    let issue = join_enrollment_issuer(&state, mesh_id(selected_mesh)?, &claim).await?;
    let claimed = state.store.claim_public_join(&claim, issue).await.map_err(|error|match error {
        StoreError::Invalid("prebound identity")=>ApiError::invalid("prebound_identity_mismatch","this invitation is bound to a different device identity; use the prepared keys or obtain a new invitation"),
        error=>ApiError::from(error),
    })?;
    state
        .metrics
        .join_completions
        .fetch_add(1, Ordering::Relaxed);
    Ok((
        StatusCode::CREATED,
        [(header::CONTENT_TYPE, "application/json")],
        claimed.response_document,
    )
        .into_response())
}

struct JoinResponseBasis {
    mesh_name: String,
    address_cidr: String,
    secondary_cidr: String,
    gateway: String,
    dns_suffix: String,
    mtu: u16,
    authority_revision: u64,
    relays: Vec<JoinRelayTarget>,
    authority_certificates: Vec<String>,
}

async fn load_join_response_basis(
    state: &AppState,
    mesh_id: MeshId,
) -> Result<JoinResponseBasis, ApiError> {
    let mesh = sqlx::query(
        "SELECT name,address_cidr::text AS address_cidr,secondary_cidr::text AS secondary_cidr,host(gateway) AS gateway,dns_suffix,mtu,
                authority_revision
         FROM meshes WHERE id=$1",
    )
        .bind(mesh_id.into_uuid())
        .fetch_one(state.store.pool())
        .await?;
    let relay_rows = sqlx::query(
        "SELECT r.id,r.peer_endpoints,c.public_key FROM relays r
         JOIN relay_credentials c ON c.mesh_id=r.mesh_id AND c.relay_id=r.id
         WHERE r.mesh_id=$1 AND r.administrative_state='enabled' AND c.lifecycle='active'
           AND c.not_before <= clock_timestamp() AND c.not_after > clock_timestamp()
         ORDER BY r.id",
    )
    .bind(mesh_id.into_uuid())
    .fetch_all(state.store.pool())
    .await?;
    let mut relays = Vec::with_capacity(relay_rows.len());
    for relay in relay_rows {
        let relay_id = RelayId::from_uuid(relay.try_get::<Uuid, _>("id")?)
            .map_err(|_| ApiError::invalid_id())?;
        let endpoints = relay
            .try_get::<Vec<String>, _>("peer_endpoints")?
            .into_iter()
            .map(|endpoint| endpoint.parse::<NetworkEndpoint>())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| {
                ApiError::unavailable(
                    "relay_directory_invalid",
                    "stored Relay endpoints are invalid",
                )
            })?;
        validate_endpoint_list(&endpoints).map_err(|_| {
            ApiError::unavailable(
                "relay_directory_invalid",
                "stored Relay endpoints are invalid",
            )
        })?;
        relays.push(JoinRelayTarget {
            relay_id,
            endpoints,
            public_key: URL_SAFE_NO_PAD.encode(relay.try_get::<Vec<u8>, _>("public_key")?),
        });
    }
    let authority_rows = sqlx::query(
        "SELECT certificate FROM mesh_authorities WHERE mesh_id=$1
         AND (lifecycle='active' OR (lifecycle='overlap' AND overlap_deadline>clock_timestamp()))
         AND not_before<=clock_timestamp() AND not_after>clock_timestamp()
         ORDER BY CASE lifecycle WHEN 'active' THEN 0 ELSE 1 END,serial",
    )
    .bind(mesh_id.into_uuid())
    .fetch_all(state.store.pool())
    .await?;
    let authority_certificates = authority_rows
        .into_iter()
        .map(|row| {
            row.try_get::<Vec<u8>, _>("certificate")
                .map(|value| URL_SAFE_NO_PAD.encode(value))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if authority_certificates.is_empty() {
        return Err(ApiError::unavailable(
            "authority_bundle_unavailable",
            "mesh has no currently valid Authority certificates",
        ));
    }
    Ok(JoinResponseBasis {
        mesh_name: mesh.try_get("name")?,
        address_cidr: mesh.try_get("address_cidr")?,
        secondary_cidr: mesh.try_get("secondary_cidr")?,
        gateway: mesh.try_get("gateway")?,
        dns_suffix: mesh.try_get("dns_suffix")?,
        mtu: u16::try_from(mesh.try_get::<i32, _>("mtu")?)
            .map_err(|_| ApiError::invalid("invalid_mtu", "stored Mesh MTU is invalid"))?,
        authority_revision: u64::try_from(mesh.try_get::<i64, _>("authority_revision")?).map_err(
            |_| ApiError::invalid("invalid_revision", "stored Authority revision is invalid"),
        )?,
        relays,
        authority_certificates,
    })
}

fn enrollment_peer_name(device_name: &str, nonce: &[u8]) -> String {
    let mut base = device_name
        .chars()
        .filter_map(|character| {
            character
                .is_ascii_alphanumeric()
                .then(|| character.to_ascii_lowercase())
                .or_else(|| matches!(character, '-' | ' ' | '_').then_some('-'))
        })
        .collect::<String>();
    base = base.trim_matches('-').to_owned();
    if base.is_empty() {
        base = "device".into();
    }
    base.truncate(50);
    let suffix = hex::encode(&Sha256::digest(nonce)[..6]);
    format!("{base}-{suffix}")
}
