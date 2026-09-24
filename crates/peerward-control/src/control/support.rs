async fn rotate_subject(
    state: &AppState,
    context: &AuthContext,
    mesh_id: MeshId,
    subject: Uuid,
    body: &CredentialRotationRequest,
    peer: bool,
    expected_version: i64,
) -> Result<(StatusCode, HeaderMap, Json<CredentialResource>), ApiError> {
    if peer {
        return Err(ApiError::forbidden(
            "peer_rotation_requires_device",
            "Peer keys must be rotated by the authenticated device",
        ));
    }
    let public_key: [u8; 32] = decode_hex(&body.public_key, 32)?
        .try_into()
        .map_err(|_| ApiError::invalid("invalid_public_key", "invalid public key"))?;
    let table = if peer {
        "peer_credentials"
    } else {
        "relay_credentials"
    };
    let subject_column = if peer { "peer_id" } else { "relay_id" };
    let credential_subject = if peer {
        SubjectId::Peer(PeerId::from_uuid(subject).map_err(|_| ApiError::invalid_id())?)
    } else {
        SubjectId::Relay(RelayId::from_uuid(subject).map_err(|_| ApiError::invalid_id())?)
    };
    let id = Uuid::new_v4();
    let mut transaction = state.store.begin_mutation().await?;
    lock_resource_version(
        &mut transaction,
        if peer {
            VersionedFamily::Peer
        } else {
            VersionedFamily::Relay
        },
        Some(mesh_id.into_uuid()),
        subject,
        expected_version,
    )
    .await?;
    let authority = sqlx::query(
        "SELECT id,not_after FROM mesh_authorities
         WHERE mesh_id=$1 AND lifecycle='active'
           AND not_before<=clock_timestamp() AND not_after>clock_timestamp()
         FOR SHARE",
    )
    .bind(mesh_id.into_uuid())
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or_else(|| {
        ApiError::invalid(
            "invalid_credential_authority",
            "the Mesh has no currently active credential Authority",
        )
    })?;
    let authority_id: Uuid = authority.try_get("id")?;
    let authority_not_after: OffsetDateTime = authority.try_get("not_after")?;
    let issuer = state
        .join_issuers
        .get(&mesh_id)
        .and_then(|issuers| {
            issuers
                .iter()
                .find(|issuer| issuer.authority_id == authority_id)
                .cloned()
        })
        .ok_or_else(|| {
            ApiError::unavailable(
                "authority_signer_unavailable",
                "the active Authority private key is not configured",
            )
        })?;
    let not_before = OffsetDateTime::now_utc();
    let requested_not_after = not_before
        + TimeDuration::seconds(i64::try_from(issuer.validity_seconds).map_err(|_| {
            ApiError::invalid(
                "invalid_validity",
                "configured credential validity is too large",
            )
        })?);
    let not_after = requested_not_after.min(authority_not_after);
    let serial = CredentialSerial::new();
    let credential = issuer
        .authority
        .issue(UnsignedSubject {
            subject: credential_subject,
            mesh_id,
            identity_public_key: match credential_subject {
                SubjectId::Peer(_) => public_key,
                SubjectId::Relay(_) => [0; 32],
            },
            public_noise_key: public_key,
            wireguard_public_key: [0; 32],
            serial,
            not_before: UnixTime(
                u64::try_from(not_before.unix_timestamp())
                    .map_err(|_| ApiError::invalid("invalid_clock", "system clock is invalid"))?,
            ),
            not_after: UnixTime(u64::try_from(not_after.unix_timestamp()).map_err(|_| {
                ApiError::invalid("invalid_validity", "credential validity is invalid")
            })?),
        })
        .map_err(|_| ApiError::invalid("invalid_validity", "credential validity is invalid"))?;
    let statement = if peer {
        format!(
            "INSERT INTO {table}(id,mesh_id,{subject_column},authority_id,serial,
             identity_public_key,public_key,not_before,not_after,lifecycle,signature)
             VALUES($1,$2,$3,$4,$5,$6,$6,$7,$8,'staged',$9)"
        )
    } else {
        format!(
            "INSERT INTO {table}(id,mesh_id,{subject_column},authority_id,serial,public_key,
             not_before,not_after,lifecycle,signature)
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,'staged',$9)"
        )
    };
    sqlx::query(&statement)
        .bind(id)
        .bind(mesh_id.into_uuid())
        .bind(subject)
        .bind(authority_id)
        .bind(serial.into_uuid())
        .bind(public_key.to_vec())
        .bind(not_before)
        .bind(not_after)
        .bind(credential.signature.to_vec())
        .execute(&mut *transaction)
        .await?;
    let subject_table = if peer { "peers" } else { "relays" };
    sqlx::query(&format!(
        "UPDATE {subject_table} SET updated_at=clock_timestamp() WHERE mesh_id=$1 AND id=$2"
    ))
    .bind(mesh_id.into_uuid())
    .bind(subject)
    .execute(&mut *transaction)
    .await?;
    let family = if peer {
        "peer_credential"
    } else {
        "relay_credential"
    };
    state
        .store
        .commit_mutation(
            transaction,
            &mutation(
                context,
                Some(mesh_id),
                &format!("{family}.rotate"),
                &format!("{family}.staged"),
                family,
                Some(id),
            ),
        )
        .await?;
    let statement = format!(
        "SELECT jsonb_build_object('id',id,'serial',serial,'authority_id',authority_id,
         'public_key',encode(public_key,'hex'),'not_before',not_before,'not_after',not_after,
         'lifecycle',lifecycle,'replacement_id',replacement_id,
         'overlap_deadline',overlap_deadline) FROM {table} WHERE id=$1"
    );
    let value: Value = sqlx::query_scalar(&statement)
        .bind(id)
        .fetch_one(state.store.pool())
        .await?;
    let resource = serde_json::from_value(value).map_err(|_| {
        ApiError::internal("credential_projection", "Credential projection is invalid")
    })?;
    let version: i64 = sqlx::query_scalar(&format!(
        "SELECT version FROM {subject_table} WHERE mesh_id=$1 AND id=$2"
    ))
    .bind(mesh_id.into_uuid())
    .bind(subject)
    .fetch_one(state.store.pool())
    .await?;
    Ok((
        StatusCode::CREATED,
        etag_headers(u64::try_from(version).map_err(|_| {
            ApiError::internal("resource_projection", "resource version is invalid")
        })?)?,
        Json(resource),
    ))
}

fn empty_object() -> Value {
    json!({})
}

fn valid_display_name(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= 128
}

fn require_if_match(headers: &HeaderMap) -> Result<i64, ApiError> {
    let value = headers.get(header::IF_MATCH).ok_or_else(|| {
        ApiError::new(
            StatusCode::PRECONDITION_REQUIRED,
            "precondition_required",
            "If-Match with the current resource ETag is required",
        )
    })?;
    let value = value
        .to_str()
        .ok()
        .and_then(|value| value.strip_prefix('"'))
        .and_then(|value| value.strip_suffix('"'))
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| *value > 0)
        .ok_or_else(|| {
            ApiError::invalid(
                "invalid_if_match",
                "If-Match must be one strong numeric ETag",
            )
        })?;
    Ok(value)
}

fn etag_headers(version: u64) -> Result<HeaderMap, ApiError> {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::ETAG,
        HeaderValue::from_str(&format!("\"{version}\""))
            .map_err(|_| ApiError::internal("etag_encoding", "resource ETag is invalid"))?,
    );
    Ok(headers)
}

#[derive(Clone, Copy)]
enum VersionedFamily {
    Mesh,
    Peer,
    Relay,
    JoinTicket,
    Service,
}

async fn lock_resource_version(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    family: VersionedFamily,
    mesh: Option<Uuid>,
    id: Uuid,
    expected: i64,
) -> Result<(), ApiError> {
    let parent = if matches!(family, VersionedFamily::Mesh) {
        id
    } else {
        mesh.ok_or_else(ApiError::invalid_id)?
    };
    let lifecycle: Option<String> =
        sqlx::query_scalar("SELECT lifecycle FROM meshes WHERE id=$1 FOR UPDATE")
            .bind(parent)
            .fetch_optional(&mut **transaction)
            .await?;
    if lifecycle.as_deref() != Some("active")
        && !(matches!(family, VersionedFamily::Mesh) && lifecycle.as_deref() == Some("creating"))
    {
        return Err(ApiError::conflict("mesh_not_active", "Mesh is not active"));
    }
    let statement = match family {
        VersionedFamily::Mesh => "SELECT version FROM meshes WHERE id=$1 FOR UPDATE",
        VersionedFamily::Peer => {
            "SELECT version FROM peers WHERE id=$1 AND mesh_id=$2 AND administrative_state<>'deleted' FOR UPDATE"
        }
        VersionedFamily::Relay => {
            "SELECT version FROM relays WHERE id=$1 AND mesh_id=$2 FOR UPDATE"
        }
        VersionedFamily::JoinTicket => {
            "SELECT version FROM join_tickets WHERE id=$1 AND mesh_id=$2 FOR UPDATE"
        }
        VersionedFamily::Service => {
            "SELECT version FROM services WHERE id=$1 AND mesh_id=$2 FOR UPDATE"
        }
    };
    let mut query = sqlx::query_scalar::<_, i64>(statement).bind(id);
    if !matches!(family, VersionedFamily::Mesh) {
        query = query.bind(mesh.ok_or_else(ApiError::invalid_id)?);
    }
    let actual = query
        .fetch_optional(&mut **transaction)
        .await?
        .ok_or_else(ApiError::not_found)?;
    if actual != expected {
        return Err(ApiError::conflict(
            "revision_conflict",
            "resource changed after the supplied ETag was read",
        ));
    }
    Ok(())
}

const fn administrative_state_name(state: AdministrativeState) -> &'static str {
    match state {
        AdministrativeState::Enabled => "enabled",
        AdministrativeState::Disabled => "disabled",
    }
}

async fn json_page<T: DeserializeOwned>(
    store: &Store,
    statement: &str,
    mesh: Uuid,
    cursor: Option<ApiPageCursor>,
    limit: u16,
) -> Result<Json<ApiPage<T>>, ApiError> {
    let rows = sqlx::query(statement)
        .bind(mesh)
        .bind(cursor.map(|cursor| cursor.timestamp))
        .bind(cursor.map(|cursor| cursor.id))
        .bind(i64::from(limit) + 1)
        .fetch_all(store.pool())
        .await?;
    rows_to_page(rows, limit)
}

fn rows_to_page<T: DeserializeOwned>(
    rows: Vec<sqlx::postgres::PgRow>,
    limit: u16,
) -> Result<Json<ApiPage<T>>, ApiError> {
    let has_more = rows.len() > usize::from(limit);
    let visible = rows.into_iter().take(usize::from(limit));
    let mut items = Vec::new();
    let mut last = None;
    for row in visible {
        let value = row.try_get::<Value, _>("item")?;
        items.push(serde_json::from_value(value).map_err(|_| {
            ApiError::internal("resource_projection", "Resource projection is invalid")
        })?);
        last = Some(ApiPageCursor {
            timestamp: row.try_get("cursor_time")?,
            id: row.try_get("id")?,
        });
    }
    Ok(Json(ApiPage {
        items,
        next_cursor: if has_more {
            last.map(encode_page_cursor)
        } else {
            None
        },
    }))
}

fn validate_policy_rule(rule: &PolicyRuleRequest) -> Result<(), ApiError> {
    if !matches!(rule.action.as_str(), "allow" | "deny")
        || peerward_types::RuleId::from_uuid(rule.id).is_err()
        || !valid_policy_selector(&rule.source)
        || !valid_policy_selector(&rule.destination)
        || match rule.protocol {
            peerward_types::PolicyProtocol::Any | peerward_types::PolicyProtocol::Icmp => {
                !rule.destination_ports.is_empty()
            }
            peerward_types::PolicyProtocol::Tcp | peerward_types::PolicyProtocol::Udp => rule
                .destination_ports
                .iter()
                .any(|span| span.first == 0 || span.first > span.last),
        }
    {
        return Err(ApiError::invalid(
            "invalid_policy_rule",
            "invalid policy rule",
        ));
    }
    Ok(())
}

fn valid_policy_selector(selector: &peerward_api::PolicySelectorRequest) -> bool {
    let peer_count = selector
        .peer_ids
        .iter()
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    let cidr_count = selector
        .cidrs
        .iter()
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    selector.peer_ids.len() <= peerward_types::MAX_SELECTOR_PEERS
        && selector.cidrs.len() <= peerward_types::MAX_SELECTOR_CIDRS
        && peer_count == selector.peer_ids.len()
        && cidr_count == selector.cidrs.len()
        && peerward_api::valid_labels(&selector.labels)
}

fn mutation(
    context: &AuthContext,
    mesh_id: Option<MeshId>,
    action: &str,
    event_type: &str,
    resource_type: &str,
    resource_id: Option<Uuid>,
) -> MutationRecord {
    MutationRecord {
        mesh_id,
        actor: context.actor.clone(),
        action: action.into(),
        event_type: event_type.into(),
        resource_type: resource_type.into(),
        resource_id,
        result: "success".into(),
        metadata: json!({"resource_id":resource_id}),
        correlation: CORRELATION_CONTEXT.try_with(|context| *context).ok(),
    }
}

fn event_to_sse(event: &OutboxEvent) -> Event {
    Event::default()
        .id(event.cursor.to_string())
        .event(event.event_type.clone())
        .json_data(event)
        .unwrap_or_else(|_| Event::default().event("error").data("serialization failed"))
}

fn audit_event_to_sse(event: &OutboxEvent) -> Event {
    Event::default()
        .id(event.cursor.to_string())
        .event("audit.changed")
        .json_data(json!({
            "cursor": event.cursor,
            "committed_at": event.committed_at,
        }))
        .unwrap_or_else(|_| Event::default().event("error").data("serialization failed"))
}

fn mesh_id(value: Uuid) -> Result<MeshId, ApiError> {
    MeshId::from_uuid(value).map_err(|_| ApiError::invalid_id())
}

fn peer_id(value: Uuid) -> Result<PeerId, ApiError> {
    PeerId::from_uuid(value).map_err(|_| ApiError::invalid_id())
}

fn relay_id(value: Uuid) -> Result<RelayId, ApiError> {
    RelayId::from_uuid(value).map_err(|_| ApiError::invalid_id())
}

fn decode_hex(value: &str, length: usize) -> Result<Vec<u8>, ApiError> {
    let bytes = hex::decode(value)
        .map_err(|_| ApiError::invalid("invalid_hex", "invalid hexadecimal value"))?;
    if bytes.len() != length {
        return Err(ApiError::invalid(
            "invalid_length",
            "invalid binary value length",
        ));
    }
    Ok(bytes)
}

fn random_secret() -> String {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

fn cookie_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|pair| {
            let (key, value) = pair.trim().split_once('=')?;
            (key == name).then_some(value)
        })
}

fn constant_time_digest_eq(left: [u8; 32], right: [u8; 32]) -> bool {
    bool::from(left.ct_eq(&right))
}

fn current_unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

include!("api_error.rs");
