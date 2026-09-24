fn validate_limit(limit: u16) -> Result<(), StoreError> {
    if (1..=500).contains(&limit) {
        Ok(())
    } else {
        Err(StoreError::Invalid("limit"))
    }
}

fn validate_dns_label(value: &str) -> Result<(), StoreError> {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 63
        || !bytes[0].is_ascii_alphanumeric()
        || !bytes[bytes.len() - 1].is_ascii_alphanumeric()
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
    {
        return Err(StoreError::Invalid("DNS label"));
    }
    Ok(())
}

fn validate_json_labels(value: &Value) -> Result<(), StoreError> {
    let labels = value
        .as_object()
        .filter(|labels| labels.len() <= peerward_types::MAX_LABELS)
        .ok_or(StoreError::Invalid("labels"))?;
    if labels.iter().all(|(key, value)| {
        !key.is_empty()
            && key.len() <= 64
            && value
                .as_str()
                .is_some_and(|value| !value.is_empty() && value.len() <= 256)
    }) {
        Ok(())
    } else {
        Err(StoreError::Invalid("labels"))
    }
}

/// Converts one DNS suffix to its canonical lower-case IDNA ASCII storage form.
pub fn normalize_dns_suffix(value: &str) -> Result<String, StoreError> {
    let unrooted = value.strip_suffix('.').unwrap_or(value);
    if unrooted.is_empty() || unrooted.len() > 253 || unrooted.contains("..") {
        return Err(StoreError::Invalid("DNS suffix"));
    }
    let ascii = idna::domain_to_ascii(unrooted)
        .map_err(|_| StoreError::Invalid("DNS suffix"))?
        .to_ascii_lowercase();
    if ascii.len() > 253
        || ascii.split('.').count() < 2
        || ascii
            .split('.')
            .any(|label| validate_dns_label(label).is_err())
    {
        return Err(StoreError::Invalid("DNS suffix"));
    }
    Ok(ascii)
}

/// Domain-separated one-way digest used for stored secrets.
pub fn secret_digest(secret: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"peerward/stored-secret/v1\0");
    digest.update((secret.len() as u64).to_be_bytes());
    digest.update(secret);
    digest.finalize().into()
}

async fn allocate_address(
    transaction: &mut Transaction<'_, Postgres>,
    mesh_id: Uuid,
    secondary: bool,
) -> Result<IpAddr, StoreError> {
    let row = sqlx::query(
        "SELECT (CASE WHEN $2 THEN secondary_cidr ELSE address_cidr END)::text AS cidr, host(CASE WHEN $2 THEN secondary_gateway ELSE gateway END) AS gateway,host(CASE WHEN $2 THEN secondary_next_address ELSE next_address END) AS next_address,
                ARRAY(SELECT host(value) FROM unnest(reserved_addresses) value) AS reserved
         FROM meshes WHERE id=$1 FOR UPDATE",
    )
    .bind(mesh_id)
    .bind(secondary)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(StoreError::NotFound)?;
    let network: IpNet = row
        .try_get::<String, _>("cidr")?
        .parse()
        .map_err(|_| StoreError::Invalid("stored CIDR"))?;
    let gateway: IpAddr = row
        .try_get::<String, _>("gateway")?
        .parse()
        .map_err(|_| StoreError::Invalid("stored gateway"))?;
    let reserved: Vec<String> = row.try_get("reserved")?;
    let reserved: HashSet<IpAddr> = reserved
        .into_iter()
        .map(|value| {
            value
                .parse()
                .map_err(|_| StoreError::Invalid("stored reservation"))
        })
        .collect::<Result<_, _>>()?;
    let usable_host = |address: &IpAddr| {
        network.contains(address)
            && *address != network.network()
            && !(address.is_ipv4() && *address == network.broadcast())
    };
    let first = increment_ip(network.network())
        .filter(usable_host)
        .ok_or(StoreError::PoolExhausted)?;
    let mut candidate = row
        .try_get::<Option<String>, _>("next_address")?
        .map(|value| {
            value
                .parse()
                .map_err(|_| StoreError::Invalid("stored address cursor"))
        })
        .transpose()?
        .filter(usable_host)
        .unwrap_or(first);
    let start = candidate;
    loop {
        let unavailable = candidate == gateway
            || reserved.contains(&candidate)
            || sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(SELECT 1 FROM peer_addresses WHERE mesh_id=$1 AND address=$2::inet
                  AND (state='active' OR (state='quarantine' AND quarantine_until>clock_timestamp())))",
            )
            .bind(mesh_id)
            .bind(candidate.to_string())
            .fetch_one(&mut **transaction)
            .await?;
        let successor = increment_ip(candidate)
            .filter(usable_host)
            .unwrap_or(first);
        if !unavailable {
            sqlx::query(if secondary {
                "UPDATE meshes SET secondary_next_address=$1::inet WHERE id=$2"
            } else {
                "UPDATE meshes SET next_address=$1::inet WHERE id=$2"
            })
            .bind(successor.to_string())
            .bind(mesh_id)
            .execute(&mut **transaction)
            .await?;
            return Ok(candidate);
        }
        candidate = successor;
        if candidate == start {
            return Err(StoreError::PoolExhausted);
        }
    }
}

#[rustfmt::skip]
fn increment_ip(address: IpAddr) -> Option<IpAddr> {
    match address {
        IpAddr::V4(value) => u32::from(value).checked_add(1).map(std::net::Ipv4Addr::from).map(IpAddr::V4),
        IpAddr::V6(value) => u128::from(value).checked_add(1).map(std::net::Ipv6Addr::from).map(IpAddr::V6),
    }
}

// Runtime writers lock the parent before dependent rows, matching management
// deletion. A deletion waits for active writers; late writers see the new state.
async fn lock_enabled_peer(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    mesh: MeshId,
    peer: PeerId,
) -> Result<bool, StoreError> {
    // Acquire the same mutation lock before child locks: rotation and health
    // writers may also update Mesh revisions. A SHARE-to-UPDATE upgrade would
    // deadlock with another writer performing the same upgrade.
    let active: Option<String> =
        sqlx::query_scalar("SELECT lifecycle FROM meshes WHERE id=$1 FOR UPDATE")
            .bind(mesh.into_uuid())
            .fetch_optional(&mut **transaction)
            .await?;
    if active.as_deref() != Some("active") {
        return Ok(false);
    }
    Ok(sqlx::query("SELECT id FROM peers WHERE mesh_id=$1 AND id=$2 AND administrative_state='enabled' AND (admission_until IS NULL OR admission_until>clock_timestamp()) FOR SHARE")
        .bind(mesh.into_uuid()).bind(peer.into_uuid())
        .fetch_optional(&mut **transaction).await?.is_some())
}

async fn transition_credential(
    pool: &PgPool,
    table: &str,
    mesh_id: MeshId,
    serial: CredentialSerial,
    lifecycle: Lifecycle,
    actor: &str,
    resource_type: &str,
    expected_subject_version: Option<(Uuid, i64)>,
) -> Result<(), StoreError> {
    let allowed = ["mesh_authorities", "peer_credentials", "relay_credentials"];
    if !allowed.contains(&table) {
        return Err(StoreError::Invalid("credential table"));
    }
    let subject_column = match table {
        "mesh_authorities" => None,
        "peer_credentials" => Some("peer_id"),
        "relay_credentials" => Some("relay_id"),
        _ => return Err(StoreError::Invalid("credential table")),
    };
    let revision_updates = match table {
        "mesh_authorities" => {
            "authority_revision=authority_revision+1,directory_revision=directory_revision+1,\
             relay_revision=relay_revision+1,\
             service_revision=service_revision+1"
        }
        "peer_credentials" => {
            "directory_revision=directory_revision+1,service_revision=service_revision+1"
        }
        "relay_credentials" => "relay_revision=relay_revision+1",
        _ => return Err(StoreError::Invalid("credential table")),
    };
    let mut transaction = pool.begin().await?;
    sqlx::query("SELECT id FROM meshes WHERE id=$1 FOR UPDATE")
        .bind(mesh_id.into_uuid())
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(StoreError::NotFound)?;
    if let Some((subject, expected)) = expected_subject_version {
        let subject_table = match table {
            "mesh_authorities" => "mesh_authorities",
            "peer_credentials" => "peers",
            "relay_credentials" => "relays",
            _ => return Err(StoreError::Invalid("credential subject version")),
        };
        let visible_subject = if table == "peer_credentials" {
            " AND administrative_state<>'deleted'"
        } else {
            ""
        };
        let statement = format!(
            "SELECT version FROM {subject_table} WHERE mesh_id=$1 AND id=$2{visible_subject} FOR UPDATE"
        );
        let actual: i64 = sqlx::query_scalar(&statement)
            .bind(mesh_id.into_uuid())
            .bind(subject)
            .fetch_optional(&mut *transaction)
            .await?
            .ok_or(StoreError::NotFound)?;
        if actual != expected {
            return Err(StoreError::Conflict);
        }
    }
    let subject_projection = subject_column.unwrap_or("NULL::uuid");
    let select = format!(
        "SELECT id,lifecycle,{subject_projection} AS subject FROM {table}
         WHERE mesh_id=$1 AND serial=$2 FOR UPDATE"
    );
    let row = sqlx::query(&select)
        .bind(mesh_id.into_uuid())
        .bind(serial.into_uuid())
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(StoreError::NotFound)?;
    let id: Uuid = row.try_get("id")?;
    let current: String = row.try_get("lifecycle")?;
    let subject: Option<Uuid> = row.try_get("subject")?;
    if let Some((expected_subject, _)) = expected_subject_version
        && subject_column.is_some()
        && subject != Some(expected_subject)
    {
        return Err(StoreError::NotFound);
    }
    if current == lifecycle.as_str() {
        transaction.rollback().await?;
        return Ok(());
    }
    match lifecycle {
        Lifecycle::Active => {
            if current != "staged" {
                return Err(StoreError::Conflict);
            }
            let previous = if let (Some(column), Some(subject)) = (subject_column, subject) {
                let statement = format!(
                    "UPDATE {table} SET lifecycle='overlap',replacement_id=$1,
                     overlap_deadline=LEAST(not_after,clock_timestamp()+make_interval(
                       secs => LEAST(m.rotation_overlap_seconds,604800)::double precision))
                     FROM meshes m WHERE {table}.mesh_id=$2 AND {column}=$3
                     AND {table}.lifecycle='active' AND m.id={table}.mesh_id"
                );
                sqlx::query(&statement)
                    .bind(id)
                    .bind(mesh_id.into_uuid())
                    .bind(subject)
                    .execute(&mut *transaction)
                    .await?
                    .rows_affected()
            } else {
                let statement = format!(
                    "UPDATE {table} SET lifecycle='overlap',replacement_id=$1,
                     overlap_deadline=LEAST(not_after,clock_timestamp()+make_interval(
                       secs => LEAST(m.rotation_overlap_seconds,604800)::double precision))
                     FROM meshes m WHERE {table}.mesh_id=$2 AND {table}.lifecycle='active'
                     AND m.id={table}.mesh_id"
                );
                sqlx::query(&statement)
                    .bind(id)
                    .bind(mesh_id.into_uuid())
                    .execute(&mut *transaction)
                    .await?
                    .rows_affected()
            };
            let activate = format!(
                "UPDATE {table} SET lifecycle='active',overlap_deadline=NULL
                 WHERE id=$1 AND mesh_id=$2 AND lifecycle='staged'"
            );
            if sqlx::query(&activate)
                .bind(id)
                .bind(mesh_id.into_uuid())
                .execute(&mut *transaction)
                .await?
                .rows_affected()
                != 1
            {
                return Err(StoreError::Conflict);
            }
            let _ = previous;
        }
        Lifecycle::Overlap => {
            if current != "active" {
                return Err(StoreError::Conflict);
            }
            let statement = format!(
                "UPDATE {table} SET lifecycle='overlap',
                 overlap_deadline=LEAST(not_after,clock_timestamp()+make_interval(
                   secs => LEAST(m.rotation_overlap_seconds,604800)::double precision))
                 FROM meshes m WHERE {table}.id=$1 AND {table}.mesh_id=$2
                 AND m.id={table}.mesh_id"
            );
            sqlx::query(&statement)
                .bind(id)
                .bind(mesh_id.into_uuid())
                .execute(&mut *transaction)
                .await?;
        }
        Lifecycle::Revoked => {
            let statement = format!(
                "UPDATE {table} SET lifecycle='revoked',overlap_deadline=NULL
                 WHERE id=$1 AND mesh_id=$2 AND lifecycle<>'revoked'"
            );
            if sqlx::query(&statement)
                .bind(id)
                .bind(mesh_id.into_uuid())
                .execute(&mut *transaction)
                .await?
                .rows_affected()
                != 1
            {
                return Err(StoreError::Conflict);
            }
        }
        Lifecycle::Staged => return Err(StoreError::Conflict),
    }
    let revision = format!(
        "UPDATE meshes SET {revision_updates},
         revocation_revision=revocation_revision+1,updated_at=clock_timestamp() WHERE id=$1"
    );
    sqlx::query(&revision)
        .bind(mesh_id.into_uuid())
        .execute(&mut *transaction)
        .await?;
    if let Some((subject, _)) = expected_subject_version
        && table != "mesh_authorities"
    {
        let subject_table = if table == "peer_credentials" {
            "peers"
        } else {
            "relays"
        };
        sqlx::query(&format!(
            "UPDATE {subject_table} SET updated_at=clock_timestamp() WHERE mesh_id=$1 AND id=$2"
        ))
        .bind(mesh_id.into_uuid())
        .bind(subject)
        .execute(&mut *transaction)
        .await?;
    }
    mutation_records(
        &mut transaction,
        mesh_id,
        actor,
        &format!("{resource_type}.transition"),
        &format!("{resource_type}.transitioned"),
        resource_type,
        id,
        json!({"serial": serial, "lifecycle": lifecycle}),
    )
    .await?;
    transaction.commit().await?;
    Ok(())
}

async fn mutation_records(
    transaction: &mut Transaction<'_, Postgres>,
    mesh_id: MeshId,
    actor: &str,
    action: &str,
    event_type: &str,
    resource_type: &str,
    resource_id: Uuid,
    metadata: Value,
) -> Result<(), StoreError> {
    append_audit(
        transaction,
        Some(mesh_id),
        actor,
        action,
        resource_type,
        Some(resource_id),
        "success",
        metadata.clone(),
    )
    .await?;
    append_event(
        transaction,
        Some(mesh_id),
        event_type,
        resource_type,
        Some(resource_id),
        metadata,
    )
    .await?;
    Ok(())
}

async fn append_event(
    transaction: &mut Transaction<'_, Postgres>,
    mesh_id: Option<MeshId>,
    event_type: &str,
    resource_type: &str,
    resource_id: Option<Uuid>,
    payload: Value,
) -> Result<EventId, StoreError> {
    append_event_with_correlation(
        transaction,
        mesh_id,
        event_type,
        resource_type,
        resource_id,
        payload,
        None,
    )
    .await
}

async fn append_event_with_correlation(
    transaction: &mut Transaction<'_, Postgres>,
    mesh_id: Option<MeshId>,
    event_type: &str,
    resource_type: &str,
    resource_id: Option<Uuid>,
    payload: Value,
    correlation: Option<peerward_types::CorrelationContext>,
) -> Result<EventId, StoreError> {
    if event_type.is_empty()
        || event_type.len() > 128
        || resource_type.is_empty()
        || resource_type.len() > 64
        || !event_type.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
        })
        || !resource_type.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
        })
    {
        return Err(StoreError::Invalid("event type"));
    }
    let cursor = EventId::new();
    let encoded = serde_json::to_vec(&json!({
        "cursor": cursor,
        "mesh_id": mesh_id,
        "event_type": event_type,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "payload": &payload,
        "committed_at": OffsetDateTime::now_utc(),
        "request_id": correlation.map(|context| context.request_id),
        "traceparent": correlation.map(peerward_types::CorrelationContext::traceparent),
    }))
    .map_err(|_| StoreError::Invalid("event payload"))?;
    let sse_overhead = 4_usize
        .saturating_add(cursor.to_string().len())
        .saturating_add(8)
        .saturating_add(event_type.len())
        .saturating_add(7)
        .saturating_add(2);
    if encoded.len().saturating_add(sse_overhead) > peerward_types::MAX_SSE_EVENT_BYTES {
        return Err(StoreError::Invalid("event payload"));
    }
    let sequence: i64 = sqlx::query_scalar(
        "INSERT INTO event_outbox
         (cursor,mesh_id,event_type,resource_type,resource_id,payload,
          request_id,trace_id,span_id,trace_flags)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING sequence",
    )
    .bind(cursor.into_uuid())
    .bind(mesh_id.map(MeshId::into_uuid))
    .bind(event_type)
    .bind(resource_type)
    .bind(resource_id)
    .bind(payload)
    .bind(correlation.map(|context| context.request_id))
    .bind(correlation.map(|context| context.trace_id.to_vec()))
    .bind(correlation.map(|context| context.span_id.to_vec()))
    .bind(correlation.map(|context| i16::from(context.flags)))
    .fetch_one(&mut **transaction)
    .await?;
    sqlx::query(
        "UPDATE event_stream_state
         SET high_water_sequence=$1,high_water_cursor=$2 WHERE singleton",
    )
    .bind(sequence)
    .bind(cursor.into_uuid())
    .execute(&mut **transaction)
    .await?;
    sqlx::query("SELECT pg_notify($1, $2)")
        .bind(EVENT_CHANNEL)
        .bind(cursor.to_string())
        .execute(&mut **transaction)
        .await?;
    Ok(cursor)
}

include!("support_rows.rs");
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_digest_is_domain_separated_and_deterministic() {
        assert_eq!(secret_digest(b"abc"), secret_digest(b"abc"));
        assert_ne!(secret_digest(b"abc"), Sha256::digest(b"abc").as_slice());
        assert_ne!(secret_digest(b"abc"), secret_digest(b"abcd"));
    }

    #[test]
    fn roles_use_an_explicit_capability_matrix() {
        assert!(Role::Auditor.allows(Capability::StatusAuditRead));
        assert!(!Role::Auditor.allows(Capability::ResourceRead));
        assert!(Role::Viewer.allows(Capability::ResourceRead));
        assert!(!Role::Viewer.allows(Capability::ResourceWrite));
        assert!(Role::Operator.allows(Capability::ResourceWrite));
        assert!(!Role::Operator.allows(Capability::TrustManage));
        assert!(Role::Admin.allows(Capability::TrustManage));
    }

    #[test]
    fn mesh_validation_rejects_outside_gateway() {
        let request = NewMesh {
            name: "test".into(),
            address_cidr: "10.0.0.0/24".parse().unwrap(),
            gateway: "10.1.0.1".parse().unwrap(),
            dns_suffix: "test.mesh".into(),
            mtu: 1380,
            reserved: vec![],
            default_policy: DefaultPolicy::Deny,
            quarantine_seconds: 10,
            rotation_overlap_seconds: 10,
        };
        assert!(matches!(
            request.validate(),
            Err(StoreError::Invalid("mesh"))
        ));
    }
}
