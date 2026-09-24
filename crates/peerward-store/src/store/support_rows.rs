fn mesh_from_row(row: sqlx::postgres::PgRow) -> Result<MeshRecord, StoreError> {
    let uuid: Uuid = row.try_get("id")?;
    Ok(MeshRecord {
        network_identifier: row.try_get("network_identifier")?,
        lease_seconds: u32::try_from(row.try_get::<i32, _>("lease_seconds")?)
            .map_err(|_| StoreError::Invalid("stored authorization duration"))?,
        lifecycle: row.try_get("lifecycle")?,
        lifecycle_revision: row.try_get("lifecycle_revision")?,
        lifecycle_job: row.try_get("lifecycle_job")?,
        id: MeshId::from_uuid(uuid).map_err(|_| StoreError::Invalid("stored mesh ID"))?,
        version: u64::try_from(row.try_get::<i64, _>("version")?)
            .map_err(|_| StoreError::Invalid("stored resource version"))?,
        name: row.try_get("name")?,
        address_cidr: row
            .try_get::<String, _>("cidr")?
            .parse()
            .map_err(|_| StoreError::Invalid("stored CIDR"))?,
        secondary_cidr: row
            .try_get::<String, _>("secondary_cidr")?
            .parse()
            .map_err(|_| StoreError::Invalid("stored secondary CIDR"))?,
        secondary_gateway: row
            .try_get::<String, _>("secondary_gateway")?
            .parse()
            .map_err(|_| StoreError::Invalid("stored secondary gateway"))?,
        gateway: row
            .try_get::<String, _>("gateway")?
            .parse()
            .map_err(|_| StoreError::Invalid("stored gateway"))?,
        dns_suffix: row.try_get("dns_suffix")?,
        mtu: u16::try_from(row.try_get::<i32, _>("mtu")?)
            .map_err(|_| StoreError::Invalid("stored MTU"))?,
        default_policy: match row.try_get::<String, _>("default_policy")?.as_str() {
            "allow" => DefaultPolicy::Allow,
            "deny" => DefaultPolicy::Deny,
            _ => return Err(StoreError::Invalid("stored default policy")),
        },
        policy_revision: u64::try_from(row.try_get::<i64, _>("policy_revision")?)
            .map_err(|_| StoreError::Invalid("stored revision"))?,
        authority_revision: u64::try_from(row.try_get::<i64, _>("authority_revision")?)
            .map_err(|_| StoreError::Invalid("stored revision"))?,
        directory_revision: u64::try_from(row.try_get::<i64, _>("directory_revision")?)
            .map_err(|_| StoreError::Invalid("stored revision"))?,
        relay_revision: u64::try_from(row.try_get::<i64, _>("relay_revision")?)
            .map_err(|_| StoreError::Invalid("stored revision"))?,
        service_revision: u64::try_from(row.try_get::<i64, _>("service_revision")?)
            .map_err(|_| StoreError::Invalid("stored revision"))?,
        revocation_revision: u64::try_from(row.try_get::<i64, _>("revocation_revision")?)
            .map_err(|_| StoreError::Invalid("stored revision"))?,
    })
}

fn event_from_row(row: sqlx::postgres::PgRow) -> Result<OutboxEvent, StoreError> {
    let cursor: Uuid = row.try_get("cursor")?;
    let mesh: Option<Uuid> = row.try_get("mesh_id")?;
    let request_id: Option<Uuid> = row.try_get("request_id")?;
    let correlation = request_id
        .map(|request_id| {
            let trace_id: Vec<u8> = row.try_get("trace_id")?;
            let span_id: Vec<u8> = row.try_get("span_id")?;
            let flags: i16 = row.try_get("trace_flags")?;
            peerward_types::CorrelationContext::from_parts(
                request_id,
                trace_id
                    .try_into()
                    .map_err(|_| StoreError::Invalid("stored trace ID"))?,
                span_id
                    .try_into()
                    .map_err(|_| StoreError::Invalid("stored span ID"))?,
                u8::try_from(flags).map_err(|_| StoreError::Invalid("stored trace flags"))?,
            )
            .map_err(|_| StoreError::Invalid("stored trace context"))
        })
        .transpose()?;
    Ok(OutboxEvent {
        sequence: row.try_get("sequence")?,
        cursor: EventId::from_uuid(cursor)
            .map_err(|_| StoreError::Invalid("stored event cursor"))?,
        mesh_id: mesh
            .map(MeshId::from_uuid)
            .transpose()
            .map_err(|_| StoreError::Invalid("stored mesh ID"))?,
        event_type: row.try_get("event_type")?,
        resource_type: row.try_get("resource_type")?,
        resource_id: row.try_get("resource_id")?,
        payload: row.try_get("payload")?,
        committed_at: row.try_get("committed_at")?,
        request_id,
        traceparent: correlation.map(peerward_types::CorrelationContext::traceparent),
    })
}

fn page_from_rows<T: Serialize>(
    rows: Vec<sqlx::postgres::PgRow>,
    limit: u16,
    convert: impl Fn(sqlx::postgres::PgRow) -> Result<T, StoreError>,
) -> Result<Page<T>, StoreError> {
    let has_more = rows.len() > usize::from(limit);
    let mut items = Vec::new();
    let mut next_cursor = None;
    for row in rows.into_iter().take(usize::from(limit)) {
        next_cursor = Some(PageCursor {
            timestamp: row.try_get("cursor_time")?,
            id: row.try_get("id")?,
        });
        items.push(convert(row)?);
    }
    Ok(Page {
        items,
        next_cursor: has_more.then_some(next_cursor).flatten(),
    })
}
