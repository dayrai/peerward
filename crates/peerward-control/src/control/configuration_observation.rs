async fn get_peer_configuration_receipts(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    Path((mesh, peer)): Path<(Uuid, Uuid)>,
) -> Result<Json<Value>, ApiError> {
    authorize(&context, &HeaderMap::new(), Capability::ResourceRead, false)?;
    mesh_id(mesh)?;
    peer_id(peer)?;
    sqlx::query("SELECT id FROM peers WHERE mesh_id=$1 AND id=$2")
        .bind(mesh)
        .bind(peer)
        .fetch_optional(state.store.pool())
        .await?
        .ok_or_else(ApiError::not_found)?;
    let latest:Option<Vec<u8>>=sqlx::query_scalar("SELECT body FROM signed_state_revisions WHERE mesh_id=$1 AND kind='configuration' ORDER BY revision DESC LIMIT 1")
        .bind(mesh).fetch_optional(state.store.pool()).await?;
    let latest = latest
        .map(|bytes| serde_json::from_slice::<peerward_management::ConfigurationDelivery>(&bytes))
        .transpose()
        .map_err(|_| publisher_error())?;
    let rows=sqlx::query("SELECT c.category,c.configuration_version,encode(c.configuration_digest,'hex') AS digest,c.lease_sequence,c.result,c.reason,c.received_at,s.body
        FROM configuration_receipts c LEFT JOIN signed_state_revisions s ON s.mesh_id=c.mesh_id AND s.kind='configuration' AND s.revision=c.lease_sequence
        WHERE c.mesh_id=$1 AND c.peer_id=$2 ORDER BY c.category")
        .bind(mesh).bind(peer).fetch_all(state.store.pool()).await?;
    let mut categories = serde_json::Map::new();
    for category in ["core", "routes", "dns", "firewall"] {
        let value = if let Some(row) = rows
            .iter()
            .find(|row| row.get::<String, _>("category") == category)
        {
            let version = row.try_get::<i64, _>("configuration_version")?;
            let digest = row.try_get::<String, _>("digest")?;
            let result = row.try_get::<String, _>("result")?;
            let matches = latest.as_ref().is_some_and(|delivery| {
                i64::try_from(delivery.manifest.manifest.version).ok() == Some(version)
                    && hex::encode(delivery.lease.lease.configuration_digest) == digest
            });
            let observed = row
                .try_get::<Option<Vec<u8>>, _>("body")?
                .map(|bytes| {
                    serde_json::from_slice::<peerward_management::ConfigurationDelivery>(&bytes)
                })
                .transpose()
                .map_err(|_| publisher_error())?;
            let expired = observed
                .as_ref()
                .is_none_or(|delivery| delivery.lease.lease.valid_until <= current_unix_seconds());
            json!({"status":if expired {"expired"}else if matches {result.as_str()}else{"pending_confirmation"},"lease_valid_until":observed.map(|delivery|delivery.lease.lease.valid_until),"version":version,"digest":digest,"lease_sequence":row.try_get::<i64,_>("lease_sequence")?,
                "reason":row.try_get::<Option<String>,_>("reason")?,"observed_at":row.try_get::<OffsetDateTime,_>("received_at")?})
        } else {
            json!({"status":"unknown"})
        };
        categories.insert(category.into(), value);
    }
    Ok(Json(
        json!({"peer_id":peer,"configuration_version":latest.as_ref().map(|delivery|delivery.manifest.manifest.version),
        "published_lease_valid_until":latest.as_ref().map(|delivery|delivery.lease.lease.valid_until),"categories":categories,"connectivity":"unknown"}),
    ))
}
