const WEBHOOK_DELIVERY_PROJECTION:&str="SELECT d.mesh_id,d.webhook_id,d.id,d.created_at,jsonb_build_object(
    'id',d.id,'webhook_id',d.webhook_id,'webhook_version',d.webhook_version,'version',d.version,'event',d.event,
    'status',d.status,'attempts',d.attempts,'next_attempt_at',d.next_attempt_at,'result_code',d.result_code,
    'http_status',d.http_status,'created_at',d.created_at,'completed_at',d.completed_at) AS item FROM webhook_deliveries d";
async fn list_webhook_events(
    Extension(context): Extension<AuthContext>,
) -> Result<Json<Vec<&'static str>>, ApiError> {
    authorize(&context, &HeaderMap::new(), Capability::ResourceRead, false)?;
    Ok(Json(WEBHOOK_EVENTS.to_vec()))
}
async fn list_webhook_deliveries(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    Path((mesh, id)): Path<(Uuid, Uuid)>,
    Query(query): Query<ListQuery>,
) -> Result<Json<ApiPage<peerward_api::WebhookDeliveryResource>>, ApiError> {
    authorize(&context, &HeaderMap::new(), Capability::ResourceRead, false)?;
    mesh_id(mesh)?;
    let cursor = query.cursor()?;
    let limit = query.limit()?;
    let rows=sqlx::query(&format!("SELECT item,id,created_at AS cursor_time FROM ({WEBHOOK_DELIVERY_PROJECTION}) d WHERE mesh_id=$1 AND webhook_id=$5 AND ($2::timestamptz IS NULL OR (created_at,id)>($2,$3)) ORDER BY created_at,id LIMIT $4"))
        .bind(mesh).bind(cursor.map(|c|c.timestamp)).bind(cursor.map(|c|c.id)).bind(i64::from(limit)+1).bind(id).fetch_all(state.store.pool()).await?;
    rows_to_page(rows, limit)
}
async fn retry_webhook_delivery(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((mesh, id, delivery)): Path<(Uuid, Uuid, Uuid)>,
) -> Result<StatusCode, ApiError> {
    authorize(&context, &headers, Capability::TrustManage, true)?;
    let expected = require_if_match(&headers)?;
    let mut tx = state.store.begin_mutation().await?;
    sqlx::query("SELECT id FROM meshes WHERE id=$1 AND lifecycle='active' FOR UPDATE")
        .bind(mesh)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(ApiError::not_found)?;
    let hook: Option<(i64, bool)> = sqlx::query_as(
        "SELECT version,enabled FROM webhooks WHERE mesh_id=$1 AND id=$2 FOR UPDATE",
    )
    .bind(mesh)
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((version, true)) = hook else {
        return Err(ApiError::conflict(
            "webhook_disabled",
            "enable the webhook before retrying",
        ));
    };
    let changed=sqlx::query("UPDATE webhook_deliveries SET status='queued',attempts=0,next_attempt_at=clock_timestamp(),retry_until=clock_timestamp()+interval '24 hours',completed_at=NULL,result_code=NULL,http_status=NULL WHERE mesh_id=$1 AND id=$2 AND webhook_id=$3 AND version=$4 AND webhook_version=$5 AND status='failed'")
        .bind(mesh).bind(delivery).bind(id).bind(expected).bind(version).execute(&mut *tx).await?.rows_affected();
    if changed != 1 {
        return Err(ApiError::conflict(
            "version_conflict",
            "only a failed delivery of the unchanged webhook can be retried; reload its status",
        ));
    }
    let mut record = mutation(
        &context,
        Some(mesh_id(mesh)?),
        "webhook.retry",
        "webhook.retry_queued",
        "webhook",
        Some(id),
    );
    record.metadata = json!({"delivery_id":delivery});
    state.store.commit_mutation(tx, &record).await?;
    Ok(StatusCode::ACCEPTED)
}

#[cfg(test)]
mod webhook_validation_tests {
    use super::*;
    #[test]
    fn destinations_are_explicit_https_and_resolved_addresses_cannot_escape_public_scope() {
        for endpoint in [
            "http://example.com/notify",
            "https://name:secret@example.com/notify",
            "https://example.com/?secret=1",
            "https://example.com/#hook",
            "https://example.com:8443/notify",
            "https://127.0.0.1/",
            "https://169.254.169.254/",
            "https://[::1]/",
            "https://[::ffff:8.8.8.8]/",
            "https://router.home.arpa/",
            "https://localhost/",
        ] {
            assert!(webhook_url(endpoint).is_err(), "{endpoint}");
        }
        assert!(webhook_url("https://events.example.com/peerward").is_ok());
        assert!(webhook_addresses(vec!["1.1.1.1:443".parse().unwrap()]).is_ok());
        for values in [
            vec![],
            vec!["127.0.0.1:443"],
            vec!["1.1.1.1:443", "10.0.0.1:443"],
            vec!["1.1.1.1:80"],
        ] {
            assert!(
                webhook_addresses(values.iter().map(|v| v.parse().unwrap()).collect()).is_err()
            );
        }
        assert!(webhook_addresses(vec!["1.1.1.1:443".parse().unwrap(); 17]).is_err());
        let id = Uuid::new_v4();
        assert!((5..10).contains(&webhook_retry_delay(1, id)));
        assert!(webhook_retry_delay(10, id) <= 3604);
    }
}
