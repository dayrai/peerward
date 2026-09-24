struct WebhookWork {
    mesh: Uuid,
    webhook: Uuid,
    id: Uuid,
    owner: Uuid,
    version: i64,
    attempt: u32,
    endpoint: String,
    event: peerward_management::WebhookEvent,
}
struct WebhookResult {
    code: &'static str,
    status: Option<u16>,
    success: bool,
    permanent: bool,
}
impl WebhookResult {
    const fn failure(code: &'static str, permanent: bool) -> Self {
        Self {
            code,
            status: None,
            success: false,
            permanent,
        }
    }
}
async fn claim_webhook(store: &Store, owner: Uuid) -> Result<Option<WebhookWork>, ApiError> {
    let mut tx = store.begin_mutation().await?;
    // Bounded housekeeping. Completed deliveries are retained for seven days;
    // full queues increment a visible drop counter rather than blocking mutations.
    sqlx::query("WITH old AS (SELECT mesh_id,id FROM webhook_deliveries WHERE completed_at<clock_timestamp()-interval '7 days' ORDER BY completed_at LIMIT 100) DELETE FROM webhook_deliveries d USING old WHERE d.mesh_id=old.mesh_id AND d.id=old.id")
        .execute(&mut *tx).await?;
    sqlx::query("WITH expired AS (SELECT mesh_id,id FROM webhook_deliveries WHERE status IN ('queued','sending') AND (lease_until IS NULL OR lease_until<=clock_timestamp()) AND (retry_until<=clock_timestamp() OR attempts>=10) ORDER BY next_attempt_at LIMIT 100) UPDATE webhook_deliveries d SET status='failed',result_code='retry_exhausted',completed_at=clock_timestamp(),lease_owner=NULL,lease_until=NULL FROM expired WHERE d.mesh_id=expired.mesh_id AND d.id=expired.id")
        .execute(&mut *tx).await?;
    let row=sqlx::query("SELECT d.mesh_id,d.webhook_id,d.id,d.webhook_version,d.attempts,d.event,w.endpoint FROM webhook_deliveries d JOIN webhooks w ON w.mesh_id=d.mesh_id AND w.id=d.webhook_id JOIN meshes m ON m.id=d.mesh_id WHERE m.lifecycle='active' AND w.enabled AND w.version=d.webhook_version AND d.status IN ('queued','sending') AND d.next_attempt_at<=clock_timestamp() AND (d.lease_until IS NULL OR d.lease_until<=clock_timestamp()) AND d.attempts<10 AND d.retry_until>clock_timestamp() ORDER BY d.next_attempt_at,d.id FOR UPDATE OF d SKIP LOCKED LIMIT 1")
        .fetch_optional(&mut *tx).await?;
    let Some(row) = row else {
        tx.commit().await?;
        return Ok(None);
    };
    let mesh: Uuid = row.try_get("mesh_id")?;
    let id: Uuid = row.try_get("id")?;
    sqlx::query("UPDATE webhook_deliveries SET status='sending',attempts=attempts+1,lease_owner=$3,lease_until=clock_timestamp()+interval '15 seconds' WHERE mesh_id=$1 AND id=$2")
        .bind(mesh).bind(id).bind(owner).execute(&mut *tx).await?;
    let work = WebhookWork {
        mesh,
        id,
        owner,
        webhook: row.try_get("webhook_id")?,
        version: row.try_get("webhook_version")?,
        attempt: u32::try_from(row.try_get::<i32, _>("attempts")?)
            .map_err(|_| publisher_error())?
            + 1,
        endpoint: row.try_get("endpoint")?,
        event: serde_json::from_value(row.try_get("event")?).map_err(|_| publisher_error())?,
    };
    tx.commit().await?;
    Ok(Some(work))
}
async fn finish_webhook(
    store: &Store,
    work: &WebhookWork,
    result: WebhookResult,
) -> Result<(), ApiError> {
    let terminal = result.success || result.permanent || work.attempt >= 10;
    let status = if result.success {
        "succeeded"
    } else if terminal {
        "failed"
    } else {
        "queued"
    };
    let delay = webhook_retry_delay(work.attempt, work.id);
    sqlx::query("UPDATE webhook_deliveries SET status=$5,result_code=$6,http_status=$7,lease_owner=NULL,lease_until=NULL,next_attempt_at=clock_timestamp()+make_interval(secs=>$8::double precision),completed_at=CASE WHEN $9 THEN clock_timestamp() ELSE NULL END WHERE mesh_id=$1 AND id=$2 AND lease_owner=$3 AND attempts=$4 AND status='sending' AND lease_until>clock_timestamp()")
        .bind(work.mesh).bind(work.id).bind(work.owner).bind(i32::try_from(work.attempt).map_err(|_|publisher_error())?)
        .bind(status).bind(result.code).bind(result.status.map(i32::from)).bind(i64::from(delay)).bind(terminal).execute(store.pool()).await?;
    Ok(())
}
fn webhook_retry_delay(attempt: u32, id: Uuid) -> u32 {
    let exponential = 5_u32
        .saturating_mul(2_u32.saturating_pow(attempt.saturating_sub(1).min(10)))
        .min(3600);
    exponential + u32::from(id.as_bytes()[0]) % 5
}
fn webhook_addresses(addresses: Vec<SocketAddr>) -> Result<Vec<SocketAddr>, WebhookResult> {
    if addresses.is_empty()
        || addresses.len() > 16
        || addresses
            .iter()
            .any(|addr| addr.port() != 443 || !peerward_management::internet_destination(addr.ip()))
    {
        return Err(WebhookResult::failure("destination_rejected", true));
    }
    Ok(addresses)
}
async fn deliver_webhook(
    store: &Store,
    registry: &IssuerRegistry,
    work: &WebhookWork,
) -> WebhookResult {
    let result=tokio::time::timeout(Duration::from_secs(8),async {
        let url=webhook_url(&work.endpoint).map_err(|_|WebhookResult::failure("destination_rejected",true))?;
        let host=url.host_str().ok_or_else(||WebhookResult::failure("destination_rejected",true))?;
        let resolved=match url.host() {
            Some(url::Host::Ipv4(ip)) => vec![SocketAddr::new(ip.into(),443)],
            Some(url::Host::Ipv6(ip)) => vec![SocketAddr::new(ip.into(),443)],
            _ => tokio::net::lookup_host((host,443)).await.map_err(|_|WebhookResult::failure("dns_unavailable",false))?.take(17).collect(),
        };
        let addresses=webhook_addresses(resolved)?;
        let issuer=webhook_issuer(store,registry,work.mesh).await.map_err(|_|WebhookResult::failure("signer_unavailable",false))?
            .ok_or_else(||WebhookResult::failure("signer_unavailable",false))?;
        let notice=peerward_management::WebhookNotification {version:1,mesh_id:mesh_id(work.mesh).map_err(|_|WebhookResult::failure("invalid_event",true))?,webhook_id:work.webhook,delivery_id:work.id,attempt:work.attempt,sent_at:current_unix_seconds(),event:work.event.clone()};
        let (body,signature)=issuer.directory.sign_webhook(&notice).map_err(|_|WebhookResult::failure("event_or_clock_invalid",false))?;
        // Check version immediately before opening the pinned destination. A
        // concurrent cancellation cannot retract bytes already on the wire.
        let active:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM webhooks WHERE mesh_id=$1 AND id=$2 AND version=$3 AND enabled)")
            .bind(work.mesh).bind(work.webhook).bind(work.version).fetch_one(store.pool()).await.map_err(|_|WebhookResult::failure("state_unavailable",false))?;
        if !active {return Err(WebhookResult::failure("webhook_changed",true));}
        let client=webhook_http_client(host,&addresses).build().map_err(|_|WebhookResult::failure("transport_unavailable",false))?;
        webhook_http_send(&client,url,work.id,body,signature).await

    }).await;
    match result {
        Ok(Ok(result) | Err(result)) => result,
        Err(_) => WebhookResult::failure("delivery_timeout", false),
    }
}
async fn run_webhooks(store: Store, registry: IssuerRegistry) {
    let owner = Uuid::new_v4();
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        match claim_webhook(&store, owner).await {
            Ok(Some(work)) => {
                let result = deliver_webhook(&store, &registry, &work).await;
                if let Err(error) = finish_webhook(&store, &work, result).await {
                    tracing::warn!(
                        ?error,
                        "Webhook result persistence failed; fenced retry remains queued"
                    );
                }
            }
            Ok(None) => {}
            Err(error) => tracing::warn!(?error, "Webhook worker state unavailable"),
        }
    }
}

/// Production callers have already enforced HTTPS, public addresses and DNS pinning.
async fn webhook_http_send(
    client: &oidc_reqwest::Client,
    url: Url,
    id: Uuid,
    body: Vec<u8>,
    signature: [u8; 64],
) -> Result<WebhookResult, WebhookResult> {
    let response = client
        .post(url)
        .header("content-type", "application/json")
        .header(
            "peerward-signature",
            format!("ed25519={}", URL_SAFE_NO_PAD.encode(signature)),
        )
        .header("peerward-delivery-id", id.to_string())
        .body(body)
        .send()
        .await
        .map_err(|_| WebhookResult::failure("transport_failed", false))?;
    let status = response.status().as_u16();
    // Never follow redirects or read unbounded receiver response bodies.
    Ok(WebhookResult {
        code: if (200..300).contains(&status) {
            "delivered"
        } else if (300..400).contains(&status) {
            "redirect_rejected"
        } else {
            "http_rejected"
        },
        status: Some(status),
        success: (200..300).contains(&status),
        permanent: (300..500).contains(&status) && ![408, 429].contains(&status),
    })
}

fn webhook_http_client(host: &str, addresses: &[SocketAddr]) -> oidc_reqwest::ClientBuilder {
    oidc_reqwest::Client::builder()
        .redirect(oidc_reqwest::redirect::Policy::none())
        .no_proxy()
        .resolve_to_addrs(host, addresses)
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(5))
}
