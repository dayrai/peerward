#[cfg(all(test, feature = "postgres-integration"))]
mod webhook_worker_postgres_tests {
    use super::*;
    #[tokio::test]
    async fn worker_claims_are_exclusive_and_late_results_cannot_override_new_attempts() {
        let url = std::env::var("PEERWARD_TEST_DATABASE_URL").unwrap();
        assert!(url.parse::<sqlx::postgres::PgConnectOptions>()
            .is_ok_and(|options| options.get_database() == Some("peerward_test")));
        let store = Store::connect(&url, 8).await.unwrap();
        store.migrate().await.unwrap();
        let mesh = store
            .create_mesh(
                &peerward_store::NewMesh {
                    name: format!("webhook-worker-{}", Uuid::new_v4()),
                    address_cidr: "10.89.0.0/24".parse().unwrap(),
                    gateway: "10.89.0.1".parse().unwrap(),
                    dns_suffix: "worker.test".into(),
                    mtu: 1280,
                    reserved: vec![],
                    default_policy: peerward_store::DefaultPolicy::Deny,
                    quarantine_seconds: 3600,
                    rotation_overlap_seconds: 3600,
                },
                "test",
            )
            .await
            .unwrap()
            .id
            .into_uuid();
        let hook = Uuid::new_v4();
        sqlx::query("INSERT INTO webhooks(mesh_id,id,name,endpoint,enabled,event_types) VALUES($1,$2,'worker fixture','https://events.example.com/hook',true,ARRAY['peer.disabled'])")
            .bind(mesh).bind(hook).execute(store.pool()).await.unwrap();
        sqlx::query("INSERT INTO event_outbox(cursor,mesh_id,event_type,resource_type,payload) VALUES($1,$2,'peer.disabled','peer','{}')")
            .bind(Uuid::new_v4()).bind(mesh).execute(store.pool()).await.unwrap();
        let (first, second) = tokio::join!(
            claim_webhook(&store, Uuid::new_v4()),
            claim_webhook(&store, Uuid::new_v4())
        );
        let candidates = [first.unwrap(), second.unwrap()];
        assert_eq!(candidates.iter().filter(|v| v.is_some()).count(), 1);
        let first = candidates.into_iter().flatten().next().unwrap();
        assert_eq!(first.attempt, 1);
        sqlx::query("UPDATE webhook_deliveries SET lease_until=clock_timestamp()-interval '1 second' WHERE mesh_id=$1 AND id=$2")
            .bind(mesh).bind(first.id).execute(store.pool()).await.unwrap();
        let next = claim_webhook(&store, Uuid::new_v4())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(next.id, first.id);
        assert_eq!(next.attempt, 2);
        finish_webhook(
            &store,
            &first,
            WebhookResult {
                code: "delivered",
                status: Some(204),
                success: true,
                permanent: false,
            },
        )
        .await
        .unwrap();
        let status: String =
            sqlx::query_scalar("SELECT status FROM webhook_deliveries WHERE mesh_id=$1 AND id=$2")
                .bind(mesh)
                .bind(first.id)
                .fetch_one(store.pool())
                .await
                .unwrap();
        assert_eq!(status, "sending");
        finish_webhook(
            &store,
            &next,
            WebhookResult {
                code: "http_rejected",
                status: Some(429),
                success: false,
                permanent: false,
            },
        )
        .await
        .unwrap();
        assert!(
            claim_webhook(&store, Uuid::new_v4())
                .await
                .unwrap()
                .is_none(),
            "backoff is persisted"
        );
        sqlx::query("UPDATE webhook_deliveries SET next_attempt_at=clock_timestamp()-interval '1 second',attempts=10 WHERE mesh_id=$1 AND id=$2").bind(mesh).bind(first.id).execute(store.pool()).await.unwrap();
        assert!(
            claim_webhook(&store, Uuid::new_v4())
                .await
                .unwrap()
                .is_none()
        );
        let status: String =
            sqlx::query_scalar("SELECT status FROM webhook_deliveries WHERE mesh_id=$1 AND id=$2")
                .bind(mesh)
                .bind(first.id)
                .fetch_one(store.pool())
                .await
                .unwrap();
        assert_eq!(status, "failed");
        sqlx::query("UPDATE webhook_deliveries SET completed_at=clock_timestamp()-interval '8 days' WHERE mesh_id=$1 AND id=$2").bind(mesh).bind(first.id).execute(store.pool()).await.unwrap();
        assert!(
            claim_webhook(&store, Uuid::new_v4())
                .await
                .unwrap()
                .is_none()
        );
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM webhook_deliveries WHERE mesh_id=$1 AND id=$2",
        )
        .bind(mesh)
        .bind(first.id)
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(count, 0);
    }
}
