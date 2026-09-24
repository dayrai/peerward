#[cfg(all(test, feature = "postgres-integration"))]
mod relay_capacity_tests {
    use super::*;

    #[tokio::test]
    async fn relay_capacity_is_host_scoped_replay_bounded_and_observational() {
        let database = std::env::var("PEERWARD_TEST_DATABASE_URL").unwrap();
        assert!(database.parse::<sqlx::postgres::PgConnectOptions>()
            .is_ok_and(|options| options.get_database() == Some("peerward_test")));
        let store = Store::connect(&database, 4).await.unwrap();
        store.migrate().await.unwrap();
        let (_, rx) = watch::channel(0);
        let state = application_state(
            store.clone(),
            AuthConfig {
                development_bearer_token: None,
                oidc: None,
                bootstrap_token: None,
            },
            IssuerRegistry::default(),
            Arc::new(ControlMetrics::default()),
            rx,
        );
        let host = Uuid::new_v4();
        let other = Uuid::new_v4();
        for id in [host, other] {
            sqlx::query("INSERT INTO relay_hosts(id,name,certificate_sha256,peer_endpoints,backbone_endpoints) VALUES($1,'capacity-test',$2,ARRAY['tcp://127.0.0.1:27777'],ARRAY['tcp://127.0.0.1:27778'])")
                .bind(id).bind(id.as_bytes().repeat(2)).execute(store.pool()).await.unwrap();
        }
        let nonce =
            relay_capacity_challenge(Extension(RelayHostIdentity(host)), State(state.clone()))
                .await
                .unwrap()
                .0
                .nonce;
        assert_eq!(
            relay_capacity_challenge(Extension(RelayHostIdentity(host)), State(state.clone()))
                .await
                .unwrap()
                .0
                .nonce,
            nonce
        );
        let mut sample = RelayCapacityReport {
            nonce,
            process_id: Uuid::new_v4(),
            uptime_millis: 1000,
            received_bytes: 10,
            accepted_bytes: 20,
            authenticated_peer_sessions: 1,
            authenticated_backbone_sessions: 0,
            session_limit: 1024,
            mesh_contexts: 1,
            router_queued_messages: 0,
            router_queued_encoded_bytes: 0,
            backbone_pending_slots: 0,
            audit_pending_slots: 0,
            no_route_total: 0,
            queue_full_total: 0,
            invalid_forwarded_frames_total: 0,
            audit_queued_total: 0,
            audit_dropped_total: 0,
        };
        assert!(
            relay_capacity_report(
                Extension(RelayHostIdentity(other)),
                State(state.clone()),
                Json(sample.clone())
            )
            .await
            .is_err()
        );
        // An expired nonce does not authorize a recent-looking observation.
        sqlx::query("UPDATE relay_host_capacity SET nonce_created_at=clock_timestamp()-interval '31 seconds' WHERE host_id=$1")
            .bind(host).execute(store.pool()).await.unwrap();
        assert!(
            relay_capacity_report(
                Extension(RelayHostIdentity(host)),
                State(state.clone()),
                Json(sample.clone())
            )
            .await
            .is_err()
        );
        sample.nonce =
            relay_capacity_challenge(Extension(RelayHostIdentity(host)), State(state.clone()))
                .await
                .unwrap()
                .0
                .nonce;
        let (first, duplicate) = tokio::join!(
            relay_capacity_report(
                Extension(RelayHostIdentity(host)),
                State(state.clone()),
                Json(sample.clone())
            ),
            relay_capacity_report(
                Extension(RelayHostIdentity(host)),
                State(state.clone()),
                Json(sample.clone())
            )
        );
        assert_eq!(first.unwrap(), StatusCode::NO_CONTENT);
        assert_eq!(duplicate.unwrap(), StatusCode::NO_CONTENT);
        sqlx::query("UPDATE relay_host_capacity SET observed_at=clock_timestamp()-interval '31 seconds' WHERE host_id=$1")
            .bind(host).execute(store.pool()).await.unwrap();
        let before: OffsetDateTime =
            sqlx::query_scalar("SELECT observed_at FROM relay_host_capacity WHERE host_id=$1")
                .bind(host)
                .fetch_one(store.pool())
                .await
                .unwrap();
        relay_capacity_report(
            Extension(RelayHostIdentity(host)),
            State(state.clone()),
            Json(sample.clone()),
        )
        .await
        .unwrap();
        let after: OffsetDateTime =
            sqlx::query_scalar("SELECT observed_at FROM relay_host_capacity WHERE host_id=$1")
                .bind(host)
                .fetch_one(store.pool())
                .await
                .unwrap();
        assert_eq!(before, after, "retry cannot renew freshness");
        sample.received_bytes = 11;
        assert!(
            relay_capacity_report(
                Extension(RelayHostIdentity(host)),
                State(state.clone()),
                Json(sample.clone())
            )
            .await
            .is_err()
        );
        sample.nonce =
            relay_capacity_challenge(Extension(RelayHostIdentity(host)), State(state.clone()))
                .await
                .unwrap()
                .0
                .nonce;
        sample.received_bytes = 9;
        assert!(
            relay_capacity_report(
                Extension(RelayHostIdentity(host)),
                State(state.clone()),
                Json(sample.clone())
            )
            .await
            .is_err()
        );
        sample.received_bytes = 110;
        sample.accepted_bytes = 220;
        sample.uptime_millis = 2000;
        sample.queue_full_total = 2;
        relay_capacity_report(
            Extension(RelayHostIdentity(host)),
            State(state.clone()),
            Json(sample.clone()),
        )
        .await
        .unwrap();
        let auth = AuthContext {
            actor: "test".into(),
            role: Role::Admin,
            source: AuthSource::Bearer,
        };
        let runner = AuthContext {
            actor: "runner:test".into(),
            role: Role::Admin,
            source: AuthSource::DeploymentRunner(Uuid::new_v4()),
        };
        assert!(
            get_relay_capacity(State(state.clone()), Extension(runner.clone()), Path(host))
                .await
                .is_err()
        );
        assert!(
            operations_status(State(state.clone()), Extension(runner))
                .await
                .is_err()
        );
        let operations = operations_status(State(state.clone()), Extension(auth.clone()))
            .await
            .unwrap()
            .0;
        assert_eq!(operations["audit"]["fresh"], true);
        assert!(operations["audit"]["storage_bytes"].as_u64().unwrap() > 0);
        assert!(operations["audit"]["estimated_growth_rows_per_hour"].is_null());
        assert!(operations["latest_successful_backup"].is_null());
        let (one, two) = tokio::join!(sample_audit_capacity(&state), sample_audit_capacity(&state));
        assert_eq!(
            one, two,
            "concurrent callers share one bounded audit sample"
        );
        let value = get_relay_capacity(State(state.clone()), Extension(auth.clone()), Path(host))
            .await
            .unwrap()
            .0;
        assert_eq!(value["fresh"], true);
        assert_eq!(value["last_interval"]["received_bytes"], 100);
        assert_eq!(value["last_interval"]["queue_full"], 2);
        assert!(value["report"].get("nonce").is_none());
        // A process restart resets the baseline, never synthesizes a negative rate.
        sample.nonce =
            relay_capacity_challenge(Extension(RelayHostIdentity(host)), State(state.clone()))
                .await
                .unwrap()
                .0
                .nonce;
        sample.process_id = Uuid::new_v4();
        sample.uptime_millis = 1;
        sample.received_bytes = 0;
        relay_capacity_report(
            Extension(RelayHostIdentity(host)),
            State(state.clone()),
            Json(sample.clone()),
        )
        .await
        .unwrap();
        assert!(
            get_relay_capacity(State(state.clone()), Extension(auth.clone()), Path(host))
                .await
                .unwrap()
                .0["last_interval"]
                .is_null()
        );
        sqlx::query("UPDATE relay_hosts SET enabled=false WHERE id=$1")
            .bind(host)
            .execute(store.pool())
            .await
            .unwrap();
        assert!(
            relay_capacity_report(
                Extension(RelayHostIdentity(host)),
                State(state.clone()),
                Json(sample)
            )
            .await
            .is_err()
        );
        assert!(
            relay_capacity_challenge(Extension(RelayHostIdentity(host)), State(state.clone()))
                .await
                .is_err()
        );
        assert_eq!(
            get_relay_capacity(State(state), Extension(auth), Path(host))
                .await
                .unwrap()
                .0["fresh"],
            false
        );
    }
}
