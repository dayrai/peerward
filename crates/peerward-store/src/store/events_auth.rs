impl Store {
    /// Resolves an optional public cursor without treating an unknown UUID as sequence zero.
    pub async fn event_replay_start(
        &self,
        after: Option<EventId>,
    ) -> Result<EventReplayStart, StoreError> {
        let state = sqlx::query(
            "SELECT state.high_water_sequence,state.high_water_cursor,
                    retained.cursor AS retained_cursor
             FROM event_stream_state state LEFT JOIN event_outbox retained
               ON retained.sequence=state.high_water_sequence
             WHERE state.singleton",
        )
        .fetch_one(&self.pool)
        .await?;
        let high_water_sequence: i64 = state.try_get("high_water_sequence")?;
        let high_water_cursor: Option<Uuid> = state.try_get("high_water_cursor")?;
        let retained_cursor: Option<Uuid> = state.try_get("retained_cursor")?;
        if retained_cursor.is_some() && retained_cursor != high_water_cursor {
            return Err(StoreError::Invalid("event high water"));
        }
        let Some(after) = after else {
            return Ok(EventReplayStart {
                after_sequence: high_water_sequence,
                cursor: retained_cursor
                    .map(EventId::from_uuid)
                    .transpose()
                    .map_err(|_| StoreError::Invalid("stored event cursor"))?,
            });
        };
        let sequence = sqlx::query_scalar("SELECT sequence FROM event_outbox WHERE cursor=$1")
            .bind(after.into_uuid())
            .fetch_optional(&self.pool)
            .await?
            .ok_or(StoreError::EventCursorExpired)?;
        Ok(EventReplayStart {
            after_sequence: sequence,
            cursor: Some(after),
        })
    }

    /// Replays mesh-scoped committed events after one durable numeric high-water mark.
    pub async fn events_after_sequence(
        &self,
        mesh_id: MeshId,
        after: i64,
        limit: u16,
    ) -> Result<Vec<OutboxEvent>, StoreError> {
        validate_limit(limit)?;
        if after < 0 {
            return Err(StoreError::Invalid("event sequence"));
        }
        let rows = sqlx::query(
            "SELECT sequence,cursor,mesh_id,event_type,resource_type,resource_id,payload,committed_at,
                    request_id,trace_id,span_id,trace_flags
             FROM event_outbox WHERE sequence>$1 AND (mesh_id=$2 OR mesh_id IS NULL)
             ORDER BY sequence LIMIT $3",
        )
        .bind(after)
        .bind(mesh_id.into_uuid())
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(event_from_row).collect()
    }

    /// Replays every committed event after one internal sequence.
    pub async fn events_after_global_sequence(
        &self,
        after: i64,
        limit: u16,
    ) -> Result<Vec<OutboxEvent>, StoreError> {
        validate_limit(limit)?;
        if after < 0 {
            return Err(StoreError::Invalid("event sequence"));
        }
        let rows = sqlx::query(
            "SELECT sequence,cursor,mesh_id,event_type,resource_type,resource_id,payload,committed_at,
                    request_id,trace_id,span_id,trace_flags
             FROM event_outbox WHERE sequence>$1 ORDER BY sequence LIMIT $2",
        )
        .bind(after)
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(event_from_row).collect()
    }

    /// Reads one Relay catch-up page and reports whether pruning invalidated its sequence.
    pub async fn event_batch_after_sequence(
        &self,
        mesh_id: MeshId,
        after: i64,
        limit: u16,
    ) -> Result<EventBatch, StoreError> {
        validate_limit(limit)?;
        if after < 0 {
            return Err(StoreError::Invalid("event sequence"));
        }
        let state = sqlx::query(
            "SELECT high_water_sequence,oldest_retained_sequence
             FROM event_stream_state WHERE singleton",
        )
        .fetch_one(&self.pool)
        .await?;
        let high_water_sequence: i64 = state.try_get("high_water_sequence")?;
        let oldest_retained_sequence: i64 = state.try_get("oldest_retained_sequence")?;
        let retention_gap = after < oldest_retained_sequence.saturating_sub(1);
        let events = if retention_gap {
            Vec::new()
        } else {
            self.events_after_sequence(mesh_id, after, limit).await?
        };
        Ok(EventBatch {
            events,
            high_water_sequence,
            retention_gap,
        })
    }

    /// Replays committed outbox events after a UUID cursor.
    pub async fn events_after(
        &self,
        after: Option<EventId>,
        limit: u16,
    ) -> Result<Vec<OutboxEvent>, StoreError> {
        validate_limit(limit)?;
        let start = self.event_replay_start(after).await?;
        let rows = sqlx::query(
            "SELECT sequence, cursor, mesh_id, event_type, resource_type, resource_id,
                    payload, committed_at, request_id, trace_id, span_id, trace_flags
             FROM event_outbox
             WHERE sequence > $1
             ORDER BY sequence LIMIT $2",
        )
        .bind(start.after_sequence)
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(event_from_row).collect()
    }

    /// Persists a short-lived one-use OIDC flow; state remains digest-only.
    pub async fn create_oidc_flow(&self, flow: &NewOidcFlow) -> Result<Uuid, StoreError> {
        if flow.expires_at <= OffsetDateTime::now_utc() {
            return Err(StoreError::Invalid("OIDC expiry"));
        }
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO oidc_flows
             (id,state_digest,nonce_digest,pkce_verifier_digest,nonce_secret,
              pkce_verifier_secret,redirect_uri,expires_at,return_to,reauthenticate)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
        )
        .bind(id)
        .bind(secret_digest(flow.state.as_bytes()).as_slice())
        .bind(secret_digest(flow.nonce.as_bytes()).as_slice())
        .bind(secret_digest(flow.pkce_verifier.as_bytes()).as_slice())
        .bind(&flow.nonce)
        .bind(&flow.pkce_verifier)
        .bind(&flow.redirect_uri)
        .bind(flow.expires_at)
        .bind(&flow.return_to)
        .bind(flow.reauthenticate)
        .execute(&self.pool)
        .await?;
        Ok(id)
    }

    /// Consumes an OIDC state exactly once and returns its nonce and PKCE verifier.
    pub async fn consume_oidc_flow(&self, state: &str) -> Result<ConsumedOidcFlow, StoreError> {
        let row = sqlx::query(
            "UPDATE oidc_flows SET consumed_at=clock_timestamp()
             WHERE state_digest=$1 AND consumed_at IS NULL AND expires_at > clock_timestamp()
             RETURNING nonce_secret,pkce_verifier_secret,redirect_uri,return_to,reauthenticate,created_at",
        )
        .bind(secret_digest(state.as_bytes()).as_slice())
        .fetch_optional(&self.pool)
        .await?
        .ok_or(StoreError::Conflict)?;
        Ok(ConsumedOidcFlow {
            return_to: row.try_get("return_to")?,
            reauthenticate: row.try_get("reauthenticate")?,
            created_at: row.try_get("created_at")?,
            nonce: row.try_get("nonce_secret")?,
            pkce_verifier: row.try_get("pkce_verifier_secret")?,
            redirect_uri: row.try_get("redirect_uri")?,
        })
    }

    /// Creates a browser session using hashed session and CSRF secrets.
    pub async fn create_session(&self, session: &NewSession) -> Result<Uuid, StoreError> {
        let id = Uuid::new_v4();
        let mut transaction = self.pool.begin().await?;
        sqlx::query(
            "INSERT INTO web_sessions
             (id,session_digest,csrf_digest,subject,role,expires_at)
             VALUES ($1,$2,$3,$4,$5,$6)",
        )
        .bind(id)
        .bind(secret_digest(session.token.as_bytes()).as_slice())
        .bind(secret_digest(session.csrf_token.as_bytes()).as_slice())
        .bind(&session.subject)
        .bind(session.role.as_str())
        .bind(session.expires_at)
        .execute(&mut *transaction)
        .await?;
        append_audit(
            &mut transaction,
            None,
            &session.subject,
            "auth.session.create",
            "web_session",
            Some(id),
            "success",
            json!({"role":session.role}),
        )
        .await?;
        append_event(
            &mut transaction,
            None,
            "auth.session_created",
            "web_session",
            Some(id),
            json!({"role":session.role}),
        )
        .await?;
        transaction.commit().await?;
        Ok(id)
    }

    /// Loads a live session by its token digest.
    pub async fn session(&self, token: &str) -> Result<SessionRecord, StoreError> {
        let row = sqlx::query(
            "SELECT id,subject,role,csrf_digest,expires_at FROM web_sessions
             WHERE session_digest=$1 AND revoked_at IS NULL AND expires_at > clock_timestamp()",
        )
        .bind(secret_digest(token.as_bytes()).as_slice())
        .fetch_optional(&self.pool)
        .await?
        .ok_or(StoreError::NotFound)?;
        Ok(SessionRecord {
            id: row.try_get("id")?,
            subject: row.try_get("subject")?,
            role: Role::from_str(row.try_get::<String, _>("role")?.as_str())?,
            csrf_digest: row
                .try_get::<Vec<u8>, _>("csrf_digest")?
                .try_into()
                .map_err(|_| StoreError::Invalid("stored digest"))?,
            expires_at: row.try_get("expires_at")?,
        })
    }

    /// Revokes a browser session.
    pub async fn revoke_session(&self, token: &str, actor: &str) -> Result<(), StoreError> {
        let mut transaction = self.pool.begin().await?;
        let id: Option<Uuid> = sqlx::query_scalar(
            "UPDATE web_sessions SET revoked_at=clock_timestamp()
             WHERE session_digest=$1 AND revoked_at IS NULL RETURNING id",
        )
        .bind(secret_digest(token.as_bytes()).as_slice())
        .fetch_optional(&mut *transaction)
        .await?;
        if let Some(id) = id {
            append_audit(
                &mut transaction,
                None,
                actor,
                "auth.logout",
                "web_session",
                Some(id),
                "success",
                json!({}),
            )
            .await?;
            append_event(
                &mut transaction,
                None,
                "auth.session_revoked",
                "web_session",
                Some(id),
                json!({}),
            )
            .await?;
        }
        transaction.commit().await?;
        Ok(())
    }

    /// Irreversibly records first bootstrap completion.
    pub async fn complete_bootstrap(
        &self,
        actor: &str,
        oidc_configuration: &Value,
    ) -> Result<(), StoreError> {
        let mut transaction = self.pool.begin().await?;
        let result = sqlx::query(
            "INSERT INTO bootstrap_state (singleton,completed_at,actor,oidc_configuration)
             VALUES (true,clock_timestamp(),$1,$2) ON CONFLICT DO NOTHING",
        )
        .bind(actor)
        .bind(oidc_configuration)
        .execute(&mut *transaction)
        .await?;
        if result.rows_affected() == 1 {
            append_audit(
                &mut transaction,
                None,
                actor,
                "auth.bootstrap",
                "bootstrap",
                None,
                "success",
                json!({}),
            )
            .await?;
            append_event(
                &mut transaction,
                None,
                "auth.bootstrapped",
                "bootstrap",
                None,
                json!({}),
            )
            .await?;
            transaction.commit().await?;
            Ok(())
        } else {
            Err(StoreError::Conflict)
        }
    }
}
