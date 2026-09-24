impl Store {
    /// Creates a single-use ticket while storing only its SHA-256 digest.
    pub async fn create_join_ticket(
        &self,
        mesh_id: MeshId,
        token: &[u8],
        expires_at: OffsetDateTime,
        actor: &str,
    ) -> Result<TicketRecord, StoreError> {
        self.create_configured_join_ticket(
            mesh_id,
            token,
            expires_at,
            actor,
            &peerward_management::JoinSettings::default(),
        )
        .await
    }

    /// Creates an immutable admission contract; only its token digest is stored.
    pub async fn create_configured_join_ticket(
        &self,
        mesh_id: MeshId,
        token: &[u8],
        expires_at: OffsetDateTime,
        actor: &str,
        settings: &peerward_management::JoinSettings,
    ) -> Result<TicketRecord, StoreError> {
        settings
            .validate()
            .map_err(|_| StoreError::Invalid("invitation settings"))?;
        if token.len() < 16 || expires_at <= OffsetDateTime::now_utc() {
            return Err(StoreError::Invalid("ticket token or expiry"));
        }
        if settings.lifecycle.deadline().is_some_and(|until| {
            until
                <= u64::try_from(OffsetDateTime::now_utc().unix_timestamp())
                    .unwrap_or(u64::MAX)
                    .saturating_add(60)
        }) {
            return Err(StoreError::Invalid(
                "device deadline must allow at least 60 seconds for enrollment",
            ));
        }
        let _admission = self
            .join_admission
            .acquire()
            .await
            .map_err(|_| StoreError::Conflict)?;
        let id = TicketId::new();
        let digest = secret_digest(token);
        let mut transaction = self.pool.begin().await?;
        lock_join_mesh(&mut transaction, mesh_id.into_uuid()).await?;
        invitation_device_groups(
            &mut transaction,
            mesh_id.into_uuid(),
            &settings.device_groups,
        )
        .await?;
        sqlx::query(
            "INSERT INTO join_tickets (id, mesh_id, token_digest, expires_at, creator, settings)
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(id.into_uuid())
        .bind(mesh_id.into_uuid())
        .bind(digest.as_slice())
        .bind(expires_at)
        .bind(actor)
        .bind(
            serde_json::to_value(settings)
                .map_err(|_| StoreError::Invalid("invitation settings"))?,
        )
        .execute(&mut *transaction)
        .await?;
        mutation_records(
            &mut transaction,
            mesh_id,
            actor,
            "join_ticket.create",
            "join_ticket.created",
            "join_ticket",
            id.into_uuid(),
            json!({"ticket_id": id, "expires_at": expires_at}),
        )
        .await?;
        transaction.commit().await?;
        Ok(TicketRecord {
            id,
            version: 1,
            mesh_id,
            expires_at,
            consumed: false,
        })
    }
}
